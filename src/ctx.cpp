/*
    Copyright (c) 2007-2010 iMatix Corporation

    This file is part of 0MQ.

    0MQ is free software; you can redistribute it and/or modify it under
    the terms of the Lesser GNU General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    0MQ is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    Lesser GNU General Public License for more details.

    You should have received a copy of the Lesser GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <new>
#include <string.h>

#include "ctx.hpp"
#include "socket_base.hpp"
#include "io_thread.hpp"
#include "platform.hpp"
#include "err.hpp"
#include "pipe.hpp"

#if defined ZMQ_HAVE_WINDOWS
#include "windows.h"
#else
#include "unistd.h"
#endif

zmq::ctx_t::ctx_t (uint32_t io_threads_) :
    no_sockets_notify (false)
{
    int rc;

#ifdef ZMQ_HAVE_WINDOWS
    //  Intialise Windows sockets. Note that WSAStartup can be called multiple
    //  times given that WSACleanup will be called for each WSAStartup.
    WORD version_requested = MAKEWORD (2, 2);
    WSADATA wsa_data;
    rc = WSAStartup (version_requested, &wsa_data);
    zmq_assert (rc == 0);
    zmq_assert (LOBYTE (wsa_data.wVersion) == 2 &&
        HIBYTE (wsa_data.wVersion) == 2);
#endif

    //  Initialise the array of signalers.
    slot_count = max_sockets + io_threads_;
    slots = (signaler_t**) malloc (sizeof (signaler_t*) * slot_count);
    zmq_assert (slots);

    //  Create I/O thread objects and launch them.
    for (uint32_t i = 0; i != io_threads_; i++) {
        io_thread_t *io_thread = new (std::nothrow) io_thread_t (this, i);
        zmq_assert (io_thread);
        io_threads.push_back (io_thread);
        slots [i] = io_thread->get_signaler ();
        io_thread->start ();
    }

    //  In the unused part of the slot array, create a list of empty slots.
    for (int32_t i = (int32_t) slot_count - 1;
          i >= (int32_t) io_threads_; i--) {
        empty_slots.push_back (i);
        slots [i] = NULL;
    }

    //  Create the logging infrastructure.
    log_socket = create_socket (ZMQ_PUB);
    zmq_assert (log_socket);
    rc = log_socket->bind ("sys://log");
    zmq_assert (rc == 0);
}

zmq::ctx_t::~ctx_t ()
{
    //  Check that there are no remaining open or zombie sockets.
    zmq_assert (sockets.empty ());
    zmq_assert (zombies.empty ());

    //  Ask I/O threads to terminate. If stop signal wasn't sent to I/O
    //  thread subsequent invocation of destructor would hang-up.
    for (io_threads_t::size_type i = 0; i != io_threads.size (); i++)
        io_threads [i]->stop ();

    //  Wait till I/O threads actually terminate.
    for (io_threads_t::size_type i = 0; i != io_threads.size (); i++)
        delete io_threads [i];

    //  Deallocate the array of slot. No special work is
    //  needed as signalers themselves were deallocated with their
    //  corresponding io_thread/socket objects.
    free (slots);
    
#ifdef ZMQ_HAVE_WINDOWS
    //  On Windows, uninitialise socket layer.
    int rc = WSACleanup ();
    wsa_assert (rc != SOCKET_ERROR);
#endif
}

int zmq::ctx_t::terminate ()
{
    //  Close the logging infrastructure.
    log_sync.lock ();
    int rc = log_socket->close ();
    zmq_assert (rc == 0);
    log_socket = NULL;
    log_sync.unlock ();

    //  First send stop command to sockets so that any
    //  blocking calls are interrupted.
    slot_sync.lock ();
    for (sockets_t::size_type i = 0; i != sockets.size (); i++)
        sockets [i]->stop ();
    if (!sockets.empty ())
        no_sockets_notify = true;
    slot_sync.unlock ();

    //  Find out whether there are any open sockets to care about.
    //  If there are open sockets, sleep till they are closed. Note that we can
    //  use no_sockets_notify safely out of the critical section as once set
    //  its value is never changed again.
    if (no_sockets_notify)
        no_sockets_sync.wait ();

    //  Note that the lock won't block anyone here. There's noone else having
    //  open sockets anyway. The only purpose of the lock is to double-check all
    //  the CPU caches have been synchronised.
    slot_sync.lock ();

    //  At this point there should be no active sockets. What we have is a set
    //  of zombies waiting to be dezombified.
    zmq_assert (sockets.empty ());

    //  Get rid of remaining zombie sockets. 
    while (!zombies.empty ()) {
        dezombify ();

        //  Sleep for 1ms not to end up busy-looping in the case the I/O threads
        //  are still busy sending data. We can possibly add a grand poll here
        //  (polling for fds associated with all the zombie sockets), but it's
        //  probably not worth of implementing it.
#if defined ZMQ_HAVE_WINDOWS
        Sleep (1);
#else
        usleep (1000);
#endif
    }
    slot_sync.unlock ();

    //  Deallocate the resources.
    delete this;

    return 0;
}

zmq::socket_base_t *zmq::ctx_t::create_socket (int type_)
{
    slot_sync.lock ();

    //  Free the slots, if possible.
    dezombify ();

    //  If max_sockets limit was reached, return error.
    if (empty_slots.empty ()) {
        slot_sync.unlock ();
        errno = EMFILE;
        return NULL;
    }

    //  Choose a slot for the socket.
    uint32_t slot = empty_slots.back ();
    empty_slots.pop_back ();

    //  Create the socket and register its signaler.
    socket_base_t *s = socket_base_t::create (type_, this, slot);
    if (!s) {
        empty_slots.push_back (slot);
        slot_sync.unlock ();
        return NULL;
    }
    sockets.push_back (s);
    slots [slot] = s->get_signaler ();

    slot_sync.unlock ();

    return s;
}

void zmq::ctx_t::zombify_socket (socket_base_t *socket_)
{
    //  Zombification of socket basically means that its ownership is tranferred
    //  from the application that created it to the context.

    //  Note that the lock provides the memory barrier needed to migrate
    //  zombie-to-be socket from it's native thread to shared data area
    //  synchronised by slot_sync.
    slot_sync.lock ();
    sockets.erase (socket_);
    zombies.push_back (socket_);

    //  Try to get rid of at least some zombie sockets at this point.
    dezombify ();

    //  If shutdown thread is interested in notification about no more
    //  open sockets, notify it now.
    if (sockets.empty () && no_sockets_notify)
        no_sockets_sync.post ();

    slot_sync.unlock ();
}

void zmq::ctx_t::send_command (uint32_t slot_, const command_t &command_)
{
    slots [slot_]->send (command_);
}

zmq::io_thread_t *zmq::ctx_t::choose_io_thread (uint64_t affinity_)
{
    if (io_threads.empty ())
        return NULL;

    //  Find the I/O thread with minimum load.
    int min_load = -1;
    io_threads_t::size_type result = 0;
    for (io_threads_t::size_type i = 0; i != io_threads.size (); i++) {
        if (!affinity_ || (affinity_ & (uint64_t (1) << i))) {
            int load = io_threads [i]->get_load ();
            if (min_load == -1 || load < min_load) {
                min_load = load;
                result = i;
            }
        }
    }
    zmq_assert (min_load != -1);
    return io_threads [result];
}

int zmq::ctx_t::register_endpoint (const char *addr_,
    socket_base_t *socket_)
{
    endpoints_sync.lock ();

    bool inserted = endpoints.insert (endpoints_t::value_type (
        std::string (addr_), socket_)).second;
    if (!inserted) {
        errno = EADDRINUSE;
        endpoints_sync.unlock ();
        return -1;
    }

    endpoints_sync.unlock ();
    return 0;
}

void zmq::ctx_t::unregister_endpoints (socket_base_t *socket_)
{
    endpoints_sync.lock ();

    endpoints_t::iterator it = endpoints.begin ();
    while (it != endpoints.end ()) {
        if (it->second == socket_) {
            endpoints_t::iterator to_erase = it;
            it++;
            endpoints.erase (to_erase);
            continue;
        }
        it++;
    }
        
    endpoints_sync.unlock ();
}

zmq::socket_base_t *zmq::ctx_t::find_endpoint (const char *addr_)
{
     endpoints_sync.lock ();

     endpoints_t::iterator it = endpoints.find (addr_);
     if (it == endpoints.end ()) {
         endpoints_sync.unlock ();
         errno = ECONNREFUSED;
         return NULL;
     }
     socket_base_t *endpoint = it->second;

     //  Increment the command sequence number of the peer so that it won't
     //  get deallocated until "bind" command is issued by the caller.
     //  The subsequent 'bind' has to be called with inc_seqnum parameter
     //  set to false, so that the seqnum isn't incremented twice.
     endpoint->inc_seqnum ();

     endpoints_sync.unlock ();
     return endpoint;
}

void zmq::ctx_t::log (zmq_msg_t *msg_)
{
    //  At this  point we migrate the log socket to the current thread.
    //  We rely on mutex for executing the memory barrier.
    log_sync.lock ();
    if (log_socket)
        log_socket->send (msg_, 0);
    log_sync.unlock ();
}

void zmq::ctx_t::dezombify ()
{
    //  Try to dezombify each zombie in the list. Note that caller is
    //  responsible for calling this method in the slot_sync critical section.
    for (zombies_t::iterator it = zombies.begin (); it != zombies.end ();) {
        uint32_t slot = (*it)->get_slot ();
        if ((*it)->dezombify ()) {
#if defined _MSC_VER

            //  HP implementation of STL requires doing it this way...
            it = zombies.erase (it);
#else
            zombies.erase (it);
#endif
            empty_slots.push_back (slot);
            slots [slot] = NULL;    
        }
        else
            it++;
    }
}

