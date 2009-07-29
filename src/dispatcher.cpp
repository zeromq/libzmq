/*
    Copyright (c) 2007-2009 FastMQ Inc.

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

#include "../include/zs.h"

#include "dispatcher.hpp"
#include "app_thread.hpp"
#include "io_thread.hpp"
#include "platform.hpp"
#include "err.hpp"
#include "pipe.hpp"
#include "pipe_reader.hpp"
#include "pipe_writer.hpp"
#include "session.hpp"
#include "i_api.hpp"

#if defined ZS_HAVE_WINDOWS
#include "windows.h"
#endif

zs::dispatcher_t::dispatcher_t (int app_threads_, int io_threads_)
{
#ifdef ZS_HAVE_WINDOWS
    //  Intialise Windows sockets. Note that WSAStartup can be called multiple
    //  times given that WSACleanup will be called for each WSAStartup.
    WORD version_requested = MAKEWORD (2, 2);
    WSADATA wsa_data;
    int rc = WSAStartup (version_requested, &wsa_data);
    zs_assert (rc == 0);
    zs_assert (LOBYTE (wsa_data.wVersion) == 2 &&
        HIBYTE (wsa_data.wVersion) == 2);
#endif

    //  Create application thread proxies.
    for (int i = 0; i != app_threads_; i++) {
        app_thread_t *app_thread = new app_thread_t (this, i);
        zs_assert (app_thread);
        app_threads.push_back (app_thread);
        signalers.push_back (app_thread->get_signaler ());
    }

    //  Create I/O thread objects.
    for (int i = 0; i != io_threads_; i++) {
        io_thread_t *io_thread = new io_thread_t (this, i + app_threads_);
        zs_assert (io_thread);
        io_threads.push_back (io_thread);
        signalers.push_back (io_thread->get_signaler ());
    }

    //  Create command pipe matrix.
    command_pipes = new command_pipe_t [signalers.size () * signalers.size ()];
    zs_assert (command_pipes);

    //  Launch I/O threads.
    for (int i = 0; i != io_threads_; i++)
        io_threads [i]->start ();
}

void zs::dispatcher_t::shutdown ()
{
     delete this;
}

zs::dispatcher_t::~dispatcher_t ()
{
    //  Ask I/O threads to terminate.
    for (io_threads_t::size_type i = 0; i != io_threads.size (); i++)
        io_threads [i]->stop ();

    //  Wait till I/O threads actually terminate.
    for (io_threads_t::size_type i = 0; i != io_threads.size (); i++)
        io_threads [i]->join ();

    //  At this point the current thread is the only thread with access to
    //  our internal data. Deallocation will be done exclusively in this thread.
    for (app_threads_t::size_type i = 0; i != app_threads.size (); i++)
        app_threads [i]->shutdown ();
    for (io_threads_t::size_type i = 0; i != io_threads.size (); i++)
        io_threads [i]->shutdown ();

    delete [] command_pipes;

    //  Deallocate all the pipes, pipe readers and pipe writers.
    for (pipes_t::iterator it = pipes.begin (); it != pipes.end (); it++) {
        delete it->pipe;
        delete it->reader;
        delete it->writer;
    }

#ifdef ZS_HAVE_WINDOWS
    //  On Windows, uninitialise socket layer.
    int rc = WSACleanup ();
    wsa_assert (rc != SOCKET_ERROR);
#endif
}

int zs::dispatcher_t::thread_slot_count ()
{
    return signalers.size ();
}

zs::i_api *zs::dispatcher_t::create_socket (int type_)
{
    threads_sync.lock ();
    app_thread_t *thread = choose_app_thread ();
    if (!thread) {
        threads_sync.unlock ();
        return NULL;
    }
    i_api *s = thread->create_socket (type_);
    threads_sync.unlock ();
    return s;
}

zs::app_thread_t *zs::dispatcher_t::choose_app_thread ()
{
    //  Check whether thread ID is already assigned. If so, return it.
    for (app_threads_t::size_type i = 0; i != app_threads.size (); i++)
        if (app_threads [i]->is_current ())
            return app_threads [i];

    //  Check whether there's an unused thread slot in the dispatcher.
    for (app_threads_t::size_type i = 0; i != app_threads.size (); i++)
        if (app_threads [i]->make_current ())
            return app_threads [i];

    //  Thread limit was exceeded.
    errno = EMFILE;
    return NULL;
}

zs::io_thread_t *zs::dispatcher_t::choose_io_thread (uint64_t taskset_)
{
    zs_assert (io_threads.size () > 0);

    //  Find the I/O thread with minimum load.
    int min_load = io_threads [0]->get_load ();
    io_threads_t::size_type result = 0;
    for (io_threads_t::size_type i = 1; i != io_threads.size (); i++) {
        if (!taskset_ || (taskset_ & (uint64_t (1) << i))) {
            int load = io_threads [i]->get_load ();
            if (load < min_load) {
                min_load = load;
                result = i;
            }
        }
    }

    return io_threads [result];
}

void zs::dispatcher_t::create_pipe (object_t *reader_parent_,
    object_t *writer_parent_, uint64_t hwm_, uint64_t lwm_,
    pipe_reader_t **reader_, pipe_writer_t **writer_)
{
    //  Create the pipe, reader & writer triple.
    pipe_t *pipe = new pipe_t;
    zs_assert (pipe);
    pipe_reader_t *reader = new pipe_reader_t (reader_parent_, pipe,
        hwm_, lwm_);
    zs_assert (reader);
    pipe_writer_t *writer = new pipe_writer_t (writer_parent_, pipe, reader,
        hwm_, lwm_);
    zs_assert (writer);
    reader->set_peer (writer);

    //  Store the pipe in the repository.
    pipe_info_t info = {pipe, reader, writer};
    pipes_sync.lock ();
    pipe->set_index (pipes.size ());
    pipes.push_back (info);
    pipes_sync.unlock ();

    *reader_ = reader;
    *writer_ = writer;
}

void zs::dispatcher_t::destroy_pipe (pipe_t *pipe_)
{
    //  Remove the pipe from the repository.
    pipe_info_t info;
    pipes_sync.lock ();
    pipes_t::size_type i = pipe_->get_index ();
    info = pipes [i];
    pipes [i] = pipes.back ();
    pipes.pop_back ();
    pipes_sync.unlock ();

    //  Deallocate the pipe and associated pipe reader & pipe writer.
    zs_assert (info.pipe == pipe_);
    delete info.pipe;
    delete info.reader;
    delete info.writer;
}

int zs::dispatcher_t::register_inproc_endpoint (const char *endpoint_,
    session_t *session_)
{
   inproc_endpoint_sync.lock ();
   inproc_endpoints_t::iterator it = inproc_endpoints.find (endpoint_);

   if (it != inproc_endpoints.end ()) {
       inproc_endpoint_sync.unlock ();
       errno = EADDRINUSE;
       return -1;
   }

   inproc_endpoints.insert (std::make_pair (endpoint_, session_));

   inproc_endpoint_sync.unlock ();
   return 0;
}

zs::object_t *zs::dispatcher_t::get_inproc_endpoint (const char *endpoint_)
{
    inproc_endpoint_sync.lock ();
    inproc_endpoints_t::iterator it = inproc_endpoints.find (endpoint_);

    if (it == inproc_endpoints.end ()) {
        inproc_endpoint_sync.unlock ();
        errno = EADDRNOTAVAIL;
        return NULL;
    }

    it->second->inc_seqnum ();
    object_t *session = it->second;

    inproc_endpoint_sync.unlock ();
    return session;
}

void zs::dispatcher_t::unregister_inproc_endpoints (session_t *session_)
{
    inproc_endpoint_sync.lock ();

    //  Remove the connection from the repository.
    //  TODO: Yes, the algorithm has O(n^2) complexity. Should be O(log n).
    for (inproc_endpoints_t::iterator it = inproc_endpoints.begin ();
          it != inproc_endpoints.end ();) {
        if (it->second == session_) {
            inproc_endpoints.erase (it);
            it = inproc_endpoints.begin ();
        }
        else
            it++;
    }
        
    inproc_endpoint_sync.unlock ();
}

