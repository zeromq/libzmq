/*
    Copyright (c) 2007-2016 Contributors as noted in the AUTHORS file

    This file is part of libzmq, the ZeroMQ core engine in C++.

    libzmq is free software; you can redistribute it and/or modify it under
    the terms of the GNU Lesser General Public License (LGPL) as published
    by the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    As a special exception, the Contributors give you permission to link
    this library with independent modules to produce an executable,
    regardless of the license terms of these independent modules, and to
    copy and distribute the resulting executable under terms of your choice,
    provided that you also meet, for each linked independent module, the
    terms and conditions of the license of that module. An independent
    module is a module which is not derived from or based on this library.
    If you modify this library, you must extend this exception to your
    version of the library.

    libzmq is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
    FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public
    License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "precompiled.hpp"
#include "own.hpp"
#include "err.hpp"
#include "io_thread.hpp"

zmq::own_t::own_t (class ctx_t *parent_, uint32_t tid_) :
    object_t (parent_, tid_),
    _terminating (false),
    _sent_seqnum (0),
    _processed_seqnum (0),
    _owner (NULL),
    _term_acks (0)
{
}

zmq::own_t::own_t (io_thread_t *io_thread_, const options_t &options_) :
    object_t (io_thread_),
    options (options_),
    _terminating (false),
    _sent_seqnum (0),
    _processed_seqnum (0),
    _owner (NULL),
    _term_acks (0)
{
}

zmq::own_t::~own_t ()
{
}

void zmq::own_t::set_owner (own_t *owner_)
{
    zmq_assert (!_owner);
    _owner = owner_;
}

void zmq::own_t::inc_seqnum ()
{
    //  This function may be called from a different thread!
    _sent_seqnum.add (1);
}

void zmq::own_t::process_seqnum ()
{
    //  Catch up with counter of processed commands.
    _processed_seqnum++;

    //  We may have catched up and still have pending terms acks.
    check_term_acks ();
}

void zmq::own_t::launch_child (own_t *object_)
{
    //  Specify the owner of the object.
    object_->set_owner (this);

    //  Plug the object into the I/O thread.
    send_plug (object_);

    //  Take ownership of the object.
    send_own (this, object_);
}

void zmq::own_t::term_child (own_t *object_)
{
    process_term_req (object_);
}

void zmq::own_t::process_term_req (own_t *object_)
{
    //  When shutting down we can ignore termination requests from owned
    //  objects. The termination request was already sent to the object.
    if (_terminating)
        return;

    //  If not found, we assume that termination request was already sent to
    //  the object so we can safely ignore the request.
    if (0 == _owned.erase (object_))
        return;

    //  If I/O object is well and alive let's ask it to terminate.
    register_term_acks (1);

    //  Note that this object is the root of the (partial shutdown) thus, its
    //  value of linger is used, rather than the value stored by the children.
    send_term (object_, options.linger.load ());
}

void zmq::own_t::process_own (own_t *object_)
{
    //  If the object is already being shut down, new owned objects are
    //  immediately asked to terminate. Note that linger is set to zero.
    if (_terminating) {
        register_term_acks (1);
        send_term (object_, 0);
        return;
    }

    //  Store the reference to the owned object.
    _owned.insert (object_);
}

void zmq::own_t::terminate ()
{
    //  If termination is already underway, there's no point
    //  in starting it anew.
    if (_terminating)
        return;

    //  As for the root of the ownership tree, there's no one to terminate it,
    //  so it has to terminate itself.
    if (!_owner) {
        process_term (options.linger.load ());
        return;
    }

    //  If I am an owned object, I'll ask my owner to terminate me.
    send_term_req (_owner, this);
}

bool zmq::own_t::is_terminating ()
{
    return _terminating;
}

void zmq::own_t::process_term (int linger_)
{
    //  Double termination should never happen.
    zmq_assert (!_terminating);

    //  Send termination request to all owned objects.
    for (owned_t::iterator it = _owned.begin (), end = _owned.end (); it != end;
         ++it)
        send_term (*it, linger_);
    register_term_acks (static_cast<int> (_owned.size ()));
    _owned.clear ();

    //  Start termination process and check whether by chance we cannot
    //  terminate immediately.
    _terminating = true;
    check_term_acks ();
}

void zmq::own_t::register_term_acks (int count_)
{
    _term_acks += count_;
}

void zmq::own_t::unregister_term_ack ()
{
    zmq_assert (_term_acks > 0);
    _term_acks--;

    //  This may be a last ack we are waiting for before termination...
    check_term_acks ();
}

void zmq::own_t::process_term_ack ()
{
    unregister_term_ack ();
}

void zmq::own_t::check_term_acks ()
{
    if (_terminating && _processed_seqnum == _sent_seqnum.get ()
        && _term_acks == 0) {
        //  Sanity check. There should be no active children at this point.
        zmq_assert (_owned.empty ());

        //  The root object has nobody to confirm the termination to.
        //  Other nodes will confirm the termination to the owner.
        if (_owner)
            send_term_ack (_owner);

        //  Deallocate the resources.
        process_destroy ();
    }
}

void zmq::own_t::process_destroy ()
{
    delete this;
}
