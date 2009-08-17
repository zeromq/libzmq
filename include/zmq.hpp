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

#ifndef __ZMQ_HPP_INCLUDED__
#define __ZMQ_HPP_INCLUDED__

#include "zmq.h"

#include <assert.h>
#include <errno.h>
#include <exception>

namespace zmq
{

    typedef zmq_free_fn free_fn;

    enum message_type_t
    {
        message_data = 1 << 0,
        message_gap = 1 << ZMQ_GAP,
        message_delimiter = 1 << ZMQ_DELIMITER
    };

    class no_memory : public std::exception
    {
        virtual const char *what ()
        {
            return "Out of memory";
        }
    };

    class invalid_argument : public std::exception
    {
        virtual const char *what ()
        {
            return "Invalid argument";
        }
    };

    class too_many_threads : public std::exception
    {
        virtual const char *what ()
        {
            return "Too many threads";
        }
    };

    class address_in_use : public std::exception
    {
        virtual const char *what ()
        {
            return "Address in use";
        }
    };

    //  A message. Caution: Don't change the body of the message once you've
    //  copied it - the behaviour is undefined. Don't change the body of the
    //  received message either - other threads may be accessing it in parallel.

    class message_t : private zmq_msg
    {
        friend class socket_t;

    public:

        //  Creates message size_ bytes long.
        inline message_t (size_t size_ = 0)
        {
            int rc = zmq_msg_init_size (this, size_);
            if (rc == -1) {
                assert (errno == ENOMEM);
                throw no_memory ();
            }
        }

        //  Creates message from the supplied buffer. 0MQ takes care of
        //  deallocating the buffer once it is not needed. The deallocation
        //  function is supplied in ffn_ parameter. If ffn_ is NULL, no
        //  deallocation happens - this is useful for sending static buffers.
        inline message_t (void *data_, size_t size_, 
            free_fn *ffn_)
        {
            int rc = zmq_msg_init_data (this, data_, size_, ffn_);
            assert (rc == 0);
        }

        //  Destroys the message.
        inline ~message_t ()
        {
            int rc = zmq_msg_close (this);
            assert (rc == 0);
        }

        //  Destroys old content of the message and allocates buffer for the
        //  new message body. Having this as a separate function allows user
        //  to reuse once-allocated message for multiple times.
        inline void rebuild (size_t size_)
        {
            int rc = zmq_msg_close (this);
            assert (rc == 0);
            rc = zmq_msg_init_size (this, size_);
            if (rc == -1) {
                assert (errno == ENOMEM);
                throw no_memory ();
            }
        }

        //  Same as above, however, the message is rebuilt from the supplied
        //  buffer. See appropriate constructor for discussion of buffer
        //  deallocation mechanism.
        inline void rebuild (void *data_, size_t size_, free_fn *ffn_)
        {
            int rc = zmq_msg_close (this);
            assert (rc == 0);
            rc = zmq_msg_init_data (this, data_, size_, ffn_);
            assert (rc == 0);
        }

        //  Moves the message content from one message to the another. If the
        //  destination message have contained data prior to the operation
        //  these get deallocated. The source message will contain 0 bytes
        //  of data after the operation.
        inline void move_to (message_t *msg_)
        {
            int rc = zmq_msg_move (this, (zmq_msg*) msg_);
            assert (rc == 0);
        }

        //  Copies the message content from one message to the another. If the
        //  destination message have contained data prior to the operation
        //  these get deallocated.
        inline void copy_to (message_t *msg_)
        {
            int rc = zmq_msg_copy (this, (zmq_msg*) msg_);
            assert (rc == 0);
        }

        //  Returns message type.
        inline message_type_t type ()
        {
            return (message_type_t) (1 << zmq_msg_type (this));
        }

        //  Returns pointer to message's data buffer.
        inline void *data ()
        {
            return zmq_msg_data (this);
        }

        //  Returns the size of message data buffer.
        inline size_t size ()
        {
            return zmq_msg_size (this);
        }

    private:

        //  Disable implicit message copying, so that users won't use shared
        //  messages (less efficient) without being aware of the fact.
        message_t (const message_t&);
        void operator = (const message_t&);
    };

    class context_t
    {
        friend class socket_t;

    public:

        inline context_t (int app_threads_, int io_threads_)
        {
            ptr = zmq_init (app_threads_, io_threads_);
            if (ptr == NULL) {
                assert (errno == EINVAL);
                throw invalid_argument ();
            }
        }

        inline ~context_t ()
        {
            int rc = zmq_term (ptr);
            assert (rc == 0);
        }

    private:

        void *ptr;

        //  Disable copying.
        context_t (const context_t&);
        void operator = (const context_t&);
    };

    class socket_t
    {
    public:

        inline socket_t (context_t &context_, int type_ = 0)
        {
            ptr = zmq_socket (context_.ptr, type_);
            if (ptr == NULL) {
                assert (errno == EMFILE || errno == EINVAL);
                if (errno == EMFILE)
                    throw too_many_threads ();
                else
                    throw invalid_argument ();
            }
        }

        inline ~socket_t ()
        {
            int rc = zmq_close (ptr);
            assert (rc == 0);
        }

        template <typename T> inline void setsockopt (int option_, T &value_)
        {
            int rc = zmq_setsockopt (ptr, option_, (void*) &value_, sizeof (T));
            assert (rc == 0);
        }

        inline void bind (const char *addr_)
        {
            int rc = zmq_bind (ptr, addr_);
            if (rc == -1) {
                assert (errno == EINVAL || errno == EADDRINUSE);
                if (errno == EINVAL)
                    throw invalid_argument ();
                else
                    throw address_in_use ();
            }
        }

        inline void connect (const char *addr_)
        {
            int rc = zmq_connect (ptr, addr_);
            if (rc == -1) {
                assert (errno == EINVAL || errno == EADDRINUSE);
                if (errno == EINVAL)
                    throw invalid_argument ();
                else
                    throw address_in_use ();
            }
        }

        inline int send (message_t &msg_, int flags_ = 0)
        {
            int rc = zmq_send (ptr, &msg_, flags_);
            assert (rc == 0 || (rc == -1 && errno == EAGAIN));
            return rc;
        }

        inline void flush ()
        {
            int rc = zmq_flush (ptr);
            assert (rc == 0);
        }

        inline int recv (message_t *msg_, int flags_ = 0)
        {
            int rc = zmq_recv (ptr, msg_, flags_);
            assert (rc == 0 || (rc == -1 && errno == EAGAIN));
            return rc;
        }

    private:

        void *ptr;

        //  Disable copying.
        socket_t (const socket_t&);
        void operator = (const socket_t&);
    };

}

#endif
