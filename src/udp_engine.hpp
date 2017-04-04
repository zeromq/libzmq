
#ifndef __ZMQ_UDP_ENGINE_HPP_INCLUDED__
#define __ZMQ_UDP_ENGINE_HPP_INCLUDED__

#include "io_object.hpp"
#include "i_engine.hpp"
#include "address.hpp"
#include "udp_address.hpp"
#include "msg.hpp"

#define MAX_UDP_MSG 8192

namespace zmq
{
    class io_thread_t;
    class session_base_t;

    class udp_engine_t : public io_object_t, public i_engine
    {
        public:
            udp_engine_t (const options_t &options_);
            ~udp_engine_t ();

            int init (address_t *address_, bool send_, bool recv_);

            //  i_engine interface implementation.
            //  Plug the engine to the session.
            void plug (zmq::io_thread_t *io_thread_, class session_base_t *session_);

            //  Terminate and deallocate the engine. Note that 'detached'
            //  events are not fired on termination.
            void terminate ();

            //  This method is called by the session to signalise that more
            //  messages can be written to the pipe.
            void restart_input ();

            //  This method is called by the session to signalise that there
            //  are messages to send available.
            void restart_output ();

            void zap_msg_available () {};

            void in_event ();
            void out_event ();

        private:

            int resolve_raw_address (char *addr_, size_t length_);
            void sockaddr_to_msg (zmq::msg_t *msg, sockaddr_in* addr);

            bool plugged;

            fd_t fd;
            session_base_t* session;
            handle_t handle;
            address_t *address;

            options_t options;

            sockaddr_in raw_address;
            const struct sockaddr* out_address;
            socklen_t out_addrlen;

            unsigned char out_buffer[MAX_UDP_MSG];
            unsigned char in_buffer[MAX_UDP_MSG];
            bool send_enabled;
            bool recv_enabled;
    };
}

#endif
