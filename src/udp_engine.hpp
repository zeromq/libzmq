
#ifndef __ZMQ_UDP_ENGINE_HPP_INCLUDED__
#define __ZMQ_UDP_ENGINE_HPP_INCLUDED__

#include "io_object.hpp"
#include "i_engine.hpp"
#include "address.hpp"
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
    bool restart_input ();

    //  This method is called by the session to signalise that there
    //  are messages to send available.
    void restart_output ();

    void zap_msg_available (){};

    void in_event ();
    void out_event ();

    const endpoint_uri_pair_t &get_endpoint () const;

  private:
    int resolve_raw_address (char *addr_, size_t length_);
    void sockaddr_to_msg (zmq::msg_t *msg_, sockaddr_in *addr_);

    const endpoint_uri_pair_t _empty_endpoint;

    bool _plugged;

    fd_t _fd;
    session_base_t *_session;
    handle_t _handle;
    address_t *_address;

    options_t _options;

    sockaddr_in _raw_address;
    const struct sockaddr *_out_address;
    zmq_socklen_t _out_address_len;

    char _out_buffer[MAX_UDP_MSG];
    char _in_buffer[MAX_UDP_MSG];
    bool _send_enabled;
    bool _recv_enabled;
};
}

#endif
