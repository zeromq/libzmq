/* SPDX-License-Identifier: MPL-2.0 */

#ifndef __ZMQ_IPC_LISTENER_HPP_INCLUDED__
#define __ZMQ_IPC_LISTENER_HPP_INCLUDED__

#if defined ZMQ_HAVE_IPC

#include <string>

#include "fd.hpp"
#include "stream_listener_base.hpp"

namespace zmq
{
class ipc_listener_t ZMQ_FINAL : public stream_listener_base_t
{
  public:
    ipc_listener_t (zmq::io_thread_t *io_thread_,
                    zmq::socket_base_t *socket_,
                    const options_t &options_);

    //  Set address to listen on.
    int set_local_address (const char *addr_);

  protected:
    std::string get_socket_name (fd_t fd_, socket_end_t socket_end_) const;

  private:
    //  Handlers for I/O events.
    void in_event ();

    //  Filter new connections if the OS provides a mechanism to get
    //  the credentials of the peer process.  Called from accept().
#if defined ZMQ_HAVE_SO_PEERCRED || defined ZMQ_HAVE_LOCAL_PEERCRED
    bool filter (fd_t sock_);
#endif

    int close ();

    //  Accept the new connection. Returns the file descriptor of the
    //  newly created connection. The function may return retired_fd
    //  if the connection was dropped while waiting in the listen backlog.
    fd_t accept ();

    //  True, if the underlying file for UNIX domain socket exists.
    bool _has_file;

    //  Name of the temporary directory (if any) that has the
    //  UNIX domain socket
    std::string _tmp_socket_dirname;

    //  Name of the file associated with the UNIX domain address.
    std::string _filename;

    ZMQ_NON_COPYABLE_NOR_MOVABLE (ipc_listener_t)
};
}

#endif

#endif
