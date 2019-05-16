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

#ifndef __ZMQ_IPC_LISTENER_HPP_INCLUDED__
#define __ZMQ_IPC_LISTENER_HPP_INCLUDED__

#if !defined ZMQ_HAVE_WINDOWS && !defined ZMQ_HAVE_OPENVMS                     \
  && !defined ZMQ_HAVE_VXWORKS

#include <string>

#include "fd.hpp"
#include "stream_listener_base.hpp"

namespace zmq
{
class ipc_listener_t : public stream_listener_base_t
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

    // Create wildcard path address
    static int create_wildcard_address (std::string &path_, std::string &file_);

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
    //  the UNIX domain socket
    std::string _tmp_socket_dirname;

    //  Name of the file associated with the UNIX domain address.
    std::string _filename;

    // Acceptable temporary directory environment variables
    static const char *tmp_env_vars[];

    ipc_listener_t (const ipc_listener_t &);
    const ipc_listener_t &operator= (const ipc_listener_t &);
};
}

#endif

#endif
