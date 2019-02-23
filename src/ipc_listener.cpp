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
#include "ipc_listener.hpp"

#if !defined ZMQ_HAVE_WINDOWS && !defined ZMQ_HAVE_OPENVMS                     \
  && !defined ZMQ_HAVE_VXWORKS

#include <new>

#include <string.h>

#include "ipc_address.hpp"
#include "io_thread.hpp"
#include "config.hpp"
#include "err.hpp"
#include "ip.hpp"
#include "socket_base.hpp"
#include "address.hpp"

#include <unistd.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <sys/un.h>
#include <sys/stat.h>

#ifdef ZMQ_HAVE_LOCAL_PEERCRED
#include <sys/types.h>
#include <sys/ucred.h>
#endif
#ifdef ZMQ_HAVE_SO_PEERCRED
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#if defined ZMQ_HAVE_OPENBSD
#define ucred sockpeercred
#endif
#endif

const char *zmq::ipc_listener_t::tmp_env_vars[] = {
  "TMPDIR", "TEMPDIR", "TMP",
  0 // Sentinel
};


int zmq::ipc_listener_t::create_wildcard_address (std::string &path_,
                                                  std::string &file_)
{
    std::string tmp_path;

    // If TMPDIR, TEMPDIR, or TMP are available and are directories, create
    // the socket directory there.
    const char **tmp_env = tmp_env_vars;
    while (tmp_path.empty () && *tmp_env != 0) {
        char *tmpdir = getenv (*tmp_env);
        struct stat statbuf;

        // Confirm it is actually a directory before trying to use
        if (tmpdir != 0 && ::stat (tmpdir, &statbuf) == 0
            && S_ISDIR (statbuf.st_mode)) {
            tmp_path.assign (tmpdir);
            if (*(tmp_path.rbegin ()) != '/') {
                tmp_path.push_back ('/');
            }
        }

        // Try the next environment variable
        ++tmp_env;
    }

    // Append a directory name
    tmp_path.append ("tmpXXXXXX");

    // We need room for tmp_path + trailing NUL
    std::vector<char> buffer (tmp_path.length () + 1);
    strcpy (&buffer[0], tmp_path.c_str ());

#ifdef HAVE_MKDTEMP
    // Create the directory.  POSIX requires that mkdtemp() creates the
    // directory with 0700 permissions, meaning the only possible race
    // with socket creation could be the same user.  However, since
    // each socket is created in a directory created by mkdtemp(), and
    // mkdtemp() guarantees a unique directory name, there will be no
    // collision.
    if (mkdtemp (&buffer[0]) == 0) {
        return -1;
    }

    path_.assign (&buffer[0]);
    file_ = path_ + "/socket";
#else
    LIBZMQ_UNUSED (path_);
    int fd = mkstemp (&buffer[0]);
    if (fd == -1)
        return -1;
    ::close (fd);

    file_.assign (&buffer[0]);
#endif

    return 0;
}

zmq::ipc_listener_t::ipc_listener_t (io_thread_t *io_thread_,
                                     socket_base_t *socket_,
                                     const options_t &options_) :
    stream_listener_base_t (io_thread_, socket_, options_),
    _has_file (false)
{
}

void zmq::ipc_listener_t::in_event ()
{
    fd_t fd = accept ();

    //  If connection was reset by the peer in the meantime, just ignore it.
    //  TODO: Handle specific errors like ENFILE/EMFILE etc.
    if (fd == retired_fd) {
        _socket->event_accept_failed (
          make_unconnected_bind_endpoint_pair (_endpoint), zmq_errno ());
        return;
    }

    //  Create the engine object for this connection.
    create_engine (fd);
}

std::string
zmq::ipc_listener_t::get_socket_name (zmq::fd_t fd_,
                                      socket_end_t socket_end_) const
{
    return zmq::get_socket_name<ipc_address_t> (fd_, socket_end_);
}

int zmq::ipc_listener_t::set_local_address (const char *addr_)
{
    //  Create addr on stack for auto-cleanup
    std::string addr (addr_);

    //  Allow wildcard file
    if (options.use_fd == -1 && addr[0] == '*') {
        if (create_wildcard_address (_tmp_socket_dirname, addr) < 0) {
            return -1;
        }
    }

    //  Get rid of the file associated with the UNIX domain socket that
    //  may have been left behind by the previous run of the application.
    //  MUST NOT unlink if the FD is managed by the user, or it will stop
    //  working after the first client connects. The user will take care of
    //  cleaning up the file after the service is stopped.
    if (options.use_fd == -1) {
        ::unlink (addr.c_str ());
    }
    _filename.clear ();

    //  Initialise the address structure.
    ipc_address_t address;
    int rc = address.resolve (addr.c_str ());
    if (rc != 0) {
        if (!_tmp_socket_dirname.empty ()) {
            // We need to preserve errno to return to the user
            int tmp_errno = errno;
            ::rmdir (_tmp_socket_dirname.c_str ());
            _tmp_socket_dirname.clear ();
            errno = tmp_errno;
        }
        return -1;
    }

    address.to_string (_endpoint);

    if (options.use_fd != -1) {
        _s = options.use_fd;
    } else {
        //  Create a listening socket.
        _s = open_socket (AF_UNIX, SOCK_STREAM, 0);
        if (_s == -1) {
            if (!_tmp_socket_dirname.empty ()) {
                // We need to preserve errno to return to the user
                int tmp_errno = errno;
                ::rmdir (_tmp_socket_dirname.c_str ());
                _tmp_socket_dirname.clear ();
                errno = tmp_errno;
            }
            return -1;
        }

        //  Bind the socket to the file path.
        rc = bind (_s, const_cast<sockaddr *> (address.addr ()),
                   address.addrlen ());
        if (rc != 0)
            goto error;

        //  Listen for incoming connections.
        rc = listen (_s, options.backlog);
        if (rc != 0)
            goto error;
    }

    _filename = ZMQ_MOVE (addr);
    _has_file = true;

    _socket->event_listening (make_unconnected_bind_endpoint_pair (_endpoint),
                              _s);
    return 0;

error:
    int err = errno;
    close ();
    errno = err;
    return -1;
}

int zmq::ipc_listener_t::close ()
{
    zmq_assert (_s != retired_fd);
    int fd_for_event = _s;
    int rc = ::close (_s);
    errno_assert (rc == 0);

    _s = retired_fd;

    if (_has_file && options.use_fd == -1) {
        if (!_tmp_socket_dirname.empty ()) {
            //  TODO review this behaviour, it is inconsistent with the use of
            //  unlink in open since 656cdb959a7482c45db979c1d08ede585d12e315;
            //  however, we must at least remove the file before removing the
            //  directory, otherwise it will always fail
            rc = ::unlink (_filename.c_str ());

            if (rc == 0) {
                rc = ::rmdir (_tmp_socket_dirname.c_str ());
                _tmp_socket_dirname.clear ();
            }
        }

        if (rc != 0) {
            _socket->event_close_failed (
              make_unconnected_bind_endpoint_pair (_endpoint), zmq_errno ());
            return -1;
        }
    }

    _socket->event_closed (make_unconnected_bind_endpoint_pair (_endpoint),
                           fd_for_event);
    return 0;
}

#if defined ZMQ_HAVE_SO_PEERCRED

bool zmq::ipc_listener_t::filter (fd_t sock_)
{
    if (options.ipc_uid_accept_filters.empty ()
        && options.ipc_pid_accept_filters.empty ()
        && options.ipc_gid_accept_filters.empty ())
        return true;

    struct ucred cred;
    socklen_t size = sizeof (cred);

    if (getsockopt (sock_, SOL_SOCKET, SO_PEERCRED, &cred, &size))
        return false;
    if (options.ipc_uid_accept_filters.find (cred.uid)
          != options.ipc_uid_accept_filters.end ()
        || options.ipc_gid_accept_filters.find (cred.gid)
             != options.ipc_gid_accept_filters.end ()
        || options.ipc_pid_accept_filters.find (cred.pid)
             != options.ipc_pid_accept_filters.end ())
        return true;

    struct passwd *pw;
    struct group *gr;

    if (!(pw = getpwuid (cred.uid)))
        return false;
    for (options_t::ipc_gid_accept_filters_t::const_iterator it =
           options.ipc_gid_accept_filters.begin ();
         it != options.ipc_gid_accept_filters.end (); it++) {
        if (!(gr = getgrgid (*it)))
            continue;
        for (char **mem = gr->gr_mem; *mem; mem++) {
            if (!strcmp (*mem, pw->pw_name))
                return true;
        }
    }
    return false;
}

#elif defined ZMQ_HAVE_LOCAL_PEERCRED

bool zmq::ipc_listener_t::filter (fd_t sock_)
{
    if (options.ipc_uid_accept_filters.empty ()
        && options.ipc_gid_accept_filters.empty ())
        return true;

    struct xucred cred;
    socklen_t size = sizeof (cred);

    if (getsockopt (sock_, 0, LOCAL_PEERCRED, &cred, &size))
        return false;
    if (cred.cr_version != XUCRED_VERSION)
        return false;
    if (options.ipc_uid_accept_filters.find (cred.cr_uid)
        != options.ipc_uid_accept_filters.end ())
        return true;
    for (int i = 0; i < cred.cr_ngroups; i++) {
        if (options.ipc_gid_accept_filters.find (cred.cr_groups[i])
            != options.ipc_gid_accept_filters.end ())
            return true;
    }

    return false;
}

#endif

zmq::fd_t zmq::ipc_listener_t::accept ()
{
    //  Accept one connection and deal with different failure modes.
    //  The situation where connection cannot be accepted due to insufficient
    //  resources is considered valid and treated by ignoring the connection.
    zmq_assert (_s != retired_fd);
#if defined ZMQ_HAVE_SOCK_CLOEXEC && defined HAVE_ACCEPT4
    fd_t sock = ::accept4 (_s, NULL, NULL, SOCK_CLOEXEC);
#else
    fd_t sock = ::accept (_s, NULL, NULL);
#endif
    if (sock == -1) {
        errno_assert (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR
                      || errno == ECONNABORTED || errno == EPROTO
                      || errno == ENFILE);
        return retired_fd;
    }

    make_socket_noninheritable (sock);

    // IPC accept() filters
#if defined ZMQ_HAVE_SO_PEERCRED || defined ZMQ_HAVE_LOCAL_PEERCRED
    if (!filter (sock)) {
        int rc = ::close (sock);
        errno_assert (rc == 0);
        return retired_fd;
    }
#endif

    if (zmq::set_nosigpipe (sock)) {
#ifdef ZMQ_HAVE_WINDOWS
        int rc = closesocket (sock);
        wsa_assert (rc != SOCKET_ERROR);
#else
        int rc = ::close (sock);
        errno_assert (rc == 0);
#endif
        return retired_fd;
    }

    return sock;
}

#endif
