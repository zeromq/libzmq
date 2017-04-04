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

#if !defined ZMQ_HAVE_WINDOWS && !defined ZMQ_HAVE_OPENVMS

#include <new>

#include <string.h>

#include "stream_engine.hpp"
#include "ipc_address.hpp"
#include "io_thread.hpp"
#include "session_base.hpp"
#include "config.hpp"
#include "err.hpp"
#include "ip.hpp"
#include "socket_base.hpp"

#include <unistd.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <sys/un.h>
#include <sys/stat.h>

#ifdef ZMQ_HAVE_LOCAL_PEERCRED
#   include <sys/types.h>
#   include <sys/ucred.h>
#endif
#ifdef ZMQ_HAVE_SO_PEERCRED
#   include <sys/types.h>
#   include <pwd.h>
#   include <grp.h>
#   if defined ZMQ_HAVE_OPENBSD
#       define ucred sockpeercred
#   endif
#endif

const char *zmq::ipc_listener_t::tmp_env_vars[] = {
  "TMPDIR",
  "TEMPDIR",
  "TMP",
  0  // Sentinel
};

int zmq::ipc_listener_t::create_wildcard_address(std::string& path_,
        std::string& file_)
{
    std::string tmp_path;

    // If TMPDIR, TEMPDIR, or TMP are available and are directories, create
    // the socket directory there.
    const char **tmp_env = tmp_env_vars;
    while ( tmp_path.empty() && *tmp_env != 0 ) {
        char *tmpdir = getenv(*tmp_env);
        struct stat statbuf;

        // Confirm it is actually a directory before trying to use
        if ( tmpdir != 0 && ::stat(tmpdir, &statbuf) == 0 && S_ISDIR(statbuf.st_mode) ) {
            tmp_path.assign(tmpdir);
            if ( *(tmp_path.rbegin()) != '/' ) {
                tmp_path.push_back('/');
            }
        }

        // Try the next environment variable
        ++tmp_env;
    }

    // Append a directory name
    tmp_path.append("tmpXXXXXX");

    // We need room for tmp_path + trailing NUL
    std::vector<char> buffer(tmp_path.length()+1);
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
    file_.assign (path_ + "/socket");
#else
    // Silence -Wunused-parameter. #pragma and __attribute__((unused)) are not
    // very portable unfortunately...
    (void) path_;
    int fd = mkstemp (&buffer[0]);
    if (fd == -1)
         return -1;
    ::close (fd);

    file_.assign (&buffer[0]);
#endif

    return 0;
}

zmq::ipc_listener_t::ipc_listener_t (io_thread_t *io_thread_,
      socket_base_t *socket_, const options_t &options_) :
    own_t (io_thread_, options_),
    io_object_t (io_thread_),
    has_file (false),
    s (retired_fd),
    socket (socket_)
{
}

zmq::ipc_listener_t::~ipc_listener_t ()
{
    zmq_assert (s == retired_fd);
}

void zmq::ipc_listener_t::process_plug ()
{
    //  Start polling for incoming connections.
    handle = add_fd (s);
    set_pollin (handle);
}

void zmq::ipc_listener_t::process_term (int linger_)
{
    rm_fd (handle);
    close ();
    own_t::process_term (linger_);
}

void zmq::ipc_listener_t::in_event ()
{
    fd_t fd = accept ();

    //  If connection was reset by the peer in the meantime, just ignore it.
    //  TODO: Handle specific errors like ENFILE/EMFILE etc.
    if (fd == retired_fd) {
        socket->event_accept_failed (endpoint, zmq_errno());
        return;
    }

    //  Create the engine object for this connection.
    stream_engine_t *engine = new (std::nothrow)
        stream_engine_t (fd, options, endpoint);
    alloc_assert (engine);

    //  Choose I/O thread to run connecter in. Given that we are already
    //  running in an I/O thread, there must be at least one available.
    io_thread_t *io_thread = choose_io_thread (options.affinity);
    zmq_assert (io_thread);

    //  Create and launch a session object.
    session_base_t *session = session_base_t::create (io_thread, false, socket,
        options, NULL);
    errno_assert (session);
    session->inc_seqnum ();
    launch_child (session);
    send_attach (session, engine, false);
    socket->event_accepted (endpoint, fd);
}

int zmq::ipc_listener_t::get_address (std::string &addr_)
{
    struct sockaddr_storage ss;
#ifdef ZMQ_HAVE_HPUX
    int sl = sizeof (ss);
#else
    socklen_t sl = sizeof (ss);
#endif
    int rc = getsockname (s, (sockaddr *) &ss, &sl);
    if (rc != 0) {
        addr_.clear ();
        return rc;
    }

    ipc_address_t addr ((struct sockaddr *) &ss, sl);
    return addr.to_string (addr_);
}

int zmq::ipc_listener_t::set_address (const char *addr_)
{
    //  Create addr on stack for auto-cleanup
    std::string addr (addr_);

    //  Allow wildcard file
    if (options.use_fd == -1 && addr [0] == '*') {
        if ( create_wildcard_address(tmp_socket_dirname, addr) < 0 ) {
            return -1;
        }
    }

    //  Get rid of the file associated with the UNIX domain socket that
    //  may have been left behind by the previous run of the application.
    //  MUST NOT unlink if the FD is managed by the user, or it will stop
    //  working after the first client connects. The user will take care of
    //  cleaning up the file after the service is stopped.
    if (options.use_fd == -1) {
        ::unlink (addr.c_str());
    }
    filename.clear ();

    //  Initialise the address structure.
    ipc_address_t address;
    int rc = address.resolve (addr.c_str());
    if (rc != 0) {
        if ( !tmp_socket_dirname.empty() ) {
            // We need to preserve errno to return to the user
            int errno_ = errno;
            ::rmdir(tmp_socket_dirname.c_str ());
            tmp_socket_dirname.clear();
            errno = errno_;
        }
        return -1;
    }

    address.to_string (endpoint);

    if (options.use_fd != -1) {
        s = options.use_fd;
    } else {
        //  Create a listening socket.
        s = open_socket (AF_UNIX, SOCK_STREAM, 0);
        if (s == -1) {
            if ( !tmp_socket_dirname.empty() ) {
                // We need to preserve errno to return to the user
                int errno_ = errno;
                ::rmdir(tmp_socket_dirname.c_str ());
                tmp_socket_dirname.clear();
                errno = errno_;
            }
            return -1;
        }

        //  Bind the socket to the file path.
        rc = bind (s, address.addr (), address.addrlen ());
        if (rc != 0)
            goto error;

        //  Listen for incoming connections.
        rc = listen (s, options.backlog);
        if (rc != 0)
            goto error;
    }

    filename.assign (addr.c_str());
    has_file = true;

    socket->event_listening (endpoint, s);
    return 0;

error:
    int err = errno;
    close ();
    errno = err;
    return -1;
}

int zmq::ipc_listener_t::close ()
{
    zmq_assert (s != retired_fd);
    int rc = ::close (s);
    errno_assert (rc == 0);

    s = retired_fd;

    //  If there's an underlying UNIX domain socket, get rid of the file it
    //  is associated with.
    //  MUST NOT unlink if the FD is managed by the user, or it will stop
    //  working after the first client connects. The user will take care of
    //  cleaning up the file after the service is stopped.
    if (has_file && options.use_fd == -1) {
        rc = 0;

        if ( !filename.empty () ) {
          rc = ::unlink(filename.c_str ());
        }

        if ( rc == 0 && !tmp_socket_dirname.empty() ) {
          rc = ::rmdir(tmp_socket_dirname.c_str ());
          tmp_socket_dirname.clear();
        }

        if (rc != 0) {
            socket->event_close_failed (endpoint, zmq_errno());
            return -1;
        }
    }

    socket->event_closed (endpoint, s);
    return 0;
}

#if defined ZMQ_HAVE_SO_PEERCRED

bool zmq::ipc_listener_t::filter (fd_t sock)
{
    if (options.ipc_uid_accept_filters.empty () &&
        options.ipc_pid_accept_filters.empty () &&
        options.ipc_gid_accept_filters.empty ())
        return true;

    struct ucred cred;
    socklen_t size = sizeof (cred);

    if (getsockopt (sock, SOL_SOCKET, SO_PEERCRED, &cred, &size))
        return false;
    if (options.ipc_uid_accept_filters.find (cred.uid) != options.ipc_uid_accept_filters.end () ||
            options.ipc_gid_accept_filters.find (cred.gid) != options.ipc_gid_accept_filters.end () ||
            options.ipc_pid_accept_filters.find (cred.pid) != options.ipc_pid_accept_filters.end ())
        return true;

    struct passwd *pw;
    struct group *gr;

    if (!(pw = getpwuid (cred.uid)))
        return false;
    for (options_t::ipc_gid_accept_filters_t::const_iterator it = options.ipc_gid_accept_filters.begin ();
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

bool zmq::ipc_listener_t::filter (fd_t sock)
{
    if (options.ipc_uid_accept_filters.empty () &&
        options.ipc_gid_accept_filters.empty ())
        return true;

    struct xucred cred;
    socklen_t size = sizeof (cred);

    if (getsockopt (sock, 0, LOCAL_PEERCRED, &cred, &size))
        return false;
    if (cred.cr_version != XUCRED_VERSION)
        return false;
    if (options.ipc_uid_accept_filters.find (cred.cr_uid) != options.ipc_uid_accept_filters.end ())
        return true;
    for (int i = 0; i < cred.cr_ngroups; i++) {
        if (options.ipc_gid_accept_filters.find (cred.cr_groups[i]) != options.ipc_gid_accept_filters.end ())
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
    zmq_assert (s != retired_fd);
#if defined ZMQ_HAVE_SOCK_CLOEXEC
    fd_t sock = ::accept4 (s, NULL, NULL, SOCK_CLOEXEC);
#else
    fd_t sock = ::accept (s, NULL, NULL);
#endif
    if (sock == -1) {
        errno_assert (errno == EAGAIN || errno == EWOULDBLOCK ||
            errno == EINTR || errno == ECONNABORTED || errno == EPROTO ||
            errno == ENFILE);
        return retired_fd;
    }

#if !defined ZMQ_HAVE_SOCK_CLOEXEC && defined FD_CLOEXEC
    //  Race condition can cause socket not to be closed (if fork happens
    //  between accept and this point).
    int rc = fcntl (sock, F_SETFD, FD_CLOEXEC);
    errno_assert (rc != -1);
#endif

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
