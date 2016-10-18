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
#include "err.hpp"

const char *zmq::errno_to_string (int errno_)
{
    switch (errno_) {
#if defined ZMQ_HAVE_WINDOWS
    case ENOTSUP:
        return "Not supported";
    case EPROTONOSUPPORT:
        return "Protocol not supported";
    case ENOBUFS:
        return "No buffer space available";
    case ENETDOWN:
        return "Network is down";
    case EADDRINUSE:
        return "Address in use";
    case EADDRNOTAVAIL:
        return "Address not available";
    case ECONNREFUSED:
        return "Connection refused";
    case EINPROGRESS:
        return "Operation in progress";
#endif
    case EFSM:
        return "Operation cannot be accomplished in current state";
    case ENOCOMPATPROTO:
        return "The protocol is not compatible with the socket type";
    case ETERM:
        return "Context was terminated";
    case EMTHREAD:
        return "No thread available";
    case EHOSTUNREACH:
        return "Host unreachable";
    default:
#if defined _MSC_VER
#pragma warning (push)
#pragma warning (disable:4996)
#endif
        return strerror (errno_);
#if defined _MSC_VER
#pragma warning (pop)
#endif
    }
}

void zmq::zmq_abort(const char *errmsg_)
{
#if defined ZMQ_HAVE_WINDOWS

    //  Raise STATUS_FATAL_APP_EXIT.
    ULONG_PTR extra_info [1];
    extra_info [0] = (ULONG_PTR) errmsg_;
    RaiseException (0x40000015, EXCEPTION_NONCONTINUABLE, 1, extra_info);
#else
    (void)errmsg_;
    print_backtrace();
    abort ();
#endif
}

#ifdef ZMQ_HAVE_WINDOWS

const char *zmq::wsa_error()
{
    const int last_error = WSAGetLastError();
    //  TODO: This is not a generic way to handle this...
    if (last_error == WSAEWOULDBLOCK)
        return NULL;

    return wsa_error_no (last_error);
}

const char *zmq::wsa_error_no (int no_)
{
    //  TODO:  It seems that list of Windows socket errors is longer than this.
    //         Investigate whether there's a way to convert it into the string
    //         automatically (wsaError->HRESULT->string?).
    return
        (no_ == WSABASEERR) ?
            "No Error" :
        (no_ == WSAEINTR) ?
            "Interrupted system call" :
        (no_ == WSAEBADF) ?
            "Bad file number" :
        (no_ == WSAEACCES) ?
            "Permission denied" :
        (no_ == WSAEFAULT) ?
            "Bad address" :
        (no_ == WSAEINVAL) ?
            "Invalid argument" :
        (no_ == WSAEMFILE) ?
            "Too many open files" :
        (no_ == WSAEWOULDBLOCK) ?
            "Operation would block" :
        (no_ == WSAEINPROGRESS) ?
            "Operation now in progress" :
        (no_ == WSAEALREADY) ?
            "Operation already in progress" :
        (no_ == WSAENOTSOCK) ?
            "Socket operation on non-socket" :
        (no_ == WSAEDESTADDRREQ) ?
            "Destination address required" :
        (no_ == WSAEMSGSIZE) ?
            "Message too long" :
        (no_ == WSAEPROTOTYPE) ?
            "Protocol wrong type for socket" :
        (no_ == WSAENOPROTOOPT) ?
            "Bad protocol option" :
        (no_ == WSAEPROTONOSUPPORT) ?
            "Protocol not supported" :
        (no_ == WSAESOCKTNOSUPPORT) ?
            "Socket type not supported" :
        (no_ == WSAEOPNOTSUPP) ?
            "Operation not supported on socket" :
        (no_ == WSAEPFNOSUPPORT) ?
            "Protocol family not supported" :
        (no_ == WSAEAFNOSUPPORT) ?
            "Address family not supported by protocol family" :
        (no_ == WSAEADDRINUSE) ?
            "Address already in use" :
        (no_ == WSAEADDRNOTAVAIL) ?
            "Can't assign requested address" :
        (no_ == WSAENETDOWN) ?
            "Network is down" :
        (no_ == WSAENETUNREACH) ?
            "Network is unreachable" :
        (no_ == WSAENETRESET) ?
            "Net dropped connection or reset" :
        (no_ == WSAECONNABORTED) ?
            "Software caused connection abort" :
        (no_ == WSAECONNRESET) ?
            "Connection reset by peer" :
        (no_ == WSAENOBUFS) ?
            "No buffer space available" :
        (no_ == WSAEISCONN) ?
            "Socket is already connected" :
        (no_ == WSAENOTCONN) ?
            "Socket is not connected" :
        (no_ == WSAESHUTDOWN) ?
            "Can't send after socket shutdown" :
        (no_ == WSAETOOMANYREFS) ?
            "Too many references can't splice" :
        (no_ == WSAETIMEDOUT) ?
            "Connection timed out" :
        (no_ == WSAECONNREFUSED) ?
            "Connection refused" :
        (no_ == WSAELOOP) ?
            "Too many levels of symbolic links" :
        (no_ == WSAENAMETOOLONG) ?
            "File name too long" :
        (no_ == WSAEHOSTDOWN) ?
            "Host is down" :
        (no_ == WSAEHOSTUNREACH) ?
            "No Route to Host" :
        (no_ == WSAENOTEMPTY) ?
            "Directory not empty" :
        (no_ == WSAEPROCLIM) ?
            "Too many processes" :
        (no_ == WSAEUSERS) ?
            "Too many users" :
        (no_ == WSAEDQUOT) ?
            "Disc Quota Exceeded" :
        (no_ == WSAESTALE) ?
            "Stale NFS file handle" :
        (no_ == WSAEREMOTE) ?
            "Too many levels of remote in path" :
        (no_ == WSASYSNOTREADY) ?
            "Network SubSystem is unavailable" :
        (no_ == WSAVERNOTSUPPORTED) ?
            "WINSOCK DLL Version out of range" :
        (no_ == WSANOTINITIALISED) ?
            "Successful WSASTARTUP not yet performed" :
        (no_ == WSAHOST_NOT_FOUND) ?
            "Host not found" :
        (no_ == WSATRY_AGAIN) ?
            "Non-Authoritative Host not found" :
        (no_ == WSANO_RECOVERY) ?
            "Non-Recoverable errors: FORMERR REFUSED NOTIMP" :
        (no_ == WSANO_DATA) ?
            "Valid name no data record of requested" :
        "error not defined";
}

void zmq::win_error (char *buffer_, size_t buffer_size_)
{
    DWORD errcode = GetLastError ();
#if defined _WIN32_WCE
    DWORD rc = FormatMessageW (FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS, NULL, errcode, MAKELANGID(LANG_NEUTRAL,
        SUBLANG_DEFAULT), (LPWSTR)buffer_, buffer_size_ / sizeof(wchar_t), NULL);
#else
    DWORD rc = FormatMessageA (FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS, NULL, errcode, MAKELANGID(LANG_NEUTRAL,
        SUBLANG_DEFAULT), buffer_, (DWORD) buffer_size_, NULL);
#endif
    zmq_assert (rc);
}

int zmq::wsa_error_to_errno (int errcode)
{
    switch (errcode) {
//  10004 - Interrupted system call.
    case WSAEINTR:
        return EINTR;
//  10009 - File handle is not valid.
    case WSAEBADF:
        return EBADF;
//  10013 - Permission denied.
    case WSAEACCES:
        return EACCES;
//  10014 - Bad address.
    case WSAEFAULT:
        return EFAULT;
//  10022 - Invalid argument.
    case WSAEINVAL:
        return EINVAL;
//  10024 - Too many open files.
    case WSAEMFILE:
        return EMFILE;
//  10035 - Operation would block.
    case WSAEWOULDBLOCK:
        return EBUSY;
//  10036 - Operation now in progress.
    case WSAEINPROGRESS:
        return EAGAIN;
//  10037 - Operation already in progress.
    case WSAEALREADY:
        return EAGAIN;
//  10038 - Socket operation on non-socket.
    case WSAENOTSOCK:
        return ENOTSOCK;
//  10039 - Destination address required.
    case WSAEDESTADDRREQ:
        return EFAULT;
//  10040 - Message too long.
    case WSAEMSGSIZE:
        return EMSGSIZE;
//  10041 - Protocol wrong type for socket.
    case WSAEPROTOTYPE:
        return EFAULT;
//  10042 - Bad protocol option.
    case WSAENOPROTOOPT:
        return EINVAL;
//  10043 - Protocol not supported.
    case WSAEPROTONOSUPPORT:
        return EPROTONOSUPPORT;
//  10044 - Socket type not supported.
    case WSAESOCKTNOSUPPORT:
        return EFAULT;
//  10045 - Operation not supported on socket.
    case WSAEOPNOTSUPP:
        return EFAULT;
//  10046 - Protocol family not supported.
    case WSAEPFNOSUPPORT:
        return EPROTONOSUPPORT;
//  10047 - Address family not supported by protocol family.
    case WSAEAFNOSUPPORT:
        return EAFNOSUPPORT;
//  10048 - Address already in use.
    case WSAEADDRINUSE:
        return EADDRINUSE;
//  10049 - Cannot assign requested address.
    case WSAEADDRNOTAVAIL:
        return EADDRNOTAVAIL;
//  10050 - Network is down.
    case WSAENETDOWN:
        return ENETDOWN;
//  10051 - Network is unreachable.
    case WSAENETUNREACH:
        return ENETUNREACH;
//  10052 - Network dropped connection on reset.
    case WSAENETRESET:
        return ENETRESET;
//  10053 - Software caused connection abort.
    case WSAECONNABORTED:
        return ECONNABORTED;
//  10054 - Connection reset by peer.
    case WSAECONNRESET:
        return ECONNRESET;
//  10055 - No buffer space available.
    case WSAENOBUFS:
        return ENOBUFS;
//  10056 - Socket is already connected.
    case WSAEISCONN:
        return EFAULT;
//  10057 - Socket is not connected.
    case WSAENOTCONN:
        return ENOTCONN;
//  10058 - Can't send after socket shutdown.
    case WSAESHUTDOWN:
        return EFAULT;
//  10059 - Too many references can't splice.
    case WSAETOOMANYREFS:
        return EFAULT;
//  10060 - Connection timed out.
    case WSAETIMEDOUT:
        return ETIMEDOUT;
//  10061 - Connection refused.
    case WSAECONNREFUSED:
        return ECONNREFUSED;
//  10062 - Too many levels of symbolic links.
    case WSAELOOP:
        return EFAULT;
//  10063 - File name too long.
    case WSAENAMETOOLONG:
        return EFAULT;
//  10064 - Host is down.
    case WSAEHOSTDOWN:
        return EAGAIN;
//  10065 - No route to host.
    case WSAEHOSTUNREACH:
        return EHOSTUNREACH;
//  10066 - Directory not empty.
    case WSAENOTEMPTY:
        return EFAULT;
//  10067 - Too many processes.
    case WSAEPROCLIM:
        return EFAULT;
//  10068 - Too many users.
    case WSAEUSERS:
        return EFAULT;
//  10069 - Disc Quota Exceeded.
    case WSAEDQUOT:
        return EFAULT;
//  10070 - Stale NFS file handle.
    case WSAESTALE:
        return EFAULT;
//  10071 - Too many levels of remote in path.
    case WSAEREMOTE:
        return EFAULT;
//  10091 - Network SubSystem is unavailable.
    case WSASYSNOTREADY:
        return EFAULT;
//  10092 - WINSOCK DLL Version out of range.
    case WSAVERNOTSUPPORTED:
        return EFAULT;
//  10093 - Successful WSASTARTUP not yet performed.
    case WSANOTINITIALISED:
        return EFAULT;
//  11001 - Host not found.
    case WSAHOST_NOT_FOUND:
        return EFAULT;
//  11002 - Non-Authoritative Host not found.
    case WSATRY_AGAIN:
        return EFAULT;
//  11003 - Non-Recoverable errors: FORMERR REFUSED NOTIMP.
    case WSANO_RECOVERY:
        return EFAULT;
//  11004 - Valid name no data record of requested.
    case WSANO_DATA:
        return EFAULT;
    default:
        wsa_assert (false);
    }
    //  Not reachable
    return 0;
}

#endif

#ifdef HAVE_LIBUNWIND

#define UNW_LOCAL_ONLY
#include <libunwind.h>
#include <dlfcn.h>
#include <cxxabi.h>

void zmq::print_backtrace (void)
{
    Dl_info dl_info;
    unw_cursor_t cursor;
    unw_context_t ctx;
    unsigned frame_n = 0;

    unw_getcontext (&ctx);
    unw_init_local (&cursor, &ctx);

    while (unw_step (&cursor) > 0) {
        unw_word_t offset;
        unw_proc_info_t p_info;
        const char *file_name;
        char *demangled_name;
        char func_name[256] = "";
        void *addr;
        int rc;

        if (unw_get_proc_info (&cursor, &p_info))
            break;

        addr = (void *)(p_info.start_ip + offset);

        if (dladdr (addr, &dl_info) && dl_info.dli_fname)
            file_name = dl_info.dli_fname;
        else
            file_name = "?";

        rc = unw_get_proc_name (&cursor, func_name, 256, &offset);
        if (rc == -UNW_ENOINFO)
            strcpy(func_name, "?");

        demangled_name = abi::__cxa_demangle (func_name, NULL, NULL, &rc);

        printf ("#%u  %p in %s (%s+0x%lx)\n", frame_n++, addr, file_name,
                rc ? func_name : demangled_name, (unsigned long) offset);
        free (demangled_name);
    }

    fflush (stdout);
}

#else

void zmq::print_backtrace (void)
{
}

#endif
