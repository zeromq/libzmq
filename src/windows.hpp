/* SPDX-License-Identifier: MPL-2.0 */

#ifndef __ZMQ_WINDOWS_HPP_INCLUDED__
#define __ZMQ_WINDOWS_HPP_INCLUDED__

#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif
#ifndef NOMINMAX
#define NOMINMAX // Macros min(a,b) and max(a,b)
#endif

//  Set target version to Windows Server 2008, Windows Vista or higher.
//  Windows XP (0x0501) is supported but without client & server socket types.
#if !defined _WIN32_WINNT && !defined ZMQ_HAVE_WINDOWS_UWP
#define _WIN32_WINNT 0x0600
#endif

#ifdef __MINGW32__
//  Require Windows XP or higher with MinGW for getaddrinfo().
#if (_WIN32_WINNT >= 0x0501)
#else
#error You need at least Windows XP target
#endif
#endif

#include <winsock2.h>
#include <windows.h>
#include <mswsock.h>
#include <iphlpapi.h>
#include <string>
#include <vector>

#if !defined __MINGW32__
#include <mstcpip.h>
#endif

//  Workaround missing mstcpip.h in mingw32 (MinGW64 provides this)
//  __MINGW64_VERSION_MAJOR is only defined when using in mingw-w64
#if defined __MINGW32__ && !defined SIO_KEEPALIVE_VALS                         \
  && !defined __MINGW64_VERSION_MAJOR
struct tcp_keepalive
{
    u_long onoff;
    u_long keepalivetime;
    u_long keepaliveinterval;
};
#define SIO_KEEPALIVE_VALS _WSAIOW (IOC_VENDOR, 4)
#endif

#include <ws2tcpip.h>
#include <ipexport.h>
#if !defined _WIN32_WCE
#include <process.h>
#endif

#if defined ZMQ_IOTHREAD_POLLER_USE_POLL || defined ZMQ_POLL_BASED_ON_POLL
static inline int poll (struct pollfd *pfd, unsigned long nfds, int timeout)
{
    return WSAPoll (pfd, nfds, timeout);
}
#endif

//  In MinGW environment AI_NUMERICSERV is not defined.
#ifndef AI_NUMERICSERV
#define AI_NUMERICSERV 0x0400
#endif

//  Need unlink() and rmdir() functions that take utf-8 encoded file path.
static inline std::wstring utf8_to_utf16 (const char *utf8_string)
{
    std::wstring retVal;

    if (utf8_string && *utf8_string) {
        const int utf16_length = ::MultiByteToWideChar (
          CP_UTF8, MB_ERR_INVALID_CHARS, utf8_string,
          -1, // assume the input string is null-terminated
          NULL, 0);

        if (utf16_length > 0) {
            retVal.resize (utf16_length);

            const int conversion_result = ::MultiByteToWideChar (
              CP_UTF8, MB_ERR_INVALID_CHARS, utf8_string,
              -1, // assume the input string is null-terminated
              &retVal[0], static_cast<int> (retVal.size ()));

            if (conversion_result == 0)
                retVal.clear ();
        }
    }

    return retVal;
}

static inline int unlink_utf8 (const char *filename)
{
    return _wunlink (utf8_to_utf16 (filename).c_str ());
}

static inline int rmdir_utf8 (const char *filename)
{
    return _wrmdir (utf8_to_utf16 (filename).c_str ());
}

//  In MSVC prior to v14, snprintf is not available
//  The closest implementation is the _snprintf_s function
#if defined(_MSC_VER) && _MSC_VER < 1900
#define snprintf(buffer_, count_, format_, ...)                                \
    _snprintf_s (buffer_, count_, _TRUNCATE, format_, __VA_ARGS__)
#endif

//  Workaround missing struct sockaddr_un in afunix.h.
//  Fix #3949.
#if defined(ZMQ_HAVE_IPC) && !defined(ZMQ_HAVE_STRUCT_SOCKADDR_UN)
struct sockaddr_un
{
    ADDRESS_FAMILY sun_family; /* AF_UNIX */
    char sun_path[108];        /* pathname */
};
#endif

#endif
