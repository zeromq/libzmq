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

#ifndef __ZMQ_FD_HPP_INCLUDED__
#define __ZMQ_FD_HPP_INCLUDED__

#if defined _WIN32
#include "windows.hpp"
#endif

namespace zmq
{
#ifdef ZMQ_HAVE_WINDOWS
#if defined _MSC_VER && _MSC_VER <= 1400
///< \todo zmq.h uses SOCKET unconditionally, so probably VS versions before
/// VS2008 are unsupported anyway. Apart from that, this seems to depend on
/// the Windows SDK version rather than the VS version.
typedef UINT_PTR fd_t;
enum
{
    retired_fd = (fd_t) (~0)
};
#else
typedef SOCKET fd_t;
enum
#if _MSC_VER >= 1800
  : fd_t
#endif
{
    retired_fd = INVALID_SOCKET
};
#endif
#else
typedef int fd_t;
enum
{
    retired_fd = -1
};
#endif
}
#endif
