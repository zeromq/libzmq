/*
    Copyright (c) 2007-2010 iMatix Corporation

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

#ifndef __ZMQ_PLATFORM_HPP_INCLUDED__
#define __ZMQ_PLATFORM_HPP_INCLUDED__

//  This is the platform definition for the Windows platform.
//  As a first step of the build process it is copied to
//  zmq directory to take place of platform.hpp generated from
//  platform.hpp.in on platforms supported by GNU autotools.

#define ZMQ_HAVE_WINDOWS
#define _WINSOCKAPI_
#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS

// Turn on only the items zmq needs on the Windows platform.

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMCX   // No Modem Configuration Extensions.
#define NOMCX
#endif
#ifndef NOIME   // No Input Method Editor.
#define NOIME
#endif
#ifndef NOSOUND // No Sound driver routines.
#define NOSOUND
#endif

#include <windows.h>
#include <objbase.h>

//  Enable winsock (not included when WIN32_LEAN_AND_MEAN is defined).
#if(_WIN32_WINNT >= 0x0400)
#include <winsock2.h>
#include <mswsock.h>
#else
#include <winsock.h>
#endif

#endif
