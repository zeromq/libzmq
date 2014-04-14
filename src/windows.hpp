/*
    Copyright (c) 2007-2013 Contributors as noted in the AUTHORS file

    This file is part of 0MQ.

    0MQ is free software; you can redistribute it and/or modify it under
    the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    0MQ is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef __ZMQ_WINDOWS_HPP_INCLUDED__
#define __ZMQ_WINDOWS_HPP_INCLUDED__

//  The purpose of this header file is to turn on only the items actually
//  needed on the windows platform.

#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOGDICAPMASKS
#define NOGDICAPMASKS     // CC_*, LC_*, PC_*, CP_*, TC_*, RC_
#endif
#ifndef NOVIRTUALKEYCODES
#define NOVIRTUALKEYCODES // VK_*
#endif
#ifndef NOWINMESSAGES
#define NOWINMESSAGES     // WM_*, EM_*, LB_*, CB_*
#endif
#ifndef NOWINSTYLES
#define NOWINSTYLES       // WS_*, CS_*, ES_*, LBS_*, SBS_*, CBS_*
#endif
#ifndef NOSYSMETRICS
#define NOSYSMETRICS      // SM_*
#endif
#ifndef NOMENUS
#define NOMENUS           // MF_*
#endif
#ifndef NOICONS
#define NOICONS           // IDI_*
#endif
#ifndef NOKEYSTATES
#define NOKEYSTATES       // MK_*
#endif
#ifndef NOSYSCOMMANDS
#define NOSYSCOMMANDS     // SC_*
#endif
#ifndef NORASTEROPS
#define NORASTEROPS       // Binary and Tertiary raster ops
#endif
#ifndef NOSHOWWINDOW
#define NOSHOWWINDOW      // SW_*
#endif
#ifndef OEMRESOURCE
#define OEMRESOURCE       // OEM Resource values
#endif
#ifndef NOATOM
#define NOATOM            // Atom Manager routines
#endif
#ifndef NOCLIPBOARD
#define NOCLIPBOARD       // Clipboard routines
#endif
#ifndef NOCOLOR
#define NOCOLOR           // Screen colors
#endif
#ifndef NOCTLMGR
#define NOCTLMGR          // Control and Dialog routines
#endif
#ifndef NODRAWTEXT
#define NODRAWTEXT        // DrawText() and DT_*
#endif
#ifndef NOGDI
#define NOGDI             // All GDI defines and routines
#endif
#ifndef NOKERNEL
#define NOKERNEL          // All KERNEL defines and routines
#endif
#ifndef NOUSER
#define NOUSER            // All USER defines and routines
#endif
#ifndef NONLS
#define NONLS             // All NLS defines and routines
#endif
#ifndef NOMB
#define NOMB              // MB_* and MessageBox()
#endif
#ifndef NOMEMMGR
#define NOMEMMGR          // GMEM_*, LMEM_*, GHND, LHND, associated routines
#endif
#ifndef NOMETAFILE
#define NOMETAFILE        // typedef METAFILEPICT
#endif
#ifndef NOMINMAX
#define NOMINMAX          // Macros min(a,b) and max(a,b)
#endif
#ifndef NOMSG
#define NOMSG             // typedef MSG and associated routines
#endif
#ifndef NOOPENFILE
#define NOOPENFILE        // OpenFile(), OemToAnsi, AnsiToOem, and OF_*
#endif
#ifndef NOSCROLL
#define NOSCROLL          // SB_* and scrolling routines
#endif
#ifndef NOSERVICE
#define NOSERVICE         // All Service Controller routines, SERVICE_ equates, etc.
#endif
#ifndef NOSOUND
#define NOSOUND           // Sound driver routines
#endif
#ifndef NOTEXTMETRIC
#define NOTEXTMETRIC      // typedef TEXTMETRIC and associated routines
#endif
#ifndef NOWH
#define NOWH              // SetWindowsHook and WH_*
#endif
#ifndef NOWINOFFSETS
#define NOWINOFFSETS      // GWL_*, GCL_*, associated routines
#endif
#ifndef NOCOMM
#define NOCOMM            // COMM driver routines
#endif
#ifndef NOKANJI
#define NOKANJI           // Kanji support stuff.
#endif
#ifndef NOHELP
#define NOHELP            // Help engine interface.
#endif
#ifndef NOPROFILER
#define NOPROFILER        // Profiler interface.
#endif
#ifndef NODEFERWINDOWPOS
#define NODEFERWINDOWPOS  // DeferWindowPos routines
#endif
#ifndef NOMCX
#define NOMCX             // Modem Configuration ExtensionsA
#endif

//  Set target version to Windows Server 2003, Windows XP/SP1 or higher.
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0501
#endif

#ifdef __MINGW32__
//  Require Windows XP or higher with MinGW for getaddrinfo().
#if(_WIN32_WINNT >= 0x0501)
#else
#undef _WIN32_WINNT
#define _WIN32_WINNT 0x0501
#endif
#endif
 
#include <winsock2.h>
#include <windows.h>
#include <mswsock.h>

#if !defined __MINGW32__
#include <Mstcpip.h>
#endif

//  Workaround missing Mstcpip.h in mingw32 (MinGW64 provides this)
//  __MINGW64_VERSION_MAJOR is only defined (through inclusion of private _mingw.h via 
//  windows.h) in mingw-w64
#if defined __MINGW32__ && !defined SIO_KEEPALIVE_VALS && !defined __MINGW64_VERSION_MAJOR
struct tcp_keepalive {
    u_long onoff;
    u_long keepalivetime;
    u_long keepaliveinterval;
};
#define SIO_KEEPALIVE_VALS _WSAIOW(IOC_VENDOR,4)
#endif

#include <ws2tcpip.h>
#include <ipexport.h>
#if !defined _WIN32_WCE
#include <process.h>
#endif

//  In MinGW environment AI_NUMERICSERV is not defined.
#ifndef AI_NUMERICSERV
#define AI_NUMERICSERV 0x0400
#endif
#endif
