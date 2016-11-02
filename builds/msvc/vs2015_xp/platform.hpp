#ifndef __PLATFORM_HPP_INCLUDED__
#define __PLATFORM_HPP_INCLUDED__

#define ZMQ_HAVE_WINDOWS
#define ZMQ_HAVE_WINDOWS_TARGET_XP

#define ZMQ_BUILD_DRAFT_API

#define ZMQ_USE_SELECT
#define FD_SETSIZE 1024

#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"Iphlpapi.lib")

#endif
