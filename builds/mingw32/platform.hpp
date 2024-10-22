/* SPDX-License-Identifier: MPL-2.0 */

#ifndef __ZMQ_PLATFORM_HPP_INCLUDED__
#define __ZMQ_PLATFORM_HPP_INCLUDED__

//  This is the platform definition for the MSVC platform.
//  As a first step of the build process it is copied to
//  zmq directory to take place of platform.hpp generated from
//  platform.hpp.in on platforms supported by GNU autotools.
//  Place any MSVC-specific definitions here.

#define ZMQ_HAVE_WINDOWS

#define ZMQ_USE_LIBSODIUM

#endif
