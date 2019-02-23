#ifndef __PLATFORM_HPP_INCLUDED__
#define __PLATFORM_HPP_INCLUDED__

#define ZMQ_HAVE_WINDOWS

// MSVC build configuration is controlled via options exposed in the Visual
// Studio user interface. The option to use libsodium is not exposed in the
// user interface unless a sibling `libsodium` directory to that of this
// repository exists and contains the following files:
//
// \builds\msvc\vs2015\libsodium.import.props
// \builds\msvc\vs2015\libsodium.import.xml

#endif
