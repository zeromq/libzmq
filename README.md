# ZeroMQ

[![Build Status](https://travis-ci.org/zeromq/libzmq.png?branch=master)](https://travis-ci.org/zeromq/libzmq)
[![Build status](https://ci.appveyor.com/api/projects/status/e2ks424yrs1un3wt?svg=true)](https://ci.appveyor.com/project/zeromq/libzmq)
[![Coverage Status](https://coveralls.io/repos/github/zeromq/libzmq/badge.svg?branch=master)](https://coveralls.io/github/zeromq/libzmq?branch=master)

## Welcome

The ZeroMQ lightweight messaging kernel is a library which extends the
standard socket interfaces with features traditionally provided by
specialised messaging middleware products. ZeroMQ sockets provide an
abstraction of asynchronous message queues, multiple messaging patterns,
message filtering (subscriptions), seamless access to multiple transport
protocols and more.

## Supported platforms <a name="#platforms"/>

Libzmq is mainly written in C++98 with some optional C++11-fragments. For
configuration either autotools or CMake is employed. See below for some lists
of platforms, where libzmq has been successfully compiled on.

### Supported platforms with primary CI

| OS and version                         | Architecture            | Compiler and version          | Build system | Remarks                                                                                                                               |
|----------------------------------------|-------------------------|-------------------------------|--------------|---------------------------------------------------------------------------------------------------------------------------------------|
| Android NDK r20                        | arm, arm64, x86, x86_64 | llvm (see NDK)                | autotools    | DRAFT                                                                                                                                       |
| Ubuntu 14.04.5 LTS (trusty)            | amd64                   | clang 5.0.0                   | autotools    | STABLE, extras: GSSAPI, PGM, NORM, C++98 mode only                                                                                    |
| Ubuntu 14.04.5 LTS (trusty)            | amd64                   | gcc 4.8.4                     | autotools    | STABLE, DRAFT, extras: GSSAPI, PGM, NORM, TIPC, IPV6, also POLLER=poll, POLLER=select, also valgrind and address sanitizer executions |
| Ubuntu 14.04.5 LTS (trusty)            | amd64                   | gcc 4.8.4                     | CMake 3.12.2 | STABLE                                                                                                                                |
| Windows Server 2012 R2                 | x86                     | Visual Studio 2008            | CMake 3.12.2 | DRAFT                                                                                                                                 |
| Windows Server 2012 R2                 | x86                     | Visual Studio 2010 SP1        | CMake 3.12.2 | DRAFT                                                                                                                                 |
| Windows Server 2012 R2                 | x86                     | Visual Studio 2012 Update 5   | CMake 3.12.2 | DRAFT                                                                                                                                 |
| Windows Server 2012 R2                 | x86, amd64              | Visual Studio 2013 Update 5   | CMake 3.12.2 | DRAFT, STABLE (x86 Release only), also POLLER=epoll                                                                                   |
| Windows Server 2012 R2                 | x86                     | Visual Studio 2015 Update 3   | CMake 3.12.2 | DRAFT                                                                                                                                 |
| Windows Server 2016                    | x86                     | Visual Studio 2017 15.9.6     | CMake 3.13.3 | DRAFT                                                                                                                                 |
| cygwin 3.0.0 on Windows Server 2012 R2 | amd64                   | gcc 7.4.0                     | CMake 3.6.2  | DRAFT                                                                                                                                 |
| MSYS2 ? on Windows Server 2012 R2      | amd64                   | gcc 6.4.0                     | CMake ?      | DRAFT                                                                                                                                 |
| Mac OS X 10.13                         | amd64                   | Xcode 9.4.1, Apple LLVM 9.1.0 | autotools    | STABLE, DRAFT                                                                                                                         |
| Mac OS X 10.13                         | amd64                   | Xcode 9.4.1, Apple LLVM 9.1.0 | CMake 3.11.4 | DRAFT                                                                                                                                 |

Note: the platforms are regularly updated by the service providers, so this information might get out of date
without any changes on the side of libzmq. For Appveyor, refer to https://www.appveyor.com/updates/ regarding
platform updates. For travis-ci, refer to https://changelog.travis-ci.com/ regarding platform updates.

### Supported platforms with secondary CI

| OS and version               | Architecture               | Compiler and version | Build system | Remarks |
|------------------------------|----------------------------|----------------------|--------------|---------|
| CentOS 6                     | x86, amd64                 | ?                    | autotools    |         |
| CentOS 7                     | amd64                      | ?                    | autotools    |         |
| Debian 8.0                   | x86, amd64                 | ?                    | autotools    |         |
| Debian 9.0                   | ARM64, x86, amd64          | ?                    | autotools    |         |
| Fedora 28                    | ARM64, ARM32, amd64        | ?                    | autotools    |         |
| Fedora 29                    | ARM64, ARM32, amd64        | ?                    | autotools    |         |
| Fedora Rawhide               | ARM64, ARM32, amd64        | ?                    | autotools    |         |
| RedHat Enterprise Linux 7    | amd64, ppc64               | ?                    | autotools    |         |
| SuSE Linux Enterprise 12 SP4 | ARM64, amd64, ppc64, s390x | ?                    | autotools    |         |
| SuSE Linux Enterprise 15     | amd64                      | ?                    | autotools    |         |
| xUbuntu 12.04                | x86, amd64                 | ?                    | autotools    |         |
| xUbuntu 14.04                | x86, amd64                 | ?                    | autotools    |         |
| xUbuntu 16.04                | x86, amd64                 | ?                    | autotools    |         |
| xUbuntu 18.04                | x86, amd64                 | ?                    | autotools    |         |
| xUbuntu 18.10                | x86, amd64                 | ?                    | autotools    |         |

### Supported platforms with known active users

At the time of writing, no explicit reports have been available. Please report your experiences by opening a PR
adding an entry or moving an entry from the section below.

Under "last report", please name either the SHA1 in case of an unreleased version, or the version number in
case of a released version.

| OS and version | Architecture      | Compiler and version | Build system | Last report             | Remarks |
|----------------|-------------------|----------------------|--------------|-------------------------|---------|
| Solaris 10     | x86, amd64, sparc | GCC 8.1.0            | CMake        | 2019/03/18              |         |
| DragonFly BSD  | amd64             | gcc 8.3              | autotools    | 2018/08/07 git-72854e63 |         |
| IBM i          | ppc64             | gcc 6.3              | autotools    | 2019/10/02 git-25320a3  |         |
| QNX 7.0        | x86_64            | gcc 5.4.0            | CMake        | 4.3.2                   |         |


### Supported platforms without known active users

Note: this list is incomplete and inaccurate and still needs some work.

| OS and version         | Architecture | Compiler and version     | Build system     | Remarks |
|------------------------|--------------|--------------------------|------------------|---------|
| Any Linux distribution | x86, amd64   | gcc ?+, clang ?+, icc ?+ | autotools, CMake |         |
| SunOS, Solaris         | x86, amd64   | SunPro                   | autotools, CMake |         |
| GNU/kFreeBSD           | ?            | ?                        | autotools, CMake |         |
| FreeBSD                | ?            | ?                        | autotools, CMake |         |
| NetBSD                 | ?            | ?                        | autotools, CMake |         |
| OpenBSD                | ?            | ?                        | autotools, CMake |         |
| DragonFly BSD          | amd64        | gcc 8.3                  | autotools, CMake |         |
| HP-UX                  | ?            | ?                        | autotools, CMake |         |
| GNU/Hurd               | ?            | ?                        | autotools        |         |
| VxWorks 6.8            | ?            | ?                        | ?                |         |
| Windows CE             | ?            | ?                        | ?                |         |
| Windows UWP            | ?            | ?                        | ?                |         |
| OpenVMS                | ?            | ?                        | ?                |         |

### Unsupported platforms

| OS and version | Architecture | Compiler and version | Remarks                                                                 |
|----------------|--------------|----------------------|-------------------------------------------------------------------------|
| QNX 6.3        | ?            | gcc 3.3.5            | see #3371, support was added by a user, but not contributed to upstream |
| Windows 10     | ARM, ARM64   | Visual Studio 2017   | see #3366, probably only minor issues                                   |

For more details, see [here](SupportedPlatforms.md).

For some platforms (Linux, Mac OS X), [prebuilt binary packages are supplied by the ZeroMQ organization](#installation).
For other platforms, you need to [build your own binaries](#build).

## Installation of binary packages <a name="installation"/>

### Linux

For Linux users, pre-built binary packages are available for most distributions.
Note that DRAFT APIs can change at any time without warning, pick a STABLE build to
avoid having them enabled.

#### Latest releases

##### DEB

[![OBS release stable](https://img.shields.io/badge/OBS%20master-stable-yellow.svg)](http://software.opensuse.org/download.html?project=network%3Amessaging%3Azeromq%3Arelease-stable&package=libzmq3-dev)
[![OBS release draft](https://img.shields.io/badge/OBS%20master-draft-yellow.svg)](http://software.opensuse.org/download.html?project=network%3Amessaging%3Azeromq%3Arelease-draft&package=libzmq3-dev)

##### RPM

[![OBS release stable](https://img.shields.io/badge/OBS%20master-stable-yellow.svg)](http://software.opensuse.org/download.html?project=network%3Amessaging%3Azeromq%3Arelease-stable&package=zeromq-devel)
[![OBS release draft](https://img.shields.io/badge/OBS%20master-draft-yellow.svg)](http://software.opensuse.org/download.html?project=network%3Amessaging%3Azeromq%3Arelease-draft&package=zeromq-devel)

#### Bleeding edge packages

##### DEB

[![OBS release stable](https://img.shields.io/badge/OBS%20master-stable-yellow.svg)](http://software.opensuse.org/download.html?project=network%3Amessaging%3Azeromq%3Agit-stable&package=libzmq3-dev)
[![OBS release draft](https://img.shields.io/badge/OBS%20master-draft-yellow.svg)](http://software.opensuse.org/download.html?project=network%3Amessaging%3Azeromq%3Agit-draft&package=libzmq3-dev)

##### RPM

[![OBS release stable](https://img.shields.io/badge/OBS%20master-stable-yellow.svg)](http://software.opensuse.org/download.html?project=network%3Amessaging%3Azeromq%3Agit-stable&package=zeromq-devel)
[![OBS release draft](https://img.shields.io/badge/OBS%20master-draft-yellow.svg)](http://software.opensuse.org/download.html?project=network%3Amessaging%3Azeromq%3Agit-draft&package=zeromq-devel)

#### Example: Debian 9 latest release, no DRAFT apis

    echo "deb http://download.opensuse.org/repositories/network:/messaging:/zeromq:/release-stable/Debian_9.0/ ./" >> /etc/apt/sources.list
    wget https://download.opensuse.org/repositories/network:/messaging:/zeromq:/release-stable/Debian_9.0/Release.key -O- | sudo apt-key add
    apt-get install libzmq3-dev

### OSX

For OSX users, packages are available via brew.

    brew install zeromq

## Build from sources <a name="build"/>

To build from sources, see the INSTALL file included with the distribution.

### Android

To build from source, see [README](./builds/android/README.md) file in the
android build directory.

## Resources

Extensive documentation is provided with the distribution. Refer to
doc/zmq.html, or "man zmq" after you have installed libzmq on your system.

Website: http://www.zeromq.org/

Development mailing list: zeromq-dev@lists.zeromq.org
Announcements mailing list: zeromq-announce@lists.zeromq.org

Git repository: http://github.com/zeromq/libzmq

ZeroMQ developers can also be found on the IRC channel #zeromq, on the
Freenode network (irc.freenode.net).

## License

The project license is specified in COPYING and COPYING.LESSER.

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

## Contributing

This project uses [C4(Collective Code Construction Contract)](https://rfc.zeromq.org/spec:42/C4/) process for contributions.
