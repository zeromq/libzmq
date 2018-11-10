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


## Building and installation

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

### Build from sources

To build from sources, see the INSTALL file included with the distribution.

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
