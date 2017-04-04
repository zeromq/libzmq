## Overview

The ZeroMQ lightweight messaging kernel is a library which extends the
standard socket interfaces with features traditionally provided by
specialised messaging middleware products. ZeroMQ sockets provide an
abstraction of asynchronous message queues, multiple messaging patterns,
message filtering (subscriptions), seamless access to multiple transport
protocols and more.

This documentation describes the internal software that makes up the
ZeroMQ C++ core engine, and not how to use its API, however it may help
you understand certain aspects better, such as the callgraph of an API method.
There are no instructions on using ZeroMQ within this documentation, only
the API internals that make up the software.

**Note:** this documentation is generated directly from the source code with
Doxygen. Since this project is constantly under active development, what you
are about to read may be out of date! If you notice any errors in the
documentation, or the code comments, then please send a pull request.

Please refer to the README file for anything else.
## Resources

Extensive documentation is provided with the distribution. Refer to
doc/zmq.html, or "man zmq" after you have installed libzmq on your system.

* Website: http://www.zeromq.org/
* Official API documentation: http://api.zeromq.org/

Development mailing list: zeromq-dev@lists.zeromq.org

Announcements mailing list: zeromq-announce@lists.zeromq.org

Git repository: http://github.com/zeromq/libzmq

ZeroMQ developers can also be found on the IRC channel \#zeromq, on the
Freenode network (irc.freenode.net).

## Copyright
Copyright (c) 2007-2016 Contributors as noted in the AUTHORS file.  
The project license is specified in COPYING and COPYING.LESSER.

The names "ØMQ", "ZeroMQ", "0MQ", and the ØMQ logo are registered trademarks
of iMatix Corporation ("iMatix") and refers to either (a) the original libzmq
C++ library, or (b) the community of projects hosted in the
https://github.com/zeromq organization.

This Doxygen configuration is adapted by Hiten Pandya, for the ZeroMQ project.
