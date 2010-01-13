;; Copyright (c) 2009 Vitaly Mayatskikh <v.mayatskih@gmail.com>
;;
;; This file is part of 0MQ.
;;
;; 0MQ is free software; you can redistribute it and/or modify it under
;; the terms of the Lesser GNU General Public License as published by
;; the Free Software Foundation; either version 3 of the License, or
;; (at your option) any later version.
;;
;; 0MQ is distributed in the hope that it will be useful,
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;; Lesser GNU General Public License for more details.
;;
;; You should have received a copy of the Lesser GNU General Public License
;; along with this program.  If not, see <http://www.gnu.org/licenses/>.

(in-package :zeromq)

(defcvar "errno" :int)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;  0MQ errors.
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defconstant hausnumero 156384712)

;;  On Windows platform some of the standard POSIX errnos are not defined.
;; #ifndef ENOTSUP
;; #define ENOTSUP (ZMQ_HAUSNUMERO + 1)
;; #endif
;; #ifndef EPROTONOSUPPORT
;; #define EPROTONOSUPPORT (ZMQ_HAUSNUMERO + 2)
;; #endif
;; #ifndef ENOBUFS
;; #define ENOBUFS (ZMQ_HAUSNUMERO + 3)
;; #endif
;; #ifndef ENETDOWN
;; #define ENETDOWN (ZMQ_HAUSNUMERO + 4)
;; #endif
;; #ifndef EADDRINUSE
;; #define EADDRINUSE (ZMQ_HAUSNUMERO + 5)
;; #endif
;; #ifndef EADDRNOTAVAIL
;; #define EADDRNOTAVAIL (ZMQ_HAUSNUMERO + 6)
;; #endif

;;  Native 0MQ error codes.
(defconstant emthread (+ hausnumero 50))
(defconstant efsm (+ hausnumero 51))
(defconstant enocompatproto (+ hausnumero 52))

(defcfun ("zmq_strerror" %strerror) :pointer
  (errnum	:int))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;  0MQ message definition.
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defconstant max-vsm-size 30)

;;  Message types. These integers may be stored in 'content' member of the
;;  message instead of regular pointer to the data.
(defconstant delimiter 31)
(defconstant vsm 32)

(defcstruct (msg)
  (content	:pointer)
  (shared	:uchar)
  (vsm-size	:uchar)
  (vsm-data	:uchar :count 30))	;; FIXME max-vsm-size

(defcfun ("zmq_msg_init" msg-init) :int
  (msg	msg))

(defcfun* ("zmq_msg_init_size" %msg-init-size) :int
  (msg	msg)
  (size	:long))

(defcallback zmq-free :void ((ptr :pointer) (hint :pointer))
  (declare (ignorable hint))
  (foreign-free ptr))

(defcfun ("zmq_msg_init_data" msg-init-data) :int
  (msg	msg)
  (data	:pointer)
  (size	:long)
  (ffn	:pointer)			; zmq_free_fn
  (hint	:pointer))

(defcfun* ("zmq_msg_close" %msg-close) :int
  (msg	msg))

(defcfun ("zmq_msg_move" %msg-move) :int
  (dest	msg)
  (src	msg))

(defcfun ("zmq_msg_copy" %msg-copy) :int
  (dest	msg)
  (src	msg))

(defcfun ("zmq_msg_data" %msg-data) :pointer
  (msg	msg))

(defcfun ("zmq_msg_size" %msg-size) :int
  (msg	msg))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;  0MQ infrastructure (a.k.a. context) initialisation & termination.
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defconstant poll 1)

(defcfun* ("zmq_init" init) :pointer
  (app-threads	:int)
  (io-threads	:int)
  (flags	:int))

(defcfun ("zmq_term" term) :int
  (context	:pointer))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;  0MQ socket definition.
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;;  Creating a 0MQ socket.
;;  **********************

(defconstant p2p 0)
(defconstant pub 1)
(defconstant sub 2)
(defconstant req 3)
(defconstant rep 4)
(defconstant xreq 5)
(defconstant xrep 6)
(defconstant upstream 7)
(defconstant downstream 8)

(defcfun* ("zmq_socket" socket) :pointer
  (context	:pointer)
  (type		:int))

;;  Destroying the socket.
;;  **********************

(defcfun ("zmq_close" close) :int
  (s	:pointer))

;;  Manipulating socket options.
;;  ****************************

;;  Available socket options, their types and default values.

(defconstant hwm 1)
(defconstant lwm 2)
(defconstant swap 3)
(defconstant affinity 4)
(defconstant identity 5)
(defconstant subscribe 6)
(defconstant unsubscribe 7)
(defconstant rate 8)
(defconstant recovery-ivl 9)
(defconstant mcast-loop 10)
(defconstant sndbuf 11)
(defconstant rcvbuf 12)

(defcfun* ("zmq_setsockopt" %setsockopt) :int
  (s		:pointer)
  (option	:int)
  (optval	:pointer)
  (optvallen	:long))

;;  Creating connections.
;;  *********************

;;  Addresses are composed of the name of the protocol to use followed by ://
;;  and a protocol-specific address. Available protocols:
;;
;;  tcp - the address is composed of IP address and port delimited by colon
;;        sign (:). The IP address can be a hostname (with 'connect') or
;;        a network interface name (with 'bind'). Examples "tcp://eth0:5555",
;;        "tcp://192.168.0.1:20000", "tcp://hq.mycompany.com:80".
;;
;;  pgm & udp - both protocols have same address format. It's network interface
;;              to use, semicolon (;), multicast group IP address, colon (:) and
;;              port. Examples: "pgm://eth2;224.0.0.1:8000",
;;              "udp://192.168.0.111;224.1.1.1:5555".

(defcfun* ("zmq_bind" %bind) :int
  (s	:pointer)
  (addr	:pointer :char))

(defcfun* ("zmq_connect" %connect) :int
  (s	:pointer)
  (addr	:pointer :char))

;;  Sending and receiving messages.
;;  *******************************

(defconstant noblock 1)

(defconstant noflush 2)

(defcfun* ("zmq_send" %send) :int
  (s		:pointer)
  (msg		msg)
  :optional
  (flags	:int))

(defcfun* ("zmq_flush" flush) :int
  (s	:pointer))

(defcfun* ("zmq_recv" %recv) :int
  (s		:pointer)
  (msg		msg)
  :optional
  (flags	:int))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;  I/O multiplexing.
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defconstant pollin 1)
(defconstant pollout 2)

(defcstruct pollitem
  (socket	:pointer)
  (fd		:int)
  (events	:short)
  (revents	:short))

(defcfun ("zmq_poll" %poll) :int
  (items	:pointer)
  (nitems	:int)
  (timeout	:long))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;  Helper functions.
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;; Helper functions used by perf tests so that they don't have to care
;; about minutiae of time-related functions on different OS platforms.

(defcfun ("zmq_stopwatch_start" stopwatch-start) :pointer)

(defcfun ("zmq_stopwatch_stop" stopwatch-stop) :ulong
  (watch	:pointer))

(defcfun ("zmq_sleep" sleep) :void
  (seconds	:int))
