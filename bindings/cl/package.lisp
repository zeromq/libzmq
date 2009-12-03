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

(defpackage #:zeromq
  (:nicknames :zmq)
  (:use :cl :cffi)
  (:shadow #:sleep #:close)
  (:export
   ;; constants
   #:affinity
   #:delimiter
   #:downstream
   #:efsm
   #:emthread
   #:enocompatproto
   #:hausnumero
   #:hwm
   #:identity
   #:lwm
   #:max-vsm-size
   #:mcast-loop
   #:noblock
   #:noflush
   #:p2p
   #:poll
   #:pollin
   #:pollout
   #:pub
   #:rate
   #:recovery-ivl
   #:rep
   #:req
   #:sub
   #:subscribe
   #:swap
   #:unsubscribe
   #:upstream
   #:vsm

   #:events

   ;; structures
   #:msg
   #:pollitem

   ;; functions
   #:bind
   #:close
   #:connect
   #:flush
   #:init
   #:msg-close
   #:msg-copy
   #:msg-data-as-array
   #:msg-data-as-is
   #:msg-data-as-string
   #:msg-init
   #:msg-init-data
   #:msg-init-size
   #:msg-move
   #:msg-size
   #:msg-type
   #:poll
   #:pollitem-events
   #:pollitem-fd
   #:pollitem-revents
   #:pollitem-socket
   #:recv
   #:send
   #:setsockopt
   #:sleep
   #:socket
   #:stopwatch-start
   #:stopwatch-stop
   #:strerror
   #:term

   ;; macros
   #:with-context
   #:with-polls
   #:with-socket
   #:with-stopwatch

   ;; conditions
   #:error-again))

(in-package :zeromq)

(eval-when (:compile-toplevel :load-toplevel :execute)
  (define-foreign-library zeromq
    (:unix (:or "libzmq.so.0.0.0" "libzmq.so"))
    (t "libzmq")))

(use-foreign-library zeromq)
