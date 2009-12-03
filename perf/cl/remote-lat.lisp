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

(asdf:oos 'asdf:load-op :zeromq)

(defpackage :zeromq-test
  (:use :cl))

(in-package :zeromq-test)

(load "lat-parms")

(defvar *elapsed* nil)
(defvar *latency* nil)

(zmq::with-context (ctx 1 1)
  (zmq:with-socket (s ctx zmq:req)
    (zmq:connect s *address*)
    (let ((msg (make-instance 'zmq:msg :size *message-size*)))
      (setf *elapsed*
	    (zmq:with-stopwatch
		(dotimes (i *roundtrip-count*)
		  (zmq:send s msg)
		  (zmq:recv s msg)))))
    (zmq:sleep 1)))

(setf *latency* (/ *elapsed* (* 2 *roundtrip-count*)))

(format t "message size: ~d [B]~%" *message-size*)
(format t "roundtrip count: ~d~%" *roundtrip-count*)
(format t "average latency: ~f [us]~%" *latency*)

(tg:gc)
#+sbcl (sb-ext:quit)
#+clisp (ext:quit)
;
