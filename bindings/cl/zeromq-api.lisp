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

(defclass msg ()
  ((raw		:accessor msg-raw :initform nil)
   (shared	:accessor msg-shared :initform 0 :initarg :shared)))

(defmethod initialize-instance :after ((inst msg) &key size data)
  (let ((obj (foreign-alloc 'msg)))
    (with-slots (raw shared) inst
      (setf raw obj)
      (tg:finalize inst (lambda ()
			  (%msg-close raw)
			  (foreign-free raw)))
      (when shared
	(setf (foreign-slot-value obj 'msg 'shared) (if shared 1 0)))
      (cond (size (%msg-init-size raw size))
	    (data
	     (multiple-value-bind (ptr len)
		 (etypecase data
		   (string (foreign-string-alloc data))
		   (array (values (foreign-alloc :uchar :initial-contents data)
				  (length data))))
	       (msg-init-data raw ptr len (callback zmq-free))))
	    (t (msg-init raw))))))

(defclass pollitem ()
  ((raw		:accessor pollitem-raw :initform nil)
   (socket	:accessor pollitem-socket :initform nil :initarg :socket)
   (fd		:accessor pollitem-fd :initform -1 :initarg :fd)
   (events	:accessor pollitem-events :initform 0 :initarg :events)
   (revents	:accessor pollitem-revents :initform 0)))

(defmethod initialize-instance :after ((inst pollitem) &key)
  (let ((obj (foreign-alloc 'pollitem)))
    (setf (pollitem-raw inst) obj)
    (tg:finalize inst (lambda () (foreign-free obj)))))

(defun bind (s address)
  (with-foreign-string (addr address)
    (%bind s addr)))

(defun connect (s address)
  (with-foreign-string (addr address)
    (%connect s addr)))

(defmacro with-context ((context app-threads io-threads &optional flags) &body body)
  `(let ((,context (init ,app-threads ,io-threads (or ,flags 0))))
     ,@body
     (term ,context)))

(defmacro with-socket ((socket context type) &body body)
  `(let ((,socket (socket ,context ,type)))
     ,@body
     (close ,socket)))

(defmacro with-stopwatch (&body body)
  (let ((watch (gensym)))
    `(with-foreign-object (,watch :long 2)
       (setq ,watch (stopwatch-start))
       ,@body
       (stopwatch-stop ,watch))))

(defun msg-data-as-is (msg)
  (%msg-data (msg-raw msg)))

(defun msg-data-as-string (msg)
  (let ((data (%msg-data (msg-raw msg))))
    (unless (zerop (pointer-address data))
      (convert-from-foreign data :string))))

(defun msg-data-as-array (msg)
  (let ((data (%msg-data (msg-raw msg))))
    (unless (zerop (pointer-address data))
      (let* ((len (msg-size msg))
	     (arr (make-array len :element-type '(unsigned-byte))))
	(dotimes (i len)
	  (setf (aref arr i) (mem-aref data :uchar i)))
	arr))))

(defun send (s msg &optional flags)
  (%send s (msg-raw msg) (or flags 0)))

(defun recv (s msg &optional flags)
  (%recv s (msg-raw msg) (or flags 0)))

(defun msg-init-size (msg size)
  (%msg-init-size (msg-raw msg) size))

(defun msg-close (msg)
  (%msg-close (msg-raw msg)))

(defun msg-size (msg)
  (%msg-size (msg-raw msg)))

(defun msg-move (dst src)
  (%msg-move (msg-raw dst) (msg-raw src)))

(defun msg-copy (dst src)
  (%msg-copy (msg-raw dst) (msg-raw src)))

(defun setsockopt (socket option value)
  (etypecase value
    (string (with-foreign-string (string value)
	      (%setsockopt socket option string (length value))))
    (integer (with-foreign-object (int :long 2)
	       (setf (mem-aref int :long 0) value)
	       (%setsockopt socket option int (foreign-type-size :long))))))

(defun poll (items)
  (let ((len (length items)))
    (with-foreign-object (%items 'pollitem len)
      (dotimes (i len)
	(let ((item (nth i items))
	      (%item (mem-aref %items 'pollitem i)))
	  (with-foreign-slots ((socket fd events revents) %item pollitem)
	    (setf socket (pollitem-socket item)
		  fd (pollitem-fd item)
		  events (pollitem-events item)))))
      (let ((ret (%poll %items len)))
	(if (> ret 0)
	    (loop for i below len
	       for revent = (foreign-slot-value (mem-aref %items 'pollitem i)
						'pollitem
						'revents)
	       collect (setf (pollitem-revents (nth i items)) revent))
	    (error (convert-from-foreign (%strerror *errno*) :string)))))))

(defmacro with-polls (list &body body)
  `(let ,(loop for (name . polls) in list
	    collect `(,name
		      (list
		       ,@(loop for (socket . events) in polls
			    collect `(make-instance 'pollitem
						    :socket ,socket
						    :events ,events)))))
     ,@body))

;
