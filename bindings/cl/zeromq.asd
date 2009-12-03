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

(cl:eval-when (:load-toplevel :execute)
  (asdf:operate 'asdf:load-op :cffi)
  (asdf:operate 'asdf:load-op :trivial-garbage)
  (asdf:operate 'asdf:load-op :iolib.syscalls))

(defpackage #:zeromq-asd
  (:use :cl :asdf))

(in-package #:zeromq-asd)

(defsystem zeromq
  :name "zeromq"
  :version "0.1"
  :author "Vitaly Mayatskikh <v.mayatskih@gmail.com>"
  :licence "LGPLv3"
  :description "Zero MQ 2 bindings"
  :serial t
  :components ((:file "package")
               (:file "meta")
               (:file "zeromq")
               (:file "zeromq-api")))
