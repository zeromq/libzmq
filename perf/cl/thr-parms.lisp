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

(in-package :zeromq-test)

;(defvar *address* "pgm://lo;224.0.0.1:8000")
(defvar *bind-address* "tcp://lo:8000")
(defvar *connect-address* "tcp://localhost:8000")
(defvar *message-count* 1000)
(defvar *message-size* 256)
(defvar *rate* 256)
