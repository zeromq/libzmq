/*
    Copyright (c) 2007-2013 Contributors as noted in the AUTHORS file

    This file is part of 0MQ.

    0MQ is free software; you can redistribute it and/or modify it under
    the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    0MQ is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef __ZMQ_PRECOMPILED_HPP_INCLUDED__
#define __ZMQ_PRECOMPILED_HPP_INCLUDED__

#ifdef _MSC_VER

// Windows headers
#include "platform.hpp"
#include "windows.hpp"
#include <fcntl.h>
#include <intrin.h>
#include <io.h>
#include <rpc.h>
#include <sys/stat.h>

// standard C++ headers
#include <algorithm>
#include <map>
#include <set>
#include <string>
#include <vector>

// 0MQ definitions and exported functions
#include "../include/zmq.h"

#endif // _MSC_VER

#endif
