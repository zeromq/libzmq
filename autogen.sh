#!/bin/sh
#   Copyright (c) 2007 FastMQ Inc.
#
#   This file is part of 0MQ.
#
#   0MQ is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation; either version 3 of the License, or
#   (at your option) any later version.

#   0MQ is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.

#   You should have received a copy of the GNU General Public License
#   along with this program.  If not, see <http://www.gnu.org/licenses/>.

# Script to generate all required files from fresh svn checkout.



autoreconf --install --force --verbose -I config

if [ $? -ne 0 ]; then
    echo
    echo "Could not run autoreconf, check autotools installation."
    echo
fi
