/*
    Copyright (c) 2007-2009 FastMQ Inc.

    This file is part of 0MQ.

    0MQ is free software; you can redistribute it and/or modify it under
    the terms of the Lesser GNU General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    0MQ is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    Lesser GNU General Public License for more details.

    You should have received a copy of the Lesser GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef __ZS_I_API_HPP_INCLUDED__
#define __ZS_I_API_HPP_INCLUDED__

namespace zs
{

    struct i_api
    {
        virtual int bind (const char *addr_, struct zs_opts *opts_) = 0;
        virtual int connect (const char *addr_, struct zs_opts *opts_) = 0;
        virtual int subscribe (const char *criteria_) = 0;
        virtual int send (struct zs_msg *msg_, int flags_) = 0;
        virtual int flush () = 0;
        virtual int recv (struct zs_msg *msg_, int flags_) = 0;
        virtual int close () = 0;
    };

}

#endif
