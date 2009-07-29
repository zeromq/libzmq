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

#ifndef __ZS_SAFE_OBJECT_HPP_INCLUDED__
#define __ZS_SAFE_OBJECT_HPP_INCLUDED__

#include "object.hpp"
#include "atomic_counter.hpp"	

namespace zs
{

    //  Same as object_t with the exception of termination mechanism. While
    //  object_t is destroyed immediately on terminate (assuming that the caller
    //  have ensured that there are no more commands for the object on the
    //  fly), safe_object_t switches into termination mode and waits for all
    //  the on-the-fly commands to be delivered before it deallocates itself.

    class safe_object_t : public object_t
    {
    public:

        safe_object_t (class dispatcher_t *dispatcher_, int thread_slot_);
        safe_object_t (object_t *parent_);

        void inc_seqnum ();
        void process_command (struct command_t &cmd_);

    protected:

        void terminate ();
        bool is_terminating ();

        virtual ~safe_object_t ();

    private:

        //  Sequence number of the last command sent to the object and last
        //  command processed by the object. The former is an atomic counter
        //  meaning that other threads can increment it safely.
        atomic_counter_t sent_seqnum;
        uint32_t processed_seqnum;

        bool terminating;

        safe_object_t (const safe_object_t&);
        void operator = (const safe_object_t&);
    };

}

#endif
