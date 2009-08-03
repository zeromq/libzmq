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

#ifndef __ZMQ_COMMAND_HPP_INCLUDED__
#define __ZMQ_COMMAND_HPP_INCLUDED__

#include "stdint.hpp"

namespace zmq
{

    //  This structure defines the commands that can be sent between threads.

    struct command_t
    {
        //  Object to process the command.
        class object_t *destination;

        enum type_t
        {
            stop,
            bind,
            head,
            tail,
            reg,
            reg_and_bind,
            unreg,
            engine,
            terminate,
            terminate_ack
        } type;

        union {

            struct {
            } stop;

            struct {
                class pipe_reader_t *reader;
                class session_t *peer;
            } bind;

            struct {
                uint64_t bytes;
            } tail;

            struct {
                uint64_t bytes;
            } head;

            struct {
                class simple_semaphore_t *smph;
            } reg;

            struct {
                class session_t *peer;
                bool flow_in;
                bool flow_out;
            } reg_and_bind;

            struct {
                class simple_semaphore_t *smph;
            } unreg;

            //  TODO: Engine object won't be deallocated on terminal shutdown
            //  while the command is still on the fly!
            struct {
                class i_engine *engine;
            } engine;

            struct {
            } terminate;

            struct {
            } terminate_ack;

        } args;
    };

}    

#endif
