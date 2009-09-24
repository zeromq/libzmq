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

#ifndef __PGM_SOCKET_HPP_INCLUDED__
#define __PGM_SOCKET_HPP_INCLUDED__

#include "platform.hpp"

#if defined ZMQ_HAVE_OPENPGM

#ifdef ZMQ_HAVE_LINUX
#include <glib.h>
#include <pgm/pgm.h>
#else
#include <Winsock2.h>
#endif

#include "stdint.hpp"
#include "options.hpp"

namespace zmq
{
    //  Encapsulates PGM socket.
    class pgm_socket_t
    {

#ifdef ZMQ_HAVE_LINUX

    public:
        //  If receiver_ is true PGM transport is not generating SPM packets.
        //  interface format: iface;mcast_group:port for raw PGM socket
        //                    udp:iface;mcast_goup:port for UDP encapsulacion
        pgm_socket_t (bool receiver_, const options_t &options_);

        //  Closes the transport.
        ~pgm_socket_t ();

        //  Initialize PGM network structures (GSI, GSRs).
        int init (bool udp_encapsulation_, const char *network_);

        //  Open PGM transport. Parameters are the same as in constructor.
        int open_transport (void);

        //  Close transport.
        void close_transport (void);
        
        //   Get receiver fds and store them into user allocated memory.
        int get_receiver_fds (int *recv_fd_, int *waiting_pipe_fd_);

        //   Get sender and receiver fds and store it to user allocated 
        //   memory. Receive fd is used to process NAKs from peers.
        int get_sender_fds (int *send_fd_, int *receive_fd_);

        //  Send data as one APDU, transmit window owned memory.
        size_t send (unsigned char *data_, size_t data_len_);

        //  Allocates one slice for packet in tx window.
        void *get_buffer (size_t *size_);

        //  Fees memory allocated by get_buffer.
        void free_buffer (void *data_);

        //  Receive data from pgm socket.
        ssize_t receive (void **data_, const pgm_tsi_t **tsi_);

        //  POLLIN on sender side should mean NAK or SPMR receiving. 
        //  process_upstream function is used to handle such a situation.
        void process_upstream (void);

    protected:
    
        //  OpenPGM transport
        pgm_transport_t* g_transport;

    private:
        
        //  Returns max tsdu size without fragmentation.
        size_t get_max_tsdu_size (void);

        //  Returns maximum count of apdus which fills readbuf_size_
        size_t get_max_apdu_at_once (size_t readbuf_size_);

        //  Compute gsi from string.
        int pgm_create_custom_gsi (const char *data_, pgm_gsi_t *gsi_);

        //  Associated socket options.
        options_t options;
       
        //  true when pgm_socket should create receiving side.
        bool receiver;

        //  TIBCO Rendezvous format network info.
        char network [256];

        //  PGM transport port number.
        uint16_t port_number;

        //  If we are using UDP encapsulation.
        bool udp_encapsulation;

        //  Array of pgm_msgv_t structures to store received data 
        //  from the socket (pgm_transport_recvmsgv).
        pgm_msgv_t *pgm_msgv;

        // How many bytes were read from pgm socket.
        ssize_t nbytes_rec;

        //  How many bytes were processed from last pgm socket read.
        ssize_t nbytes_processed;
        
        //  How many messages from pgm_msgv were already sent up.
        ssize_t pgm_msgv_processed;

        //  Size of pgm_msgv array.
        ssize_t pgm_msgv_len;

        //  Sender transport uses 2 fd.
        enum {pgm_sender_fd_count = 2};
    
        //  Receiver transport uses 2 fd.
        enum {pgm_receiver_fd_count = 2};
#endif
    };
}
#endif

#endif
