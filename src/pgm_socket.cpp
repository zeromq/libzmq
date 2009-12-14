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

#include "platform.hpp"

#ifdef ZMQ_HAVE_OPENPGM

#ifdef ZMQ_HAVE_WINDOWS
#include "windows.hpp"
#endif

#ifdef ZMQ_HAVE_LINUX
#include <poll.h>
//  Has to be defined befiore including pgm/pgm.h
#define CONFIG_HAVE_POLL
#endif

#include <pgm/pgm.h>
#include <string>
#include <iostream>

#include "options.hpp"
#include "pgm_socket.hpp"
#include "config.hpp"
#include "err.hpp"
#include "uuid.hpp"

zmq::pgm_socket_t::pgm_socket_t (bool receiver_, const options_t &options_) :
    transport (NULL),
    options (options_),
    receiver (receiver_),
    port_number (0),
    udp_encapsulation (false),
    pgm_msgv (NULL),
    nbytes_rec (0),
    nbytes_processed (0),
    pgm_msgv_processed (0),
    pgm_msgv_len (0)
{
    
}

int zmq::pgm_socket_t::init (bool udp_encapsulation_, const char *network_)
{
    udp_encapsulation = udp_encapsulation_;
 
    //  Parse port number.
    const char *port_delim = strchr (network_, ':');
    if (!port_delim) {
        errno = EINVAL;
        return -1;
    }

    port_number = atoi (port_delim + 1);
  
    if (port_delim - network_ >= (int) sizeof (network) - 1) {
        errno = EINVAL;
        return -1;
    }

    memset (network, '\0', sizeof (network));
    memcpy (network, network_, port_delim - network_);

    //  Open PGM transport.
    int rc = open_transport ();
    if (rc != 0)
        return -1;

    //  For receiver transport preallocate pgm_msgv array.
    //  in_batch_size configured in confing.hpp
    if (receiver) {
        pgm_msgv_len = get_max_apdu_at_once (in_batch_size);
        pgm_msgv = new pgm_msgv_t [pgm_msgv_len];
    }

    return 0;
}

int zmq::pgm_socket_t::open_transport ()
{
    //  Can not open transport before destroying old one. 
    zmq_assert (transport == NULL);

    //  Zero counter used in msgrecv.
    nbytes_rec = 0;
    nbytes_processed = 0;
    pgm_msgv_processed = 0;

    //  TODO: Converting bool to int? Not nice.
    int pgm_ok = true;
    GError *pgm_error = NULL;

    //  Init PGM transport.
    //  Ensure threading enabled, ensure timer enabled and find PGM protocol id.
    //
    //  Note that if you want to use gettimeofday and sleep for openPGM timing,
    //  set environment variables PGM_TIMER to "GTOD" 
    //  and PGM_SLEEP to "USLEEP".
    int rc = pgm_init ();
    if (rc != 0) {
        errno = EINVAL;
        return -1;
    }

    //  PGM transport GSI.
    pgm_gsi_t gsi;
 
    std::string gsi_base;

    if (options.identity.size () > 0) {

        //  Create gsi from identity string.
        gsi_base = options.identity;
    } else {

        //  Generate random gsi.
        gsi_base = uuid_t ().to_string ();
    }

    rc = pgm_gsi_create_from_string (&gsi, gsi_base.c_str (), -1);

    if (rc != pgm_ok) {
        errno = EINVAL;
        return -1;
    }

    //zmq_log (1, "Transport GSI: %s, %s(%i)\n", pgm_print_gsi (&gsi),
    //    __FILE__, __LINE__);

    struct pgm_transport_info_t *res = NULL;

    if (!pgm_if_get_transport_info (network, NULL, &res, &pgm_error)) {
        errno = EINVAL;
        return -1;
    }

    res->ti_gsi = gsi;
    res->ti_dport = port_number;

    //  If we are using UDP encapsulation update gsr or res. 
    if (udp_encapsulation) {
        res->ti_udp_encap_ucast_port = port_number;
        res->ti_udp_encap_mcast_port = port_number;
    }

    if (!pgm_transport_create (&transport, res, &pgm_error)) { 
        pgm_if_free_transport_info (res);
        //  TODO: tranlate errors from glib into errnos.
        errno = EINVAL;
        return -1;
    }

    pgm_if_free_transport_info (res);

    //  Common parameters for receiver and sender.

    //  Set maximum transport protocol data unit size (TPDU).
    rc = pgm_transport_set_max_tpdu (transport, pgm_max_tpdu);
    if (rc != pgm_ok) {
        errno = EINVAL;
        return -1;
    }

    //  Set maximum number of network hops to cross.
    rc = pgm_transport_set_hops (transport, 16);
    if (rc != pgm_ok) {
        errno = EINVAL;
        return -1;
    }

    //  Set nonblocking send/recv sockets.
    if (!pgm_transport_set_nonblocking (transport, true)) {
        errno = EINVAL;
        return -1;
    }

    if (receiver) {

         //  Receiver transport.
        
        //  Set transport->can_send_data = FALSE.
        //  Note that NAKs are still generated by the transport.
        rc = pgm_transport_set_recv_only (transport, true, false);
        zmq_assert (rc == pgm_ok);

        if (options.rcvbuf) {
            rc = pgm_transport_set_rcvbuf (transport, (int) options.rcvbuf);
            if (rc != pgm_ok)
                return -1;
        }

        //  Set NAK transmit back-off interval [us].
        rc = pgm_transport_set_nak_bo_ivl (transport, 50 * 1000);
        zmq_assert (rc == pgm_ok);

        //  Set timeout before repeating NAK [us].
        rc = pgm_transport_set_nak_rpt_ivl (transport, 200 * 1000);
        zmq_assert (rc == pgm_ok);

        //  Set timeout for receiving RDATA.
        rc = pgm_transport_set_nak_rdata_ivl (transport, 200 * 1000);
        zmq_assert (rc == pgm_ok);

        //  Set retries for NAK without NCF/DATA (NAK_DATA_RETRIES).
        rc = pgm_transport_set_nak_data_retries (transport, 5);
        zmq_assert (rc == pgm_ok);

        //  Set retries for NCF after NAK (NAK_NCF_RETRIES).
        rc = pgm_transport_set_nak_ncf_retries (transport, 2);
        zmq_assert (rc == pgm_ok);

        //  Set timeout for removing a dead peer [us].
        rc = pgm_transport_set_peer_expiry (transport, 5 * 8192 * 1000);
        zmq_assert (rc == pgm_ok);

        //  Set expiration time of SPM Requests [us].
        rc = pgm_transport_set_spmr_expiry (transport, 25 * 1000);
        zmq_assert (rc == pgm_ok);

        //  Set the size of the receive window.
        //  Data rate is in [B/s]. options.rate is in [kb/s].
        if (options.rate <= 0) {
            errno = EINVAL;
            return -1;
        }
        rc = pgm_transport_set_rxw_max_rte (transport, 
            options.rate * 1000 / 8);
        if (rc != pgm_ok) {
            errno = EINVAL;
            return -1;
        }

        //  Recovery interval [s]. 
        if (options.recovery_ivl <= 0) {
            errno = EINVAL;
            return -1;
        }
        rc = pgm_transport_set_rxw_secs (transport, options.recovery_ivl);
        if (rc != pgm_ok) {
            errno = EINVAL;
            return -1;
        }

    } else {

        //  Sender transport.

        //  Set transport->can_recv = FALSE, waiting_pipe will not be read.
        rc = pgm_transport_set_send_only (transport, TRUE);
        zmq_assert (rc == pgm_ok);

        if (options.sndbuf) {
            rc = pgm_transport_set_sndbuf (transport, (int) options.sndbuf);
            if (rc != pgm_ok)
                return -1;
        }

        //  Set the size of the send window.
        //  Data rate is in [B/s] options.rate is in [kb/s].
        if (options.rate <= 0) {
            errno = EINVAL;
            return -1;
        }
        rc = pgm_transport_set_txw_max_rte (transport, 
            options.rate * 1000 / 8);
        if (rc != pgm_ok) {
            errno = EINVAL;
            return -1;
        }

        //  Recovery interval [s]. 
        if (options.recovery_ivl <= 0) {
            errno = EINVAL;
            return -1;
        }
        rc = pgm_transport_set_txw_secs (transport, options.recovery_ivl);
        if (rc != pgm_ok) {
            errno = EINVAL;
            return -1;
        }

        //  Set interval of background SPM packets [us].
        rc = pgm_transport_set_ambient_spm (transport, 8192 * 1000);
        zmq_assert (rc == pgm_ok);

        //  Set intervals of data flushing SPM packets [us].
        guint spm_heartbeat[] = {4 * 1000, 4 * 1000, 8 * 1000, 16 * 1000, 
            32 * 1000, 64 * 1000, 128 * 1000, 256 * 1000, 512 * 1000, 
            1024 * 1000, 2048 * 1000, 4096 * 1000, 8192 * 1000};
        rc = pgm_transport_set_heartbeat_spm (transport, spm_heartbeat, 
            G_N_ELEMENTS(spm_heartbeat));
        zmq_assert (rc == pgm_ok);
    }
    
    //  Enable multicast loopback.
    if (options.use_multicast_loop) {
        rc = pgm_transport_set_multicast_loop (transport, true);
        zmq_assert (rc == pgm_ok);
    }

    //  Bind a transport to the specified network devices.
    if (!pgm_transport_bind (transport, &pgm_error)) {
        //  TODO: tranlate errors from glib into errnos.
        return -1;
    }

    return 0;
}

zmq::pgm_socket_t::~pgm_socket_t ()
{
    //  Celanup.
    if (pgm_msgv) {
        delete [] pgm_msgv;
    }

    if (transport)
        close_transport ();
}

void zmq::pgm_socket_t::close_transport ()
{   
    //  transport has to be valid.
    zmq_assert (transport);

    pgm_transport_destroy (transport, TRUE);

    transport = NULL;
}

//   Get receiver fds. recv_fd is from transport->recv_sock
//   waiting_pipe_fd is from transport->waiting_pipe [0]
void zmq::pgm_socket_t::get_receiver_fds (int *receive_fd_, 
    int *waiting_pipe_fd_)
{
    zmq_assert (receive_fd_);
    zmq_assert (waiting_pipe_fd_);

    //  recv_sock2 should not be used - check it.
    zmq_assert (transport->recv_sock2 == -1);

    //  Check if transport can receive data and can not send.
    zmq_assert (transport->can_recv_data);
    zmq_assert (!transport->can_send_data);

    //  Take FDs directly from transport.
    *receive_fd_ = pgm_transport_get_recv_fd (transport);
    *waiting_pipe_fd_ = pgm_transport_get_pending_fd (transport);
}

//  Get fds and store them into user allocated memory. 
//  sender_fd is from pgm_transport->send_sock.
//  receive_fd_ is from  transport->recv_sock.
//  rdata_notify_fd_ is from transport->rdata_notify (PGM2 only).
void zmq::pgm_socket_t::get_sender_fds (int *send_fd_, int *receive_fd_, 
    int *rdata_notify_fd_)
{
    zmq_assert (send_fd_);
    zmq_assert (receive_fd_);

    zmq_assert (rdata_notify_fd_);

    //  recv_sock2 should not be used - check it.
    zmq_assert (transport->recv_sock2 == -1);

    //  Check if transport can send data and can not receive.
    zmq_assert (transport->can_send_data);
    zmq_assert (!transport->can_recv_data);

    //  Take FDs directly from transport.
    *receive_fd_ = pgm_transport_get_recv_fd (transport);
    *rdata_notify_fd_ = pgm_transport_get_repair_fd (transport);
    *send_fd_ = pgm_transport_get_send_fd (transport);
}

//  Send one APDU, transmit window owned memory.
size_t zmq::pgm_socket_t::send (unsigned char *data_, size_t data_len_)
{
    size_t nbytes = 0;
   
    PGMIOStatus status = pgm_send (transport, data_, data_len_, &nbytes);

    if (nbytes != data_len_) {
        zmq_assert (status == PGM_IO_STATUS_RATE_LIMITED);
        zmq_assert (nbytes == 0);
    }
    
    // We have to write all data as one packet.
    if (nbytes > 0)
        zmq_assert ((ssize_t) nbytes == (ssize_t) data_len_);

    return nbytes;
}

//  Return max TSDU size without fragmentation from current PGM transport.
size_t zmq::pgm_socket_t::get_max_tsdu_size ()
{
    return (size_t)pgm_transport_max_tsdu (transport, false);
}

//  Returns how many APDUs are needed to fill reading buffer.
size_t zmq::pgm_socket_t::get_max_apdu_at_once (size_t readbuf_size_)
{
    zmq_assert (readbuf_size_ > 0);

    //  Read max TSDU size without fragmentation.
    size_t max_tsdu_size = get_max_tsdu_size ();

    //  Calculate number of APDUs needed to fill the reading buffer.
    size_t apdu_count = (int)readbuf_size_ / max_tsdu_size;

    if ((int) readbuf_size_ % max_tsdu_size)
        apdu_count ++;

    //  Have to have at least one APDU.
    zmq_assert (apdu_count);

    return apdu_count;
}

//  Allocate buffer for one packet from the transmit window, The memory buffer 
//  is owned by the transmit window and so must be returned to the window with 
//  content via pgm_transport_send() calls or unused with pgm_packetv_free1(). 
void *zmq::pgm_socket_t::get_buffer (size_t *size_)
{
    //  Store size.
    *size_ = get_max_tsdu_size ();

    //  Allocate buffer.
    unsigned char *apdu_buff = new unsigned char [*size_]; 
    zmq_assert (apdu_buff);
    return apdu_buff;
}

//  Return an unused packet allocated from the transmit window 
//  via pgm_packetv_alloc(). 
void zmq::pgm_socket_t::free_buffer (void *data_)
{
    delete [] (unsigned char*) data_;
}


//  pgm_transport_recvmsgv is called to fill the pgm_msgv array up to 
//  pgm_msgv_len. In subsequent calls data from pgm_msgv structure are 
//  returned.
ssize_t zmq::pgm_socket_t::receive (void **raw_data_, const pgm_tsi_t **tsi_)
{
    size_t raw_data_len = 0;

    //  We just sent all data from pgm_transport_recvmsgv up 
    //  and have to return 0 that another engine in this thread is scheduled.
    if (nbytes_rec == nbytes_processed && nbytes_rec > 0) {

        //  Reset all the counters.
        nbytes_rec = 0;
        nbytes_processed = 0;
        pgm_msgv_processed = 0;
        return 0;
    }

    //  If we have are going first time or if we have processed all pgm_msgv_t
    //  structure previously read from the pgm socket.
    if (nbytes_rec == nbytes_processed) {

        //  Check program flow.
        zmq_assert (pgm_msgv_processed == 0);
        zmq_assert (nbytes_processed == 0);
        zmq_assert (nbytes_rec == 0);

        //  Receive a vector of Application Protocol Domain Unit's (APDUs) 
        //  from the transport.
        GError *pgm_error = NULL;

        const PGMIOStatus status = pgm_recvmsgv (transport, pgm_msgv,
            pgm_msgv_len, MSG_DONTWAIT, &nbytes_rec, &pgm_error);
     
        //  In a case when no ODATA/RDATA fired POLLIN event (SPM...)
        //  pgm_recvmsg returns ?.
        if (status == PGM_IO_STATUS_TIMER_PENDING) {

            zmq_assert (nbytes_rec == 0);

            //  In case if no RDATA/ODATA caused POLLIN 0 is 
            //  returned.
            nbytes_rec = 0;
            return 0;
        }

        //  Data loss.
        if (status == PGM_IO_STATUS_RESET) {

            pgm_peer_t* peer = (pgm_peer_t*) transport->peers_pending->data;

            //  Save lost data TSI.
            *tsi_ = &peer->tsi;
            nbytes_rec = 0;

            //  In case of dala loss -1 is returned.
            return -1;
        }

        //  Catch the rest of the errors. 
        zmq_assert (status == PGM_IO_STATUS_NORMAL);
    }

    zmq_assert (nbytes_rec > 0);

    // Only one APDU per pgm_msgv_t structure is allowed.
    zmq_assert (pgm_msgv [pgm_msgv_processed].msgv_len == 1);
 
    struct pgm_sk_buff_t* skb = 
        pgm_msgv [pgm_msgv_processed].msgv_skb [0];

    //  Take pointers from pgm_msgv_t structure.
    *raw_data_ = skb->data;
    raw_data_len = skb->len;

    //  Save current TSI.
    *tsi_ = &skb->tsi;

    //  Move the the next pgm_msgv_t structure.
    pgm_msgv_processed++;
    nbytes_processed +=raw_data_len;

    return raw_data_len;
}

void zmq::pgm_socket_t::process_upstream ()
{
    pgm_msgv_t dummy_msg;

    size_t dummy_bytes = 0;
    GError *pgm_error = NULL;

    PGMIOStatus status = pgm_recvmsgv (transport, &dummy_msg,
        1, MSG_DONTWAIT, &dummy_bytes, &pgm_error);

    //  No data should be returned.
    zmq_assert (dummy_bytes == 0 && (status == PGM_IO_STATUS_TIMER_PENDING || 
        status == PGM_IO_STATUS_RATE_LIMITED));
}

#endif

