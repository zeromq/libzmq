/*
    Copyright (c) 2007-2010 iMatix Corporation

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
#endif

#include <stdlib.h>
#include <string.h>
#include <string>

#include "options.hpp"
#include "pgm_socket.hpp"
#include "config.hpp"
#include "err.hpp"
#include "uuid.hpp"
#include "stdint.hpp"

zmq::pgm_socket_t::pgm_socket_t (bool receiver_, const options_t &options_) :
    transport (NULL),
    options (options_),
    receiver (receiver_),
    pgm_msgv (NULL),
    pgm_msgv_len (0),
    nbytes_rec (0),
    nbytes_processed (0),
    pgm_msgv_processed (0)
{
}

int zmq::pgm_socket_t::init (bool udp_encapsulation_, const char *network_)
{
    //  Can not open transport before destroying old one. 
    zmq_assert (transport == NULL);
 
    //  Parse port number.
    const char *port_delim = strchr (network_, ':');
    if (!port_delim) {
        errno = EINVAL;
        return -1;
    }

    uint16_t port_number = atoi (port_delim + 1);
  
    char network [256];
    if (port_delim - network_ >= (int) sizeof (network) - 1) {
        errno = EINVAL;
        return -1;
    }
    memset (network, '\0', sizeof (network));
    memcpy (network, network_, port_delim - network_);
    
    //  Zero counter used in msgrecv.
    nbytes_rec = 0;
    nbytes_processed = 0;
    pgm_msgv_processed = 0;

    int rc;
    GError *pgm_error = NULL;

    //  PGM transport GSI.
    pgm_gsi_t gsi;
 
    std::string gsi_base;

    if (options.identity.size () > 0) {

        //  Create gsi from identity.
        //  TODO: We assume that identity is standard C string here.
        //  What if it contains binary zeroes?
        gsi_base.assign ((const char*) options.identity.data (),
            options.identity.size ());
    } else {

        //  Generate random gsi.
        gsi_base = uuid_t ().to_string ();
    }

    rc = pgm_gsi_create_from_string (&gsi, gsi_base.c_str (), -1);
    if (rc != TRUE) {
        errno = EINVAL;
        return -1;
    }

    struct pgm_transport_info_t *res = NULL;
    struct pgm_transport_info_t hint;
    memset (&hint, 0, sizeof (hint));
    hint.ti_family = AF_INET;
    
    if (!pgm_if_get_transport_info (network, &hint, &res, &pgm_error)) {
        if (pgm_error->domain == PGM_IF_ERROR && (
              pgm_error->code == PGM_IF_ERROR_INVAL ||
              pgm_error->code == PGM_IF_ERROR_XDEV ||
              pgm_error->code == PGM_IF_ERROR_NODEV ||
              pgm_error->code == PGM_IF_ERROR_NOTUNIQ ||
              pgm_error->code == PGM_IF_ERROR_ADDRFAMILY ||
              pgm_error->code == PGM_IF_ERROR_FAMILY ||
              pgm_error->code == PGM_IF_ERROR_NODATA ||
              pgm_error->code == PGM_IF_ERROR_NONAME ||
              pgm_error->code == PGM_IF_ERROR_SERVICE)) {
            g_error_free (pgm_error);
            errno = EINVAL;
            return -1;
        }

        zmq_assert (false);
    }

    res->ti_gsi = gsi;
    res->ti_dport = port_number;

    //  If we are using UDP encapsulation update gsr or res. 
    if (udp_encapsulation_) {
        res->ti_udp_encap_ucast_port = port_number;
        res->ti_udp_encap_mcast_port = port_number;
    }

    if (!pgm_transport_create (&transport, res, &pgm_error)) {
        if (pgm_error->domain == PGM_TRANSPORT_ERROR && (
              pgm_error->code == PGM_TRANSPORT_ERROR_INVAL ||
              pgm_error->code == PGM_TRANSPORT_ERROR_PERM ||
              pgm_error->code == PGM_TRANSPORT_ERROR_NODEV)) {
            pgm_if_free_transport_info (res);
            g_error_free (pgm_error);
            errno = EINVAL;
            return -1;
        }

        zmq_assert (false);
    }

    pgm_if_free_transport_info (res);

    //  Common parameters for receiver and sender.

    //  Set maximum transport protocol data unit size (TPDU).
    rc = pgm_transport_set_max_tpdu (transport, pgm_max_tpdu);
    if (rc != TRUE) {
        errno = EINVAL;
        return -1;
    }

    //  Set maximum number of network hops to cross.
    rc = pgm_transport_set_hops (transport, 16);
    if (rc != TRUE) {
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
        
        //  Note that NAKs are still generated by the transport.
        rc = pgm_transport_set_recv_only (transport, true, false);
        zmq_assert (rc == TRUE);

        if (options.rcvbuf) {
            rc = pgm_transport_set_rcvbuf (transport, (int) options.rcvbuf);
            if (rc != TRUE)
                return -1;
        }

        //  Set NAK transmit back-off interval [us].
        rc = pgm_transport_set_nak_bo_ivl (transport, 50 * 1000);
        zmq_assert (rc == TRUE);

        //  Set timeout before repeating NAK [us].
        rc = pgm_transport_set_nak_rpt_ivl (transport, 200 * 1000);
        zmq_assert (rc == TRUE);

        //  Set timeout for receiving RDATA.
        rc = pgm_transport_set_nak_rdata_ivl (transport, 200 * 1000);
        zmq_assert (rc == TRUE);

        //  Set retries for NAK without NCF/DATA (NAK_DATA_RETRIES).
        rc = pgm_transport_set_nak_data_retries (transport, 5);
        zmq_assert (rc == TRUE);

        //  Set retries for NCF after NAK (NAK_NCF_RETRIES).
        rc = pgm_transport_set_nak_ncf_retries (transport, 2);
        zmq_assert (rc == TRUE);

        //  Set timeout for removing a dead peer [us].
        rc = pgm_transport_set_peer_expiry (transport, 5 * 8192 * 1000);
        zmq_assert (rc == TRUE);

        //  Set expiration time of SPM Requests [us].
        rc = pgm_transport_set_spmr_expiry (transport, 25 * 1000);
        zmq_assert (rc == TRUE);

        //  Set the size of the receive window.
        //  Data rate is in [B/s]. options.rate is in [kb/s].
        if (options.rate <= 0) {
            errno = EINVAL;
            return -1;
        }
        rc = pgm_transport_set_rxw_max_rte (transport, 
            options.rate * 1000 / 8);
        if (rc != TRUE) {
            errno = EINVAL;
            return -1;
        }

        //  Recovery interval [s]. 
        if (options.recovery_ivl <= 0) {
            errno = EINVAL;
            return -1;
        }
        rc = pgm_transport_set_rxw_secs (transport, options.recovery_ivl);
        if (rc != TRUE) {
            errno = EINVAL;
            return -1;
        }

    } else {

        //  Sender transport.

        //  Waiting pipe won't be read.
        rc = pgm_transport_set_send_only (transport, TRUE);
        zmq_assert (rc == TRUE);

        if (options.sndbuf) {
            rc = pgm_transport_set_sndbuf (transport, (int) options.sndbuf);
            if (rc != TRUE)
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
        if (rc != TRUE) {
            errno = EINVAL;
            return -1;
        }

        //  Recovery interval [s]. 
        if (options.recovery_ivl <= 0) {
            errno = EINVAL;
            return -1;
        }
        rc = pgm_transport_set_txw_secs (transport, options.recovery_ivl);
        if (rc != TRUE) {
            errno = EINVAL;
            return -1;
        }

        //  Set interval of background SPM packets [us].
        rc = pgm_transport_set_ambient_spm (transport, 8192 * 1000);
        zmq_assert (rc == TRUE);

        //  Set intervals of data flushing SPM packets [us].
        guint spm_heartbeat[] = {4 * 1000, 4 * 1000, 8 * 1000, 16 * 1000, 
            32 * 1000, 64 * 1000, 128 * 1000, 256 * 1000, 512 * 1000, 
            1024 * 1000, 2048 * 1000, 4096 * 1000, 8192 * 1000};
        rc = pgm_transport_set_heartbeat_spm (transport, spm_heartbeat, 
            G_N_ELEMENTS(spm_heartbeat));
        zmq_assert (rc == TRUE);
    }
    
    //  Enable multicast loopback.
    if (options.use_multicast_loop) {
        rc = pgm_transport_set_multicast_loop (transport, true);
        zmq_assert (rc == TRUE);
    }

    //  Bind a transport to the specified network devices.
    if (!pgm_transport_bind (transport, &pgm_error)) {
        if (pgm_error->domain == PGM_IF_ERROR && (
              pgm_error->code == PGM_IF_ERROR_INVAL ||
              pgm_error->code == PGM_IF_ERROR_XDEV ||
              pgm_error->code == PGM_IF_ERROR_NODEV ||
              pgm_error->code == PGM_IF_ERROR_NOTUNIQ ||
              pgm_error->code == PGM_IF_ERROR_ADDRFAMILY ||
              pgm_error->code == PGM_IF_ERROR_FAMILY ||
              pgm_error->code == PGM_IF_ERROR_NODATA ||
              pgm_error->code == PGM_IF_ERROR_NONAME ||
              pgm_error->code == PGM_IF_ERROR_SERVICE)) {
            g_error_free (pgm_error);
            errno = EINVAL;
            return -1;
        }
        if (pgm_error->domain == PGM_TRANSPORT_ERROR && (
              pgm_error->code == PGM_TRANSPORT_ERROR_FAILED)) {
            g_error_free (pgm_error);
            errno = EINVAL;
            return -1;
        }

        zmq_assert (false);
    }

    //  For receiver transport preallocate pgm_msgv array.
    //  TODO: ?
    if (receiver) {
        zmq_assert (in_batch_size > 0);
        size_t max_tsdu_size = get_max_tsdu_size ();
        pgm_msgv_len = (int) in_batch_size / max_tsdu_size;
        if ((int) in_batch_size % max_tsdu_size)
            pgm_msgv_len++;
        zmq_assert (pgm_msgv_len);

        pgm_msgv = (pgm_msgv_t*) malloc (sizeof (pgm_msgv_t) * pgm_msgv_len);
    }

    return 0;
}

zmq::pgm_socket_t::~pgm_socket_t ()
{
    if (pgm_msgv)
        free (pgm_msgv);
    if (transport) 
        pgm_transport_destroy (transport, TRUE);
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
//  rdata_notify_fd_ is from transport->rdata_notify.
//  pending_notify_fd_ is from transport->pending_notify.
void zmq::pgm_socket_t::get_sender_fds (int *send_fd_, int *receive_fd_, 
    int *rdata_notify_fd_, int *pending_notify_fd_)
{
    zmq_assert (send_fd_);
    zmq_assert (receive_fd_);

    zmq_assert (rdata_notify_fd_);
    zmq_assert (pending_notify_fd_);

    //  recv_sock2 should not be used - check it.
    zmq_assert (transport->recv_sock2 == -1);

    //  Check if transport can send data and can not receive.
    zmq_assert (transport->can_send_data);
    zmq_assert (!transport->can_recv_data);

    //  Take FDs from transport.
    *send_fd_ = pgm_transport_get_send_fd (transport);
    *receive_fd_ = pgm_transport_get_recv_fd (transport);

    *rdata_notify_fd_ = pgm_transport_get_repair_fd (transport);
    *pending_notify_fd_ = pgm_transport_get_pending_fd (transport);
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
    return (size_t) pgm_transport_max_tsdu (transport, false);
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

        zmq_assert (status != PGM_IO_STATUS_ERROR);

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
            errno = EINVAL;
            g_error_free (pgm_error);
            return -1;
        }

        zmq_assert (status == PGM_IO_STATUS_NORMAL);
    }
    else
    {
        zmq_assert (pgm_msgv_processed <= pgm_msgv_len);
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
    zmq_assert (pgm_msgv_processed <= pgm_msgv_len);
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

    zmq_assert (status != PGM_IO_STATUS_ERROR);

    //  No data should be returned.
    zmq_assert (dummy_bytes == 0 && (status == PGM_IO_STATUS_TIMER_PENDING || 
        status == PGM_IO_STATUS_RATE_LIMITED));
}

#endif

