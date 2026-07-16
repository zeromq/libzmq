/* SPDX-License-Identifier: MPL-2.0 */

#ifndef __ZMQ_SHM_STATE_HPP_INCLUDED__
#define __ZMQ_SHM_STATE_HPP_INCLUDED__

#if defined ZMQ_HAVE_LINUX

#include "atomic_counter.hpp"
#include "fd.hpp"
#include "macros.hpp"
#include "msg.hpp"
#include "mutex.hpp"
#include "shm_channel.hpp"
#include "stdint.hpp"

#include <stddef.h>

namespace zmq
{
class shm_state_t
{
  public:
    static shm_state_t *create (void *mapping_,
                                size_t mapping_size_,
                                bool server_,
                                fd_t control_fd_,
                                fd_t release_fd_);

    void add_ref ();
    void drop_ref ();
    bool valid () const;

    void set_control_fd (fd_t fd_);
    void clear_control_fd (fd_t fd_);

    int init_direct_message (msg_t *msg_, size_t size_);
    int send_direct_message (msg_t *msg_, int flags_);
    static bool is_shm_message (const msg_t *msg_);

    void *try_reserve_copy (size_t size_,
                            unsigned char flags_,
                            uint64_t *position_);
    void publish_copy (uint64_t position_);

    bool try_receive (uint64_t position_,
                      const void **data_,
                      size_t *size_,
                      unsigned char *flags_) const;
    int init_received_message (msg_t *msg_,
                               uint64_t position_,
                               const void *data_,
                               size_t size_,
                               unsigned char flags_);

  private:
    enum token_kind_t
    {
        direct_send_token,
        receive_token
    };

    struct token_t
    {
        msg_t::content_t content;
        uint64_t magic;
        shm_state_t *state;
        uint64_t position;
        unsigned char kind;
        unsigned char published;
    };

    shm_state_t (void *mapping_,
                 size_t mapping_size_,
                 bool server_,
                 fd_t control_fd_,
                 fd_t release_fd_);
    ~shm_state_t ();

    static void free_message (void *data_, void *hint_);
    static uint64_t token_magic ();
    static token_t *token_from_message (const msg_t *msg_);
    token_t *create_token (token_kind_t kind_, uint64_t position_);
    void cancel_direct (uint64_t position_);
    void release_receive (uint64_t position_);
    bool notify_data ();

    atomic_counter_t _refs;
    void *_mapping;
    size_t _mapping_size;
    shm_channel_t *_channel;
    mutable mutex_t _sync;
    fd_t _control_fd;
    fd_t _release_fd;
    uint64_t _send_position;
    bool _send_reserved;
    bool _direct_mode;

    ZMQ_NON_COPYABLE_NOR_MOVABLE (shm_state_t)
};
}

#endif

#endif
