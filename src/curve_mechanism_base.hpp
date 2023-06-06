/* SPDX-License-Identifier: MPL-2.0 */

#ifndef __ZMQ_CURVE_MECHANISM_BASE_HPP_INCLUDED__
#define __ZMQ_CURVE_MECHANISM_BASE_HPP_INCLUDED__

#ifdef ZMQ_HAVE_CURVE

#if defined(ZMQ_USE_LIBSODIUM)
#include "sodium.h"
#endif

#if crypto_box_NONCEBYTES != 24 || crypto_box_PUBLICKEYBYTES != 32             \
  || crypto_box_SECRETKEYBYTES != 32 || crypto_box_ZEROBYTES != 32             \
  || crypto_box_BOXZEROBYTES != 16 || crypto_secretbox_NONCEBYTES != 24        \
  || crypto_secretbox_ZEROBYTES != 32 || crypto_secretbox_BOXZEROBYTES != 16
#error "CURVE library not built properly"
#endif

#include "mechanism_base.hpp"
#include "options.hpp"

#include <memory>

namespace zmq
{
class curve_encoding_t
{
  public:
    curve_encoding_t (const char *encode_nonce_prefix_,
                      const char *decode_nonce_prefix_,
                      const bool downgrade_sub_);

    int encode (msg_t *msg_);
    int decode (msg_t *msg_, int *error_event_code_);

    uint8_t *get_writable_precom_buffer () { return _cn_precom; }
    const uint8_t *get_precom_buffer () const { return _cn_precom; }

    typedef uint64_t nonce_t;

    nonce_t get_and_inc_nonce () { return _cn_nonce++; }
    void set_peer_nonce (nonce_t peer_nonce_) { _cn_peer_nonce = peer_nonce_; };

  private:
    int check_validity (msg_t *msg_, int *error_event_code_);

    const char *_encode_nonce_prefix;
    const char *_decode_nonce_prefix;

    nonce_t _cn_nonce;
    nonce_t _cn_peer_nonce;

    //  Intermediary buffer used to speed up boxing and unboxing.
    uint8_t _cn_precom[crypto_box_BEFORENMBYTES];

    const bool _downgrade_sub;

    ZMQ_NON_COPYABLE_NOR_MOVABLE (curve_encoding_t)
};

class curve_mechanism_base_t : public virtual mechanism_base_t,
                               public curve_encoding_t
{
  public:
    curve_mechanism_base_t (session_base_t *session_,
                            const options_t &options_,
                            const char *encode_nonce_prefix_,
                            const char *decode_nonce_prefix_,
                            const bool downgrade_sub_);

    // mechanism implementation
    int encode (msg_t *msg_) ZMQ_OVERRIDE;
    int decode (msg_t *msg_) ZMQ_OVERRIDE;
};
}

#endif

#endif
