/* SPDX-License-Identifier: MPL-2.0 */

#ifndef __ZMQ_MECHANISM_BASE_HPP_INCLUDED__
#define __ZMQ_MECHANISM_BASE_HPP_INCLUDED__

#include "mechanism.hpp"

namespace zmq
{
class msg_t;

class mechanism_base_t : public mechanism_t
{
  protected:
    mechanism_base_t (session_base_t *session_, const options_t &options_);

    session_base_t *const session;

    int check_basic_command_structure (msg_t *msg_) const;

    void handle_error_reason (const char *error_reason_,
                              size_t error_reason_len_);

    bool zap_required () const;
};
}

#endif
