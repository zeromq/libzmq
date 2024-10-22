/* SPDX-License-Identifier: MPL-2.0 */

#ifndef __ZMQ_METADATA_HPP_INCLUDED__
#define __ZMQ_METADATA_HPP_INCLUDED__

#include <map>
#include <string>

#include "atomic_counter.hpp"

namespace zmq
{
class metadata_t
{
  public:
    typedef std::map<std::string, std::string> dict_t;

    metadata_t (const dict_t &dict_);

    //  Returns pointer to property value or NULL if
    //  property is not found.
    const char *get (const std::string &property_) const;

    void add_ref ();

    //  Drop reference. Returns true iff the reference
    //  counter drops to zero.
    bool drop_ref ();

  private:
    //  Reference counter.
    atomic_counter_t _ref_cnt;

    //  Dictionary holding metadata.
    const dict_t _dict;

    ZMQ_NON_COPYABLE_NOR_MOVABLE (metadata_t)
};
}

#endif
