/* SPDX-License-Identifier: MPL-2.0 */

#include "precompiled.hpp"
#include "metadata.hpp"

zmq::metadata_t::metadata_t (const dict_t &dict_) : _ref_cnt (1), _dict (dict_)
{
}

const char *zmq::metadata_t::get (const std::string &property_) const
{
    const dict_t::const_iterator it = _dict.find (property_);
    if (it == _dict.end ()) {
        /** \todo remove this when support for the deprecated name "Identity" is dropped */
        if (property_ == "Identity")
            return get (ZMQ_MSG_PROPERTY_ROUTING_ID);

        return NULL;
    }
    return it->second.c_str ();
}

void zmq::metadata_t::add_ref ()
{
    _ref_cnt.add (1);
}

bool zmq::metadata_t::drop_ref ()
{
    return !_ref_cnt.sub (1);
}
