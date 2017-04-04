/*
    Copyright (c) 2007-2016 Contributors as noted in the AUTHORS file

    This file is part of libzmq, the ZeroMQ core engine in C++.

    libzmq is free software; you can redistribute it and/or modify it under
    the terms of the GNU Lesser General Public License (LGPL) as published
    by the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    As a special exception, the Contributors give you permission to link
    this library with independent modules to produce an executable,
    regardless of the license terms of these independent modules, and to
    copy and distribute the resulting executable under terms of your choice,
    provided that you also meet, for each linked independent module, the
    terms and conditions of the license of that module. An independent
    module is a module which is not derived from or based on this library.
    If you modify this library, you must extend this exception to your
    version of the library.

    libzmq is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
    FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public
    License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

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
            typedef std::map <std::string, std::string> dict_t;

            metadata_t (const dict_t &dict);

            //  Returns pointer to property value or NULL if
            //  property is not found.
            const char *get (const std::string &property) const;

            void add_ref ();

            //  Drop reference. Returns true iff the reference
            //  counter drops to zero.
            bool drop_ref ();

        private:
            metadata_t(const metadata_t&);
            metadata_t & operator=(const metadata_t&);

            //  Reference counter.
            atomic_counter_t ref_cnt;

            //  Dictionary holding metadata.
            dict_t dict;
    };

}

#endif
