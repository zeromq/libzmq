/* SPDX-License-Identifier: MPL-2.0 */

#ifndef __ZMQ_SOCKET_POLLING_UTIL_HPP_INCLUDED__
#define __ZMQ_SOCKET_POLLING_UTIL_HPP_INCLUDED__

#include <stdlib.h>
#include <vector>

#if defined ZMQ_HAVE_WINDOWS
#include <winsock.h>
#else
#include <sys/select.h>
#endif

#include "macros.hpp"
#include "stdint.hpp"
#include "platform.hpp"
#include "err.hpp"

namespace zmq
{
template <typename T, size_t S> class fast_vector_t
{
  public:
    explicit fast_vector_t (const size_t nitems_)
    {
        if (nitems_ > S) {
            _buf = new (std::nothrow) T[nitems_];
            //  TODO since this function is called by a client, we could return errno == ENOMEM here
            alloc_assert (_buf);
        } else {
            _buf = _static_buf;
        }
    }

    T &operator[] (const size_t i) { return _buf[i]; }

    ~fast_vector_t ()
    {
        if (_buf != _static_buf)
            delete[] _buf;
    }

  private:
    T _static_buf[S];
    T *_buf;

    ZMQ_NON_COPYABLE_NOR_MOVABLE (fast_vector_t)
};

template <typename T, size_t S> class resizable_fast_vector_t
{
  public:
    resizable_fast_vector_t () : _dynamic_buf (NULL) {}

    void resize (const size_t nitems_)
    {
        if (_dynamic_buf) {
            _dynamic_buf->resize (nitems_);
        } else if (nitems_ > S) {
            _dynamic_buf = new (std::nothrow) std::vector<T> (nitems_);
            //  TODO since this function is called by a client, we could return errno == ENOMEM here
            alloc_assert (_dynamic_buf);
            memcpy (&(*_dynamic_buf)[0], _static_buf, sizeof _static_buf);
        }
    }

    T *get_buf ()
    {
        // e.g. MSVC 2008 does not have std::vector::data, so we use &...[0]
        return _dynamic_buf ? &(*_dynamic_buf)[0] : _static_buf;
    }

    T &operator[] (const size_t i) { return get_buf ()[i]; }

    ~resizable_fast_vector_t () { delete _dynamic_buf; }

  private:
    T _static_buf[S];
    std::vector<T> *_dynamic_buf;

    ZMQ_NON_COPYABLE_NOR_MOVABLE (resizable_fast_vector_t)
};

#if defined ZMQ_POLL_BASED_ON_POLL
typedef int timeout_t;

timeout_t
compute_timeout (bool first_pass_, long timeout_, uint64_t now_, uint64_t end_);
#endif
#if (!defined ZMQ_POLL_BASED_ON_POLL && defined ZMQ_POLL_BASED_ON_SELECT)      \
  || defined ZMQ_HAVE_PPOLL
#if defined ZMQ_HAVE_WINDOWS
inline size_t valid_pollset_bytes (const fd_set &pollset_)
{
    // On Windows we don't need to copy the whole fd_set.
    // SOCKETS are continuous from the beginning of fd_array in fd_set.
    // We just need to copy fd_count elements of fd_array.
    // We gain huge memcpy() improvement if number of used SOCKETs is much lower than FD_SETSIZE.
    return reinterpret_cast<const char *> (
             &pollset_.fd_array[pollset_.fd_count])
           - reinterpret_cast<const char *> (&pollset_);
}
#else
inline size_t valid_pollset_bytes (const fd_set & /*pollset_*/)
{
    return sizeof (fd_set);
}
#endif


#if defined ZMQ_HAVE_WINDOWS
// struct fd_set {
//  u_int   fd_count;
//  SOCKET  fd_array[1];
// };
// NOTE: offsetof(fd_set, fd_array)==sizeof(SOCKET) on both x86 and x64
//       due to alignment bytes for the latter.
class optimized_fd_set_t
{
  public:
    explicit optimized_fd_set_t (size_t nevents_) : _fd_set (1 + nevents_) {}

    fd_set *get () { return reinterpret_cast<fd_set *> (&_fd_set[0]); }

  private:
    fast_vector_t<SOCKET, 1 + ZMQ_POLLITEMS_DFLT> _fd_set;
};

class resizable_optimized_fd_set_t
{
  public:
    void resize (size_t nevents_) { _fd_set.resize (1 + nevents_); }

    fd_set *get () { return reinterpret_cast<fd_set *> (&_fd_set[0]); }

  private:
    resizable_fast_vector_t<SOCKET, 1 + ZMQ_POLLITEMS_DFLT> _fd_set;
};
#else
class optimized_fd_set_t
{
  public:
    explicit optimized_fd_set_t (size_t /*nevents_*/) {}

    fd_set *get () { return &_fd_set; }

  private:
    fd_set _fd_set;
};

class resizable_optimized_fd_set_t : public optimized_fd_set_t
{
  public:
    resizable_optimized_fd_set_t () : optimized_fd_set_t (0) {}

    void resize (size_t /*nevents_*/) {}
};
#endif
#endif
}

#endif
