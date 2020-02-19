#ifndef __ZMQ_PLATFORM_HPP_INCLUDED__
#define __ZMQ_PLATFORM_HPP_INCLUDED__

#define ZMQ_USE_CV_IMPL_STL11
/* #undef ZMQ_USE_CV_IMPL_WIN32API */
/* #undef ZMQ_USE_CV_IMPL_PTHREADS */
/* #undef ZMQ_USE_CV_IMPL_NONE */

/* #undef ZMQ_IOTHREAD_POLLER_USE_KQUEUE */
#define ZMQ_IOTHREAD_POLLER_USE_EPOLL
/* #undef ZMQ_IOTHREAD_POLLER_USE_EPOLL_CLOEXEC */
/* #undef ZMQ_IOTHREAD_POLLER_USE_DEVPOLL */
/* #undef ZMQ_IOTHREAD_POLLER_USE_POLL */
/* #undef ZMQ_IOTHREAD_POLLER_USE_SELECT */

/* #undef ZMQ_POLL_BASED_ON_SELECT */
#define ZMQ_POLL_BASED_ON_POLL

#define ZMQ_CACHELINE_SIZE 64

/* #undef ZMQ_FORCE_MUTEXES */

/* #undef HAVE_FORK */
/* #undef HAVE_CLOCK_GETTIME */
/* #undef HAVE_GETHRTIME */
/* #undef HAVE_MKDTEMP */
/* #undef ZMQ_HAVE_UIO */

#define ZMQ_HAVE_NOEXCEPT

#ifdef ZMQ_HAVE_WSS
    #undef ZMQ_HAVE_WSS
#endif

/* #undef ZMQ_HAVE_EVENTFD */
/* #undef ZMQ_HAVE_EVENTFD_CLOEXEC */
/* #undef ZMQ_HAVE_IFADDRS */
/* #undef ZMQ_HAVE_SO_BINDTODEVICE */

/* #undef ZMQ_HAVE_SO_PEERCRED */
/* #undef ZMQ_HAVE_LOCAL_PEERCRED */

/* #undef ZMQ_HAVE_O_CLOEXEC */

/* #undef ZMQ_HAVE_SOCK_CLOEXEC */
/* #undef ZMQ_HAVE_SO_KEEPALIVE */
/* #undef ZMQ_HAVE_TCP_KEEPCNT */
/* #undef ZMQ_HAVE_TCP_KEEPIDLE */
/* #undef ZMQ_HAVE_TCP_KEEPINTVL */
/* #undef ZMQ_HAVE_TCP_KEEPALIVE */
/* #undef ZMQ_HAVE_PTHREAD_SETNAME_1 */
/* #undef ZMQ_HAVE_PTHREAD_SETNAME_2 */
/* #undef ZMQ_HAVE_PTHREAD_SETNAME_3 */
/* #undef ZMQ_HAVE_PTHREAD_SET_NAME */
/* #undef ZMQ_HAVE_PTHREAD_SET_AFFINITY */
/* #undef HAVE_ACCEPT4 */
#define HAVE_STRNLEN

#define ZMQ_HAVE_IPC

#define ZMQ_USE_BUILTIN_SHA1
/* #undef ZMQ_USE_NSS */
#define ZMQ_HAVE_WS

/* #undef ZMQ_HAVE_OPENPGM */
/* #undef ZMQ_MAKE_VALGRIND_HAPPY */

#define ZMQ_HAVE_CURVE
/* #undef ZMQ_USE_TWEETNACL */
#define ZMQ_USE_LIBSODIUM
/* #undef SODIUM_STATIC */

#ifdef _AIX
  #define ZMQ_HAVE_AIX
#endif

#if defined __ANDROID__
  #define ZMQ_HAVE_ANDROID
#endif

#if defined __CYGWIN__
  #define ZMQ_HAVE_CYGWIN
#endif

#if defined __MINGW32__
  #define ZMQ_HAVE_MINGW32
#endif

#if defined(__FreeBSD__) || defined(__FreeBSD_kernel__)
  #define ZMQ_HAVE_FREEBSD
#endif

#if defined(__DragonFly__)
  #define ZMQ_HAVE_FREEBSD
  #define ZMQ_HAVE_DRAGONFLY
#endif

#if defined __hpux
  #define ZMQ_HAVE_HPUX
#endif

#if defined __linux__
  #define ZMQ_HAVE_LINUX
#endif

#if defined __NetBSD__
  #define ZMQ_HAVE_NETBSD
#endif

#if defined __OpenBSD__
  #define ZMQ_HAVE_OPENBSD
#endif

// TODO better move OS-specific defines to the automake files, and check for availability of IPC with an explicit test there
#if defined __VMS
  #define ZMQ_HAVE_OPENVMS
  #undef ZMQ_HAVE_IPC
#endif

#if defined __APPLE__
  #define ZMQ_HAVE_OSX
#endif

#if defined __QNXNTO__
  #define ZMQ_HAVE_QNXNTO
#endif

#if defined(sun) || defined(__sun)
  #define ZMQ_HAVE_SOLARIS
#endif

#define ZMQ_HAVE_WINDOWS
/* #undef ZMQ_HAVE_WINDOWS_UWP */

#endif
