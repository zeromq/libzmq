

macro(zmq_check_sock_cloexec)
  message(STATUS "Checking whether SOCK_CLOEXEC is supported")
  check_c_source_runs(
    "
#include <sys/types.h>
#include <sys/socket.h>

int main(int argc, char *argv [])
{
    int s = socket(PF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    return(s == -1);
}
"
    ZMQ_HAVE_SOCK_CLOEXEC)
endmacro()

macro(zmq_check_efd_cloexec)
  message(STATUS "Checking whether EFD_CLOEXEC is supported")
  check_c_source_runs(
    "
#include <sys/eventfd.h>

int main(int argc, char *argv [])
{
    int s = eventfd (0, EFD_CLOEXEC);
    return(s == -1);
}
"
    ZMQ_HAVE_EVENTFD_CLOEXEC)
endmacro()

macro(zmq_check_o_cloexec)
  message(STATUS "Checking whether O_CLOEXEC is supported")
  check_c_source_runs(
    "
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

int main(int argc, char *argv [])
{
    int s = open (\"/dev/null\", O_CLOEXEC | O_RDONLY);
    return s == -1;
}
"
    ZMQ_HAVE_O_CLOEXEC)
endmacro()

macro(zmq_check_so_bindtodevice)
  message(STATUS "Checking whether SO_BINDTODEVICE is supported")
  check_c_source_runs(
"
#include <sys/socket.h>

int main(int argc, char *argv [])
{
/* Actually making the setsockopt() call requires CAP_NET_RAW */
#ifndef SO_BINDTODEVICE
    return 1;
#else
    return 0;
#endif
}
"
    ZMQ_HAVE_SO_BINDTODEVICE)
endmacro()

# TCP keep-alives Checks.

macro(zmq_check_so_keepalive)
  message(STATUS "Checking whether SO_KEEPALIVE is supported")
  check_c_source_runs(
"
#include <sys/types.h>
#include <sys/socket.h>

int main(int argc, char *argv [])
{
    int s, rc, opt = 1;
    return(
       ((s = socket(PF_INET, SOCK_STREAM, 0)) == -1) ||
       ((rc = setsockopt(s, SOL_SOCKET, SO_KEEPALIVE,(char*) &opt, sizeof(int))) == -1)
    );
}
"
    ZMQ_HAVE_SO_KEEPALIVE)
endmacro()

macro(zmq_check_tcp_keepcnt)
  message(STATUS "Checking whether TCP_KEEPCNT is supported")
  check_c_source_runs(
    "
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

int main(int argc, char *argv [])
{
    int s, rc, opt = 1;
    return(
       ((s = socket(PF_INET, SOCK_STREAM, 0)) == -1) ||
       ((rc = setsockopt(s, SOL_SOCKET, SO_KEEPALIVE,(char*) &opt, sizeof(int))) == -1) ||
       ((rc = setsockopt(s, IPPROTO_TCP, TCP_KEEPCNT,(char*) &opt, sizeof(int))) == -1)
    );
}
"
    ZMQ_HAVE_TCP_KEEPCNT)
endmacro()

macro(zmq_check_tcp_keepidle)
  message(STATUS "Checking whether TCP_KEEPIDLE is supported")
  check_c_source_runs(
    "
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

int main(int argc, char *argv [])
{
    int s, rc, opt = 1;
    return(
       ((s = socket(PF_INET, SOCK_STREAM, 0)) == -1) ||
       ((rc = setsockopt(s, SOL_SOCKET, SO_KEEPALIVE,(char*) &opt, sizeof(int))) == -1) ||
       ((rc = setsockopt(s, IPPROTO_TCP, TCP_KEEPIDLE,(char*) &opt, sizeof(int))) == -1)
    );
}
"
    ZMQ_HAVE_TCP_KEEPIDLE)
endmacro()


macro(zmq_check_tcp_keepintvl)
  message(STATUS "Checking whether TCP_KEEPINTVL is supported")
  check_c_source_runs(
    "
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

int main(int argc, char *argv [])
{
    int s, rc, opt = 1;
    return(
       ((s = socket(PF_INET, SOCK_STREAM, 0)) == -1) ||
       ((rc = setsockopt(s, SOL_SOCKET, SO_KEEPALIVE,(char*) &opt, sizeof(int))) == -1) ||
       ((rc = setsockopt(s, IPPROTO_TCP, TCP_KEEPINTVL,(char*) &opt, sizeof(int))) == -1)
    );
}

"
    ZMQ_HAVE_TCP_KEEPINTVL)
endmacro()


macro(zmq_check_tcp_keepalive)
  message(STATUS "Checking whether TCP_KEEPALIVE is supported")
  check_c_source_runs(
    "
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

int main(int argc, char *argv [])
{
    int s, rc, opt = 1;
    return(
       ((s = socket(PF_INET, SOCK_STREAM, 0)) == -1) ||
       ((rc = setsockopt(s, SOL_SOCKET, SO_KEEPALIVE,(char*) &opt, sizeof(int))) == -1) ||
       ((rc = setsockopt(s, IPPROTO_TCP, TCP_KEEPALIVE,(char*) &opt, sizeof(int))) == -1)
    );
}
"
    ZMQ_HAVE_TCP_KEEPALIVE)
endmacro()


macro(zmq_check_tcp_tipc)
  message(STATUS "Checking whether TIPC is supported")
  check_c_source_runs(
    "
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <linux/tipc.h>

int main(int argc, char *argv [])
{
    struct sockaddr_tipc topsrv;
    int sd = socket(AF_TIPC, SOCK_SEQPACKET, 0);
    memset(&topsrv, 0, sizeof(topsrv));
    topsrv.family = AF_TIPC;
    topsrv.addrtype = TIPC_ADDR_NAME;
    topsrv.addr.name.name.type = TIPC_TOP_SRV;
    topsrv.addr.name.name.instance = TIPC_TOP_SRV;
    fcntl(sd, F_SETFL, O_NONBLOCK);
}
"
    ZMQ_HAVE_TIPC)
endmacro()


macro(zmq_check_pthread_setname)
  message(STATUS "Checking pthread_setname signature")
  set(SAVE_CMAKE_REQUIRED_FLAGS ${CMAKE_REQUIRED_FLAGS})
  set(CMAKE_REQUIRED_FLAGS "-D_GNU_SOURCE -Werror -pthread")
  check_c_source_runs(
    "
#include <pthread.h>

int main(int argc, char *argv [])
{
    pthread_setname_np (\"foo\");
    return 0;
}
"
    ZMQ_HAVE_PTHREAD_SETNAME_1)
  check_c_source_runs(
    "
#include <pthread.h>

int main(int argc, char *argv [])
{
    pthread_setname_np (pthread_self(), \"foo\");
    return 0;
}
"
    ZMQ_HAVE_PTHREAD_SETNAME_2)
  check_c_source_runs(
    "
#include <pthread.h>

int main(int argc, char *argv [])
{
    pthread_setname_np (pthread_self(), \"foo\", (void *)0);
    return 0;
}
"
    ZMQ_HAVE_PTHREAD_SETNAME_3)
  check_c_source_runs(
    "
#include <pthread.h>

int main(int argc, char *argv [])
{
    pthread_set_name_np (pthread_self(), \"foo\");
    return 0;
}
"
    ZMQ_HAVE_PTHREAD_SET_NAME)
  set(CMAKE_REQUIRED_FLAGS ${SAVE_CMAKE_REQUIRED_FLAGS})
endmacro()

macro(zmq_check_pthread_setaffinity)
  message(STATUS "Checking pthread_setaffinity signature")
  set(SAVE_CMAKE_REQUIRED_FLAGS ${CMAKE_REQUIRED_FLAGS})
  set(CMAKE_REQUIRED_FLAGS "-D_GNU_SOURCE -Werror -pthread")
  check_c_source_runs(
    "
#include <pthread.h>

int main(int argc, char *argv [])
{
    cpu_set_t test; 
    pthread_setaffinity_np (pthread_self(), sizeof(cpu_set_t), &test);
    return 0;
}
"
    ZMQ_HAVE_PTHREAD_SETAFFINITY)
  set(CMAKE_REQUIRED_FLAGS ${SAVE_CMAKE_REQUIRED_FLAGS})
endmacro()


macro(zmq_check_getrandom)
  message(STATUS "Checking whether getrandom is supported")
  check_c_source_runs(
    "
#include <sys/random.h>

int main (int argc, char *argv [])
{
    char buf[4];
    int rc = getrandom(buf, 4, 0);
    return rc == -1 ? 1 : 0;
}
"
    ZMQ_HAVE_GETRANDOM)
endmacro()

macro(zmq_check_noexcept)
  message(STATUS "Checking whether noexcept is supported")
  check_cxx_source_compiles(
"
struct X 
{
    X(int i) noexcept {}
};

int main(int argc, char *argv [])
{
    X x(5);
    return 0;
}
"
    ZMQ_HAVE_NOEXCEPT)
endmacro()
