

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
