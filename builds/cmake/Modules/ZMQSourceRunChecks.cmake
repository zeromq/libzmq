

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
    if (sd == -EAFNOSUPPORT) {
        return 1;
    }
    memset(&topsrv, 0, sizeof(topsrv));
    topsrv.family = AF_TIPC;
    topsrv.addrtype = TIPC_ADDR_NAME;
    topsrv.addr.name.name.type = TIPC_TOP_SRV;
    topsrv.addr.name.name.instance = TIPC_TOP_SRV;
    fcntl(sd, F_SETFL, O_NONBLOCK);
    if (connect(sd, (struct sockaddr *)&topsrv, sizeof(topsrv)) != 0) {
        if (errno != EINPROGRESS)
            return -1;
    }
}
"
    ZMQ_HAVE_TIPC)
endmacro()
