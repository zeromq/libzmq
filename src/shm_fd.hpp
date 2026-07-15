/* SPDX-License-Identifier: MPL-2.0 */

#ifndef __ZMQ_SHM_FD_HPP_INCLUDED__
#define __ZMQ_SHM_FD_HPP_INCLUDED__

#include "stdint.hpp"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif

namespace zmq
{
inline int shm_create_fd (size_t size_)
{
    if (size_ == 0) {
        errno = EINVAL;
        return -1;
    }
#if defined SYS_memfd_create
    const int fd = static_cast<int> (
      syscall (SYS_memfd_create, "libzmq-shm", MFD_CLOEXEC));
#else
    errno = ENOSYS;
    const int fd = -1;
#endif
    if (fd == -1)
        return -1;
    if (ftruncate (fd, static_cast<off_t> (size_)) == -1) {
        const int saved_errno = errno;
        close (fd);
        errno = saved_errno;
        return -1;
    }
    return fd;
}

inline void *shm_map_fd (int fd_, size_t size_)
{
    if (fd_ < 0 || size_ == 0) {
        errno = EINVAL;
        return MAP_FAILED;
    }
    return mmap (NULL, size_, PROT_READ | PROT_WRITE, MAP_SHARED, fd_, 0);
}

inline int shm_send_fd (int socket_, int fd_, size_t size_)
{
    if (socket_ < 0 || fd_ < 0 || size_ == 0) {
        errno = EINVAL;
        return -1;
    }
    struct stat stat_buf;
    if (fstat (fd_, &stat_buf) != 0
        || stat_buf.st_size != static_cast<off_t> (size_)) {
        if (errno == 0)
            errno = EINVAL;
        return -1;
    }

    const unsigned char marker = 1;
    struct iovec iov;
    iov.iov_base = const_cast<unsigned char *> (&marker);
    iov.iov_len = sizeof marker;

    union
    {
        struct cmsghdr align;
        unsigned char data[CMSG_SPACE (sizeof (int))];
    } control;
    memset (&control, 0, sizeof control);

    struct msghdr message;
    memset (&message, 0, sizeof message);
    message.msg_iov = &iov;
    message.msg_iovlen = 1;
    message.msg_control = control.data;
    message.msg_controllen = sizeof control.data;

    struct cmsghdr *const cmsg = CMSG_FIRSTHDR (&message);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN (sizeof (int));
    memcpy (CMSG_DATA (cmsg), &fd_, sizeof fd_);

    ssize_t rc;
    do {
        rc = sendmsg (socket_, &message, MSG_NOSIGNAL);
    } while (rc == -1 && errno == EINTR);
    return rc == static_cast<ssize_t> (sizeof marker) ? 0 : -1;
}

inline int shm_recv_fd (int socket_, int *fd_, size_t *size_)
{
    if (socket_ < 0 || !fd_ || !size_) {
        errno = EINVAL;
        return -1;
    }

    unsigned char marker = 0;
    struct iovec iov;
    iov.iov_base = &marker;
    iov.iov_len = sizeof marker;

    union
    {
        struct cmsghdr align;
        unsigned char data[CMSG_SPACE (sizeof (int))];
    } control;
    memset (&control, 0, sizeof control);

    struct msghdr message;
    memset (&message, 0, sizeof message);
    message.msg_iov = &iov;
    message.msg_iovlen = 1;
    message.msg_control = control.data;
    message.msg_controllen = sizeof control.data;

    ssize_t rc;
    do {
#ifdef MSG_CMSG_CLOEXEC
        rc = recvmsg (socket_, &message, MSG_CMSG_CLOEXEC);
#else
        rc = recvmsg (socket_, &message, 0);
#endif
    } while (rc == -1 && errno == EINTR);
    if (rc == -1 && (errno == EAGAIN || errno == EWOULDBLOCK))
        return -1;
    struct cmsghdr *const cmsg = CMSG_FIRSTHDR (&message);
    int received_fd = -1;
    if (cmsg && cmsg->cmsg_level == SOL_SOCKET
        && cmsg->cmsg_type == SCM_RIGHTS
        && cmsg->cmsg_len >= CMSG_LEN (sizeof (int)))
        memcpy (&received_fd, CMSG_DATA (cmsg), sizeof received_fd);

    if (rc != static_cast<ssize_t> (sizeof marker) || marker != 1
        || (message.msg_flags & MSG_CTRUNC) || !cmsg
        || cmsg->cmsg_level != SOL_SOCKET
        || cmsg->cmsg_type != SCM_RIGHTS
        || cmsg->cmsg_len != CMSG_LEN (sizeof (int))) {
        if (received_fd != -1)
            close (received_fd);
        errno = EPROTO;
        return -1;
    }

#ifndef MSG_CMSG_CLOEXEC
    fcntl (received_fd, F_SETFD, FD_CLOEXEC);
#endif
    struct stat stat_buf;
    if (fstat (received_fd, &stat_buf) != 0) {
        const int saved_errno = errno;
        close (received_fd);
        errno = saved_errno;
        return -1;
    }
    if (stat_buf.st_size <= 0) {
        close (received_fd);
        errno = EPROTO;
        return -1;
    }
    *fd_ = received_fd;
    *size_ = static_cast<size_t> (stat_buf.st_size);
    return 0;
}
}

#endif
