/*
 * wepoll - epoll for Windows
 * https://github.com/piscisaureus/wepoll
 *
 * Copyright 2012-2018, Bert Belder <bertbelder@gmail.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef WEPOLL_EXPORT
#define WEPOLL_EXPORT
#endif

#include <stdint.h>

/* clang-format off */

enum EPOLL_EVENTS {
  EPOLLIN      = (int) (1U <<  0),
  EPOLLPRI     = (int) (1U <<  1),
  EPOLLOUT     = (int) (1U <<  2),
  EPOLLERR     = (int) (1U <<  3),
  EPOLLHUP     = (int) (1U <<  4),
  EPOLLRDNORM  = (int) (1U <<  6),
  EPOLLRDBAND  = (int) (1U <<  7),
  EPOLLWRNORM  = (int) (1U <<  8),
  EPOLLWRBAND  = (int) (1U <<  9),
  EPOLLMSG     = (int) (1U << 10), /* Never reported. */
  EPOLLRDHUP   = (int) (1U << 13),
  EPOLLONESHOT = (int) (1U << 31)
};

#define EPOLLIN      (1U <<  0)
#define EPOLLPRI     (1U <<  1)
#define EPOLLOUT     (1U <<  2)
#define EPOLLERR     (1U <<  3)
#define EPOLLHUP     (1U <<  4)
#define EPOLLRDNORM  (1U <<  6)
#define EPOLLRDBAND  (1U <<  7)
#define EPOLLWRNORM  (1U <<  8)
#define EPOLLWRBAND  (1U <<  9)
#define EPOLLMSG     (1U << 10)
#define EPOLLRDHUP   (1U << 13)
#define EPOLLONESHOT (1U << 31)

#define EPOLL_CTL_ADD 1
#define EPOLL_CTL_MOD 2
#define EPOLL_CTL_DEL 3

/* clang-format on */

typedef void* HANDLE;
typedef uintptr_t SOCKET;

typedef union epoll_data {
  void* ptr;
  int fd;
  uint32_t u32;
  uint64_t u64;
  SOCKET sock; /* Windows specific */
  HANDLE hnd;  /* Windows specific */
} epoll_data_t;

struct epoll_event {
  uint32_t events;   /* Epoll events and flags */
  epoll_data_t data; /* User data variable */
};

#ifdef __cplusplus
extern "C" {
#endif

WEPOLL_EXPORT HANDLE epoll_create(int size);
WEPOLL_EXPORT HANDLE epoll_create1(int flags);

WEPOLL_EXPORT int epoll_close(HANDLE ephnd);

WEPOLL_EXPORT int epoll_ctl(HANDLE ephnd,
                            int op,
                            SOCKET sock,
                            struct epoll_event* event);

WEPOLL_EXPORT int epoll_wait(HANDLE ephnd,
                             struct epoll_event* events,
                             int maxevents,
                             int timeout);

#ifdef __cplusplus
} /* extern "C" */
#endif

#include <malloc.h>
#include <stdlib.h>

#define WEPOLL_INTERNAL static
#define WEPOLL_INTERNAL_VAR static

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wreserved-id-macro"
#endif

#if defined(_WIN32_WINNT) && _WIN32_WINNT < 0x0600
#undef _WIN32_WINNT
#endif

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif

#ifdef __clang__
#pragma clang diagnostic pop
#endif

#ifndef __GNUC__
#pragma warning(push, 1)
#endif

#include <WS2tcpip.h>
#include <WinSock2.h>
#include <Windows.h>

#ifndef __GNUC__
#pragma warning(pop)
#endif

WEPOLL_INTERNAL int nt_global_init(void);

typedef LONG NTSTATUS;
typedef NTSTATUS* PNTSTATUS;

#ifndef NT_SUCCESS
#define NT_SUCCESS(status) (((NTSTATUS)(status)) >= 0)
#endif

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS) 0x00000000L)
#endif

#ifndef STATUS_PENDING
#define STATUS_PENDING ((NTSTATUS) 0x00000103L)
#endif

#ifndef STATUS_CANCELLED
#define STATUS_CANCELLED ((NTSTATUS) 0xC0000120L)
#endif

typedef struct _IO_STATUS_BLOCK {
  union {
    NTSTATUS Status;
    PVOID Pointer;
  };
  ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef VOID(NTAPI* PIO_APC_ROUTINE)(PVOID ApcContext,
                                     PIO_STATUS_BLOCK IoStatusBlock,
                                     ULONG Reserved);

typedef struct _LSA_UNICODE_STRING {
  USHORT Length;
  USHORT MaximumLength;
  PWSTR Buffer;
} LSA_UNICODE_STRING, *PLSA_UNICODE_STRING, UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
  ULONG Length;
  HANDLE RootDirectory;
  PUNICODE_STRING ObjectName;
  ULONG Attributes;
  PVOID SecurityDescriptor;
  PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

#define NTDLL_IMPORT_LIST(X)                                                 \
  X(NTSTATUS,                                                                \
    NTAPI,                                                                   \
    NtDeviceIoControlFile,                                                   \
    (HANDLE FileHandle,                                                      \
     HANDLE Event,                                                           \
     PIO_APC_ROUTINE ApcRoutine,                                             \
     PVOID ApcContext,                                                       \
     PIO_STATUS_BLOCK IoStatusBlock,                                         \
     ULONG IoControlCode,                                                    \
     PVOID InputBuffer,                                                      \
     ULONG InputBufferLength,                                                \
     PVOID OutputBuffer,                                                     \
     ULONG OutputBufferLength))                                              \
                                                                             \
  X(ULONG, WINAPI, RtlNtStatusToDosError, (NTSTATUS Status))                 \
                                                                             \
  X(NTSTATUS,                                                                \
    NTAPI,                                                                   \
    NtCreateKeyedEvent,                                                      \
    (PHANDLE handle,                                                         \
     ACCESS_MASK access,                                                     \
     POBJECT_ATTRIBUTES attr,                                                \
     ULONG flags))                                                           \
                                                                             \
  X(NTSTATUS,                                                                \
    NTAPI,                                                                   \
    NtWaitForKeyedEvent,                                                     \
    (HANDLE handle, PVOID key, BOOLEAN alertable, PLARGE_INTEGER mstimeout)) \
                                                                             \
  X(NTSTATUS,                                                                \
    NTAPI,                                                                   \
    NtReleaseKeyedEvent,                                                     \
    (HANDLE handle, PVOID key, BOOLEAN alertable, PLARGE_INTEGER mstimeout))

#define X(return_type, attributes, name, parameters) \
  WEPOLL_INTERNAL_VAR return_type(attributes* name) parameters;
NTDLL_IMPORT_LIST(X)
#undef X

#include <assert.h>
#include <stddef.h>

#ifndef _SSIZE_T_DEFINED
typedef intptr_t ssize_t;
#endif

#define array_count(a) (sizeof(a) / (sizeof((a)[0])))

/* clang-format off */
#define container_of(ptr, type, member) \
  ((type*) ((uintptr_t) (ptr) - offsetof(type, member)))
/* clang-format on */

#define unused_var(v) ((void) (v))

/* Polyfill `inline` for older versions of msvc (up to Visual Studio 2013) */
#if defined(_MSC_VER) && _MSC_VER < 1900
#define inline __inline
#endif

/* Polyfill `static_assert` for some versions of clang and gcc. */
#if (defined(__clang__) || defined(__GNUC__)) && !defined(static_assert)
#define static_assert(condition, message) typedef __attribute__( \
    (__unused__)) int __static_assert_##__LINE__[(condition) ? 1 : -1]
#endif

/* clang-format off */
#define AFD_POLL_RECEIVE           0x0001
#define AFD_POLL_RECEIVE_EXPEDITED 0x0002
#define AFD_POLL_SEND              0x0004
#define AFD_POLL_DISCONNECT        0x0008
#define AFD_POLL_ABORT             0x0010
#define AFD_POLL_LOCAL_CLOSE       0x0020
#define AFD_POLL_CONNECT           0x0040
#define AFD_POLL_ACCEPT            0x0080
#define AFD_POLL_CONNECT_FAIL      0x0100
/* clang-format on */

typedef struct _AFD_POLL_HANDLE_INFO {
  HANDLE Handle;
  ULONG Events;
  NTSTATUS Status;
} AFD_POLL_HANDLE_INFO, *PAFD_POLL_HANDLE_INFO;

typedef struct _AFD_POLL_INFO {
  LARGE_INTEGER Timeout;
  ULONG NumberOfHandles;
  ULONG Exclusive;
  AFD_POLL_HANDLE_INFO Handles[1];
} AFD_POLL_INFO, *PAFD_POLL_INFO;

WEPOLL_INTERNAL int afd_global_init(void);

WEPOLL_INTERNAL int afd_create_driver_socket(HANDLE iocp,
                                             SOCKET* driver_socket_out);

WEPOLL_INTERNAL int afd_poll(SOCKET driver_socket,
                             AFD_POLL_INFO* poll_info,
                             OVERLAPPED* overlapped);

#define return_map_error(value) \
  do {                          \
    err_map_win_error();        \
    return (value);             \
  } while (0)

#define return_set_error(value, error) \
  do {                                 \
    err_set_win_error(error);          \
    return (value);                    \
  } while (0)

WEPOLL_INTERNAL void err_map_win_error(void);
WEPOLL_INTERNAL void err_set_win_error(DWORD error);
WEPOLL_INTERNAL int err_check_handle(HANDLE handle);

WEPOLL_INTERNAL int ws_global_init(void);

WEPOLL_INTERNAL SOCKET ws_get_base_socket(SOCKET socket);
WEPOLL_INTERNAL int ws_get_protocol_catalog(WSAPROTOCOL_INFOW** infos_out,
                                            size_t* infos_count_out);

#define IOCTL_AFD_POLL 0x00012024

/* clang-format off */
static const GUID _AFD_PROVIDER_GUID_LIST[] = {
  /* MSAFD Tcpip [TCP+UDP+RAW / IP] */
  {0xe70f1aa0, 0xab8b, 0x11cf,
   {0x8c, 0xa3, 0x00, 0x80, 0x5f, 0x48, 0xa1, 0x92}},
  /* MSAFD Tcpip [TCP+UDP+RAW / IPv6] */
  {0xf9eab0c0, 0x26d4, 0x11d0,
   {0xbb, 0xbf, 0x00, 0xaa, 0x00, 0x6c, 0x34, 0xe4}},
  /* MSAFD RfComm [Bluetooth] */
  {0x9fc48064, 0x7298, 0x43e4,
   {0xb7, 0xbd, 0x18, 0x1f, 0x20, 0x89, 0x79, 0x2a}},
  /* MSAFD Irda [IrDA] */
  {0x3972523d, 0x2af1, 0x11d1,
   {0xb6, 0x55, 0x00, 0x80, 0x5f, 0x36, 0x42, 0xcc}}};
/* clang-format on */

static const int _AFD_ANY_PROTOCOL = -1;

/* This protocol info record is used by afd_create_driver_socket() to create
 * sockets that can be used as the first argument to afd_poll(). It is
 * populated on startup by afd_global_init(). */
static WSAPROTOCOL_INFOW _afd_driver_socket_template;

static const WSAPROTOCOL_INFOW* _afd_find_protocol_info(
    const WSAPROTOCOL_INFOW* infos, size_t infos_count, int protocol_id) {
  size_t i, j;

  for (i = 0; i < infos_count; i++) {
    const WSAPROTOCOL_INFOW* info = &infos[i];

    /* Apply protocol id filter. */
    if (protocol_id != _AFD_ANY_PROTOCOL && protocol_id != info->iProtocol)
      continue;

    /* Filter out non-MSAFD protocols. */
    for (j = 0; j < array_count(_AFD_PROVIDER_GUID_LIST); j++) {
      if (memcmp(&info->ProviderId,
                 &_AFD_PROVIDER_GUID_LIST[j],
                 sizeof info->ProviderId) == 0)
        return info;
    }
  }

  return NULL; /* Not found. */
}

int afd_global_init(void) {
  WSAPROTOCOL_INFOW* infos;
  size_t infos_count;
  const WSAPROTOCOL_INFOW* afd_info;

  /* Load the winsock catalog. */
  if (ws_get_protocol_catalog(&infos, &infos_count) < 0)
    return -1;

  /* Find a WSAPROTOCOL_INFOW structure that we can use to create an MSAFD
   * socket. Preferentially we pick a UDP socket, otherwise try TCP or any
   * other type. */
  for (;;) {
    afd_info = _afd_find_protocol_info(infos, infos_count, IPPROTO_UDP);
    if (afd_info != NULL)
      break;

    afd_info = _afd_find_protocol_info(infos, infos_count, IPPROTO_TCP);
    if (afd_info != NULL)
      break;

    afd_info = _afd_find_protocol_info(infos, infos_count, _AFD_ANY_PROTOCOL);
    if (afd_info != NULL)
      break;

    free(infos);
    return_set_error(-1, WSAENETDOWN); /* No suitable protocol found. */
  }

  /* Copy found protocol information from the catalog to a static buffer. */
  _afd_driver_socket_template = *afd_info;

  free(infos);
  return 0;
}

int afd_create_driver_socket(HANDLE iocp, SOCKET* driver_socket_out) {
  SOCKET socket;

  socket = WSASocketW(_afd_driver_socket_template.iAddressFamily,
                      _afd_driver_socket_template.iSocketType,
                      _afd_driver_socket_template.iProtocol,
                      &_afd_driver_socket_template,
                      0,
                      WSA_FLAG_OVERLAPPED);
  if (socket == INVALID_SOCKET)
    return_map_error(-1);

  /* TODO: use WSA_FLAG_NOINHERIT on Windows versions that support it. */
  if (!SetHandleInformation((HANDLE) socket, HANDLE_FLAG_INHERIT, 0))
    goto error;

  if (CreateIoCompletionPort((HANDLE) socket, iocp, 0, 0) == NULL)
    goto error;

  *driver_socket_out = socket;
  return 0;

error:;
  DWORD error = GetLastError();
  closesocket(socket);
  return_set_error(-1, error);
}

int afd_poll(SOCKET driver_socket,
             AFD_POLL_INFO* poll_info,
             OVERLAPPED* overlapped) {
  IO_STATUS_BLOCK iosb;
  IO_STATUS_BLOCK* iosb_ptr;
  HANDLE event = NULL;
  void* apc_context;
  NTSTATUS status;

  if (overlapped != NULL) {
    /* Overlapped operation. */
    iosb_ptr = (IO_STATUS_BLOCK*) &overlapped->Internal;
    event = overlapped->hEvent;

    /* Do not report iocp completion if hEvent is tagged. */
    if ((uintptr_t) event & 1) {
      event = (HANDLE)((uintptr_t) event & ~(uintptr_t) 1);
      apc_context = NULL;
    } else {
      apc_context = overlapped;
    }

  } else {
    /* Blocking operation. */
    iosb_ptr = &iosb;
    event = CreateEventW(NULL, FALSE, FALSE, NULL);
    if (event == NULL)
      return_map_error(-1);
    apc_context = NULL;
  }

  iosb_ptr->Status = STATUS_PENDING;
  status = NtDeviceIoControlFile((HANDLE) driver_socket,
                                 event,
                                 NULL,
                                 apc_context,
                                 iosb_ptr,
                                 IOCTL_AFD_POLL,
                                 poll_info,
                                 sizeof *poll_info,
                                 poll_info,
                                 sizeof *poll_info);

  if (overlapped == NULL) {
    /* If this is a blocking operation, wait for the event to become signaled,
     * and then grab the real status from the io status block. */
    if (status == STATUS_PENDING) {
      DWORD r = WaitForSingleObject(event, INFINITE);

      if (r == WAIT_FAILED) {
        DWORD error = GetLastError();
        CloseHandle(event);
        return_set_error(-1, error);
      }

      status = iosb_ptr->Status;
    }

    CloseHandle(event);
  }

  if (status == STATUS_SUCCESS)
    return 0;
  else if (status == STATUS_PENDING)
    return_set_error(-1, ERROR_IO_PENDING);
  else
    return_set_error(-1, RtlNtStatusToDosError(status));
}

WEPOLL_INTERNAL int api_global_init(void);

WEPOLL_INTERNAL int init(void);

#include <stdbool.h>

typedef struct queue_node queue_node_t;

typedef struct queue_node {
  queue_node_t* prev;
  queue_node_t* next;
} queue_node_t;

typedef struct queue {
  queue_node_t head;
} queue_t;

WEPOLL_INTERNAL void queue_init(queue_t* queue);
WEPOLL_INTERNAL void queue_node_init(queue_node_t* node);

WEPOLL_INTERNAL queue_node_t* queue_first(const queue_t* queue);
WEPOLL_INTERNAL queue_node_t* queue_last(const queue_t* queue);

WEPOLL_INTERNAL void queue_prepend(queue_t* queue, queue_node_t* node);
WEPOLL_INTERNAL void queue_append(queue_t* queue, queue_node_t* node);
WEPOLL_INTERNAL void queue_move_first(queue_t* queue, queue_node_t* node);
WEPOLL_INTERNAL void queue_move_last(queue_t* queue, queue_node_t* node);
WEPOLL_INTERNAL void queue_remove(queue_node_t* node);

WEPOLL_INTERNAL bool queue_empty(const queue_t* queue);
WEPOLL_INTERNAL bool queue_enqueued(const queue_node_t* node);

typedef struct port_state port_state_t;
typedef struct poll_group poll_group_t;

WEPOLL_INTERNAL poll_group_t* poll_group_acquire(port_state_t* port);
WEPOLL_INTERNAL void poll_group_release(poll_group_t* poll_group);

WEPOLL_INTERNAL void poll_group_delete(poll_group_t* poll_group);

WEPOLL_INTERNAL poll_group_t* poll_group_from_queue_node(
    queue_node_t* queue_node);
WEPOLL_INTERNAL SOCKET poll_group_get_socket(poll_group_t* poll_group);

/* N.b.: the tree functions do not set errno or LastError when they fail. Each
 * of the API functions has at most one failure mode. It is up to the caller to
 * set an appropriate error code when necessary. */

typedef struct tree tree_t;
typedef struct tree_node tree_node_t;

typedef struct tree {
  tree_node_t* root;
} tree_t;

typedef struct tree_node {
  tree_node_t* left;
  tree_node_t* right;
  tree_node_t* parent;
  uintptr_t key;
  bool red;
} tree_node_t;

WEPOLL_INTERNAL void tree_init(tree_t* tree);
WEPOLL_INTERNAL void tree_node_init(tree_node_t* node);

WEPOLL_INTERNAL int tree_add(tree_t* tree, tree_node_t* node, uintptr_t key);
WEPOLL_INTERNAL void tree_del(tree_t* tree, tree_node_t* node);

WEPOLL_INTERNAL tree_node_t* tree_find(const tree_t* tree, uintptr_t key);
WEPOLL_INTERNAL tree_node_t* tree_root(const tree_t* tree);

typedef struct port_state port_state_t;
typedef struct sock_state sock_state_t;

WEPOLL_INTERNAL sock_state_t* sock_new(port_state_t* port_state,
                                       SOCKET socket);
WEPOLL_INTERNAL void sock_delete(port_state_t* port_state,
                                 sock_state_t* sock_state);
WEPOLL_INTERNAL void sock_force_delete(port_state_t* port_state,
                                       sock_state_t* sock_state);

WEPOLL_INTERNAL int sock_set_event(port_state_t* port_state,
                                   sock_state_t* sock_state,
                                   const struct epoll_event* ev);

WEPOLL_INTERNAL int sock_update(port_state_t* port_state,
                                sock_state_t* sock_state);
WEPOLL_INTERNAL int sock_feed_event(port_state_t* port_state,
                                    OVERLAPPED* overlapped,
                                    struct epoll_event* ev);

WEPOLL_INTERNAL sock_state_t* sock_state_from_queue_node(
    queue_node_t* queue_node);
WEPOLL_INTERNAL queue_node_t* sock_state_to_queue_node(
    sock_state_t* sock_state);
WEPOLL_INTERNAL sock_state_t* sock_state_from_tree_node(
    tree_node_t* tree_node);
WEPOLL_INTERNAL tree_node_t* sock_state_to_tree_node(sock_state_t* sock_state);

/* The reflock is a special kind of lock that normally prevents a chunk of
 * memory from being freed, but does allow the chunk of memory to eventually be
 * released in a coordinated fashion.
 *
 * Under normal operation, threads increase and decrease the reference count,
 * which are wait-free operations.
 *
 * Exactly once during the reflock's lifecycle, a thread holding a reference to
 * the lock may "destroy" the lock; this operation blocks until all other
 * threads holding a reference to the lock have dereferenced it. After
 * "destroy" returns, the calling thread may assume that no other threads have
 * a reference to the lock.
 *
 * Attemmpting to lock or destroy a lock after reflock_unref_and_destroy() has
 * been called is invalid and results in undefined behavior. Therefore the user
 * should use another lock to guarantee that this can't happen.
 */

typedef struct reflock {
  uint32_t state;
} reflock_t;

WEPOLL_INTERNAL int reflock_global_init(void);

WEPOLL_INTERNAL void reflock_init(reflock_t* reflock);
WEPOLL_INTERNAL void reflock_ref(reflock_t* reflock);
WEPOLL_INTERNAL void reflock_unref(reflock_t* reflock);
WEPOLL_INTERNAL void reflock_unref_and_destroy(reflock_t* reflock);

typedef struct ts_tree {
  tree_t tree;
  SRWLOCK lock;
} ts_tree_t;

typedef struct ts_tree_node {
  tree_node_t tree_node;
  reflock_t reflock;
} ts_tree_node_t;

WEPOLL_INTERNAL void ts_tree_init(ts_tree_t* rtl);
WEPOLL_INTERNAL void ts_tree_node_init(ts_tree_node_t* node);

WEPOLL_INTERNAL int ts_tree_add(ts_tree_t* ts_tree,
                                ts_tree_node_t* node,
                                uintptr_t key);

WEPOLL_INTERNAL ts_tree_node_t* ts_tree_del_and_ref(ts_tree_t* ts_tree,
                                                    uintptr_t key);
WEPOLL_INTERNAL ts_tree_node_t* ts_tree_find_and_ref(ts_tree_t* ts_tree,
                                                     uintptr_t key);

WEPOLL_INTERNAL void ts_tree_node_unref(ts_tree_node_t* node);
WEPOLL_INTERNAL void ts_tree_node_unref_and_destroy(ts_tree_node_t* node);

typedef struct port_state port_state_t;
typedef struct sock_state sock_state_t;

typedef struct port_state {
  HANDLE iocp;
  tree_t sock_tree;
  queue_t sock_update_queue;
  queue_t sock_deleted_queue;
  queue_t poll_group_queue;
  ts_tree_node_t handle_tree_node;
  CRITICAL_SECTION lock;
  size_t active_poll_count;
} port_state_t;

WEPOLL_INTERNAL port_state_t* port_new(HANDLE* iocp_out);
WEPOLL_INTERNAL int port_close(port_state_t* port_state);
WEPOLL_INTERNAL int port_delete(port_state_t* port_state);

WEPOLL_INTERNAL int port_wait(port_state_t* port_state,
                              struct epoll_event* events,
                              int maxevents,
                              int timeout);

WEPOLL_INTERNAL int port_ctl(port_state_t* port_state,
                             int op,
                             SOCKET sock,
                             struct epoll_event* ev);

WEPOLL_INTERNAL int port_register_socket_handle(port_state_t* port_state,
                                                sock_state_t* sock_state,
                                                SOCKET socket);
WEPOLL_INTERNAL void port_unregister_socket_handle(port_state_t* port_state,
                                                   sock_state_t* sock_state);
WEPOLL_INTERNAL sock_state_t* port_find_socket(port_state_t* port_state,
                                               SOCKET socket);

WEPOLL_INTERNAL void port_request_socket_update(port_state_t* port_state,
                                                sock_state_t* sock_state);
WEPOLL_INTERNAL void port_cancel_socket_update(port_state_t* port_state,
                                               sock_state_t* sock_state);

WEPOLL_INTERNAL void port_add_deleted_socket(port_state_t* port_state,
                                             sock_state_t* sock_state);
WEPOLL_INTERNAL void port_remove_deleted_socket(port_state_t* port_state,
                                                sock_state_t* sock_state);

static ts_tree_t _epoll_handle_tree;

static inline port_state_t* _handle_tree_node_to_port(
    ts_tree_node_t* tree_node) {
  return container_of(tree_node, port_state_t, handle_tree_node);
}

int api_global_init(void) {
  ts_tree_init(&_epoll_handle_tree);
  return 0;
}

static HANDLE _epoll_create(void) {
  port_state_t* port_state;
  HANDLE ephnd;

  if (init() < 0)
    return NULL;

  port_state = port_new(&ephnd);
  if (port_state == NULL)
    return NULL;

  if (ts_tree_add(&_epoll_handle_tree,
                  &port_state->handle_tree_node,
                  (uintptr_t) ephnd) < 0) {
    /* This should never happen. */
    port_delete(port_state);
    return_set_error(NULL, ERROR_ALREADY_EXISTS);
  }

  return ephnd;
}

HANDLE epoll_create(int size) {
  if (size <= 0)
    return_set_error(NULL, ERROR_INVALID_PARAMETER);

  return _epoll_create();
}

HANDLE epoll_create1(int flags) {
  if (flags != 0)
    return_set_error(NULL, ERROR_INVALID_PARAMETER);

  return _epoll_create();
}

int epoll_close(HANDLE ephnd) {
  ts_tree_node_t* tree_node;
  port_state_t* port_state;

  if (init() < 0)
    return -1;

  tree_node = ts_tree_del_and_ref(&_epoll_handle_tree, (uintptr_t) ephnd);
  if (tree_node == NULL) {
    err_set_win_error(ERROR_INVALID_PARAMETER);
    goto err;
  }

  port_state = _handle_tree_node_to_port(tree_node);
  port_close(port_state);

  ts_tree_node_unref_and_destroy(tree_node);

  return port_delete(port_state);

err:
  err_check_handle(ephnd);
  return -1;
}

int epoll_ctl(HANDLE ephnd, int op, SOCKET sock, struct epoll_event* ev) {
  ts_tree_node_t* tree_node;
  port_state_t* port_state;
  int r;

  if (init() < 0)
    return -1;

  tree_node = ts_tree_find_and_ref(&_epoll_handle_tree, (uintptr_t) ephnd);
  if (tree_node == NULL) {
    err_set_win_error(ERROR_INVALID_PARAMETER);
    goto err;
  }

  port_state = _handle_tree_node_to_port(tree_node);
  r = port_ctl(port_state, op, sock, ev);

  ts_tree_node_unref(tree_node);

  if (r < 0)
    goto err;

  return 0;

err:
  /* On Linux, in the case of epoll_ctl_mod(), EBADF takes priority over other
   * errors. Wepoll mimics this behavior. */
  err_check_handle(ephnd);
  err_check_handle((HANDLE) sock);
  return -1;
}

int epoll_wait(HANDLE ephnd,
               struct epoll_event* events,
               int maxevents,
               int timeout) {
  ts_tree_node_t* tree_node;
  port_state_t* port_state;
  int num_events;

  if (maxevents <= 0)
    return_set_error(-1, ERROR_INVALID_PARAMETER);

  if (init() < 0)
    return -1;

  tree_node = ts_tree_find_and_ref(&_epoll_handle_tree, (uintptr_t) ephnd);
  if (tree_node == NULL) {
    err_set_win_error(ERROR_INVALID_PARAMETER);
    goto err;
  }

  port_state = _handle_tree_node_to_port(tree_node);
  num_events = port_wait(port_state, events, maxevents, timeout);

  ts_tree_node_unref(tree_node);

  if (num_events < 0)
    goto err;

  return num_events;

err:
  err_check_handle(ephnd);
  return -1;
}

#include <errno.h>

#define ERR__ERRNO_MAPPINGS(X)               \
  X(ERROR_ACCESS_DENIED, EACCES)             \
  X(ERROR_ALREADY_EXISTS, EEXIST)            \
  X(ERROR_BAD_COMMAND, EACCES)               \
  X(ERROR_BAD_EXE_FORMAT, ENOEXEC)           \
  X(ERROR_BAD_LENGTH, EACCES)                \
  X(ERROR_BAD_NETPATH, ENOENT)               \
  X(ERROR_BAD_NET_NAME, ENOENT)              \
  X(ERROR_BAD_NET_RESP, ENETDOWN)            \
  X(ERROR_BAD_PATHNAME, ENOENT)              \
  X(ERROR_BROKEN_PIPE, EPIPE)                \
  X(ERROR_CANNOT_MAKE, EACCES)               \
  X(ERROR_COMMITMENT_LIMIT, ENOMEM)          \
  X(ERROR_CONNECTION_ABORTED, ECONNABORTED)  \
  X(ERROR_CONNECTION_ACTIVE, EISCONN)        \
  X(ERROR_CONNECTION_REFUSED, ECONNREFUSED)  \
  X(ERROR_CRC, EACCES)                       \
  X(ERROR_DIR_NOT_EMPTY, ENOTEMPTY)          \
  X(ERROR_DISK_FULL, ENOSPC)                 \
  X(ERROR_DUP_NAME, EADDRINUSE)              \
  X(ERROR_FILENAME_EXCED_RANGE, ENOENT)      \
  X(ERROR_FILE_NOT_FOUND, ENOENT)            \
  X(ERROR_GEN_FAILURE, EACCES)               \
  X(ERROR_GRACEFUL_DISCONNECT, EPIPE)        \
  X(ERROR_HOST_DOWN, EHOSTUNREACH)           \
  X(ERROR_HOST_UNREACHABLE, EHOSTUNREACH)    \
  X(ERROR_INSUFFICIENT_BUFFER, EFAULT)       \
  X(ERROR_INVALID_ADDRESS, EADDRNOTAVAIL)    \
  X(ERROR_INVALID_FUNCTION, EINVAL)          \
  X(ERROR_INVALID_HANDLE, EBADF)             \
  X(ERROR_INVALID_NETNAME, EADDRNOTAVAIL)    \
  X(ERROR_INVALID_PARAMETER, EINVAL)         \
  X(ERROR_INVALID_USER_BUFFER, EMSGSIZE)     \
  X(ERROR_IO_PENDING, EINPROGRESS)           \
  X(ERROR_LOCK_VIOLATION, EACCES)            \
  X(ERROR_MORE_DATA, EMSGSIZE)               \
  X(ERROR_NETNAME_DELETED, ECONNABORTED)     \
  X(ERROR_NETWORK_ACCESS_DENIED, EACCES)     \
  X(ERROR_NETWORK_BUSY, ENETDOWN)            \
  X(ERROR_NETWORK_UNREACHABLE, ENETUNREACH)  \
  X(ERROR_NOACCESS, EFAULT)                  \
  X(ERROR_NONPAGED_SYSTEM_RESOURCES, ENOMEM) \
  X(ERROR_NOT_ENOUGH_MEMORY, ENOMEM)         \
  X(ERROR_NOT_ENOUGH_QUOTA, ENOMEM)          \
  X(ERROR_NOT_FOUND, ENOENT)                 \
  X(ERROR_NOT_LOCKED, EACCES)                \
  X(ERROR_NOT_READY, EACCES)                 \
  X(ERROR_NOT_SAME_DEVICE, EXDEV)            \
  X(ERROR_NOT_SUPPORTED, ENOTSUP)            \
  X(ERROR_NO_MORE_FILES, ENOENT)             \
  X(ERROR_NO_SYSTEM_RESOURCES, ENOMEM)       \
  X(ERROR_OPERATION_ABORTED, EINTR)          \
  X(ERROR_OUT_OF_PAPER, EACCES)              \
  X(ERROR_PAGED_SYSTEM_RESOURCES, ENOMEM)    \
  X(ERROR_PAGEFILE_QUOTA, ENOMEM)            \
  X(ERROR_PATH_NOT_FOUND, ENOENT)            \
  X(ERROR_PIPE_NOT_CONNECTED, EPIPE)         \
  X(ERROR_PORT_UNREACHABLE, ECONNRESET)      \
  X(ERROR_PROTOCOL_UNREACHABLE, ENETUNREACH) \
  X(ERROR_REM_NOT_LIST, ECONNREFUSED)        \
  X(ERROR_REQUEST_ABORTED, EINTR)            \
  X(ERROR_REQ_NOT_ACCEP, EWOULDBLOCK)        \
  X(ERROR_SECTOR_NOT_FOUND, EACCES)          \
  X(ERROR_SEM_TIMEOUT, ETIMEDOUT)            \
  X(ERROR_SHARING_VIOLATION, EACCES)         \
  X(ERROR_TOO_MANY_NAMES, ENOMEM)            \
  X(ERROR_TOO_MANY_OPEN_FILES, EMFILE)       \
  X(ERROR_UNEXP_NET_ERR, ECONNABORTED)       \
  X(ERROR_WAIT_NO_CHILDREN, ECHILD)          \
  X(ERROR_WORKING_SET_QUOTA, ENOMEM)         \
  X(ERROR_WRITE_PROTECT, EACCES)             \
  X(ERROR_WRONG_DISK, EACCES)                \
  X(WSAEACCES, EACCES)                       \
  X(WSAEADDRINUSE, EADDRINUSE)               \
  X(WSAEADDRNOTAVAIL, EADDRNOTAVAIL)         \
  X(WSAEAFNOSUPPORT, EAFNOSUPPORT)           \
  X(WSAECONNABORTED, ECONNABORTED)           \
  X(WSAECONNREFUSED, ECONNREFUSED)           \
  X(WSAECONNRESET, ECONNRESET)               \
  X(WSAEDISCON, EPIPE)                       \
  X(WSAEFAULT, EFAULT)                       \
  X(WSAEHOSTDOWN, EHOSTUNREACH)              \
  X(WSAEHOSTUNREACH, EHOSTUNREACH)           \
  X(WSAEINPROGRESS, EBUSY)                   \
  X(WSAEINTR, EINTR)                         \
  X(WSAEINVAL, EINVAL)                       \
  X(WSAEISCONN, EISCONN)                     \
  X(WSAEMSGSIZE, EMSGSIZE)                   \
  X(WSAENETDOWN, ENETDOWN)                   \
  X(WSAENETRESET, EHOSTUNREACH)              \
  X(WSAENETUNREACH, ENETUNREACH)             \
  X(WSAENOBUFS, ENOMEM)                      \
  X(WSAENOTCONN, ENOTCONN)                   \
  X(WSAENOTSOCK, ENOTSOCK)                   \
  X(WSAEOPNOTSUPP, EOPNOTSUPP)               \
  X(WSAEPROCLIM, ENOMEM)                     \
  X(WSAESHUTDOWN, EPIPE)                     \
  X(WSAETIMEDOUT, ETIMEDOUT)                 \
  X(WSAEWOULDBLOCK, EWOULDBLOCK)             \
  X(WSANOTINITIALISED, ENETDOWN)             \
  X(WSASYSNOTREADY, ENETDOWN)                \
  X(WSAVERNOTSUPPORTED, ENOSYS)

static errno_t _err_map_win_error_to_errno(DWORD error) {
  switch (error) {
#define X(error_sym, errno_sym) \
  case error_sym:               \
    return errno_sym;
    ERR__ERRNO_MAPPINGS(X)
#undef X
  }
  return EINVAL;
}

void err_map_win_error(void) {
  errno = _err_map_win_error_to_errno(GetLastError());
}

void err_set_win_error(DWORD error) {
  SetLastError(error);
  errno = _err_map_win_error_to_errno(error);
}

int err_check_handle(HANDLE handle) {
  DWORD flags;

  /* GetHandleInformation() succeeds when passed INVALID_HANDLE_VALUE, so check
   * for this condition explicitly. */
  if (handle == INVALID_HANDLE_VALUE)
    return_set_error(-1, ERROR_INVALID_HANDLE);

  if (!GetHandleInformation(handle, &flags))
    return_map_error(-1);

  return 0;
}

static bool _initialized = false;
static INIT_ONCE _once = INIT_ONCE_STATIC_INIT;

static BOOL CALLBACK _init_once_callback(INIT_ONCE* once,
                                         void* parameter,
                                         void** context) {
  unused_var(once);
  unused_var(parameter);
  unused_var(context);

  /* N.b. that initialization order matters here. */
  if (ws_global_init() < 0 || nt_global_init() < 0 || afd_global_init() < 0 ||
      reflock_global_init() < 0 || api_global_init() < 0)
    return FALSE;

  _initialized = true;
  return TRUE;
}

int init(void) {
  if (!_initialized &&
      !InitOnceExecuteOnce(&_once, _init_once_callback, NULL, NULL))
    return -1; /* LastError and errno aren't touched InitOnceExecuteOnce. */

  return 0;
}

#define X(return_type, attributes, name, parameters) \
  WEPOLL_INTERNAL return_type(attributes* name) parameters = NULL;
NTDLL_IMPORT_LIST(X)
#undef X

int nt_global_init(void) {
  HMODULE ntdll;

  ntdll = GetModuleHandleW(L"ntdll.dll");
  if (ntdll == NULL)
    return -1;

#define X(return_type, attributes, name, parameters)                         \
  name = (return_type(attributes*) parameters) GetProcAddress(ntdll, #name); \
  if (name == NULL)                                                          \
    return -1;
  NTDLL_IMPORT_LIST(X)
#undef X

  return 0;
}

#include <string.h>

static const size_t _POLL_GROUP_MAX_GROUP_SIZE = 32;

typedef struct poll_group {
  port_state_t* port_state;
  queue_node_t queue_node;
  SOCKET socket;
  size_t group_size;
} poll_group_t;

static poll_group_t* _poll_group_new(port_state_t* port_state) {
  poll_group_t* poll_group = malloc(sizeof *poll_group);
  if (poll_group == NULL)
    return_set_error(NULL, ERROR_NOT_ENOUGH_MEMORY);

  memset(poll_group, 0, sizeof *poll_group);

  queue_node_init(&poll_group->queue_node);
  poll_group->port_state = port_state;

  if (afd_create_driver_socket(port_state->iocp, &poll_group->socket) < 0) {
    free(poll_group);
    return NULL;
  }

  queue_append(&port_state->poll_group_queue, &poll_group->queue_node);

  return poll_group;
}

void poll_group_delete(poll_group_t* poll_group) {
  assert(poll_group->group_size == 0);
  closesocket(poll_group->socket);
  queue_remove(&poll_group->queue_node);
  free(poll_group);
}

poll_group_t* poll_group_from_queue_node(queue_node_t* queue_node) {
  return container_of(queue_node, poll_group_t, queue_node);
}

SOCKET poll_group_get_socket(poll_group_t* poll_group) {
  return poll_group->socket;
}

poll_group_t* poll_group_acquire(port_state_t* port_state) {
  queue_t* queue = &port_state->poll_group_queue;
  poll_group_t* poll_group =
      !queue_empty(queue)
          ? container_of(queue_last(queue), poll_group_t, queue_node)
          : NULL;

  if (poll_group == NULL ||
      poll_group->group_size >= _POLL_GROUP_MAX_GROUP_SIZE)
    poll_group = _poll_group_new(port_state);
  if (poll_group == NULL)
    return NULL;

  if (++poll_group->group_size == _POLL_GROUP_MAX_GROUP_SIZE)
    queue_move_first(&port_state->poll_group_queue, &poll_group->queue_node);

  return poll_group;
}

void poll_group_release(poll_group_t* poll_group) {
  port_state_t* port_state = poll_group->port_state;

  poll_group->group_size--;
  assert(poll_group->group_size < _POLL_GROUP_MAX_GROUP_SIZE);

  queue_move_last(&port_state->poll_group_queue, &poll_group->queue_node);

  /* Poll groups are currently only freed when the epoll port is closed. */
}

#define PORT__MAX_ON_STACK_COMPLETIONS 256

static port_state_t* _port_alloc(void) {
  port_state_t* port_state = malloc(sizeof *port_state);
  if (port_state == NULL)
    return_set_error(NULL, ERROR_NOT_ENOUGH_MEMORY);

  return port_state;
}

static void _port_free(port_state_t* port) {
  assert(port != NULL);
  free(port);
}

static HANDLE _port_create_iocp(void) {
  HANDLE iocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
  if (iocp == NULL)
    return_map_error(NULL);

  return iocp;
}

port_state_t* port_new(HANDLE* iocp_out) {
  port_state_t* port_state;
  HANDLE iocp;

  port_state = _port_alloc();
  if (port_state == NULL)
    goto err1;

  iocp = _port_create_iocp();
  if (iocp == NULL)
    goto err2;

  memset(port_state, 0, sizeof *port_state);

  port_state->iocp = iocp;
  tree_init(&port_state->sock_tree);
  queue_init(&port_state->sock_update_queue);
  queue_init(&port_state->sock_deleted_queue);
  queue_init(&port_state->poll_group_queue);
  ts_tree_node_init(&port_state->handle_tree_node);
  InitializeCriticalSection(&port_state->lock);

  *iocp_out = iocp;
  return port_state;

err2:
  _port_free(port_state);
err1:
  return NULL;
}

static int _port_close_iocp(port_state_t* port_state) {
  HANDLE iocp = port_state->iocp;
  port_state->iocp = NULL;

  if (!CloseHandle(iocp))
    return_map_error(-1);

  return 0;
}

int port_close(port_state_t* port_state) {
  int result;

  EnterCriticalSection(&port_state->lock);
  result = _port_close_iocp(port_state);
  LeaveCriticalSection(&port_state->lock);

  return result;
}

int port_delete(port_state_t* port_state) {
  tree_node_t* tree_node;
  queue_node_t* queue_node;

  /* At this point the IOCP port should have been closed. */
  assert(port_state->iocp == NULL);

  while ((tree_node = tree_root(&port_state->sock_tree)) != NULL) {
    sock_state_t* sock_state = sock_state_from_tree_node(tree_node);
    sock_force_delete(port_state, sock_state);
  }

  while ((queue_node = queue_first(&port_state->sock_deleted_queue)) != NULL) {
    sock_state_t* sock_state = sock_state_from_queue_node(queue_node);
    sock_force_delete(port_state, sock_state);
  }

  while ((queue_node = queue_first(&port_state->poll_group_queue)) != NULL) {
    poll_group_t* poll_group = poll_group_from_queue_node(queue_node);
    poll_group_delete(poll_group);
  }

  assert(queue_empty(&port_state->sock_update_queue));

  DeleteCriticalSection(&port_state->lock);

  _port_free(port_state);

  return 0;
}

static int _port_update_events(port_state_t* port_state) {
  queue_t* sock_update_queue = &port_state->sock_update_queue;

  /* Walk the queue, submitting new poll requests for every socket that needs
   * it. */
  while (!queue_empty(sock_update_queue)) {
    queue_node_t* queue_node = queue_first(sock_update_queue);
    sock_state_t* sock_state = sock_state_from_queue_node(queue_node);

    if (sock_update(port_state, sock_state) < 0)
      return -1;

    /* sock_update() removes the socket from the update queue. */
  }

  return 0;
}

static void _port_update_events_if_polling(port_state_t* port_state) {
  if (port_state->active_poll_count > 0)
    _port_update_events(port_state);
}

static int _port_feed_events(port_state_t* port_state,
                             struct epoll_event* epoll_events,
                             OVERLAPPED_ENTRY* iocp_events,
                             DWORD iocp_event_count) {
  int epoll_event_count = 0;
  DWORD i;

  for (i = 0; i < iocp_event_count; i++) {
    OVERLAPPED* overlapped = iocp_events[i].lpOverlapped;
    struct epoll_event* ev = &epoll_events[epoll_event_count];

    epoll_event_count += sock_feed_event(port_state, overlapped, ev);
  }

  return epoll_event_count;
}

static int _port_poll(port_state_t* port_state,
                      struct epoll_event* epoll_events,
                      OVERLAPPED_ENTRY* iocp_events,
                      DWORD maxevents,
                      DWORD timeout) {
  DWORD completion_count;

  if (_port_update_events(port_state) < 0)
    return -1;

  port_state->active_poll_count++;

  LeaveCriticalSection(&port_state->lock);

  BOOL r = GetQueuedCompletionStatusEx(port_state->iocp,
                                       iocp_events,
                                       maxevents,
                                       &completion_count,
                                       timeout,
                                       FALSE);

  EnterCriticalSection(&port_state->lock);

  port_state->active_poll_count--;

  if (!r)
    return_map_error(-1);

  return _port_feed_events(
      port_state, epoll_events, iocp_events, completion_count);
}

int port_wait(port_state_t* port_state,
              struct epoll_event* events,
              int maxevents,
              int timeout) {
  OVERLAPPED_ENTRY stack_iocp_events[PORT__MAX_ON_STACK_COMPLETIONS];
  OVERLAPPED_ENTRY* iocp_events;
  uint64_t due = 0;
  DWORD gqcs_timeout;
  int result;

  /* Check whether `maxevents` is in range. */
  if (maxevents <= 0)
    return_set_error(-1, ERROR_INVALID_PARAMETER);

  /* Decide whether the IOCP completion list can live on the stack, or allocate
   * memory for it on the heap. */
  if ((size_t) maxevents <= array_count(stack_iocp_events)) {
    iocp_events = stack_iocp_events;
  } else if ((iocp_events =
                  malloc((size_t) maxevents * sizeof *iocp_events)) == NULL) {
    iocp_events = stack_iocp_events;
    maxevents = array_count(stack_iocp_events);
  }

  /* Compute the timeout for GetQueuedCompletionStatus, and the wait end
   * time, if the user specified a timeout other than zero or infinite. */
  if (timeout > 0) {
    due = GetTickCount64() + (uint64_t) timeout;
    gqcs_timeout = (DWORD) timeout;
  } else if (timeout == 0) {
    gqcs_timeout = 0;
  } else {
    gqcs_timeout = INFINITE;
  }

  EnterCriticalSection(&port_state->lock);

  /* Dequeue completion packets until either at least one interesting event
   * has been discovered, or the timeout is reached. */
  for (;;) {
    uint64_t now;

    result = _port_poll(
        port_state, events, iocp_events, (DWORD) maxevents, gqcs_timeout);
    if (result < 0 || result > 0)
      break; /* Result, error, or time-out. */

    if (timeout < 0)
      continue; /* When timeout is negative, never time out. */

    /* Update time. */
    now = GetTickCount64();

    /* Do not allow the due time to be in the past. */
    if (now >= due) {
      SetLastError(WAIT_TIMEOUT);
      break;
    }

    /* Recompute time-out argument for GetQueuedCompletionStatus. */
    gqcs_timeout = (DWORD)(due - now);
  }

  _port_update_events_if_polling(port_state);

  LeaveCriticalSection(&port_state->lock);

  if (iocp_events != stack_iocp_events)
    free(iocp_events);

  if (result >= 0)
    return result;
  else if (GetLastError() == WAIT_TIMEOUT)
    return 0;
  else
    return -1;
}

static int _port_ctl_add(port_state_t* port_state,
                         SOCKET sock,
                         struct epoll_event* ev) {
  sock_state_t* sock_state = sock_new(port_state, sock);
  if (sock_state == NULL)
    return -1;

  if (sock_set_event(port_state, sock_state, ev) < 0) {
    sock_delete(port_state, sock_state);
    return -1;
  }

  _port_update_events_if_polling(port_state);

  return 0;
}

static int _port_ctl_mod(port_state_t* port_state,
                         SOCKET sock,
                         struct epoll_event* ev) {
  sock_state_t* sock_state = port_find_socket(port_state, sock);
  if (sock_state == NULL)
    return -1;

  if (sock_set_event(port_state, sock_state, ev) < 0)
    return -1;

  _port_update_events_if_polling(port_state);

  return 0;
}

static int _port_ctl_del(port_state_t* port_state, SOCKET sock) {
  sock_state_t* sock_state = port_find_socket(port_state, sock);
  if (sock_state == NULL)
    return -1;

  sock_delete(port_state, sock_state);

  return 0;
}

static int _port_ctl_op(port_state_t* port_state,
                        int op,
                        SOCKET sock,
                        struct epoll_event* ev) {
  switch (op) {
    case EPOLL_CTL_ADD:
      return _port_ctl_add(port_state, sock, ev);
    case EPOLL_CTL_MOD:
      return _port_ctl_mod(port_state, sock, ev);
    case EPOLL_CTL_DEL:
      return _port_ctl_del(port_state, sock);
    default:
      return_set_error(-1, ERROR_INVALID_PARAMETER);
  }
}

int port_ctl(port_state_t* port_state,
             int op,
             SOCKET sock,
             struct epoll_event* ev) {
  int result;

  EnterCriticalSection(&port_state->lock);
  result = _port_ctl_op(port_state, op, sock, ev);
  LeaveCriticalSection(&port_state->lock);

  return result;
}

int port_register_socket_handle(port_state_t* port_state,
                                sock_state_t* sock_state,
                                SOCKET socket) {
  if (tree_add(&port_state->sock_tree,
               sock_state_to_tree_node(sock_state),
               socket) < 0)
    return_set_error(-1, ERROR_ALREADY_EXISTS);
  return 0;
}

void port_unregister_socket_handle(port_state_t* port_state,
                                   sock_state_t* sock_state) {
  tree_del(&port_state->sock_tree, sock_state_to_tree_node(sock_state));
}

sock_state_t* port_find_socket(port_state_t* port_state, SOCKET socket) {
  tree_node_t* tree_node = tree_find(&port_state->sock_tree, socket);
  if (tree_node == NULL)
    return_set_error(NULL, ERROR_NOT_FOUND);
  return sock_state_from_tree_node(tree_node);
}

void port_request_socket_update(port_state_t* port_state,
                                sock_state_t* sock_state) {
  if (queue_enqueued(sock_state_to_queue_node(sock_state)))
    return;
  queue_append(&port_state->sock_update_queue,
               sock_state_to_queue_node(sock_state));
}

void port_cancel_socket_update(port_state_t* port_state,
                               sock_state_t* sock_state) {
  unused_var(port_state);
  if (!queue_enqueued(sock_state_to_queue_node(sock_state)))
    return;
  queue_remove(sock_state_to_queue_node(sock_state));
}

void port_add_deleted_socket(port_state_t* port_state,
                             sock_state_t* sock_state) {
  if (queue_enqueued(sock_state_to_queue_node(sock_state)))
    return;
  queue_append(&port_state->sock_deleted_queue,
               sock_state_to_queue_node(sock_state));
}

void port_remove_deleted_socket(port_state_t* port_state,
                                sock_state_t* sock_state) {
  unused_var(port_state);
  if (!queue_enqueued(sock_state_to_queue_node(sock_state)))
    return;
  queue_remove(sock_state_to_queue_node(sock_state));
}

void queue_init(queue_t* queue) {
  queue_node_init(&queue->head);
}

void queue_node_init(queue_node_t* node) {
  node->prev = node;
  node->next = node;
}

static inline void _queue_detach(queue_node_t* node) {
  node->prev->next = node->next;
  node->next->prev = node->prev;
}

queue_node_t* queue_first(const queue_t* queue) {
  return !queue_empty(queue) ? queue->head.next : NULL;
}

queue_node_t* queue_last(const queue_t* queue) {
  return !queue_empty(queue) ? queue->head.prev : NULL;
}

void queue_prepend(queue_t* queue, queue_node_t* node) {
  node->next = queue->head.next;
  node->prev = &queue->head;
  node->next->prev = node;
  queue->head.next = node;
}

void queue_append(queue_t* queue, queue_node_t* node) {
  node->next = &queue->head;
  node->prev = queue->head.prev;
  node->prev->next = node;
  queue->head.prev = node;
}

void queue_move_first(queue_t* queue, queue_node_t* node) {
  _queue_detach(node);
  queue_prepend(queue, node);
}

void queue_move_last(queue_t* queue, queue_node_t* node) {
  _queue_detach(node);
  queue_append(queue, node);
}

void queue_remove(queue_node_t* node) {
  _queue_detach(node);
  queue_node_init(node);
}

bool queue_empty(const queue_t* queue) {
  return !queue_enqueued(&queue->head);
}

bool queue_enqueued(const queue_node_t* node) {
  return node->prev != node;
}

/* clang-format off */
static const uint32_t _REF          = 0x00000001;
static const uint32_t _REF_MASK     = 0x0fffffff;
static const uint32_t _DESTROY      = 0x10000000;
static const uint32_t _DESTROY_MASK = 0xf0000000;
static const uint32_t _POISON       = 0x300DEAD0;
/* clang-format on */

static HANDLE _keyed_event = NULL;

int reflock_global_init(void) {
  NTSTATUS status =
      NtCreateKeyedEvent(&_keyed_event, ~(ACCESS_MASK) 0, NULL, 0);
  if (status != STATUS_SUCCESS)
    return_set_error(-1, RtlNtStatusToDosError(status));
  return 0;
}

void reflock_init(reflock_t* reflock) {
  reflock->state = 0;
}

static void _signal_event(void* address) {
  NTSTATUS status = NtReleaseKeyedEvent(_keyed_event, address, FALSE, NULL);
  if (status != STATUS_SUCCESS)
    abort();
}

static void _await_event(void* address) {
  NTSTATUS status = NtWaitForKeyedEvent(_keyed_event, address, FALSE, NULL);
  if (status != STATUS_SUCCESS)
    abort();
}

static inline uint32_t _sync_add_and_fetch(volatile uint32_t* target,
                                           uint32_t value) {
  static_assert(sizeof(*target) == sizeof(long), "");
  return (uint32_t) InterlockedAdd((volatile long*) target, (long) value);
}

static inline uint32_t _sync_fetch_and_set(volatile uint32_t* target,
                                           uint32_t value) {
  static_assert(sizeof(*target) == sizeof(long), "");
  return (uint32_t) InterlockedExchange((volatile long*) target, (long) value);
}

void reflock_ref(reflock_t* reflock) {
  uint32_t state = _sync_add_and_fetch(&reflock->state, _REF);
  unused_var(state);
  assert((state & _DESTROY_MASK) == 0); /* Overflow or destroyed. */
}

void reflock_unref(reflock_t* reflock) {
  uint32_t state = _sync_add_and_fetch(&reflock->state, 0 - _REF);
  uint32_t ref_count = state & _REF_MASK;
  uint32_t destroy = state & _DESTROY_MASK;

  unused_var(ref_count);
  unused_var(destroy);

  if (state == _DESTROY)
    _signal_event(reflock);
  else
    assert(destroy == 0 || ref_count > 0);
}

void reflock_unref_and_destroy(reflock_t* reflock) {
  uint32_t state = _sync_add_and_fetch(&reflock->state, _DESTROY - _REF);
  uint32_t ref_count = state & _REF_MASK;

  assert((state & _DESTROY_MASK) ==
         _DESTROY); /* Underflow or already destroyed. */

  if (ref_count != 0)
    _await_event(reflock);

  state = _sync_fetch_and_set(&reflock->state, _POISON);
  assert(state == _DESTROY);
}

static const uint32_t _SOCK_KNOWN_EPOLL_EVENTS =
    EPOLLIN | EPOLLPRI | EPOLLOUT | EPOLLERR | EPOLLHUP | EPOLLRDNORM |
    EPOLLRDBAND | EPOLLWRNORM | EPOLLWRBAND | EPOLLMSG | EPOLLRDHUP;

typedef enum _poll_status {
  _POLL_IDLE = 0,
  _POLL_PENDING,
  _POLL_CANCELLED
} _poll_status_t;

typedef struct sock_state {
  OVERLAPPED overlapped;
  AFD_POLL_INFO poll_info;
  queue_node_t queue_node;
  tree_node_t tree_node;
  poll_group_t* poll_group;
  SOCKET base_socket;
  epoll_data_t user_data;
  uint32_t user_events;
  uint32_t pending_events;
  _poll_status_t poll_status;
  bool delete_pending;
} sock_state_t;

static inline sock_state_t* _sock_alloc(void) {
  sock_state_t* sock_state = malloc(sizeof *sock_state);
  if (sock_state == NULL)
    return_set_error(NULL, ERROR_NOT_ENOUGH_MEMORY);
  return sock_state;
}

static inline void _sock_free(sock_state_t* sock_state) {
  free(sock_state);
}

static int _sock_cancel_poll(sock_state_t* sock_state) {
  HANDLE driver_handle =
      (HANDLE)(uintptr_t) poll_group_get_socket(sock_state->poll_group);
  assert(sock_state->poll_status == _POLL_PENDING);

  /* CancelIoEx() may fail with ERROR_NOT_FOUND if the overlapped operation has
   * already completed. This is not a problem and we proceed normally. */
  if (!CancelIoEx(driver_handle, &sock_state->overlapped) &&
      GetLastError() != ERROR_NOT_FOUND)
    return_map_error(-1);

  sock_state->poll_status = _POLL_CANCELLED;
  sock_state->pending_events = 0;
  return 0;
}

sock_state_t* sock_new(port_state_t* port_state, SOCKET socket) {
  SOCKET base_socket;
  poll_group_t* poll_group;
  sock_state_t* sock_state;

  if (socket == 0 || socket == INVALID_SOCKET)
    return_set_error(NULL, ERROR_INVALID_HANDLE);

  base_socket = ws_get_base_socket(socket);
  if (base_socket == INVALID_SOCKET)
    return NULL;

  poll_group = poll_group_acquire(port_state);
  if (poll_group == NULL)
    return NULL;

  sock_state = _sock_alloc();
  if (sock_state == NULL)
    goto err1;

  memset(sock_state, 0, sizeof *sock_state);

  sock_state->base_socket = base_socket;
  sock_state->poll_group = poll_group;

  tree_node_init(&sock_state->tree_node);
  queue_node_init(&sock_state->queue_node);

  if (port_register_socket_handle(port_state, sock_state, socket) < 0)
    goto err2;

  return sock_state;

err2:
  _sock_free(sock_state);
err1:
  poll_group_release(poll_group);

  return NULL;
}

static int _sock_delete(port_state_t* port_state,
                        sock_state_t* sock_state,
                        bool force) {
  if (!sock_state->delete_pending) {
    if (sock_state->poll_status == _POLL_PENDING)
      _sock_cancel_poll(sock_state);

    port_cancel_socket_update(port_state, sock_state);
    port_unregister_socket_handle(port_state, sock_state);

    sock_state->delete_pending = true;
  }

  /* If the poll request still needs to complete, the sock_state object can't
   * be free()d yet. `sock_feed_event()` or `port_close()` will take care
   * of this later. */
  if (force || sock_state->poll_status == _POLL_IDLE) {
    /* Free the sock_state now. */
    port_remove_deleted_socket(port_state, sock_state);
    poll_group_release(sock_state->poll_group);
    _sock_free(sock_state);
  } else {
    /* Free the socket later. */
    port_add_deleted_socket(port_state, sock_state);
  }

  return 0;
}

void sock_delete(port_state_t* port_state, sock_state_t* sock_state) {
  _sock_delete(port_state, sock_state, false);
}

void sock_force_delete(port_state_t* port_state, sock_state_t* sock_state) {
  _sock_delete(port_state, sock_state, true);
}

int sock_set_event(port_state_t* port_state,
                   sock_state_t* sock_state,
                   const struct epoll_event* ev) {
  /* EPOLLERR and EPOLLHUP are always reported, even when not requested by the
   * caller. However they are disabled after a event has been reported for a
   * socket for which the EPOLLONESHOT flag as set. */
  uint32_t events = ev->events | EPOLLERR | EPOLLHUP;

  sock_state->user_events = events;
  sock_state->user_data = ev->data;

  if ((events & _SOCK_KNOWN_EPOLL_EVENTS & ~sock_state->pending_events) != 0)
    port_request_socket_update(port_state, sock_state);

  return 0;
}

static inline DWORD _epoll_events_to_afd_events(uint32_t epoll_events) {
  /* Always monitor for AFD_POLL_LOCAL_CLOSE, which is triggered when the
   * socket is closed with closesocket() or CloseHandle(). */
  DWORD afd_events = AFD_POLL_LOCAL_CLOSE;

  if (epoll_events & (EPOLLIN | EPOLLRDNORM))
    afd_events |= AFD_POLL_RECEIVE | AFD_POLL_ACCEPT;
  if (epoll_events & (EPOLLPRI | EPOLLRDBAND))
    afd_events |= AFD_POLL_RECEIVE_EXPEDITED;
  if (epoll_events & (EPOLLOUT | EPOLLWRNORM | EPOLLWRBAND))
    afd_events |= AFD_POLL_SEND | AFD_POLL_CONNECT;
  if (epoll_events & (EPOLLIN | EPOLLRDNORM | EPOLLRDHUP))
    afd_events |= AFD_POLL_DISCONNECT;
  if (epoll_events & EPOLLHUP)
    afd_events |= AFD_POLL_ABORT;
  if (epoll_events & EPOLLERR)
    afd_events |= AFD_POLL_CONNECT_FAIL;

  return afd_events;
}

static inline uint32_t _afd_events_to_epoll_events(DWORD afd_events) {
  uint32_t epoll_events = 0;

  if (afd_events & (AFD_POLL_RECEIVE | AFD_POLL_ACCEPT))
    epoll_events |= EPOLLIN | EPOLLRDNORM;
  if (afd_events & AFD_POLL_RECEIVE_EXPEDITED)
    epoll_events |= EPOLLPRI | EPOLLRDBAND;
  if (afd_events & (AFD_POLL_SEND | AFD_POLL_CONNECT))
    epoll_events |= EPOLLOUT | EPOLLWRNORM | EPOLLWRBAND;
  if (afd_events & AFD_POLL_DISCONNECT)
    epoll_events |= EPOLLIN | EPOLLRDNORM | EPOLLRDHUP;
  if (afd_events & AFD_POLL_ABORT)
    epoll_events |= EPOLLHUP;
  if (afd_events & AFD_POLL_CONNECT_FAIL)
    epoll_events |= EPOLLERR;

  return epoll_events;
}

int sock_update(port_state_t* port_state, sock_state_t* sock_state) {
  assert(!sock_state->delete_pending);

  if ((sock_state->poll_status == _POLL_PENDING) &&
      (sock_state->user_events & _SOCK_KNOWN_EPOLL_EVENTS &
       ~sock_state->pending_events) == 0) {
    /* All the events the user is interested in are already being monitored by
     * the pending poll operation. It might spuriously complete because of an
     * event that we're no longer interested in; when that happens we'll submit
     * a new poll operation with the updated event mask. */

  } else if (sock_state->poll_status == _POLL_PENDING) {
    /* A poll operation is already pending, but it's not monitoring for all the
     * events that the user is interested in. Therefore, cancel the pending
     * poll operation; when we receive it's completion package, a new poll
     * operation will be submitted with the correct event mask. */
    if (_sock_cancel_poll(sock_state) < 0)
      return -1;

  } else if (sock_state->poll_status == _POLL_CANCELLED) {
    /* The poll operation has already been cancelled, we're still waiting for
     * it to return. For now, there's nothing that needs to be done. */

  } else if (sock_state->poll_status == _POLL_IDLE) {
    /* No poll operation is pending; start one. */
    sock_state->poll_info.Exclusive = FALSE;
    sock_state->poll_info.NumberOfHandles = 1;
    sock_state->poll_info.Timeout.QuadPart = INT64_MAX;
    sock_state->poll_info.Handles[0].Handle = (HANDLE) sock_state->base_socket;
    sock_state->poll_info.Handles[0].Status = 0;
    sock_state->poll_info.Handles[0].Events =
        _epoll_events_to_afd_events(sock_state->user_events);

    memset(&sock_state->overlapped, 0, sizeof sock_state->overlapped);

    if (afd_poll(poll_group_get_socket(sock_state->poll_group),
                 &sock_state->poll_info,
                 &sock_state->overlapped) < 0) {
      switch (GetLastError()) {
        case ERROR_IO_PENDING:
          /* Overlapped poll operation in progress; this is expected. */
          break;
        case ERROR_INVALID_HANDLE:
          /* Socket closed; it'll be dropped from the epoll set. */
          return _sock_delete(port_state, sock_state, false);
        default:
          /* Other errors are propagated to the caller. */
          return_map_error(-1);
      }
    }

    /* The poll request was successfully submitted. */
    sock_state->poll_status = _POLL_PENDING;
    sock_state->pending_events = sock_state->user_events;

  } else {
    /* Unreachable. */
    assert(false);
  }

  port_cancel_socket_update(port_state, sock_state);
  return 0;
}

int sock_feed_event(port_state_t* port_state,
                    OVERLAPPED* overlapped,
                    struct epoll_event* ev) {
  sock_state_t* sock_state =
      container_of(overlapped, sock_state_t, overlapped);
  AFD_POLL_INFO* poll_info = &sock_state->poll_info;
  uint32_t epoll_events = 0;

  sock_state->poll_status = _POLL_IDLE;
  sock_state->pending_events = 0;

  if (sock_state->delete_pending) {
    /* Socket has been deleted earlier and can now be freed. */
    return _sock_delete(port_state, sock_state, false);

  } else if ((NTSTATUS) overlapped->Internal == STATUS_CANCELLED) {
    /* The poll request was cancelled by CancelIoEx. */

  } else if (!NT_SUCCESS(overlapped->Internal)) {
    /* The overlapped request itself failed in an unexpected way. */
    epoll_events = EPOLLERR;

  } else if (poll_info->NumberOfHandles < 1) {
    /* This poll operation succeeded but didn't report any socket events. */

  } else if (poll_info->Handles[0].Events & AFD_POLL_LOCAL_CLOSE) {
    /* The poll operation reported that the socket was closed. */
    return _sock_delete(port_state, sock_state, false);

  } else {
    /* Events related to our socket were reported. */
    epoll_events = _afd_events_to_epoll_events(poll_info->Handles[0].Events);
  }

  /* Requeue the socket so a new poll request will be submitted. */
  port_request_socket_update(port_state, sock_state);

  /* Filter out events that the user didn't ask for. */
  epoll_events &= sock_state->user_events;

  /* Return if there are no epoll events to report. */
  if (epoll_events == 0)
    return 0;

  /* If the the socket has the EPOLLONESHOT flag set, unmonitor all events,
   * even EPOLLERR and EPOLLHUP. But always keep looking for closed sockets. */
  if (sock_state->user_events & EPOLLONESHOT)
    sock_state->user_events = 0;

  ev->data = sock_state->user_data;
  ev->events = epoll_events;
  return 1;
}

queue_node_t* sock_state_to_queue_node(sock_state_t* sock_state) {
  return &sock_state->queue_node;
}

sock_state_t* sock_state_from_tree_node(tree_node_t* tree_node) {
  return container_of(tree_node, sock_state_t, tree_node);
}

tree_node_t* sock_state_to_tree_node(sock_state_t* sock_state) {
  return &sock_state->tree_node;
}

sock_state_t* sock_state_from_queue_node(queue_node_t* queue_node) {
  return container_of(queue_node, sock_state_t, queue_node);
}

void ts_tree_init(ts_tree_t* ts_tree) {
  tree_init(&ts_tree->tree);
  InitializeSRWLock(&ts_tree->lock);
}

void ts_tree_node_init(ts_tree_node_t* node) {
  tree_node_init(&node->tree_node);
  reflock_init(&node->reflock);
}

int ts_tree_add(ts_tree_t* ts_tree, ts_tree_node_t* node, uintptr_t key) {
  int r;

  AcquireSRWLockExclusive(&ts_tree->lock);
  r = tree_add(&ts_tree->tree, &node->tree_node, key);
  ReleaseSRWLockExclusive(&ts_tree->lock);

  return r;
}

static inline ts_tree_node_t* _ts_tree_find_node(ts_tree_t* ts_tree,
                                                 uintptr_t key) {
  tree_node_t* tree_node = tree_find(&ts_tree->tree, key);
  if (tree_node == NULL)
    return NULL;

  return container_of(tree_node, ts_tree_node_t, tree_node);
}

ts_tree_node_t* ts_tree_del_and_ref(ts_tree_t* ts_tree, uintptr_t key) {
  ts_tree_node_t* ts_tree_node;

  AcquireSRWLockExclusive(&ts_tree->lock);

  ts_tree_node = _ts_tree_find_node(ts_tree, key);
  if (ts_tree_node != NULL) {
    tree_del(&ts_tree->tree, &ts_tree_node->tree_node);
    reflock_ref(&ts_tree_node->reflock);
  }

  ReleaseSRWLockExclusive(&ts_tree->lock);

  return ts_tree_node;
}

ts_tree_node_t* ts_tree_find_and_ref(ts_tree_t* ts_tree, uintptr_t key) {
  ts_tree_node_t* ts_tree_node;

  AcquireSRWLockShared(&ts_tree->lock);

  ts_tree_node = _ts_tree_find_node(ts_tree, key);
  if (ts_tree_node != NULL)
    reflock_ref(&ts_tree_node->reflock);

  ReleaseSRWLockShared(&ts_tree->lock);

  return ts_tree_node;
}

void ts_tree_node_unref(ts_tree_node_t* node) {
  reflock_unref(&node->reflock);
}

void ts_tree_node_unref_and_destroy(ts_tree_node_t* node) {
  reflock_unref_and_destroy(&node->reflock);
}

void tree_init(tree_t* tree) {
  memset(tree, 0, sizeof *tree);
}

void tree_node_init(tree_node_t* node) {
  memset(node, 0, sizeof *node);
}

#define TREE__ROTATE(cis, trans)   \
  tree_node_t* p = node;           \
  tree_node_t* q = node->trans;    \
  tree_node_t* parent = p->parent; \
                                   \
  if (parent) {                    \
    if (parent->left == p)         \
      parent->left = q;            \
    else                           \
      parent->right = q;           \
  } else {                         \
    tree->root = q;                \
  }                                \
                                   \
  q->parent = parent;              \
  p->parent = q;                   \
  p->trans = q->cis;               \
  if (p->trans)                    \
    p->trans->parent = p;          \
  q->cis = p;

static inline void _tree_rotate_left(tree_t* tree, tree_node_t* node) {
  TREE__ROTATE(left, right)
}

static inline void _tree_rotate_right(tree_t* tree, tree_node_t* node) {
  TREE__ROTATE(right, left)
}

#define TREE__INSERT_OR_DESCEND(side) \
  if (parent->side) {                 \
    parent = parent->side;            \
  } else {                            \
    parent->side = node;              \
    break;                            \
  }

#define TREE__FIXUP_AFTER_INSERT(cis, trans) \
  tree_node_t* grandparent = parent->parent; \
  tree_node_t* uncle = grandparent->trans;   \
                                             \
  if (uncle && uncle->red) {                 \
    parent->red = uncle->red = false;        \
    grandparent->red = true;                 \
    node = grandparent;                      \
  } else {                                   \
    if (node == parent->trans) {             \
      _tree_rotate_##cis(tree, parent);      \
      node = parent;                         \
      parent = node->parent;                 \
    }                                        \
    parent->red = false;                     \
    grandparent->red = true;                 \
    _tree_rotate_##trans(tree, grandparent); \
  }

int tree_add(tree_t* tree, tree_node_t* node, uintptr_t key) {
  tree_node_t* parent;

  parent = tree->root;
  if (parent) {
    for (;;) {
      if (key < parent->key) {
        TREE__INSERT_OR_DESCEND(left)
      } else if (key > parent->key) {
        TREE__INSERT_OR_DESCEND(right)
      } else {
        return -1;
      }
    }
  } else {
    tree->root = node;
  }

  node->key = key;
  node->left = node->right = NULL;
  node->parent = parent;
  node->red = true;

  for (; parent && parent->red; parent = node->parent) {
    if (parent == parent->parent->left) {
      TREE__FIXUP_AFTER_INSERT(left, right)
    } else {
      TREE__FIXUP_AFTER_INSERT(right, left)
    }
  }
  tree->root->red = false;

  return 0;
}

#define TREE__FIXUP_AFTER_REMOVE(cis, trans)       \
  tree_node_t* sibling = parent->trans;            \
                                                   \
  if (sibling->red) {                              \
    sibling->red = false;                          \
    parent->red = true;                            \
    _tree_rotate_##cis(tree, parent);              \
    sibling = parent->trans;                       \
  }                                                \
  if ((sibling->left && sibling->left->red) ||     \
      (sibling->right && sibling->right->red)) {   \
    if (!sibling->trans || !sibling->trans->red) { \
      sibling->cis->red = false;                   \
      sibling->red = true;                         \
      _tree_rotate_##trans(tree, sibling);         \
      sibling = parent->trans;                     \
    }                                              \
    sibling->red = parent->red;                    \
    parent->red = sibling->trans->red = false;     \
    _tree_rotate_##cis(tree, parent);              \
    node = tree->root;                             \
    break;                                         \
  }                                                \
  sibling->red = true;

void tree_del(tree_t* tree, tree_node_t* node) {
  tree_node_t* parent = node->parent;
  tree_node_t* left = node->left;
  tree_node_t* right = node->right;
  tree_node_t* next;
  bool red;

  if (!left) {
    next = right;
  } else if (!right) {
    next = left;
  } else {
    next = right;
    while (next->left)
      next = next->left;
  }

  if (parent) {
    if (parent->left == node)
      parent->left = next;
    else
      parent->right = next;
  } else {
    tree->root = next;
  }

  if (left && right) {
    red = next->red;
    next->red = node->red;
    next->left = left;
    left->parent = next;
    if (next != right) {
      parent = next->parent;
      next->parent = node->parent;
      node = next->right;
      parent->left = node;
      next->right = right;
      right->parent = next;
    } else {
      next->parent = parent;
      parent = next;
      node = next->right;
    }
  } else {
    red = node->red;
    node = next;
  }

  if (node)
    node->parent = parent;
  if (red)
    return;
  if (node && node->red) {
    node->red = false;
    return;
  }

  do {
    if (node == tree->root)
      break;
    if (node == parent->left) {
      TREE__FIXUP_AFTER_REMOVE(left, right)
    } else {
      TREE__FIXUP_AFTER_REMOVE(right, left)
    }
    node = parent;
    parent = parent->parent;
  } while (!node->red);

  if (node)
    node->red = false;
}

tree_node_t* tree_find(const tree_t* tree, uintptr_t key) {
  tree_node_t* node = tree->root;
  while (node) {
    if (key < node->key)
      node = node->left;
    else if (key > node->key)
      node = node->right;
    else
      return node;
  }
  return NULL;
}

tree_node_t* tree_root(const tree_t* tree) {
  return tree->root;
}

#ifndef SIO_BASE_HANDLE
#define SIO_BASE_HANDLE 0x48000022
#endif

#define WS__INITIAL_CATALOG_BUFFER_SIZE 0x4000 /* 16kb. */

int ws_global_init(void) {
  int r;
  WSADATA wsa_data;

  r = WSAStartup(MAKEWORD(2, 2), &wsa_data);
  if (r != 0)
    return_set_error(-1, (DWORD) r);

  return 0;
}

SOCKET ws_get_base_socket(SOCKET socket) {
  SOCKET base_socket;
  DWORD bytes;

  if (WSAIoctl(socket,
               SIO_BASE_HANDLE,
               NULL,
               0,
               &base_socket,
               sizeof base_socket,
               &bytes,
               NULL,
               NULL) == SOCKET_ERROR)
    return_map_error(INVALID_SOCKET);

  return base_socket;
}

/* Retrieves a copy of the winsock catalog.
 * The infos pointer must be released by the caller with free(). */
int ws_get_protocol_catalog(WSAPROTOCOL_INFOW** infos_out,
                            size_t* infos_count_out) {
  DWORD buffer_size = WS__INITIAL_CATALOG_BUFFER_SIZE;
  int count;
  WSAPROTOCOL_INFOW* infos;

  for (;;) {
    infos = malloc(buffer_size);
    if (infos == NULL)
      return_set_error(-1, ERROR_NOT_ENOUGH_MEMORY);

    count = WSAEnumProtocolsW(NULL, infos, &buffer_size);
    if (count == SOCKET_ERROR) {
      free(infos);
      if (WSAGetLastError() == WSAENOBUFS)
        continue; /* Try again with bigger buffer size. */
      else
        return_map_error(-1);
    }

    *infos_out = infos;
    *infos_count_out = (size_t) count;
    return 0;
  }
}
