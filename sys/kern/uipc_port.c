/*-
 * Copyright (c) 2015 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Stephan Wiebusch.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */


#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/port.h>
#include <sys/queue.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/kauth.h>
#include <sys/syscallargs.h>


static const size_t PORT_INITIAL_BUF_SIZE = 4 * 1024 * 1024;
static const size_t PORT_TOTAL_SPACE_LIMIT = 64 * 1024 * 1024;
static const size_t PORT_PROC_SPACE_LIMIT = 8 * 1024 * 1024;
static const size_t PORT_BUFFER_GROW_RATE = 4 * 1024 * 1024;

#define PORT_MAX 4096
#define PORT_MAX_QUEUE_LENGTH 4096
#define PORT_MAX_MESSAGE_SIZE (256 * 1024)
#define PORT_MAX_NAME_LENGTH 32

static uint32_t port_max = PORT_MAX;
static uint32_t nports = 0;
static port_id port_next_id = 1;
static kmutex_t kport_mutex;

enum {
  PORT_TIMEOUT;
};

enum kp_state {
  kp_unused = 0,
  kp_active,
  kp_deleted
};

struct kport {
  LIST_ENTRY(kport) kp_entry; /* global list entry */
  SIMPLEQ_HEAD(, kp_msg) kp_msgq; /* head of message queue */
  kmutex_t kp_interlock;  /* lock on this kport */
  kcondvar_t  kp_rdcv;  /* reader CV */
  kcondvar_t  kp_wrcv;  /* writer CV */
  port_id kp_id;  /* id of this port */
  pid_t kp_owner; /* owner PID assigned to this port */
  char *kp_name;  /* name of this port */
  size_t kp_namelen; /* length of name */
  uint32_t kp_nmsg;  /* number of messages */
  uint32_t kp_qlen;  /* queue length */
  uid_t kp_uid; /* creator uid */
  gid_t kp_gid; /* creator gid */
  int32_t kp_state; /* state of this port */
};

struct kp_msg {
  SIMPLEQ_ENTRY(kp_msg) kp_msg_next; /* message queue entry */
  int32_t kp_msg_code; /* message code */
  size_t kp_msg_size; /* bytes in message */
  uid_t kp_msg_sender_uid; /* uid of sender */
  gid_t kp_msg_sender_gid; /* gid of sender */
  pid_t kp_msg_sender_pid; /* pid of sender */
  char *kp_msg_buffer; /* message data */
};

/* XXX: Only one list for the moment. To prevent contention around kport_mutex, an array of lists/locks is to be added
 * along with a suitable distribution algorithm. */

LIST_HEAD(kport_list, kport);
static struct kport_list kport_head = LIST_HEAD_INITIALIZER(&kport_head);

void
kport_init(void)
{
  mutex_init(&kport_mutex, MUTEX_DEFAULT, IPL_NONE);
}

static struct kport *
kport_lookup_byid(port_id id)
{
  struct kport *kp;
  
  KASSERT(mutex_owned(&kport_mutex));
  LIST_FOREACH(kp, &kport_head, kp_entry) {
    if (kp->kp_id == id) {
      mutex_enter(&kp->kp_interlock);
      return kp;
    }
  }
  return NULL;
}

static struct kport *
kport_lookup_byname(const char *name)
{
  struct kport *kp;
  
  KASSERT(mutex_owned(&kport_mutex));
  LIST_FOREACH(kp, &kport_head, kp_entry) {
    if (strcmp(kp->kp_name, name) == 0) {
      mutex_enter(&kp->kp_interlock);
      return kp;
    }
  }
  return NULL;
}

static int
kport_create(struct lwp *l, const int queue_length, const char *name, port_id *val)
{
  struct kport *ret;
  kauth_cred_t uc;
  int error;
  size_t namelen;
  char namebuf[PORT_MAX_NAME_LENGTH + 1];

  error = copyinstr(name, namebuf, sizeof(namebuf), &namelen);
  if (error)
    return error;
 
  uc = l->l_cred;
  ret = kmem_zalloc(sizeof(*ret), KM_SLEEP);

  if (queue_length < 1 || queue_length > PORT_MAX_QUEUE_LENGTH ) {
    kmem_free(ret, sizeof(*ret));
    return EINVAL;
  }
  if (namelen >= PORT_MAX_NAME_LENGTH) {
    kmem_free(ret, sizeof(*ret));
    return ENAMETOOLONG;
  }
  ret->kp_namelen = namelen + 1;
  ret->kp_name = kmem_alloc(ret->kp_namelen, KM_SLEEP);
  strlcpy(ret->kp_name, namebuf, namelen + 1);
  ret->kp_uid = kauth_cred_geteuid(uc);
  ret->kp_gid = kauth_cred_getegid(uc);
  ret->kp_owner = l->l_proc->p_pid;
  ret->kp_nmsg = 0;
  ret->kp_qlen = queue_length;
  ret->kp_state = kp_unused;
  SIMPLEQ_INIT(&ret->kp_msgq);
  mutex_init(&ret->kp_interlock, MUTEX_DEFAULT, IPL_NONE);
  cv_init(&ret->kp_rdcv, "port_read");
  cv_init(&ret->kp_wrcv, "port_write");
  
  mutex_enter(&kport_mutex);
  if (nports >= port_max) {
    mutex_exit(&kport_mutex);
    kmem_free(ret->kp_name, ret->kp_namelen);
    kmem_free(ret, sizeof(*ret));
    return ENFILE;
  }
  if (kport_lookup_byname(namebuf)) {
    mutex_exit(&kport_mutex);
    kmem_free(ret->kp_name, ret->kp_namelen);
    kmem_free(ret, sizeof(*ret));
    return EEXIST;
  }
  nports++;
  while (kport_lookup_byid(port_next_id) != NULL) {
    port_next_id++;
  }
  ret->kp_id = port_next_id;
  LIST_INSERT_HEAD(&kport_head, ret, kp_entry);
  mutex_exit(&kport_mutex);
  
  *val = ret->kp_id;
  return 0;
}

static int
kport_write_etc(struct lwp *l, port_id id, int32_t code, void *data, size_t size, uint32_t flags, int timeout)
{
  struct kport *port;
  struct kp_msg *msg;
  kauth_cred_t uc;
  int error;
  
  uc = l->l_cred;
  
  mutex_enter(&kport_mutex);
  port = kport_lookup_byid(id);
  if (port == NULL) {
    mutex_exit(&kport_mutex);
    return ENOENT;
  }
  mutex_exit(&kport_mutex);
  
  if (port->kp_state == kp_deleted) {
    mutex_exit(&port->kp_interlock);
    return ENOENT;
  }
  if (size > PORT_MAX_MESSAGE_SIZE) {
    mutex_exit(&port->kp_interlock);
    return EMSGSIZE;
  }
  if (port->kp_nmsg == port->kp_qlen) {
    if (!(flags & PORT_TIMEOUT)) {
      mutex_exit(&port->kp_interlock);
      return EAGAIN;
    }
    else {
      error = cv_timedwait_sig(&port->kp_rdcv, &port->kp_interlock, (mstohz(timeout) / 1000)); /* XXX: microseconds? */
      if (error || (port->kp_state == kp_deleted)) {
        error = (error == EWOULDBLOCK) ? ETIMEDOUT : ENOENT;
        mutex_exit(&port->kp_interlock);
        return error;
      }
    }
  }
  
  msg = kmem_zalloc(sizeof(*msg), KM_SLEEP);
  msg->kp_msg_code = code;
  msg->kp_msg_size = size;
  msg->kp_msg_sender_uid = kauth_cred_geteuid(uc);
  msg->kp_msg_sender_gid = kauth_cred_getegid(uc);
  msg->kp_msg_sender_pid = l->l_proc->p_pid;
  msg->kp_msg_buffer = kmem_alloc(size, KM_SLEEP);
  
  error = copyin(data, msg->kp_msg_buffer, size);
  if (error) {
    mutex_exit(&port->kp_interlock);
    kmem_free(msg->kp_msg_buffer, size);
    kmem_free(msg, sizeof(*msg));
    return error;
  }
  
  SIMPLEQ_INSERT_TAIL(&port->kp_msgq, msg, kp_msg_next);
  port->kp_nmsg++;
  cv_signal(&port->kp_wrcv);
  mutex_exit(&port->kp_interlock);
  return 0;
}

static int
kport_read_etc(struct lwp *l, port_id id, int32_t *code, void *data, size_t size, uint32_t flags, int timeout, int *bytes_read)
{
  struct kport *port;
  struct kp_msg *msg;
  kauth_cred_t uc;
  int error;
  int copyout_size;
  
  uc = l->l_cred;
  
  mutex_enter(&kport_mutex);
  port = kport_lookup_byid(id);
  if (port == NULL) {
    mutex_exit(&kport_mutex);
    return ENOENT;
  }
  mutex_exit(&kport_mutex);
  
  if (timeout && (flags < 0)) {
    mutex_exit(&port->kp_interlock);
    return EINVAL;
  }
  if (port->kp_state == kp_deleted) {
    mutex_exit(&port->kp_interlock);
    return ENOENT;
  }
  
  if (port->kp_nmsg == 0) {
    if (!(flags & PORT_TIMEOUT)) {
      mutex_exit(&port->kp_interlock);
      return EAGAIN;
    }
    else {
      error = cv_timedwait_sig(&port->kp_wrcv, &port->kp_interlock, (mstohz(timeout) / 1000)); /* XXX: microseconds? */
      if (error || (port->kp_state == kp_deleted)) {
        error = (error == EWOULDBLOCK) ? ETIMEDOUT : ENOENT;
        mutex_exit(&port->kp_interlock);
        return error;
      }
    }
  }
  if (port->kp_state == kp_deleted) {
    mutex_exit(&port->kp_interlock);
    return ENOENT;
  }
  
  msg = SIMPLEQ_FIRST(&port->kp_msgq);
  copyout_size = (msg->size > size) ? size : msg_size;
  *code = msg->kp_msg_code;
  error = copyout(msg->kp_msg_buffer, data, copyout_size);
  if (error) {
    mutex_exit(&port->kp_interlock);
    return (error);
  }
  
  SIMPLEQ_REMOVE_HEAD(&port->kp_msgq, kp_msg_next);
  kmem_free(msg->kp_msg_buffer, msg->kp_msg_size);
  kmem_free(msg, sizeof(*msg));
  port->kp_nmsg--;
  cv_signal(&port->kp_rdcv);
  mutex_exit(&port->kp_interlock);
  *bytes_read = copyout_size;
  return 0;
}

int
sys_create_port(struct lwp *l, const struct sys_create_port_args *uap, register_t *retval)
{
        /* {
                syscallarg(int) queue_length;
                syscallarg(const char *) name;
           } */
  port_id port;
  int error;

  error = kport_create(l, SCARG(uap, queue_length), SCARG(uap, name), &port);
  if (error == 0)
          *retval = port;

  return error;
}

int
write_port(struct lwp *l, const struct sys_write_port_args *uap, register_t *retval)
{
        /* {
                syscallarg(int) port_id;
                syscallarg(int) msg_code;
                syscallarg(void*) msg_buffer;
                syscallarg(int) buffer_size;
           } */
  int error;
  
  error = kport_write_etc(l, SCARG(uap, port_id), SCARG(uap, msg_code), SCARG(uap, msg_buffer), SCARG(uap, buffer_size), 0, 0);
  if (error == 0)
    *retval = error;
  
  return error;
}

int write_port_etc(struct lwp *l, const struct sys_write_port_etc_args *uap, register_t *retval)
{
        /* {
                syscallarg(int) port_id;
                syscallarg(int) msg_code;
                syscallarg(void*) msg_buffer;
                syscallarg(int) buffer_size;
                syscallarg(uint32_t) flags;
                syscallarg(int) timeout;
           } */
    int error;
  
  error = kport_write_etc(l, SCARG(uap, port_id), SCARG(uap, msg_code), SCARG(uap, msg_buffer), SCARG(uap, buffer_size), SCARG(uap, flags), SCARG(uap, timeout));
  if (error == 0)
    *retval = error;
  
  return error;
}

int
read_port(struct lwp *l, const struct sys_write_port_args *uap, register_t *retval)
{
        /* {
                syscallarg(int) port_id;
                syscallarg(int*) msg_code;
                syscallarg(void*) msg_buffer;
                syscallarg(int) buffer_size;
           } */
  int error;
  int nread;
  
  error = kport_read_etc(l, SCARG(uap, port_id), SCARG(uap, msg_code), SCARG(uap, msg_buffer), SCARG(uap, buffer_size), 0, 0, &nread);
  if (error == 0)
    *retval = nread;

  return error;
}

int
read_port_etc(struct lwp *l, const struct sys_write_port_args *uap, register_t *retval)
{
        /* {
                syscallarg(int) port_id;
                syscallarg(int*) msg_code;
                syscallarg(void*) msg_buffer;
                syscallarg(int) buffer_size;
                syscallarg(uint32_t) flags;
                syscallarg(int) timeout;
           } */
  int error;
  int nread;
  
  error = kport_read_etc(l, SCARG(uap, port_id), SCARG(uap, msg_code), SCARG(uap, msg_buffer), SCARG(uap, buffer_size), flags, timeout, &nread);
  if (error == 0)
    *retval = nread;

  return error;
}
