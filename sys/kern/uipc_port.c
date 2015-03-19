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

enum kp_state {
  kp_unused = 0,
  kp_active,
  kp_deleted
};

struct kport {
  LIST_ENTRY(kport) kp_entry; /* global list entry */
  kmutex_t kp_interlock;  /* lock on this kport */
  kcondvar_t  kp_cv;  /* condition variable */
  port_id kp_id;  /* id of this port */
  pid_t kp_owner; /* owner PID assigned to this port */
  char *kp_name;  /* name of this port */
  size_t kp_namelen; /* length of name */
  uint32_t kp_nmsg;  /* number of messages */
  uid_t kp_uid; /* creator uid */
  gid_t kp_gid; /* creator gid */
  int32_t kp_state; /* state of this port */
};

struct kp_msg {
  int32_t kp_msg_code; /* message code */
  size_t kp_msg_size; /* bytes in message */
  uid_t kp_msg_sender_uid; /* uid of sender */
  gid_t kp_msg_sender_gid; /* gid of sender */
  pid_t kp_msg_sender_pid; /* pid of sender */
  char *kp_msg_buffer; /* message data */
};

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
      return kp;
    }
  }
  return NULL;
}

static int
kport_create(struct lwp *l, const char *name, struct kport **kpret)
{
  struct kport *ret;
  kauth_cred_t uc;
  size_t namelen;
  
  uc = l->l_cred;
  ret = kmem_zalloc(sizeof(*ret), KM_SLEEP);
  
  namelen = strlen(name);
  if (namelen >= PORT_MAX_NAME_LENGTH) {
    kmem_free(ret, sizeof(*ret));
    return ENAMETOOLONG;
  }
  ret->kp_namelen = namelen + 1;
  ret->kp_name = kmem_alloc(ret->kp_namelen, KM_SLEEP);
  strlcpy(ret->kp_name, name, namelen + 1);
  ret->kp_uid = kauth_cred_geteuid(uc);
  ret->kp_gid = kauth_cred_getegid(uc);
  ret->kp_owner = l->l_proc->p_pid;
  ret->kp_nmsg = 0;
  ret->kp_state = kp_unused;
  mutex_init(&ret->kp_interlock, MUTEX_DEFAULT, IPL_NONE);
  cv_init(&ret->kp_cv, "kport");
  
  mutex_enter(&kport_mutex);
  if (nports >= port_max) {
    mutex_exit(&kport_mutex);
    kmem_free(ret->kp_name, ret->kp_namelen);
    kmem_free(ret, sizeof(*ret));
    return ENFILE;
  }
  nports++;
  while (kport_lookup_byid(port_next_id) != NULL) {
    port_next_id++;
  }
  ret->kp_id = port_next_id;
  LIST_INSERT_HEAD(&kport_head, ret, kp_entry);
  mutex_exit(&kport_mutex);
  
  *kpret = ret;
  return 0;
}
