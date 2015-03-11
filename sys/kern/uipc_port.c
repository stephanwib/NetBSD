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
#include <sys/queue.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <OS.h>


static const size_t PORT_INITIAL_BUF_SIZE = 4 * 1024 * 1024;
static const size_t PORT_TOTAL_SPACE_LIMIT = 64 * 1024 * 1024;
static const size_t PORT_PROC_SPACE_LIMIT = 8 * 1024 * 1024;
static const size_t PORT_BUFFER_GROW_RATE = PORT_INITIAL_BUF_SIZE;

#define PORT_MAX 4096
#define PORT_MAX_QUEUE_LENGTH 4096
#define PORT_MAX_MESSAGE_SIZE (256 * 1024)

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
  uint32_t kp_nmsg;  /* number of messages */
  uid_t kp_uid; /* creator uid */
  gid_t kp_gid; /* creator gid */
  int32_t kp_state; /* state of this port */
};

struct kp_msg {
  int32_t kp_msg_code;
  size_t kp_msg_size;
  uid_t kp_msg_sender_uid;
  gid_t kp_msg_sender_gid;
  pid_t kp_msg_sender_pid;
  char *kp_msg_buffer;
};

LIST_HEAD(kport_list, kport);
static struct kport_list kport_head = LIST_HEAD_INITIALIZER(&kport_head);

void kport_init(void)
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
}
