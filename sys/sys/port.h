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


#ifndef _SYS_PORT_H
#define _SYS_PORT_H

typedef u_int port_id;


#ifdef _KERNEL

#include <sys/queue.h>
#include <sys/mutex.h>
#include <sys/condvar.h>

enum {
  PORT_TIMEOUT
};

enum kp_state {
  kp_closed = 0,
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
  int kp_state; /* state of this port */
  int kp_nmsg;  /* number of messages */
  int kp_qlen;  /* queue length */
  int kp_waiters;  /* count of waiters */
  uid_t kp_uid; /* creator uid */
  gid_t kp_gid; /* creator gid */
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


/* Prototypes */
void kport_init(void);

#endif	/* _KERNEL */

#endif	/* _SYS_PORT_H_ */
