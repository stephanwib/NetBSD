/*	$NetBSD: drm_wait_netbsd.h,v 1.7 2015/02/28 03:22:50 riastradh Exp $	*/

/*-
 * Copyright (c) 2013 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Taylor R. Campbell.
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

#ifndef _DRM_DRM_WAIT_NETBSD_H_
#define _DRM_DRM_WAIT_NETBSD_H_

#include <sys/param.h>
#include <sys/condvar.h>
#if DIAGNOSTIC
#include <sys/cpu.h>		/* cpu_intr_p */
#endif
#include <sys/kernel.h>
#include <sys/mutex.h>
#include <sys/systm.h>

#include <linux/mutex.h>
#include <linux/spinlock.h>

typedef kcondvar_t drm_waitqueue_t;

#define	DRM_HZ	hz		/* XXX Hurk...  */

#define	DRM_UDELAY	DELAY

static inline void
DRM_INIT_WAITQUEUE(drm_waitqueue_t *q, const char *name)
{
	cv_init(q, name);
}

static inline void
DRM_DESTROY_WAITQUEUE(drm_waitqueue_t *q)
{
	cv_destroy(q);
}

static inline bool
DRM_WAITERS_P(drm_waitqueue_t *q, struct mutex *interlock)
{
	KASSERT(mutex_is_locked(interlock));
	return cv_has_waiters(q);
}

static inline void
DRM_WAKEUP_ONE(drm_waitqueue_t *q, struct mutex *interlock)
{
	KASSERT(mutex_is_locked(interlock));
	cv_signal(q);
}

static inline void
DRM_WAKEUP_ALL(drm_waitqueue_t *q, struct mutex *interlock)
{
	KASSERT(mutex_is_locked(interlock));
	cv_broadcast(q);
}

static inline bool
DRM_SPIN_WAITERS_P(drm_waitqueue_t *q, spinlock_t *interlock)
{
	KASSERT(spin_is_locked(interlock));
	return cv_has_waiters(q);
}

static inline void
DRM_SPIN_WAKEUP_ONE(drm_waitqueue_t *q, spinlock_t *interlock)
{
	KASSERT(spin_is_locked(interlock));
	cv_signal(q);
}

static inline void
DRM_SPIN_WAKEUP_ALL(drm_waitqueue_t *q, spinlock_t *interlock)
{
	KASSERT(spin_is_locked(interlock));
	cv_broadcast(q);
}

/*
 * WARNING: These DRM_*WAIT*_UNTIL macros are designed to replace the
 * Linux wait_event_* macros.  They have a different return value
 * convention from the legacy portability DRM_WAIT_ON macro and a
 * different return value convention from cv_*wait*.  Specifically,
 * DRM_*WAIT*_UNTIL and Linux wait_event_*
 *
 * - return negative error code on failure (e.g., interruption),
 * - return zero on timeout, and
 * - return one on success.
 *
 * Contrast DRM_WAIT_ON which returns -EINTR/-ERESTART on interruption,
 * -EBUSY on timeout, and zero on success; and cv_*wait*, which return
 * -EINTR/-ERESTART on interruption, -EWOULDBLOCK on timeout, and zero
 * on success.
 *
 * We don't simply implement DRM_WAIT_ON because, like Linux
 * wait_event_*, it lacks an interlock, whereas we require an interlock
 * for any waits in order to avoid the standard race conditions
 * associated with non-interlocked waits that plague Linux drivers.
 */

#define	_DRM_WAIT_UNTIL(RET, WAIT, Q, INTERLOCK, CONDITION) do		\
{									\
	KASSERT(mutex_is_locked((INTERLOCK)));				\
	ASSERT_SLEEPABLE();						\
	KASSERT(!cold);							\
	for (;;) {							\
		if (CONDITION) {					\
			(RET) = 0;					\
			break;						\
		}							\
		/* XXX errno NetBSD->Linux */				\
		(RET) = -WAIT((Q), &(INTERLOCK)->mtx_lock);		\
		if (RET)						\
			break;						\
	}								\
} while (0)

#define	cv_wait_nointr(Q, I)	(cv_wait((Q), (I)), 0)

#define	DRM_WAIT_NOINTR_UNTIL(RET, Q, I, C)				\
	_DRM_WAIT_UNTIL(RET, cv_wait_nointr, Q, I, C)

#define	DRM_WAIT_UNTIL(RET, Q, I, C)				\
	_DRM_WAIT_UNTIL(RET, cv_wait_sig, Q, I, C)

/*
 * Timed wait.  Return:
 *
 * - 0 if condition is false after timeout,
 * - 1 if condition is true after timeout or one tick before timeout,
 * - number of ticks left if condition evaluated to true before timeout, or
 * - negative error if failure (e.g., interrupted).
 *
 * XXX Comments in Linux say it returns -ERESTARTSYS if interrupted.
 * What if by a signal without SA_RESTART?  Shouldn't it be -EINTR
 * then?  I'm going to leave it as what cv_timedwait returned, which is
 * ERESTART for signals with SA_RESTART and EINTR otherwise.
 */
#define	_DRM_TIMED_WAIT_UNTIL(RET, WAIT, Q, INTERLOCK, TICKS, CONDITION) do \
{									\
	extern int hardclock_ticks;					\
	const int _dtwu_start = hardclock_ticks;			\
	int _dtwu_ticks = (TICKS);					\
	KASSERT(mutex_is_locked((INTERLOCK)));				\
	ASSERT_SLEEPABLE();						\
	KASSERT(!cold);							\
	for (;;) {							\
		if (CONDITION) {					\
			(RET) = _dtwu_ticks;				\
			break;						\
		}							\
		/* XXX errno NetBSD->Linux */				\
		(RET) = -WAIT((Q), &(INTERLOCK)->mtx_lock,		\
		    _dtwu_ticks);					\
		if (RET) {						\
			if ((RET) == -EWOULDBLOCK)			\
				(RET) = (CONDITION) ? 1 : 0;		\
			break;						\
		}							\
		const int _dtwu_now = hardclock_ticks;			\
		KASSERT(_dtwu_start <= _dtwu_now);			\
		if ((_dtwu_now - _dtwu_start) < _dtwu_ticks) {		\
			_dtwu_ticks -= (_dtwu_now - _dtwu_start);	\
		} else {						\
			(RET) = (CONDITION) ? 1 : 0;			\
			break;						\
		}							\
	}								\
} while (0)

#define	DRM_TIMED_WAIT_NOINTR_UNTIL(RET, Q, I, T, C)			\
	_DRM_TIMED_WAIT_UNTIL(RET, cv_timedwait, Q, I, T, C)

#define	DRM_TIMED_WAIT_UNTIL(RET, Q, I, T, C)			\
	_DRM_TIMED_WAIT_UNTIL(RET, cv_timedwait_sig, Q, I, T, C)

/*
 * XXX Can't assert sleepable here because we hold a spin lock.  At
 * least we can assert that we're not in (soft) interrupt context, and
 * hope that nobody tries to use these with a sometimes quickly
 * satisfied condition while holding a different spin lock.
 */

#define	_DRM_SPIN_WAIT_UNTIL(RET, WAIT, Q, INTERLOCK, CONDITION) do	\
{									\
	KASSERT(spin_is_locked((INTERLOCK)));				\
	KASSERT(!cpu_intr_p());						\
	KASSERT(!cpu_softintr_p());					\
	KASSERT(!cold);							\
	(RET) = 0;							\
	while (!(CONDITION)) {						\
		/* XXX errno NetBSD->Linux */				\
		(RET) = -WAIT((Q), &(INTERLOCK)->sl_lock);		\
		if (RET)						\
			break;						\
	}								\
} while (0)

#define	DRM_SPIN_WAIT_NOINTR_UNTIL(RET, Q, I, C)			\
	_DRM_SPIN_WAIT_UNTIL(RET, cv_wait_nointr, Q, I, C)

#define	DRM_SPIN_WAIT_UNTIL(RET, Q, I, C)				\
	_DRM_SPIN_WAIT_UNTIL(RET, cv_wait_sig, Q, I, C)

#define	_DRM_SPIN_TIMED_WAIT_UNTIL(RET, WAIT, Q, INTERLOCK, TICKS, CONDITION) \
	do								\
{									\
	extern int hardclock_ticks;					\
	const int _dstwu_start = hardclock_ticks;			\
	int _dstwu_ticks = (TICKS);					\
	KASSERT(spin_is_locked((INTERLOCK)));				\
	KASSERT(!cpu_intr_p());						\
	KASSERT(!cpu_softintr_p());					\
	KASSERT(!cold);							\
	for (;;) {							\
		if (CONDITION) {					\
			(RET) = _dstwu_ticks;				\
			break;						\
		}							\
		/* XXX errno NetBSD->Linux */				\
		(RET) = -WAIT((Q), &(INTERLOCK)->sl_lock,		\
		    _dstwu_ticks);					\
		if (RET) {						\
			if ((RET) == -EWOULDBLOCK)			\
				(RET) = (CONDITION) ? 1 : 0;		\
			break;						\
		}							\
		const int _dstwu_now = hardclock_ticks;			\
		KASSERT(_dstwu_start <= _dstwu_now);			\
		if ((_dstwu_now - _dstwu_start) < _dstwu_ticks) {	\
			_dstwu_ticks -= (_dstwu_now - _dstwu_start);	\
		} else {						\
			(RET) = (CONDITION) ? 1 : 0;			\
			break;						\
		}							\
	}								\
} while (0)

#define	DRM_SPIN_TIMED_WAIT_NOINTR_UNTIL(RET, Q, I, T, C)		\
	_DRM_SPIN_TIMED_WAIT_UNTIL(RET, cv_timedwait, Q, I, T, C)

#define	DRM_SPIN_TIMED_WAIT_UNTIL(RET, Q, I, T, C)			\
	_DRM_SPIN_TIMED_WAIT_UNTIL(RET, cv_timedwait_sig, Q, I, T, C)

#endif  /* _DRM_DRM_WAIT_NETBSD_H_ */
