#	$NetBSD: Makefile,v 1.3 2014/03/16 14:14:40 pooka Exp $
#

LIB=	rumpkern_sys_sunos

SRCS=	rump_sunos_compat.c rump_sunos_sysent.c
SRCS+=	sys_sunos_component.c

# XXX
CPPFLAGS+= -I${.CURDIR} -I${RUMPTOP}/librump/rumpkern

.include <bsd.lib.mk>
.include <bsd.klinks.mk>
