#	$NetBSD: Makefile,v 1.7 2014/03/13 01:52:37 pooka Exp $
#

.PATH:	${.CURDIR}/../../../../dev

LIB=	rumpdev_rnd

SRCS=	rndpseudo.c

SRCS+=	rnd_component.c

# sys/rump/Makefile.rump sets CPPFLAGS+= -DCOMPAT_50=1,
# so we need rndpseudo_50.c from the compat/common directory.
.PATH:	${.CURDIR}/../../../../compat/common
SRCS+=	rndpseudo_50.c

CPPFLAGS+=	-I${RUMPTOP}/librump/rumpvfs

.include <bsd.lib.mk>
.include <bsd.klinks.mk>
