#	$NetBSD: Makefile,v 1.1.1.2 2014/02/26 10:57:34 mrg Exp $

.include <bsd.own.mk>
.include <bsd.init.mk>

.include "${.CURDIR}/../../arch/${GCC_MACHINE_ARCH}/defs.mk"

.cc: # disable .cc->NULL transform

INCS=		${G_tr1_impl_headers}
INCSDIR=	/usr/include/g++/tr1_impl

# Get default targets including <bsd.inc.mk>.
.include <bsd.prog.mk>

.PATH: ${DIST}/libstdc++-v3/include/tr1_impl
