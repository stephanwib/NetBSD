#	$NetBSD: Makefile,v 1.7 2011/05/26 12:56:25 joerg Exp $

PROG=	mdnsd

.include <bsd.init.mk>

.PATH:	${DIST}/mDNSPosix ${DIST}/mDNSCore ${DIST}/mDNSShared

CPPFLAGS+=-I${DIST}/mDNSCore -I${DIST}/mDNSShared \
	-DPROGRAM_NAME=\"mdnsd\" -DHAVE_SIGINFO
SRCS=	PosixDaemon.c mDNSPosix.c mDNSUNP.c mDNS.c DNSDigest.c uDNS.c \
	DNSCommon.c uds_daemon.c mDNSDebug.c dnssd_ipc.c GenLinkedList.c \
	PlatformCommon.c

COPTS.uds_daemon.c += -Wno-stack-protector

MAN=	mdnsd.8

CWARNFLAGS.clang+=	-Wno-unused-value

.include <bsd.prog.mk>
