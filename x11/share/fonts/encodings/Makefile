#	$NetBSD: Makefile,v 1.4 2005/03/23 01:00:33 rtr Exp $

.include <bsd.own.mk>

ENCDIR=	encodings
ENCARGS=-e large

FILES=	ansi-1251.enc armscii-8.enc dec-special.enc \
	ibm-cp437.enc ibm-cp850.enc ibm-cp852.enc ibm-cp866.enc \
	iso8859-6.8x.enc iso8859-6.16.enc iso8859-11.enc iso8859-13.enc \
	iso8859-16.enc microsoft-cp1250.enc microsoft-cp1251.enc \
	microsoft-cp1252.enc microsoft-cp1253.enc microsoft-cp1254.enc \
	microsoft-cp1255.enc microsoft-cp1256.enc microsoft-cp1257.enc \
	microsoft-cp1258.enc microsoft-win3.1.enc mulearabic-0.enc \
	mulearabic-1.enc mulearabic-2.enc mulelao-1.enc sun_eu_greek.enc \
	tcvn-0.enc tis620-2.enc

GZFILES=adobe-dingbats.enc.gz adobe-standard.enc.gz adobe-symbol.enc.gz \
	viscii1.1-1.enc.gz

SUBDIR=	large

.include "Makefile.enc"

.include <bsd.x11.mk>
.include <bsd.prog.mk>
.include <bsd.subdir.mk>
