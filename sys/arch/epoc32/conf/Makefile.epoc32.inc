#	$NetBSD: Makefile.epoc32.inc,v 1.2 2014/11/15 14:25:22 uebayasi Exp $

MACHINE_ARCH=		arm
CPPFLAGS+=		-D${MACHINE}

SYSTEM_FIRST_OBJ=	epoc32_start.o
SYSTEM_FIRST_SFILE=	${THISARM}/epoc32/epoc32_start.S

KERNEL_BASE_VIRT=	$(LOADADDRESS)

LINKSCRIPT=		-T ldscript

EXTRA_CLEAN+=		netbsd.map assym.d ldscript tmp

netbsd:	ldscript	# XXX

# generate ldscript from common template
ldscript: ${THISARM}/conf/ldscript.epoc32 ${THISARM}/conf/Makefile.epoc32.inc Makefile
	${TOOL_SED} -e 's/@KERNEL_BASE_PHYS@/${KERNEL_BASE_PHYS}/' \
	    -e 's/@KERNEL_BASE_VIRT@/${KERNEL_BASE_VIRT}/' \
	    ${THISARM}/conf/ldscript.epoc32 > tmp && mv tmp $@
