#	$NetBSD: Makefile.shark.inc,v 1.23 2014/11/25 07:42:35 martin Exp $

CPPFLAGS+=		-D${MACHINE}
COPTS+=			-fno-unwind-tables
GENASSYM_EXTRAS+=	${THISARM}/shark/genassym.cf

# Need to convert the kernel from ELF to a.out so that OpenFirmware
# can load it.

LINKSCRIPT=	-T ldscript
LOADADDRESS=	0xF0000020

SYSTEM_LD_HEAD_EXTRA+=; \
	( cat ${ARM}/conf/kern.ldscript.head ; \
	  OBJDUMP=${OBJDUMP} ${HOST_SH} $S/conf/mkldscript.sh \
		${SYSTEM_OBJ} ; \
	  cat ${ARM}/conf/kern.ldscript.tail ) > ldscript
KERNLDSCRIPT=	${ARM}/conf/kern.ldscript.head \
		$S/conf/mkldscript.sh \
		${ARM}/conf/kern.ldscript.tail

SYSTEM_LD_TAIL_EXTRA+=; \
	echo "${OBJCOPY} ${OBJCOPY_ELF2AOUT_FLAGS} $@ $@.aout"; \
	${OBJCOPY} ${OBJCOPY_ELF2AOUT_FLAGS} $@ $@.aout

KERNIMAGES=	netbsd netbsd.aout
