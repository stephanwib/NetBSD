/* This file is automatically generated.  DO NOT EDIT! */
/* Generated from: NetBSD: mknative-gcc.old,v 1.1 2014/02/26 09:54:34 mrg Exp  */
/* Generated from: NetBSD: mknative.common,v 1.11 2014/02/17 21:39:43 christos Exp  */

#ifndef GCC_TM_H
#define GCC_TM_H
#define TARGET_CPU_DEFAULT ((MASK_PA_11|MASK_NO_SPACE_REGS|MASK_BIG_SWITCH|MASK_GAS|MASK_JUMP_IN_DELAY))
#ifndef NETBSD_ENABLE_PTHREADS
# define NETBSD_ENABLE_PTHREADS
#endif
#ifdef IN_GCC
# include "options.h"
# include "config/pa/pa.h"
# include "config/dbxelf.h"
# include "config/elfos.h"
# include "config/svr4.h"
# include "config/netbsd.h"
# include "config/netbsd-elf.h"
# include "config/pa/pa-netbsd.h"
# include "config/pa/pa32-regs.h"
# include "config/pa/pa32-netbsd.h"
# include "defaults.h"
#endif
#if defined IN_GCC && !defined GENERATOR_FILE && !defined USED_FOR_TARGET
# include "insn-constants.h"
# include "insn-flags.h"
#endif
#endif /* GCC_TM_H */
