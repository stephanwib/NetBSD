/* $NetBSD: amlogic_reg.h,v 1.2 2015/02/27 19:57:10 jmcneill Exp $ */

/*-
 * Copyright (c) 2015 Jared D. McNeill <jmcneill@invisible.ca>
 * All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _ARM_AMLOGIC_REG_H
#define _ARM_AMLOGIC_REG_H

#define CONSADDR_VA	(CONSADDR - AMLOGIC_CORE_BASE + AMLOGIC_CORE_VBASE)

#define AMLOGIC_CORE_BASE	0xc0000000
#define AMLOGIC_CORE_SIZE	0x10200000
#define AMLOGIC_CORE_VBASE	0xe0000000

#define AMLOGIC_CBUS_OFFSET	0x01100000
#define AMLOGIC_UART0_OFFSET	0x01102130
#define AMLOGIC_UART1_OFFSET	0x01102137
#define AMLOGIC_UART2_OFFSET	0x011021c0
#define AMLOGIC_UART0AO_OFFSET	0x081004c0
#define AMLOGIC_UART2AO_OFFSET	0x081004e0
#define AMLOGIC_UART_SIZE	0x20
#define AMLOGIC_UART_FREQ	24000000

#define AMLOGIC_PL310_OFFSET	0x04200000

#endif /* _ARM_AMLOGIC_REG_H */
