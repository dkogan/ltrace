/*
 * This file is part of ltrace.
 * Copyright (C) 2013 Petr Machata, Red Hat Inc.
 * Copyright (C) 1998,2002,2004,2008,2009 Juan Cespedes
 * Copyright (C) 2009 Juan Cespedes
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */

#include "config.h"

#include <sys/types.h>
#include <sys/ptrace.h>
#include <asm/ptrace.h>
#include <errno.h>

#include "proc.h"
#include "common.h"
#include "regs.h"

#if (!defined(PTRACE_PEEKUSER) && defined(PTRACE_PEEKUSR))
# define PTRACE_PEEKUSER PTRACE_PEEKUSR
#endif

#if (!defined(PTRACE_POKEUSER) && defined(PTRACE_POKEUSR))
# define PTRACE_POKEUSER PTRACE_POKEUSR
#endif

#define off_pc ((void *)60)
#define off_lr ((void *)56)
#define off_sp ((void *)52)

int
arm_get_register(struct process *proc, enum arm_register reg, uint32_t *lp)
{
	errno = 0;
	long l = ptrace(PTRACE_PEEKUSER, proc->pid, (void *)(reg * 4L), 0);
	if (l == -1 && errno != 0)
		return -1;
	*lp = (uint32_t)l;
	return 0;
}

int
arm_get_register_offpc(struct process *proc, enum arm_register reg,
		       uint32_t *lp)
{
	if (arm_get_register(proc, reg, lp) < 0)
		return -1;
	if (reg == ARM_REG_PC)
		*lp += 8;
	return 0;
}

int
arm_get_shifted_register(struct process *proc, uint32_t inst, int carry,
			 arch_addr_t pc_val, uint32_t *lp)
{
	enum arm_register rm = BITS(inst, 0, 3);
	unsigned long shifttype = BITS(inst, 5, 6);

	uint32_t shift;
	if (BIT(inst, 4)) {
		if (arm_get_register_offpc(proc, BITS(inst, 8, 11), &shift) < 0)
			return -1;
		shift &= 0xff;
	} else {
		shift = BITS(inst, 7, 11);
	}

	uint32_t res;
	if (rm == ARM_REG_PC)
		/* xxx double cast */
		res = (uintptr_t)pc_val + (BIT(inst, 4) ? 12 : 8);
	else if (arm_get_register(proc, rm, &res) < 0)
		return -1;

	switch (shifttype) {
	case 0:			/* LSL */
		res = shift >= 32 ? 0 : res << shift;
		break;

	case 1:			/* LSR */
		res = shift >= 32 ? 0 : res >> shift;
		break;

	case 2:			/* ASR */
		if (shift >= 32)
			shift = 31;
		res = ((res & 0x80000000L)
		       ? ~((~res) >> shift) : res >> shift);
		break;

	case 3:			/* ROR/RRX */
		shift &= 31;
		if (shift == 0)
			res = (res >> 1) | (carry ? 0x80000000L : 0);
		else
			res = (res >> shift) | (res << (32 - shift));
		break;
	}

	*lp = res & 0xffffffff;
	return 0;
}

arch_addr_t
get_instruction_pointer(struct process *proc)
{
	uint32_t reg;
	if (arm_get_register(proc, ARM_REG_PC, &reg) < 0)
		/* XXX double cast. */
		return (arch_addr_t)-1;
	/* XXX double cast.  */
	return (arch_addr_t)(uintptr_t)reg;
}

void
set_instruction_pointer(struct process *proc, void *addr)
{
	ptrace(PTRACE_POKEUSER, proc->pid, off_pc, addr);
}

void *
get_stack_pointer(struct process *proc)
{
	return (void *)ptrace(PTRACE_PEEKUSER, proc->pid, off_sp, 0);
}

/* really, this is given the *stack_pointer expecting
 * a CISC architecture; in our case, we don't need that */
void *
get_return_addr(struct process *proc, void *stack_pointer)
{
	long addr = ptrace(PTRACE_PEEKUSER, proc->pid, off_lr, 0);

	/* Remember & unset the thumb mode bit.  XXX This is really a
	 * bit of a hack, as we assume that the following
	 * insert_breakpoint call will be related to this address.
	 * This interface should really be get_return_breakpoint, or
	 * maybe install_return_breakpoint.  */
	proc->thumb_mode = addr & 1;
	if (proc->thumb_mode)
		addr &= ~1;

	return (void *)addr;
}
