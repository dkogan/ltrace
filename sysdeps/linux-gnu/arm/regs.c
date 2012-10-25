/*
 * This file is part of ltrace.
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

#include "proc.h"
#include "common.h"

#if (!defined(PTRACE_PEEKUSER) && defined(PTRACE_PEEKUSR))
# define PTRACE_PEEKUSER PTRACE_PEEKUSR
#endif

#if (!defined(PTRACE_POKEUSER) && defined(PTRACE_POKEUSR))
# define PTRACE_POKEUSER PTRACE_POKEUSR
#endif

#define off_pc ((void *)60)
#define off_lr ((void *)56)
#define off_sp ((void *)52)

void *
get_instruction_pointer(Process *proc) {
	return (void *)ptrace(PTRACE_PEEKUSER, proc->pid, off_pc, 0);
}

void
set_instruction_pointer(Process *proc, void *addr) {
	ptrace(PTRACE_POKEUSER, proc->pid, off_pc, addr);
}

void *
get_stack_pointer(Process *proc) {
	return (void *)ptrace(PTRACE_PEEKUSER, proc->pid, off_sp, 0);
}

/* really, this is given the *stack_pointer expecting
 * a CISC architecture; in our case, we don't need that */
void *
get_return_addr(Process *proc, void *stack_pointer) {
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

void
set_return_addr(Process *proc, void *addr) {
	long iaddr = (int)addr | proc->thumb_mode;
	ptrace(PTRACE_POKEUSER, proc->pid, off_lr, (void *)iaddr);
}
