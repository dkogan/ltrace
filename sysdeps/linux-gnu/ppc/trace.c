/*
 * This file is part of ltrace.
 * Copyright (C) 2010,2012 Petr Machata, Red Hat Inc.
 * Copyright (C) 2011 Andreas Schwab
 * Copyright (C) 2002,2004,2008,2009 Juan Cespedes
 * Copyright (C) 2008 Luis Machado, IBM Corporation
 * Copyright (C) 2006 Ian Wienand
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
#include <sys/wait.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <asm/ptrace.h>
#include <elf.h>
#include <errno.h>
#include <string.h>

#include "proc.h"
#include "common.h"
#include "ptrace.h"
#include "breakpoint.h"
#include "type.h"
#include "backend.h"

#if (!defined(PTRACE_PEEKUSER) && defined(PTRACE_PEEKUSR))
# define PTRACE_PEEKUSER PTRACE_PEEKUSR
#endif

#if (!defined(PTRACE_POKEUSER) && defined(PTRACE_POKEUSR))
# define PTRACE_POKEUSER PTRACE_POKEUSR
#endif

void
get_arch_dep(Process *proc) {
	if (proc->arch_ptr == NULL) {
		proc->arch_ptr = malloc(sizeof(proc_archdep));
#ifdef __powerpc64__
		proc->mask_32bit = (proc->e_machine == EM_PPC);
#endif
	}

	proc_archdep *a = (proc_archdep *) (proc->arch_ptr);
	a->valid = (ptrace(PTRACE_GETREGS, proc->pid, 0, &a->regs) >= 0)
		&& (ptrace(PTRACE_GETFPREGS, proc->pid, 0, &a->fpregs) >= 0);
}

#define SYSCALL_INSN   0x44000002

/* Returns 1 if syscall, 2 if sysret, 0 otherwise. */
int
syscall_p(Process *proc, int status, int *sysnum) {
	if (WIFSTOPPED(status)
	    && WSTOPSIG(status) == (SIGTRAP | proc->tracesysgood)) {
		long pc = (long)get_instruction_pointer(proc);
		int insn =
		    (int)ptrace(PTRACE_PEEKTEXT, proc->pid, pc - sizeof(long),
				0);

		if (insn == SYSCALL_INSN) {
			*sysnum =
			    (int)ptrace(PTRACE_PEEKUSER, proc->pid,
					sizeof(long) * PT_R0, 0);
			if (proc->callstack_depth > 0 &&
					proc->callstack[proc->callstack_depth - 1].is_syscall &&
					proc->callstack[proc->callstack_depth - 1].c_un.syscall == *sysnum) {
				return 2;
			}
			return 1;
		}
	}
	return 0;
}

/* The atomic skip code is mostly taken from GDB.  */

/* Instruction masks used during single-stepping of atomic
 * sequences.  This was lifted from GDB.  */
#define LWARX_MASK 0xfc0007fe
#define LWARX_INSTRUCTION 0x7c000028
#define LDARX_INSTRUCTION 0x7c0000A8
#define STWCX_MASK 0xfc0007ff
#define STWCX_INSTRUCTION 0x7c00012d
#define STDCX_INSTRUCTION 0x7c0001ad
#define BC_MASK 0xfc000000
#define BC_INSN 0x40000000
#define BRANCH_MASK 0xfc000000

/* In plt.h.  XXX make this official interface.  */
int read_target_4(struct Process *proc, target_address_t addr, uint32_t *lp);

int
arch_atomic_singlestep(struct Process *proc, struct breakpoint *sbp,
		       int (*add_cb)(void *addr, void *data),
		       void *add_cb_data)
{
	target_address_t ip = get_instruction_pointer(proc);
	struct breakpoint *other = address2bpstruct(proc->leader, ip);

	debug(1, "arch_atomic_singlestep pid=%d addr=%p %s(%p)",
	      proc->pid, ip, breakpoint_name(sbp), sbp->addr);

	/* If the original instruction was lwarx/ldarx, we can't
	 * single-step over it, instead we have to execute the whole
	 * atomic block at once.  */
	union {
		uint32_t insn;
		char buf[BREAKPOINT_LENGTH];
	} u;
	if (other != NULL) {
		memcpy(u.buf, sbp->orig_value, BREAKPOINT_LENGTH);
	} else if (read_target_4(proc, ip, &u.insn) < 0) {
		fprintf(stderr, "couldn't read instruction at IP %p\n", ip);
		/* Do the normal singlestep.  */
		return 1;
	}

	if ((u.insn & LWARX_MASK) != LWARX_INSTRUCTION
	    && (u.insn & LWARX_MASK) != LDARX_INSTRUCTION)
		return 1;

	debug(1, "singlestep over atomic block at %p", ip);

	int insn_count;
	target_address_t addr = ip;
	for (insn_count = 0; ; ++insn_count) {
		addr += 4;
		unsigned long l = ptrace(PTRACE_PEEKTEXT, proc->pid, addr, 0);
		if (l == (unsigned long)-1 && errno)
			return -1;
		uint32_t insn;
#ifdef __powerpc64__
		insn = l >> 32;
#else
		insn = l;
#endif

		/* If a conditional branch is found, put a breakpoint
		 * in its destination address.  */
		if ((insn & BRANCH_MASK) == BC_INSN) {
			int immediate = ((insn & 0xfffc) ^ 0x8000) - 0x8000;
			int absolute = insn & 2;

			/* XXX drop the following casts.  */
			target_address_t branch_addr;
			if (absolute)
				branch_addr = (void *)(uintptr_t)immediate;
			else
				branch_addr = addr + (uintptr_t)immediate;

			debug(1, "pid=%d, branch in atomic block from %p to %p",
			      proc->pid, addr, branch_addr);
			if (add_cb(branch_addr, add_cb_data) < 0)
				return -1;
		}

		/* Assume that the atomic sequence ends with a
		 * stwcx/stdcx instruction.  */
		if ((insn & STWCX_MASK) == STWCX_INSTRUCTION
		    || (insn & STWCX_MASK) == STDCX_INSTRUCTION) {
			debug(1, "pid=%d, found end of atomic block %p at %p",
			      proc->pid, ip, addr);
			break;
		}

		/* Arbitrary cut-off.  If we didn't find the
		 * terminating instruction by now, just give up.  */
		if (insn_count > 16) {
			fprintf(stderr, "[%d] couldn't find end of atomic block"
				" at %p\n", proc->pid, ip);
			return -1;
		}
	}

	/* Put the breakpoint to the next instruction.  */
	addr += 4;
	if (add_cb(addr, add_cb_data) < 0)
		return -1;

	debug(1, "PTRACE_CONT");
	ptrace(PTRACE_CONT, proc->pid, 0, 0);
	return 0;
}
