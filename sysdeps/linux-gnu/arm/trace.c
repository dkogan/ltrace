/*
 * This file is part of ltrace.
 * Copyright (C) 2012, 2013 Petr Machata, Red Hat Inc.
 * Copyright (C) 1998,2004,2008,2009 Juan Cespedes
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

#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <asm/ptrace.h>

#include "proc.h"
#include "common.h"
#include "output.h"
#include "ptrace.h"
#include "regs.h"

#if (!defined(PTRACE_PEEKUSER) && defined(PTRACE_PEEKUSR))
# define PTRACE_PEEKUSER PTRACE_PEEKUSR
#endif

#if (!defined(PTRACE_POKEUSER) && defined(PTRACE_POKEUSR))
# define PTRACE_POKEUSER PTRACE_POKEUSR
#endif

#define off_r0 ((void *)0)
#define off_r7 ((void *)28)
#define off_ip ((void *)48)
#define off_pc ((void *)60)
#define off_cpsr ((void *)64)

void
get_arch_dep(struct process *proc)
{
	proc_archdep *a;

	if (!proc->arch_ptr)
		proc->arch_ptr = (void *)malloc(sizeof(proc_archdep));
	a = (proc_archdep *) (proc->arch_ptr);
	a->valid = (ptrace(PTRACE_GETREGS, proc->pid, 0, &a->regs) >= 0);
}

/* Returns 0 if not a syscall,
 *         1 if syscall entry, 2 if syscall exit,
 *         3 if arch-specific syscall entry, 4 if arch-specific syscall exit,
 *         -1 on error.
 */
int
syscall_p(struct process *proc, int status, int *sysnum)
{
	if (WIFSTOPPED(status)
	    && WSTOPSIG(status) == (SIGTRAP | proc->tracesysgood)) {
		/* get the user's pc (plus 8) */
		unsigned pc = ptrace(PTRACE_PEEKUSER, proc->pid, off_pc, 0);
		pc = pc - 4;
		/* fetch the SWI instruction */
		unsigned insn = ptrace(PTRACE_PEEKTEXT, proc->pid,
				       (void *)pc, 0);
		int ip = ptrace(PTRACE_PEEKUSER, proc->pid, off_ip, 0);

		if (insn == 0xef000000 || insn == 0x0f000000
		    || (insn & 0xffff0000) == 0xdf000000) {
			/* EABI syscall */
			*sysnum = ptrace(PTRACE_PEEKUSER, proc->pid, off_r7, 0);
		} else if ((insn & 0xfff00000) == 0xef900000) {
			/* old ABI syscall */
			*sysnum = insn & 0xfffff;
		} else {
			/* TODO: handle swi<cond> variations */
			/* one possible reason for getting in here is that we
			 * are coming from a signal handler, so the current
			 * PC does not point to the instruction just after the
			 * "swi" one. */
			output_line(proc, "unexpected instruction 0x%x at %p",
				    insn, pc);
			return 0;
		}
		if ((*sysnum & 0xf0000) == 0xf0000) {
			/* arch-specific syscall */
			*sysnum &= ~0xf0000;
			return ip ? 4 : 3;
		}
		/* ARM syscall convention: on syscall entry, ip is zero;
		 * on syscall exit, ip is non-zero */
		return ip ? 2 : 1;
	}
	return 0;
}

long
gimme_arg(enum tof type, struct process *proc, int arg_num,
	  struct arg_type_info *info)
{
	proc_archdep *a = (proc_archdep *) proc->arch_ptr;

	if (arg_num == -1) {	/* return value */
		return ptrace(PTRACE_PEEKUSER, proc->pid, off_r0, 0);
	}

	/* deal with the ARM calling conventions */
	if (type == LT_TOF_FUNCTION || type == LT_TOF_FUNCTIONR) {
		if (arg_num < 4) {
			if (a->valid && type == LT_TOF_FUNCTION)
				return a->regs.uregs[arg_num];
			if (a->valid && type == LT_TOF_FUNCTIONR)
				return a->func_arg[arg_num];
			return ptrace(PTRACE_PEEKUSER, proc->pid,
				      (void *)(4 * arg_num), 0);
		} else {
			return ptrace(PTRACE_PEEKDATA, proc->pid,
				      proc->stack_pointer + 4 * (arg_num - 4),
				      0);
		}
	} else if (type == LT_TOF_SYSCALL || type == LT_TOF_SYSCALLR) {
		if (arg_num < 5) {
			if (a->valid && type == LT_TOF_SYSCALL)
				return a->regs.uregs[arg_num];
			if (a->valid && type == LT_TOF_SYSCALLR)
				return a->sysc_arg[arg_num];
			return ptrace(PTRACE_PEEKUSER, proc->pid,
				      (void *)(4 * arg_num), 0);
		} else {
			return ptrace(PTRACE_PEEKDATA, proc->pid,
				      proc->stack_pointer + 4 * (arg_num - 5),
				      0);
		}
	} else {
		fprintf(stderr, "gimme_arg called with wrong arguments\n");
		exit(1);
	}

	return 0;
}

static arch_addr_t
arm_branch_dest(const arch_addr_t pc, const uint32_t insn)
{
	/* Bits 0-23 are signed immediate value.  */
	return pc + ((((insn & 0xffffff) ^ 0x800000) - 0x800000) << 2) + 8;
}

/* Addresses for calling Thumb functions have the bit 0 set.
   Here are some macros to test, set, or clear bit 0 of addresses.  */
/* XXX double cast */
#define IS_THUMB_ADDR(addr)	((uintptr_t)(addr) & 1)
#define MAKE_THUMB_ADDR(addr)	((arch_addr_t)((uintptr_t)(addr) | 1))
#define UNMAKE_THUMB_ADDR(addr) ((arch_addr_t)((uintptr_t)(addr) & ~1))

static int
get_next_pcs(struct process *proc,
	     const arch_addr_t pc, arch_addr_t next_pcs[2])
{
	uint32_t this_instr;
	uint32_t status;
	if (proc_read_32(proc, pc, &this_instr) < 0
	    || arm_get_register(proc, ARM_REG_CPSR, &status) < 0)
		return -1;

	/* In theory, we sometimes don't even need to add any
	 * breakpoints at all.  If the conditional bits of the
	 * instruction indicate that it should not be taken, then we
	 * can just skip it altogether without bothering.  We could
	 * also emulate the instruction under the breakpoint.  GDB
	 * does both.
	 *
	 * Here, we make it as simple as possible (though We Accept
	 * Patches).  */
	int nr = 0;

	/* ARM can branch either relatively by using a branch
	 * instruction, or absolutely, by doing arbitrary arithmetic
	 * with PC as the destination.  */
	enum {
		COND_ALWAYS = 0xe,
		COND_NV = 0xf,
		FLAG_C = 0x20000000,
	};
	const unsigned cond = BITS(this_instr, 28, 31);
	const unsigned opcode = BITS(this_instr, 24, 27);

	if (cond == COND_NV)
		switch (opcode) {
			arch_addr_t addr;
		case 0xa:
		case 0xb:
			/* Branch with Link and change to Thumb.  */
			/* XXX double cast.  */
			addr = (arch_addr_t)
				((uint32_t)arm_branch_dest(pc, this_instr)
				 | (((this_instr >> 24) & 0x1) << 1));
			next_pcs[nr++] = MAKE_THUMB_ADDR(addr);
			break;
		}
	else
		switch (opcode) {
			uint32_t operand1, operand2, result = 0;
		case 0x0:
		case 0x1:			/* data processing */
		case 0x2:
		case 0x3:
			if (BITS(this_instr, 12, 15) != ARM_REG_PC)
				break;

			if (BITS(this_instr, 22, 25) == 0
			    && BITS(this_instr, 4, 7) == 9) {	/* multiply */
			invalid:
				fprintf(stderr,
				"Invalid update to pc in instruction.\n");
				break;
			}

			/* BX <reg>, BLX <reg> */
			if (BITS(this_instr, 4, 27) == 0x12fff1
			    || BITS(this_instr, 4, 27) == 0x12fff3) {
				enum arm_register reg = BITS(this_instr, 0, 3);
				/* XXX double cast: no need to go
				 * through tmp.  */
				uint32_t tmp;
				if (arm_get_register_offpc(proc, reg, &tmp) < 0)
					return -1;
				next_pcs[nr++] = (arch_addr_t)tmp;
				return 0;
			}

			/* Multiply into PC.  */
			if (arm_get_register_offpc
			    (proc, BITS(this_instr, 16, 19), &operand1) < 0)
				return -1;

			int c = (status & FLAG_C) ? 1 : 0;
			if (BIT(this_instr, 25)) {
				uint32_t immval = BITS(this_instr, 0, 7);
				uint32_t rotate = 2 * BITS(this_instr, 8, 11);
				operand2 = (((immval >> rotate)
					     | (immval << (32 - rotate)))
					    & 0xffffffff);
			} else {
				/* operand 2 is a shifted register.  */
				if (arm_get_shifted_register
				    (proc, this_instr, c, pc, &operand2) < 0)
					return -1;
			}

			switch (BITS(this_instr, 21, 24)) {
			case 0x0:	/*and */
				result = operand1 & operand2;
				break;

			case 0x1:	/*eor */
				result = operand1 ^ operand2;
				break;

			case 0x2:	/*sub */
				result = operand1 - operand2;
				break;

			case 0x3:	/*rsb */
				result = operand2 - operand1;
				break;

			case 0x4:	/*add */
				result = operand1 + operand2;
				break;

			case 0x5:	/*adc */
				result = operand1 + operand2 + c;
				break;

			case 0x6:	/*sbc */
				result = operand1 - operand2 + c;
				break;

			case 0x7:	/*rsc */
				result = operand2 - operand1 + c;
				break;

			case 0x8:
			case 0x9:
			case 0xa:
			case 0xb:	/* tst, teq, cmp, cmn */
				/* Only take the default branch.  */
				result = 0;
				break;

			case 0xc:	/*orr */
				result = operand1 | operand2;
				break;

			case 0xd:	/*mov */
				/* Always step into a function.  */
				result = operand2;
				break;

			case 0xe:	/*bic */
				result = operand1 & ~operand2;
				break;

			case 0xf:	/*mvn */
				result = ~operand2;
				break;
			}

			/* XXX double cast */
			next_pcs[nr++] = (arch_addr_t)result;
			break;

		case 0x4:
		case 0x5:		/* data transfer */
		case 0x6:
		case 0x7:
			/* Ignore if insn isn't load or Rn not PC.  */
			if (!BIT(this_instr, 20)
			    || BITS(this_instr, 12, 15) != ARM_REG_PC)
				break;

			if (BIT(this_instr, 22))
				goto invalid;

			/* byte write to PC */
			uint32_t base;
			if (arm_get_register_offpc
			    (proc, BITS(this_instr, 16, 19), &base) < 0)
				return -1;

			if (BIT(this_instr, 24)) {
				/* pre-indexed */
				int c = (status & FLAG_C) ? 1 : 0;
				uint32_t offset;
				if (BIT(this_instr, 25)) {
					if (arm_get_shifted_register
					    (proc, this_instr, c,
					     pc, &offset) < 0)
						return -1;
				} else {
					offset = BITS(this_instr, 0, 11);
				}

				if (BIT(this_instr, 23))
					base += offset;
				else
					base -= offset;
			}

			/* XXX two double casts.  */
			uint32_t next;
			if (proc_read_32(proc, (arch_addr_t)base, &next) < 0)
				return -1;
			next_pcs[nr++] = (arch_addr_t)next;
			break;

		case 0xb:		/* branch & link */
		case 0xa:		/* branch */
			next_pcs[nr++] = arm_branch_dest(pc, this_instr);
			break;
		}

	/* Otherwise take the next instruction.  */
	if (cond != COND_ALWAYS || nr == 0)
		next_pcs[nr++] = pc + 4;
	return 0;
}

enum sw_singlestep_status
arch_sw_singlestep(struct process *proc, struct breakpoint *sbp,
		   int (*add_cb)(arch_addr_t, struct sw_singlestep_data *),
		   struct sw_singlestep_data *add_cb_data)
{
	arch_addr_t pc = get_instruction_pointer(proc);
	arch_addr_t next_pcs[2] = {};
	if (get_next_pcs(proc, pc, next_pcs) < 0)
		return SWS_FAIL;

	int i;
	for (i = 0; i < 2; ++i) {
		if (next_pcs[i] != 0 && add_cb(next_pcs[i], add_cb_data) < 0)
			return SWS_FAIL;
	}

	debug(1, "PTRACE_CONT");
	ptrace(PTRACE_CONT, proc->pid, 0, 0);
	return SWS_OK;
}
