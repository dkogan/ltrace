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

unsigned int greg = 3;
unsigned int freg = 1;

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

static long
gimme_arg_regset(enum tof type, Process *proc, int arg_num, arg_type_info *info,
		 gregset_t *regs, fpregset_t *fpregs)
{
	union { long val; float fval; double dval; } cvt;

	if (info->type == ARGTYPE_FLOAT || info->type == ARGTYPE_DOUBLE) {
		if (freg <= 13 || (proc->mask_32bit && freg <= 8)) {
			double val = GET_FPREG(*fpregs, freg);

			if (info->type == ARGTYPE_FLOAT)
				cvt.fval = val;
			else
				cvt.dval = val;

			freg++;
			greg++;

			return cvt.val;
		}
	}
	else if (greg <= 10)
		return (*regs)[greg++];
	else {
#ifdef __powerpc64__
		if (proc->mask_32bit)
			return ptrace (PTRACE_PEEKDATA, proc->pid,
				       proc->stack_pointer + 8 +
				       sizeof (int) * (arg_num - 8), 0) >> 32;
		else
			return ptrace (PTRACE_PEEKDATA, proc->pid,
				       proc->stack_pointer + 112 +
				       sizeof (long) * (arg_num - 8), 0);
#else
		return ptrace (PTRACE_PEEKDATA, proc->pid,
			       proc->stack_pointer + 8 +
			       sizeof (long) * (arg_num - 8), 0);
#endif
	}

	return 0;
}

static long
gimme_retval(Process *proc, int arg_num, arg_type_info *info,
	     gregset_t *regs, fpregset_t *fpregs)
{
	union { long val; float fval; double dval; } cvt;
	if (info->type == ARGTYPE_FLOAT || info->type == ARGTYPE_DOUBLE) {
		double val = GET_FPREG(*fpregs, 1);

		if (info->type == ARGTYPE_FLOAT)
			cvt.fval = val;
		else
			cvt.dval = val;

		return cvt.val;
	}
	else 
		return (*regs)[3];
}

/* Grab functions arguments based on the PPC64 ABI.  */
long
gimme_arg(enum tof type, Process *proc, int arg_num, arg_type_info *info)
{
	proc_archdep *arch = (proc_archdep *)proc->arch_ptr;
	if (arch == NULL || !arch->valid)
		return -1;

	/* Check if we're entering a new function call to list parameters.  If
	   so, initialize the register control variables to keep track of where
	   the parameters were stored.  */
	if ((type == LT_TOF_FUNCTION || type == LT_TOF_FUNCTIONR)
	    && arg_num == 0) {
		/* Initialize the set of registrers for parameter passing.  */
		greg = 3;
		freg = 1;
	}


	if (type == LT_TOF_FUNCTIONR) {
		if (arg_num == -1)
			return gimme_retval(proc, arg_num, info,
					    &arch->regs, &arch->fpregs);
		else
			return gimme_arg_regset(type, proc, arg_num, info,
						&arch->regs_copy,
						&arch->fpregs_copy);
	}
	else
		return gimme_arg_regset(type, proc, arg_num, info,
					&arch->regs, &arch->fpregs);
}

void
save_register_args(enum tof type, Process *proc) {
	proc_archdep *arch = (proc_archdep *)proc->arch_ptr;
	if (arch == NULL || !arch->valid)
		return;

	memcpy(&arch->regs_copy, &arch->regs, sizeof(arch->regs));
	memcpy(&arch->fpregs_copy, &arch->fpregs, sizeof(arch->fpregs));
}

/* Read a single long from the process's memory address 'addr'.  */
int
arch_umovelong (Process *proc, void *addr, long *result, arg_type_info *info) {
	long pointed_to;

	errno = 0;

	pointed_to = ptrace (PTRACE_PEEKTEXT, proc->pid, addr, 0);

	if (pointed_to == -1 && errno)
		return -errno;

#if SIZEOF_LONG == 8
	/* Since int's are 4-bytes (long is 8-bytes) in length for ppc64, we
	   need to shift the long values returned by ptrace to end up with
	   the correct value.  */

	if (info) {
		if (info->type == ARGTYPE_INT || (proc->mask_32bit && (info->type == ARGTYPE_POINTER
		    || info->type == ARGTYPE_STRING))) {
			pointed_to = (long) (((unsigned long) pointed_to) >> 32);
		}
	}
#endif

	*result = pointed_to;
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
