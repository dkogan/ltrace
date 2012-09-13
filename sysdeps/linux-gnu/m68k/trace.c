#include "config.h"

#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
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

void
get_arch_dep(Process *proc) {
}

/* Returns 1 if syscall, 2 if sysret, 0 otherwise.
 */
int
syscall_p(Process *proc, int status, int *sysnum) {
	int depth;

	if (WIFSTOPPED(status)
	    && WSTOPSIG(status) == (SIGTRAP | proc->tracesysgood)) {
		*sysnum = ptrace(PTRACE_PEEKUSER, proc->pid, 4 * PT_ORIG_D0, 0);
		if (*sysnum == -1)
			return 0;
		if (*sysnum >= 0) {
			depth = proc->callstack_depth;
			if (depth > 0 &&
					proc->callstack[depth - 1].is_syscall &&
					proc->callstack[depth - 1].c_un.syscall == *sysnum) {
				return 2;
			} else {
				return 1;
			}
		}
	}
	return 0;
}
