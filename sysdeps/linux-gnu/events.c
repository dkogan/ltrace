#include "config.h"

#define	_GNU_SOURCE	1
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <sys/ptrace.h>

#include "common.h"

static Event event;

static enum pcb_status
first (Process * proc, void * data)
{
	return pcb_stop;
}

Event *
next_event(void)
{
	pid_t pid;
	int status;
	int tmp;
	int stop_signal;

	debug(DEBUG_FUNCTION, "next_event()");
	if (!each_process(NULL, &first, NULL)) {
		debug(DEBUG_EVENT, "event: No more traced programs: exiting");
		exit(0);
	}
	pid = waitpid(-1, &status, __WALL);
	if (pid == -1) {
		if (errno == ECHILD) {
			debug(DEBUG_EVENT, "event: No more traced programs: exiting");
			exit(0);
		} else if (errno == EINTR) {
			debug(DEBUG_EVENT, "event: none (wait received EINTR?)");
			event.type = EVENT_NONE;
			return &event;
		}
		perror("wait");
		exit(1);
	}
	event.proc = pid2proc(pid);
	if (!event.proc || event.proc->state == STATE_BEING_CREATED) {
		event.type = EVENT_NEW;
		event.e_un.newpid = pid;
		debug(DEBUG_EVENT, "event: NEW: pid=%d", pid);
		return &event;
	}
	get_arch_dep(event.proc);
	debug(3, "event from pid %u", pid);
	if (event.proc->breakpoints_enabled == -1)
		trace_set_options(event.proc, event.proc->pid);
	Process *leader = event.proc->leader;
	if (leader == event.proc) {
		if (event.proc->breakpoints_enabled == -1) {
			event.type = EVENT_NONE;
			enable_all_breakpoints(event.proc);
			continue_process(event.proc->pid);
			debug(DEBUG_EVENT,
			      "event: NONE: pid=%d (enabling breakpoints)",
			      pid);
			return &event;
		} else if (!event.proc->libdl_hooked) {
			/* debug struct may not have been written yet.. */
			if (linkmap_init(event.proc, &main_lte) == 0) {
				event.proc->libdl_hooked = 1;
			}
		}
	}

	event.proc->instruction_pointer = (void *)(uintptr_t)-1;

	event.proc->instruction_pointer = get_instruction_pointer(event.proc);
	if (event.proc->instruction_pointer == (void *)(uintptr_t)-1) {
		if (errno != 0)
			perror("get_instruction_pointer");
	}

	switch (syscall_p(event.proc, status, &tmp)) {
		case 1:
			event.type = EVENT_SYSCALL;
			event.e_un.sysnum = tmp;
			debug(DEBUG_EVENT, "event: SYSCALL: pid=%d, sysnum=%d", pid, tmp);
			return &event;
		case 2:
			event.type = EVENT_SYSRET;
			event.e_un.sysnum = tmp;
			debug(DEBUG_EVENT, "event: SYSRET: pid=%d, sysnum=%d", pid, tmp);
			return &event;
		case 3:
			event.type = EVENT_ARCH_SYSCALL;
			event.e_un.sysnum = tmp;
			debug(DEBUG_EVENT, "event: ARCH_SYSCALL: pid=%d, sysnum=%d", pid, tmp);
			return &event;
		case 4:
			event.type = EVENT_ARCH_SYSRET;
			event.e_un.sysnum = tmp;
			debug(DEBUG_EVENT, "event: ARCH_SYSRET: pid=%d, sysnum=%d", pid, tmp);
			return &event;
		case -1:
			event.type = EVENT_NONE;
			continue_process(event.proc->pid);
			debug(DEBUG_EVENT, "event: NONE: pid=%d (syscall_p returned -1)", pid);
			return &event;
	}
	if (WIFSTOPPED(status) && ((status>>16 == PTRACE_EVENT_FORK) || (status>>16 == PTRACE_EVENT_VFORK) || (status>>16 == PTRACE_EVENT_CLONE))) {
		unsigned long data;
		ptrace(PTRACE_GETEVENTMSG, pid, NULL, &data);
		event.type = EVENT_CLONE;
		event.e_un.newpid = data;
		debug(DEBUG_EVENT, "event: CLONE: pid=%d, newpid=%d", pid, (int)data);
		return &event;
	}
	if (WIFSTOPPED(status) && (status>>16 == PTRACE_EVENT_EXEC)) {
		event.type = EVENT_EXEC;
		debug(DEBUG_EVENT, "event: EXEC: pid=%d", pid);
		return &event;
	}
	if (WIFEXITED(status)) {
		event.type = EVENT_EXIT;
		event.e_un.ret_val = WEXITSTATUS(status);
		debug(DEBUG_EVENT, "event: EXIT: pid=%d, status=%d", pid, event.e_un.ret_val);
		return &event;
	}
	if (WIFSIGNALED(status)) {
		event.type = EVENT_EXIT_SIGNAL;
		event.e_un.signum = WTERMSIG(status);
		debug(DEBUG_EVENT, "event: EXIT_SIGNAL: pid=%d, signum=%d", pid, event.e_un.signum);
		return &event;
	}
	if (!WIFSTOPPED(status)) {
		/* should never happen */
		event.type = EVENT_NONE;
		debug(DEBUG_EVENT, "event: NONE: pid=%d (wait error?)", pid);
		return &event;
	}

	stop_signal = WSTOPSIG(status);

	/* On some targets, breakpoints are signalled not using
	   SIGTRAP, but also with SIGILL, SIGSEGV or SIGEMT.  SIGEMT
	   is not defined on Linux, but check for the others.

	   N.B. see comments in GDB's infrun.c for details.  I've
	   actually seen this on an Itanium machine on RHEL 5, I don't
	   remember the exact kernel version anymore.  ia64-sigill.s
	   in the test suite tests this.  Petr Machata 2011-06-08.  */
	void * break_address
		= event.proc->instruction_pointer - DECR_PC_AFTER_BREAK;
	if ((stop_signal == SIGSEGV || stop_signal == SIGILL)
	    && leader != NULL
	    && address2bpstruct(leader, break_address))
			stop_signal = SIGTRAP;

	if (stop_signal != (SIGTRAP | event.proc->tracesysgood)
			&& stop_signal != SIGTRAP) {
		event.type = EVENT_SIGNAL;
		event.e_un.signum = stop_signal;
		debug(DEBUG_EVENT, "event: SIGNAL: pid=%d, signum=%d", pid, stop_signal);
		return &event;
	}

	/* last case [by exhaustion] */
	event.type = EVENT_BREAKPOINT;

	event.e_un.brk_addr = break_address;
	debug(DEBUG_EVENT, "event: BREAKPOINT: pid=%d, addr=%p", pid, event.e_un.brk_addr);

	return &event;
}
