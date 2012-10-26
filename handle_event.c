/*
 * This file is part of ltrace.
 * Copyright (C) 2011,2012 Petr Machata, Red Hat Inc.
 * Copyright (C) 2010 Arnaud Patard, Mandriva SA
 * Copyright (C) 1998,2001,2002,2003,2004,2007,2008,2009 Juan Cespedes
 * Copyright (C) 2008 Luis Machado, IBM Corporation
 * Copyright (C) 2006 Ian Wienand
 * Copyright (C) 2006 Paul Gilliam, IBM Corporation
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

#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include "backend.h"
#include "breakpoint.h"
#include "common.h"
#include "fetch.h"
#include "library.h"
#include "proc.h"
#include "value_dict.h"

static void handle_signal(Event *event);
static void handle_exit(Event *event);
static void handle_exit_signal(Event *event);
static void handle_syscall(Event *event);
static void handle_arch_syscall(Event *event);
static void handle_sysret(Event *event);
static void handle_arch_sysret(Event *event);
static void handle_clone(Event *event);
static void handle_exec(Event *event);
static void handle_breakpoint(Event *event);
static void handle_new(Event *event);

static void callstack_push_syscall(Process *proc, int sysnum);
static void callstack_push_symfunc(Process *proc,
				   struct library_symbol *sym);
/* XXX Stack maintenance should be moved to a dedicated module, or to
 * proc.c, and push/pop should be visible outside this module.  For
 * now, because we need this in proc.c, this is non-static.  */
void callstack_pop(struct Process *proc);

static char * shortsignal(Process *proc, int signum);
static char * sysname(Process *proc, int sysnum);
static char * arch_sysname(Process *proc, int sysnum);

static Event *
call_handler(Process * proc, Event * event)
{
	assert(proc != NULL);

	struct event_handler *handler = proc->event_handler;
	if (handler == NULL)
		return event;

	return (*handler->on_event) (handler, event);
}

void
handle_event(Event *event)
{
	if (exiting == 1) {
		debug(1, "ltrace about to exit");
		os_ltrace_exiting();
		exiting = 2;
	}
	debug(DEBUG_FUNCTION, "handle_event(pid=%d, type=%d)",
	      event->proc ? event->proc->pid : -1, event->type);

	/* If the thread group or an individual task define an
	   overriding event handler, give them a chance to kick in.
	   We will end up calling both handlers, if the first one
	   doesn't sink the event.  */
	if (event->proc != NULL) {
		event = call_handler(event->proc, event);
		if (event == NULL)
			/* It was handled.  */
			return;

		/* Note: the previous handler has a chance to alter
		 * the event.  */
		if (event->proc != NULL
		    && event->proc->leader != NULL
		    && event->proc != event->proc->leader) {
			event = call_handler(event->proc->leader, event);
			if (event == NULL)
				return;
		}
	}

	switch (event->type) {
	case EVENT_NONE:
		debug(1, "event: none");
		return;
	case EVENT_SIGNAL:
		debug(1, "[%d] event: signal (%s [%d])",
		      event->proc->pid,
		      shortsignal(event->proc, event->e_un.signum),
		      event->e_un.signum);
		handle_signal(event);
		return;
	case EVENT_EXIT:
		debug(1, "[%d] event: exit (%d)",
		      event->proc->pid,
		      event->e_un.ret_val);
		handle_exit(event);
		return;
	case EVENT_EXIT_SIGNAL:
		debug(1, "[%d] event: exit signal (%s [%d])",
		      event->proc->pid,
		      shortsignal(event->proc, event->e_un.signum),
		      event->e_un.signum);
		handle_exit_signal(event);
		return;
	case EVENT_SYSCALL:
		debug(1, "[%d] event: syscall (%s [%d])",
		      event->proc->pid,
		      sysname(event->proc, event->e_un.sysnum),
		      event->e_un.sysnum);
		handle_syscall(event);
		return;
	case EVENT_SYSRET:
		debug(1, "[%d] event: sysret (%s [%d])",
		      event->proc->pid,
		      sysname(event->proc, event->e_un.sysnum),
		      event->e_un.sysnum);
		handle_sysret(event);
		return;
	case EVENT_ARCH_SYSCALL:
		debug(1, "[%d] event: arch_syscall (%s [%d])",
		      event->proc->pid,
		      arch_sysname(event->proc, event->e_un.sysnum),
		      event->e_un.sysnum);
		handle_arch_syscall(event);
		return;
	case EVENT_ARCH_SYSRET:
		debug(1, "[%d] event: arch_sysret (%s [%d])",
		      event->proc->pid,
		      arch_sysname(event->proc, event->e_un.sysnum),
		      event->e_un.sysnum);
		handle_arch_sysret(event);
		return;
	case EVENT_CLONE:
	case EVENT_VFORK:
		debug(1, "[%d] event: clone (%u)",
		      event->proc->pid, event->e_un.newpid);
		handle_clone(event);
		return;
	case EVENT_EXEC:
		debug(1, "[%d] event: exec()",
		      event->proc->pid);
		handle_exec(event);
		return;
	case EVENT_BREAKPOINT:
		debug(1, "[%d] event: breakpoint %p",
		      event->proc->pid, event->e_un.brk_addr);
		handle_breakpoint(event);
		return;
	case EVENT_NEW:
		debug(1, "[%d] event: new process",
		      event->e_un.newpid);
		handle_new(event);
		return;
	default:
		fprintf(stderr, "Error! unknown event?\n");
		exit(1);
	}
}

typedef struct Pending_New Pending_New;
struct Pending_New {
	pid_t pid;
	Pending_New * next;
};
static Pending_New * pending_news = NULL;

static int
pending_new(pid_t pid) {
	Pending_New * p;

	debug(DEBUG_FUNCTION, "pending_new(%d)", pid);

	p = pending_news;
	while (p) {
		if (p->pid == pid) {
			return 1;
		}
		p = p->next;
	}
	return 0;
}

static void
pending_new_insert(pid_t pid) {
	Pending_New * p;

	debug(DEBUG_FUNCTION, "pending_new_insert(%d)", pid);

	p = malloc(sizeof(Pending_New));
	if (!p) {
		perror("malloc()");
		exit(1);
	}
	p->pid = pid;
	p->next = pending_news;
	pending_news = p;
}

static void
pending_new_remove(pid_t pid) {
	Pending_New *p, *pred;

	debug(DEBUG_FUNCTION, "pending_new_remove(%d)", pid);

	p = pending_news;
	pred = NULL;
	if (p->pid == pid) {
		pending_news = p->next;
		free(p);
	} else {
		while (p) {
			if (p->pid == pid) {
				pred->next = p->next;
				free(p);
			}
			pred = p;
			p = p->next;
		}
	}
}

static void
handle_clone(Event *event)
{
	debug(DEBUG_FUNCTION, "handle_clone(pid=%d)", event->proc->pid);

	struct Process *proc = malloc(sizeof(*proc));
	if (proc == NULL) {
	fail:
		free(proc);
		fprintf(stderr,
			"Error during init of tracing process %d\n"
			"This process won't be traced.\n",
			event->proc->pid);
		return;
	}

	if (process_clone(proc, event->proc, event->e_un.newpid) < 0)
		goto fail;
	proc->parent = event->proc;

	/* We save register values to the arch pointer, and these need
	   to be per-thread.  */
	proc->arch_ptr = NULL;

	if (pending_new(proc->pid)) {
		pending_new_remove(proc->pid);
		/* XXX this used to be destroy_event_handler call, but
		 * I don't think we want to call that on a shared
		 * state.  */
		proc->event_handler = NULL;
		if (event->proc->state == STATE_ATTACHED && options.follow)
			proc->state = STATE_ATTACHED;
		else
			proc->state = STATE_IGNORED;
		continue_process(proc->pid);
	} else {
		proc->state = STATE_BEING_CREATED;
	}

	if (event->type == EVENT_VFORK)
		continue_after_vfork(proc);
	else
		continue_process(event->proc->pid);
}

static void
handle_new(Event * event) {
	Process * proc;

	debug(DEBUG_FUNCTION, "handle_new(pid=%d)", event->e_un.newpid);

	proc = pid2proc(event->e_un.newpid);
	if (!proc) {
		pending_new_insert(event->e_un.newpid);
	} else {
		assert(proc->state == STATE_BEING_CREATED);
		if (options.follow) {
			proc->state = STATE_ATTACHED;
		} else {
			proc->state = STATE_IGNORED;
		}
		continue_process(proc->pid);
	}
}

static char *
shortsignal(Process *proc, int signum) {
	static char *signalent0[] = {
#include "signalent.h"
	};
	static char *signalent1[] = {
#include "signalent1.h"
	};
	static char **signalents[] = { signalent0, signalent1 };
	int nsignals[] = { sizeof signalent0 / sizeof signalent0[0],
		sizeof signalent1 / sizeof signalent1[0]
	};

	debug(DEBUG_FUNCTION, "shortsignal(pid=%d, signum=%d)", proc->pid, signum);

	if (proc->personality > sizeof signalents / sizeof signalents[0])
		abort();
	if (signum < 0 || signum >= nsignals[proc->personality]) {
		return "UNKNOWN_SIGNAL";
	} else {
		return signalents[proc->personality][signum];
	}
}

static char *
sysname(Process *proc, int sysnum) {
	static char result[128];
	static char *syscalent0[] = {
#include "syscallent.h"
	};
	static char *syscalent1[] = {
#include "syscallent1.h"
	};
	static char **syscalents[] = { syscalent0, syscalent1 };
	int nsyscals[] = { sizeof syscalent0 / sizeof syscalent0[0],
		sizeof syscalent1 / sizeof syscalent1[0]
	};

	debug(DEBUG_FUNCTION, "sysname(pid=%d, sysnum=%d)", proc->pid, sysnum);

	if (proc->personality > sizeof syscalents / sizeof syscalents[0])
		abort();
	if (sysnum < 0 || sysnum >= nsyscals[proc->personality]) {
		sprintf(result, "SYS_%d", sysnum);
		return result;
	} else {
		sprintf(result, "SYS_%s",
			syscalents[proc->personality][sysnum]);
		return result;
	}
}

static char *
arch_sysname(Process *proc, int sysnum) {
	static char result[128];
	static char *arch_syscalent[] = {
#include "arch_syscallent.h"
	};
	int nsyscals = sizeof arch_syscalent / sizeof arch_syscalent[0];

	debug(DEBUG_FUNCTION, "arch_sysname(pid=%d, sysnum=%d)", proc->pid, sysnum);

	if (sysnum < 0 || sysnum >= nsyscals) {
		sprintf(result, "ARCH_%d", sysnum);
		return result;
	} else {
		sprintf(result, "ARCH_%s",
				arch_syscalent[sysnum]);
		return result;
	}
}

static void
handle_signal(Event *event) {
	debug(DEBUG_FUNCTION, "handle_signal(pid=%d, signum=%d)", event->proc->pid, event->e_un.signum);
	if (event->proc->state != STATE_IGNORED && !options.no_signals) {
		output_line(event->proc, "--- %s (%s) ---",
				shortsignal(event->proc, event->e_un.signum),
				strsignal(event->e_un.signum));
	}
	continue_after_signal(event->proc->pid, event->e_un.signum);
}

static void
handle_exit(Event *event) {
	debug(DEBUG_FUNCTION, "handle_exit(pid=%d, status=%d)", event->proc->pid, event->e_un.ret_val);
	if (event->proc->state != STATE_IGNORED) {
		output_line(event->proc, "+++ exited (status %d) +++",
				event->e_un.ret_val);
	}
	remove_process(event->proc);
}

static void
handle_exit_signal(Event *event) {
	debug(DEBUG_FUNCTION, "handle_exit_signal(pid=%d, signum=%d)", event->proc->pid, event->e_un.signum);
	if (event->proc->state != STATE_IGNORED) {
		output_line(event->proc, "+++ killed by %s +++",
				shortsignal(event->proc, event->e_un.signum));
	}
	remove_process(event->proc);
}

static void
output_syscall(struct Process *proc, const char *name, enum tof tof,
	       void (*output)(enum tof, struct Process *,
			      struct library_symbol *))
{
	struct library_symbol syscall;
	if (library_symbol_init(&syscall, 0, name, 0, LS_TOPLT_NONE) >= 0) {
		(*output)(tof, proc, &syscall);
		library_symbol_destroy(&syscall);
	}
}

static void
output_syscall_left(struct Process *proc, const char *name)
{
	output_syscall(proc, name, LT_TOF_SYSCALL, &output_left);
}

static void
output_syscall_right(struct Process *proc, const char *name)
{
	output_syscall(proc, name, LT_TOF_SYSCALLR, &output_right);
}

static void
handle_syscall(Event *event) {
	debug(DEBUG_FUNCTION, "handle_syscall(pid=%d, sysnum=%d)", event->proc->pid, event->e_un.sysnum);
	if (event->proc->state != STATE_IGNORED) {
		callstack_push_syscall(event->proc, event->e_un.sysnum);
		if (options.syscalls)
			output_syscall_left(event->proc,
					    sysname(event->proc,
						    event->e_un.sysnum));
	}
	continue_after_syscall(event->proc, event->e_un.sysnum, 0);
}

static void
handle_exec(Event * event) {
	Process * proc = event->proc;

	/* Save the PID so that we can use it after unsuccessful
	 * process_exec.  */
	pid_t pid = proc->pid;

	debug(DEBUG_FUNCTION, "handle_exec(pid=%d)", proc->pid);
	if (proc->state == STATE_IGNORED) {
	untrace:
		untrace_pid(pid);
		remove_process(proc);
		return;
	}
	output_line(proc, "--- Called exec() ---");

	if (process_exec(proc) < 0) {
		fprintf(stderr,
			"couldn't reinitialize process %d after exec\n", pid);
		goto untrace;
	}

	continue_process(proc->pid);

	/* After the exec, we expect to hit the first executable
	 * instruction.
	 *
	 * XXX TODO It would be nice to have this removed, but then we
	 * need to do that also for initial call to wait_for_proc in
	 * execute_program.  In that case we could generate a
	 * EVENT_FIRST event or something, or maybe this could somehow
	 * be rolled into EVENT_NEW.  */
	wait_for_proc(proc->pid);
	continue_process(proc->pid);
}

static void
handle_arch_syscall(Event *event) {
	debug(DEBUG_FUNCTION, "handle_arch_syscall(pid=%d, sysnum=%d)", event->proc->pid, event->e_un.sysnum);
	if (event->proc->state != STATE_IGNORED) {
		callstack_push_syscall(event->proc, 0xf0000 + event->e_un.sysnum);
		if (options.syscalls) {
			output_syscall_left(event->proc,
					    arch_sysname(event->proc,
							 event->e_un.sysnum));
		}
	}
	continue_process(event->proc->pid);
}

struct timeval current_time_spent;

static void
calc_time_spent(Process *proc) {
	struct timeval tv;
	struct timezone tz;
	struct timeval diff;
	struct callstack_element *elem;

	debug(DEBUG_FUNCTION, "calc_time_spent(pid=%d)", proc->pid);
	elem = &proc->callstack[proc->callstack_depth - 1];

	gettimeofday(&tv, &tz);

	diff.tv_sec = tv.tv_sec - elem->time_spent.tv_sec;
	if (tv.tv_usec >= elem->time_spent.tv_usec) {
		diff.tv_usec = tv.tv_usec - elem->time_spent.tv_usec;
	} else {
		diff.tv_sec--;
		diff.tv_usec = 1000000 + tv.tv_usec - elem->time_spent.tv_usec;
	}
	current_time_spent = diff;
}

static void
handle_sysret(Event *event) {
	debug(DEBUG_FUNCTION, "handle_sysret(pid=%d, sysnum=%d)", event->proc->pid, event->e_un.sysnum);
	if (event->proc->state != STATE_IGNORED) {
		if (opt_T || options.summary) {
			calc_time_spent(event->proc);
		}
		if (options.syscalls)
			output_syscall_right(event->proc,
					     sysname(event->proc,
						     event->e_un.sysnum));

		assert(event->proc->callstack_depth > 0);
		unsigned d = event->proc->callstack_depth - 1;
		assert(event->proc->callstack[d].is_syscall);
		callstack_pop(event->proc);
	}
	continue_after_syscall(event->proc, event->e_un.sysnum, 1);
}

static void
handle_arch_sysret(Event *event) {
	debug(DEBUG_FUNCTION, "handle_arch_sysret(pid=%d, sysnum=%d)", event->proc->pid, event->e_un.sysnum);
	if (event->proc->state != STATE_IGNORED) {
		if (opt_T || options.summary) {
			calc_time_spent(event->proc);
		}
		if (options.syscalls)
			output_syscall_right(event->proc,
					     arch_sysname(event->proc,
							  event->e_un.sysnum));
		callstack_pop(event->proc);
	}
	continue_process(event->proc->pid);
}

static void
output_right_tos(struct Process *proc)
{
	size_t d = proc->callstack_depth;
	struct callstack_element *elem = &proc->callstack[d - 1];
	if (proc->state != STATE_IGNORED)
		output_right(LT_TOF_FUNCTIONR, proc, elem->c_un.libfunc);
}

#ifndef ARCH_HAVE_SYMBOL_RET
void arch_symbol_ret(struct Process *proc, struct library_symbol *libsym)
{
}
#endif

static void
handle_breakpoint(Event *event)
{
	int i, j;
	struct breakpoint *sbp;
	Process *leader = event->proc->leader;
	void *brk_addr = event->e_un.brk_addr;

	/* The leader has terminated.  */
	if (leader == NULL) {
		continue_process(event->proc->pid);
		return;
	}

	debug(DEBUG_FUNCTION, "handle_breakpoint(pid=%d, addr=%p)",
	      event->proc->pid, brk_addr);
	debug(2, "event: breakpoint (%p)", brk_addr);

	for (i = event->proc->callstack_depth - 1; i >= 0; i--) {
		if (brk_addr == event->proc->callstack[i].return_addr) {
			for (j = event->proc->callstack_depth - 1; j > i; j--) {
				callstack_pop(event->proc);
			}
			if (event->proc->state != STATE_IGNORED) {
				if (opt_T || options.summary) {
					calc_time_spent(event->proc);
				}
			}
			event->proc->return_addr = brk_addr;

			struct library_symbol *libsym =
			    event->proc->callstack[i].c_un.libfunc;

			arch_symbol_ret(event->proc, libsym);
			output_right_tos(event->proc);
			callstack_pop(event->proc);

			/* Pop also any other entries that seem like
			 * they are linked to the current one: they
			 * have the same return address, but were made
			 * for different symbols.  This should only
			 * happen for entry point tracing, i.e. for -x
			 * everywhere, or -x and -e on MIPS.  */
			while (event->proc->callstack_depth > 0) {
				struct callstack_element *prev;
				size_t d = event->proc->callstack_depth;
				prev = &event->proc->callstack[d - 1];

				if (prev->c_un.libfunc == libsym
				    || prev->return_addr != brk_addr)
					break;

				arch_symbol_ret(event->proc,
						prev->c_un.libfunc);
				output_right_tos(event->proc);
				callstack_pop(event->proc);
			}

			/* Maybe the previous callstack_pop's got rid
			 * of the breakpoint, but if we are in a
			 * recursive call, it's still enabled.  In
			 * that case we need to skip it properly.  */
			if ((sbp = address2bpstruct(leader, brk_addr)) != NULL) {
				continue_after_breakpoint(event->proc, sbp);
			} else {
				set_instruction_pointer(event->proc, brk_addr);
				continue_process(event->proc->pid);
			}
			return;
		}
	}

	if ((sbp = address2bpstruct(leader, brk_addr)) != NULL)
		breakpoint_on_hit(sbp, event->proc);
	else if (event->proc->state != STATE_IGNORED)
		output_line(event->proc,
			    "unexpected breakpoint at %p", brk_addr);

	/* breakpoint_on_hit may delete its own breakpoint, so we have
	 * to look it up again.  */
	if ((sbp = address2bpstruct(leader, brk_addr)) != NULL) {
		if (event->proc->state != STATE_IGNORED
		    && sbp->libsym != NULL) {
			event->proc->stack_pointer = get_stack_pointer(event->proc);
			event->proc->return_addr =
				get_return_addr(event->proc, event->proc->stack_pointer);
			callstack_push_symfunc(event->proc, sbp->libsym);
			output_left(LT_TOF_FUNCTION, event->proc, sbp->libsym);
		}

		breakpoint_on_continue(sbp, event->proc);
		return;
	} else {
		set_instruction_pointer(event->proc, brk_addr);
	}

	continue_process(event->proc->pid);
}

static void
callstack_push_syscall(Process *proc, int sysnum) {
	struct callstack_element *elem;

	debug(DEBUG_FUNCTION, "callstack_push_syscall(pid=%d, sysnum=%d)", proc->pid, sysnum);
	/* FIXME: not good -- should use dynamic allocation. 19990703 mortene. */
	if (proc->callstack_depth == MAX_CALLDEPTH - 1) {
		fprintf(stderr, "%s: Error: call nesting too deep!\n", __func__);
		abort();
		return;
	}

	elem = &proc->callstack[proc->callstack_depth];
	*elem = (struct callstack_element){};
	elem->is_syscall = 1;
	elem->c_un.syscall = sysnum;
	elem->return_addr = NULL;

	proc->callstack_depth++;
	if (opt_T || options.summary) {
		struct timezone tz;
		gettimeofday(&elem->time_spent, &tz);
	}
}

static void
callstack_push_symfunc(Process *proc, struct library_symbol *sym) {
	struct callstack_element *elem;

	debug(DEBUG_FUNCTION, "callstack_push_symfunc(pid=%d, symbol=%s)", proc->pid, sym->name);
	/* FIXME: not good -- should use dynamic allocation. 19990703 mortene. */
	if (proc->callstack_depth == MAX_CALLDEPTH - 1) {
		fprintf(stderr, "%s: Error: call nesting too deep!\n", __func__);
		abort();
		return;
	}

	elem = &proc->callstack[proc->callstack_depth++];
	*elem = (struct callstack_element){};
	elem->is_syscall = 0;
	elem->c_un.libfunc = sym;

	elem->return_addr = proc->return_addr;
	if (elem->return_addr)
		insert_breakpoint(proc, elem->return_addr, NULL);

	if (opt_T || options.summary) {
		struct timezone tz;
		gettimeofday(&elem->time_spent, &tz);
	}
}

void
callstack_pop(struct Process *proc)
{
	struct callstack_element *elem;
	assert(proc->callstack_depth > 0);

	debug(DEBUG_FUNCTION, "callstack_pop(pid=%d)", proc->pid);
	elem = &proc->callstack[proc->callstack_depth - 1];
	if (!elem->is_syscall && elem->return_addr)
		delete_breakpoint(proc, elem->return_addr);

	if (elem->fetch_context != NULL)
		fetch_arg_done(elem->fetch_context);

	if (elem->arguments != NULL) {
		val_dict_destroy(elem->arguments);
		free(elem->arguments);
	}

	proc->callstack_depth--;
}
