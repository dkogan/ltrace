/*
 * This file is part of ltrace.
 * Copyright (C) 2007,2011,2012 Petr Machata, Red Hat Inc.
 * Copyright (C) 2010 Joe Damato
 * Copyright (C) 1998,2002,2003,2004,2008,2009 Juan Cespedes
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

#include <asm/unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef HAVE_LIBSELINUX
# include <selinux/selinux.h>
#endif

#include "linux-gnu/trace.h"
#include "linux-gnu/trace-defs.h"
#include "backend.h"
#include "breakpoint.h"
#include "debug.h"
#include "events.h"
#include "options.h"
#include "proc.h"
#include "ptrace.h"
#include "type.h"

void
trace_fail_warning(pid_t pid)
{
	/* This was adapted from GDB.  */
#ifdef HAVE_LIBSELINUX
	static int checked = 0;
	if (checked)
		return;
	checked = 1;

	/* -1 is returned for errors, 0 if it has no effect, 1 if
	 * PTRACE_ATTACH is forbidden.  */
	if (security_get_boolean_active("deny_ptrace") == 1)
		fprintf(stderr,
"The SELinux boolean 'deny_ptrace' is enabled, which may prevent ltrace from\n"
"tracing other processes.  You can disable this process attach protection by\n"
"issuing 'setsebool deny_ptrace=0' in the superuser context.\n");
#endif /* HAVE_LIBSELINUX */
}

void
trace_me(void)
{
	debug(DEBUG_PROCESS, "trace_me: pid=%d", getpid());
	if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) {
		perror("PTRACE_TRACEME");
		trace_fail_warning(getpid());
		exit(1);
	}
}

/* There's a (hopefully) brief period of time after the child process
 * forks when we can't trace it yet.  Here we wait for kernel to
 * prepare the process.  */
int
wait_for_proc(pid_t pid)
{
	/* man ptrace: PTRACE_ATTACH attaches to the process specified
	   in pid.  The child is sent a SIGSTOP, but will not
	   necessarily have stopped by the completion of this call;
	   use wait() to wait for the child to stop. */
	if (waitpid(pid, NULL, __WALL) != pid) {
		perror ("trace_pid: waitpid");
		return -1;
	}

	return 0;
}

int
trace_pid(pid_t pid)
{
	debug(DEBUG_PROCESS, "trace_pid: pid=%d", pid);
	/* This shouldn't emit error messages, as there are legitimate
	 * reasons that the PID can't be attached: like it may have
	 * already ended.  */
	if (ptrace(PTRACE_ATTACH, pid, 0, 0) < 0)
		return -1;

	return wait_for_proc(pid);
}

void
trace_set_options(struct Process *proc)
{
	if (proc->tracesysgood & 0x80)
		return;

	pid_t pid = proc->pid;
	debug(DEBUG_PROCESS, "trace_set_options: pid=%d", pid);

	long options = PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEFORK |
		PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE |
		PTRACE_O_TRACEEXEC;
	if (ptrace(PTRACE_SETOPTIONS, pid, 0, (void *)options) < 0 &&
	    ptrace(PTRACE_OLDSETOPTIONS, pid, 0, (void *)options) < 0) {
		perror("PTRACE_SETOPTIONS");
		return;
	}
	proc->tracesysgood |= 0x80;
}

void
untrace_pid(pid_t pid) {
	debug(DEBUG_PROCESS, "untrace_pid: pid=%d", pid);
	ptrace(PTRACE_DETACH, pid, 0, 0);
}

void
continue_after_signal(pid_t pid, int signum)
{
	debug(DEBUG_PROCESS, "continue_after_signal: pid=%d, signum=%d",
	      pid, signum);
	ptrace(PTRACE_SYSCALL, pid, 0, (void *)(uintptr_t)signum);
}

static enum ecb_status
event_for_pid(Event *event, void *data)
{
	if (event->proc != NULL && event->proc->pid == (pid_t)(uintptr_t)data)
		return ecb_yield;
	return ecb_cont;
}

static int
have_events_for(pid_t pid)
{
	return each_qd_event(event_for_pid, (void *)(uintptr_t)pid) != NULL;
}

void
continue_process(pid_t pid)
{
	debug(DEBUG_PROCESS, "continue_process: pid=%d", pid);

	/* Only really continue the process if there are no events in
	   the queue for this process.  Otherwise just wait for the
	   other events to arrive.  */
	if (!have_events_for(pid))
		/* We always trace syscalls to control fork(),
		 * clone(), execve()... */
		ptrace(PTRACE_SYSCALL, pid, 0, 0);
	else
		debug(DEBUG_PROCESS,
		      "putting off the continue, events in que.");
}

static struct pid_task *
get_task_info(struct pid_set *pids, pid_t pid)
{
	assert(pid != 0);
	size_t i;
	for (i = 0; i < pids->count; ++i)
		if (pids->tasks[i].pid == pid)
			return &pids->tasks[i];

	return NULL;
}

static struct pid_task *
add_task_info(struct pid_set *pids, pid_t pid)
{
	if (pids->count == pids->alloc) {
		size_t ns = (2 * pids->alloc) ?: 4;
		struct pid_task *n = realloc(pids->tasks,
					     sizeof(*pids->tasks) * ns);
		if (n == NULL)
			return NULL;
		pids->tasks = n;
		pids->alloc = ns;
	}
	struct pid_task * task_info = &pids->tasks[pids->count++];
	memset(task_info, 0, sizeof(*task_info));
	task_info->pid = pid;
	return task_info;
}

static enum callback_status
task_stopped(struct Process *task, void *data)
{
	enum process_status st = process_status(task->pid);
	if (data != NULL)
		*(enum process_status *)data = st;

	/* If the task is already stopped, don't worry about it.
	 * Likewise if it managed to become a zombie or terminate in
	 * the meantime.  This can happen when the whole thread group
	 * is terminating.  */
	switch (st) {
	case ps_invalid:
	case ps_tracing_stop:
	case ps_zombie:
		return CBS_CONT;
	case ps_sleeping:
	case ps_stop:
	case ps_other:
		return CBS_STOP;
	}

	abort ();
}

/* Task is blocked if it's stopped, or if it's a vfork parent.  */
static enum callback_status
task_blocked(struct Process *task, void *data)
{
	struct pid_set *pids = data;
	struct pid_task *task_info = get_task_info(pids, task->pid);
	if (task_info != NULL
	    && task_info->vforked)
		return CBS_CONT;

	return task_stopped(task, NULL);
}

static Event *process_vfork_on_event(struct event_handler *super, Event *event);

static enum callback_status
task_vforked(struct Process *task, void *data)
{
	if (task->event_handler != NULL
	    && task->event_handler->on_event == &process_vfork_on_event)
		return CBS_STOP;
	return CBS_CONT;
}

static int
is_vfork_parent(struct Process *task)
{
	return each_task(task->leader, NULL, &task_vforked, NULL) != NULL;
}

static enum callback_status
send_sigstop(struct Process *task, void *data)
{
	struct Process *leader = task->leader;
	struct pid_set *pids = data;

	/* Look for pre-existing task record, or add new.  */
	struct pid_task *task_info = get_task_info(pids, task->pid);
	if (task_info == NULL)
		task_info = add_task_info(pids, task->pid);
	if (task_info == NULL) {
		perror("send_sigstop: add_task_info");
		destroy_event_handler(leader);
		/* Signal failure upwards.  */
		return CBS_STOP;
	}

	/* This task still has not been attached to.  It should be
	   stopped by the kernel.  */
	if (task->state == STATE_BEING_CREATED)
		return CBS_CONT;

	/* Don't bother sending SIGSTOP if we are already stopped, or
	 * if we sent the SIGSTOP already, which happens when we are
	 * handling "onexit" and inherited the handler from breakpoint
	 * re-enablement.  */
	enum process_status st;
	if (task_stopped(task, &st) == CBS_CONT)
		return CBS_CONT;
	if (task_info->sigstopped) {
		if (!task_info->delivered)
			return CBS_CONT;
		task_info->delivered = 0;
	}

	/* Also don't attempt to stop the process if it's a parent of
	 * vforked process.  We set up event handler specially to hint
	 * us.  In that case parent is in D state, which we use to
	 * weed out unnecessary looping.  */
	if (st == ps_sleeping
	    && is_vfork_parent (task)) {
		task_info->vforked = 1;
		return CBS_CONT;
	}

	if (task_kill(task->pid, SIGSTOP) >= 0) {
		debug(DEBUG_PROCESS, "send SIGSTOP to %d", task->pid);
		task_info->sigstopped = 1;
	} else
		fprintf(stderr,
			"Warning: couldn't send SIGSTOP to %d\n", task->pid);

	return CBS_CONT;
}

/* On certain kernels, detaching right after a singlestep causes the
   tracee to be killed with a SIGTRAP (that even though the singlestep
   was properly caught by waitpid.  The ugly workaround is to put a
   breakpoint where IP points and let the process continue.  After
   this the breakpoint can be retracted and the process detached.  */
static void
ugly_workaround(struct Process *proc)
{
	void *ip = get_instruction_pointer(proc);
	struct breakpoint *sbp = dict_find_entry(proc->leader->breakpoints, ip);
	if (sbp != NULL)
		enable_breakpoint(proc, sbp);
	else
		insert_breakpoint(proc, ip, NULL);
	ptrace(PTRACE_CONT, proc->pid, 0, 0);
}

static void
process_stopping_done(struct process_stopping_handler *self,
		      struct Process *leader)
{
	debug(DEBUG_PROCESS, "process stopping done %d",
	      self->task_enabling_breakpoint->pid);

	if (!self->exiting) {
		size_t i;
		for (i = 0; i < self->pids.count; ++i)
			if (self->pids.tasks[i].pid != 0
			    && (self->pids.tasks[i].delivered
				|| self->pids.tasks[i].sysret))
				continue_process(self->pids.tasks[i].pid);
		continue_process(self->task_enabling_breakpoint->pid);
	}

	if (self->exiting) {
	ugly_workaround:
		self->state = psh_ugly_workaround;
		ugly_workaround(self->task_enabling_breakpoint);
	} else {
		switch ((self->ugly_workaround_p)(self)) {
		case CBS_FAIL:
			/* xxx handle me */
		case CBS_STOP:
			break;
		case CBS_CONT:
			goto ugly_workaround;
		}
		destroy_event_handler(leader);
	}
}

/* Before we detach, we need to make sure that task's IP is on the
 * edge of an instruction.  So for tasks that have a breakpoint event
 * in the queue, we adjust the instruction pointer, just like
 * continue_after_breakpoint does.  */
static enum ecb_status
undo_breakpoint(Event *event, void *data)
{
	if (event != NULL
	    && event->proc->leader == data
	    && event->type == EVENT_BREAKPOINT)
		set_instruction_pointer(event->proc, event->e_un.brk_addr);
	return ecb_cont;
}

static enum callback_status
untrace_task(struct Process *task, void *data)
{
	if (task != data)
		untrace_pid(task->pid);
	return CBS_CONT;
}

static enum callback_status
remove_task(struct Process *task, void *data)
{
	/* Don't untrace leader just yet.  */
	if (task != data)
		remove_process(task);
	return CBS_CONT;
}

static enum callback_status
retract_breakpoint_cb(struct Process *proc, struct breakpoint *bp, void *data)
{
	breakpoint_on_retract(bp, proc);
	return CBS_CONT;
}

static void
detach_process(struct Process *leader)
{
	each_qd_event(&undo_breakpoint, leader);
	disable_all_breakpoints(leader);
	proc_each_breakpoint(leader, NULL, retract_breakpoint_cb, NULL);

	/* Now untrace the process, if it was attached to by -p.  */
	struct opt_p_t *it;
	for (it = opt_p; it != NULL; it = it->next) {
		struct Process *proc = pid2proc(it->pid);
		if (proc == NULL)
			continue;
		if (proc->leader == leader) {
			each_task(leader, NULL, &untrace_task, NULL);
			break;
		}
	}
	each_task(leader, NULL, &remove_task, leader);
	destroy_event_handler(leader);
	remove_task(leader, NULL);
}

static void
handle_stopping_event(struct pid_task *task_info, Event **eventp)
{
	/* Mark all events, so that we know whom to SIGCONT later.  */
	if (task_info != NULL)
		task_info->got_event = 1;

	Event *event = *eventp;

	/* In every state, sink SIGSTOP events for tasks that it was
	 * sent to.  */
	if (task_info != NULL
	    && event->type == EVENT_SIGNAL
	    && event->e_un.signum == SIGSTOP) {
		debug(DEBUG_PROCESS, "SIGSTOP delivered to %d", task_info->pid);
		if (task_info->sigstopped
		    && !task_info->delivered) {
			task_info->delivered = 1;
			*eventp = NULL; // sink the event
		} else
			fprintf(stderr, "suspicious: %d got SIGSTOP, but "
				"sigstopped=%d and delivered=%d\n",
				task_info->pid, task_info->sigstopped,
				task_info->delivered);
	}
}

/* Some SIGSTOPs may have not been delivered to their respective tasks
 * yet.  They are still in the queue.  If we have seen an event for
 * that process, continue it, so that the SIGSTOP can be delivered and
 * caught by ltrace.  We don't mind that the process is after
 * breakpoint (and therefore potentially doesn't have aligned IP),
 * because the signal will be delivered without the process actually
 * starting.  */
static void
continue_for_sigstop_delivery(struct pid_set *pids)
{
	size_t i;
	for (i = 0; i < pids->count; ++i) {
		if (pids->tasks[i].pid != 0
		    && pids->tasks[i].sigstopped
		    && !pids->tasks[i].delivered
		    && pids->tasks[i].got_event) {
			debug(DEBUG_PROCESS, "continue %d for SIGSTOP delivery",
			      pids->tasks[i].pid);
			ptrace(PTRACE_SYSCALL, pids->tasks[i].pid, 0, 0);
		}
	}
}

static int
event_exit_p(Event *event)
{
	return event != NULL && (event->type == EVENT_EXIT
				 || event->type == EVENT_EXIT_SIGNAL);
}

static int
event_exit_or_none_p(Event *event)
{
	return event == NULL || event_exit_p(event)
		|| event->type == EVENT_NONE;
}

static int
await_sigstop_delivery(struct pid_set *pids, struct pid_task *task_info,
		       Event *event)
{
	/* If we still didn't get our SIGSTOP, continue the process
	 * and carry on.  */
	if (event != NULL && !event_exit_or_none_p(event)
	    && task_info != NULL && task_info->sigstopped) {
		debug(DEBUG_PROCESS, "continue %d for SIGSTOP delivery",
		      task_info->pid);
		/* We should get the signal the first thing
		 * after this, so it should be OK to continue
		 * even if we are over a breakpoint.  */
		ptrace(PTRACE_SYSCALL, task_info->pid, 0, 0);

	} else {
		/* If all SIGSTOPs were delivered, uninstall the
		 * handler and continue everyone.  */
		/* XXX I suspect that we should check tasks that are
		 * still around.  Is things are now, there should be a
		 * race between waiting for everyone to stop and one
		 * of the tasks exiting.  */
		int all_clear = 1;
		size_t i;
		for (i = 0; i < pids->count; ++i)
			if (pids->tasks[i].pid != 0
			    && pids->tasks[i].sigstopped
			    && !pids->tasks[i].delivered) {
				all_clear = 0;
				break;
			}
		return all_clear;
	}

	return 0;
}

static int
all_stops_accountable(struct pid_set *pids)
{
	size_t i;
	for (i = 0; i < pids->count; ++i)
		if (pids->tasks[i].pid != 0
		    && !pids->tasks[i].got_event
		    && !have_events_for(pids->tasks[i].pid))
			return 0;
	return 1;
}

/* The protocol is: 0 for success, negative for failure, positive if
 * default singlestep is to be used.  */
int arch_atomic_singlestep(struct Process *proc, struct breakpoint *sbp,
			   int (*add_cb)(void *addr, void *data),
			   void *add_cb_data);

#ifndef ARCH_HAVE_ATOMIC_SINGLESTEP
int
arch_atomic_singlestep(struct Process *proc, struct breakpoint *sbp,
		       int (*add_cb)(void *addr, void *data),
		       void *add_cb_data)
{
	return 1;
}
#endif

static Event *process_stopping_on_event(struct event_handler *super,
					Event *event);

static void
remove_atomic_breakpoints(struct Process *proc)
{
	struct process_stopping_handler *self
		= (void *)proc->leader->event_handler;
	assert(self != NULL);
	assert(self->super.on_event == process_stopping_on_event);

	int ct = sizeof(self->atomic_skip_bp_addrs)
		/ sizeof(*self->atomic_skip_bp_addrs);
	int i;
	for (i = 0; i < ct; ++i)
		if (self->atomic_skip_bp_addrs[i] != 0) {
			delete_breakpoint(proc, self->atomic_skip_bp_addrs[i]);
			self->atomic_skip_bp_addrs[i] = 0;
		}
}

static void
atomic_singlestep_bp_on_hit(struct breakpoint *bp, struct Process *proc)
{
	remove_atomic_breakpoints(proc);
}

static int
atomic_singlestep_add_bp(void *addr, void *data)
{
	struct process_stopping_handler *self = data;
	struct Process *proc = self->task_enabling_breakpoint;

	int ct = sizeof(self->atomic_skip_bp_addrs)
		/ sizeof(*self->atomic_skip_bp_addrs);
	int i;
	for (i = 0; i < ct; ++i)
		if (self->atomic_skip_bp_addrs[i] == 0) {
			self->atomic_skip_bp_addrs[i] = addr;
			static struct bp_callbacks cbs = {
				.on_hit = atomic_singlestep_bp_on_hit,
			};
			struct breakpoint *bp
				= insert_breakpoint(proc, addr, NULL);
			breakpoint_set_callbacks(bp, &cbs);
			return 0;
		}

	assert(!"Too many atomic singlestep breakpoints!");
	abort();
}

static int
singlestep(struct process_stopping_handler *self)
{
	struct Process *proc = self->task_enabling_breakpoint;

	int status = arch_atomic_singlestep(self->task_enabling_breakpoint,
					    self->breakpoint_being_enabled,
					    &atomic_singlestep_add_bp, self);

	/* Propagate failure and success.  */
	if (status <= 0)
		return status;

	/* Otherwise do the default action: singlestep.  */
	debug(1, "PTRACE_SINGLESTEP");
	if (ptrace(PTRACE_SINGLESTEP, proc->pid, 0, 0)) {
		perror("PTRACE_SINGLESTEP");
		return -1;
	}
	return 0;
}

static void
post_singlestep(struct process_stopping_handler *self,
		struct Event **eventp)
{
	continue_for_sigstop_delivery(&self->pids);

	if (*eventp != NULL && (*eventp)->type == EVENT_BREAKPOINT)
		*eventp = NULL; // handled

	struct Process *proc = self->task_enabling_breakpoint;

	remove_atomic_breakpoints(proc);
	self->breakpoint_being_enabled = NULL;
}

static void
singlestep_error(struct process_stopping_handler *self)
{
	struct Process *teb = self->task_enabling_breakpoint;
	struct breakpoint *sbp = self->breakpoint_being_enabled;
	fprintf(stderr, "%d couldn't continue when handling %s (%p) at %p\n",
		teb->pid, breakpoint_name(sbp),	sbp->addr,
		get_instruction_pointer(teb));
	delete_breakpoint(teb->leader, sbp->addr);
}

static void
pt_continue(struct process_stopping_handler *self)
{
	struct Process *teb = self->task_enabling_breakpoint;
	debug(1, "PTRACE_CONT");
	ptrace(PTRACE_CONT, teb->pid, 0, 0);
}

static void
pt_singlestep(struct process_stopping_handler *self)
{
	if (singlestep(self) < 0)
		singlestep_error(self);
}

static void
disable_and(struct process_stopping_handler *self,
	    void (*do_this)(struct process_stopping_handler *self))
{
	struct Process *teb = self->task_enabling_breakpoint;
	debug(DEBUG_PROCESS, "all stopped, now singlestep/cont %d", teb->pid);
	if (self->breakpoint_being_enabled->enabled)
		disable_breakpoint(teb, self->breakpoint_being_enabled);
	(do_this)(self);
	self->state = psh_singlestep;
}

void
linux_ptrace_disable_and_singlestep(struct process_stopping_handler *self)
{
	disable_and(self, &pt_singlestep);
}

void
linux_ptrace_disable_and_continue(struct process_stopping_handler *self)
{
	disable_and(self, &pt_continue);
}

/* This event handler is installed when we are in the process of
 * stopping the whole thread group to do the pointer re-enablement for
 * one of the threads.  We pump all events to the queue for later
 * processing while we wait for all the threads to stop.  When this
 * happens, we let the re-enablement thread to PTRACE_SINGLESTEP,
 * re-enable, and continue everyone.  */
static Event *
process_stopping_on_event(struct event_handler *super, Event *event)
{
	struct process_stopping_handler *self = (void *)super;
	struct Process *task = event->proc;
	struct Process *leader = task->leader;
	struct Process *teb = self->task_enabling_breakpoint;

	debug(DEBUG_PROCESS,
	      "process_stopping_on_event: pid %d; event type %d; state %d",
	      task->pid, event->type, self->state);

	struct pid_task *task_info = get_task_info(&self->pids, task->pid);
	if (task_info == NULL)
		fprintf(stderr, "new task??? %d\n", task->pid);
	handle_stopping_event(task_info, &event);

	int state = self->state;
	int event_to_queue = !event_exit_or_none_p(event);

	/* Deactivate the entry if the task exits.  */
	if (event_exit_p(event) && task_info != NULL)
		task_info->pid = 0;

	/* Always handle sysrets.  Whether sysret occurred and what
	 * sys it rets from may need to be determined based on process
	 * stack, so we need to keep that in sync with reality.  Note
	 * that we don't continue the process after the sysret is
	 * handled.  See continue_after_syscall.  */
	if (event != NULL && event->type == EVENT_SYSRET) {
		debug(1, "%d LT_EV_SYSRET", event->proc->pid);
		event_to_queue = 0;
		task_info->sysret = 1;
	}

	switch (state) {
	case psh_stopping:
		/* If everyone is stopped, singlestep.  */
		if (each_task(leader, NULL, &task_blocked,
			      &self->pids) == NULL) {
			(self->on_all_stopped)(self);
			state = self->state;
		}
		break;

	case psh_singlestep:
		/* In singlestep state, breakpoint signifies that we
		 * have now stepped, and can re-enable the breakpoint.  */
		if (event != NULL && task == teb) {

			/* If this was caused by a real breakpoint, as
			 * opposed to a singlestep, assume that it's
			 * an artificial breakpoint installed for some
			 * reason for the re-enablement.  In that case
			 * handle it.  */
			if (event->type == EVENT_BREAKPOINT) {
				arch_addr_t ip
					= get_instruction_pointer(task);
				struct breakpoint *other
					= address2bpstruct(leader, ip);
				if (other != NULL)
					breakpoint_on_hit(other, task);
			}

			/* If we got SIGNAL instead of BREAKPOINT,
			 * then this is not singlestep at all.  */
			if (event->type == EVENT_SIGNAL) {
			do_singlestep:
				if (singlestep(self) < 0) {
					singlestep_error(self);
					post_singlestep(self, &event);
					goto psh_sinking;
				}
				break;
			} else {
				switch ((self->keep_stepping_p)(self)) {
				case CBS_FAIL:
					/* XXX handle me */
				case CBS_STOP:
					break;
				case CBS_CONT:
					/* Sink singlestep event.  */
					if (event->type == EVENT_BREAKPOINT)
						event = NULL;
					goto do_singlestep;
				}
			}

			/* Re-enable the breakpoint that we are
			 * stepping over.  */
			struct breakpoint *sbp = self->breakpoint_being_enabled;
			if (sbp->enabled)
				enable_breakpoint(teb, sbp);

			post_singlestep(self, &event);
			goto psh_sinking;
		}
		break;

	psh_sinking:
		state = self->state = psh_sinking;
	case psh_sinking:
		if (await_sigstop_delivery(&self->pids, task_info, event))
			process_stopping_done(self, leader);
		break;

	case psh_ugly_workaround:
		if (event == NULL)
			break;
		if (event->type == EVENT_BREAKPOINT) {
			undo_breakpoint(event, leader);
			if (task == teb)
				self->task_enabling_breakpoint = NULL;
		}
		if (self->task_enabling_breakpoint == NULL
		    && all_stops_accountable(&self->pids)) {
			undo_breakpoint(event, leader);
			detach_process(leader);
			event = NULL; // handled
		}
	}

	if (event != NULL && event_to_queue) {
		enque_event(event);
		event = NULL; // sink the event
	}

	return event;
}

static void
process_stopping_destroy(struct event_handler *super)
{
	struct process_stopping_handler *self = (void *)super;
	free(self->pids.tasks);
}

static enum callback_status
no(struct process_stopping_handler *self)
{
	return CBS_STOP;
}

int
process_install_stopping_handler(struct Process *proc, struct breakpoint *sbp,
				 void (*as)(struct process_stopping_handler *),
				 enum callback_status (*ks)
					 (struct process_stopping_handler *),
				 enum callback_status (*uw)
					(struct process_stopping_handler *))
{
	debug(DEBUG_FUNCTION,
	      "process_install_stopping_handler: pid=%d", proc->pid);

	struct process_stopping_handler *handler = calloc(sizeof(*handler), 1);
	if (handler == NULL)
		return -1;

	if (as == NULL)
		as = &linux_ptrace_disable_and_singlestep;
	if (ks == NULL)
		ks = &no;
	if (uw == NULL)
		uw = &no;

	handler->super.on_event = process_stopping_on_event;
	handler->super.destroy = process_stopping_destroy;
	handler->task_enabling_breakpoint = proc;
	handler->breakpoint_being_enabled = sbp;
	handler->on_all_stopped = as;
	handler->keep_stepping_p = ks;
	handler->ugly_workaround_p = uw;

	install_event_handler(proc->leader, &handler->super);

	if (each_task(proc->leader, NULL, &send_sigstop,
		      &handler->pids) != NULL) {
		destroy_event_handler(proc);
		return -1;
	}

	/* And deliver the first fake event, in case all the
	 * conditions are already fulfilled.  */
	Event ev = {
		.type = EVENT_NONE,
		.proc = proc,
	};
	process_stopping_on_event(&handler->super, &ev);

	return 0;
}

void
continue_after_breakpoint(Process *proc, struct breakpoint *sbp)
{
	debug(DEBUG_PROCESS,
	      "continue_after_breakpoint: pid=%d, addr=%p",
	      proc->pid, sbp->addr);

	set_instruction_pointer(proc, sbp->addr);

	if (sbp->enabled == 0) {
		continue_process(proc->pid);
	} else {
#if defined __sparc__  || defined __ia64___
		/* we don't want to singlestep here */
		continue_process(proc->pid);
#else
		if (process_install_stopping_handler
		    (proc, sbp, NULL, NULL, NULL) < 0) {
			perror("process_stopping_handler_create");
			/* Carry on not bothering to re-enable.  */
			continue_process(proc->pid);
		}
#endif
	}
}

/**
 * Ltrace exit.  When we are about to exit, we have to go through all
 * the processes, stop them all, remove all the breakpoints, and then
 * detach the processes that we attached to using -p.  If we left the
 * other tasks running, they might hit stray return breakpoints and
 * produce artifacts, so we better stop everyone, even if it's a bit
 * of extra work.
 */
struct ltrace_exiting_handler
{
	struct event_handler super;
	struct pid_set pids;
};

static Event *
ltrace_exiting_on_event(struct event_handler *super, Event *event)
{
	struct ltrace_exiting_handler *self = (void *)super;
	struct Process *task = event->proc;
	struct Process *leader = task->leader;

	debug(DEBUG_PROCESS,
	      "ltrace_exiting_on_event: pid %d; event type %d",
	      task->pid, event->type);

	struct pid_task *task_info = get_task_info(&self->pids, task->pid);
	handle_stopping_event(task_info, &event);

	if (event != NULL && event->type == EVENT_BREAKPOINT)
		undo_breakpoint(event, leader);

	if (await_sigstop_delivery(&self->pids, task_info, event)
	    && all_stops_accountable(&self->pids))
		detach_process(leader);

	/* Sink all non-exit events.  We are about to exit, so we
	 * don't bother with queuing them. */
	if (event_exit_or_none_p(event))
		return event;

	return NULL;
}

static void
ltrace_exiting_destroy(struct event_handler *super)
{
	struct ltrace_exiting_handler *self = (void *)super;
	free(self->pids.tasks);
}

static int
ltrace_exiting_install_handler(struct Process *proc)
{
	/* Only install to leader.  */
	if (proc->leader != proc)
		return 0;

	/* Perhaps we are already installed, if the user passed
	 * several -p options that are tasks of one process.  */
	if (proc->event_handler != NULL
	    && proc->event_handler->on_event == &ltrace_exiting_on_event)
		return 0;

	/* If stopping handler is already present, let it do the
	 * work.  */
	if (proc->event_handler != NULL) {
		assert(proc->event_handler->on_event
		       == &process_stopping_on_event);
		struct process_stopping_handler *other
			= (void *)proc->event_handler;
		other->exiting = 1;
		return 0;
	}

	struct ltrace_exiting_handler *handler
		= calloc(sizeof(*handler), 1);
	if (handler == NULL) {
		perror("malloc exiting handler");
	fatal:
		/* XXXXXXXXXXXXXXXXXXX fixme */
		return -1;
	}

	handler->super.on_event = ltrace_exiting_on_event;
	handler->super.destroy = ltrace_exiting_destroy;
	install_event_handler(proc->leader, &handler->super);

	if (each_task(proc->leader, NULL, &send_sigstop,
		      &handler->pids) != NULL)
		goto fatal;

	return 0;
}

/*
 * When the traced process vforks, it's suspended until the child
 * process calls _exit or exec*.  In the meantime, the two share the
 * address space.
 *
 * The child process should only ever call _exit or exec*, but we
 * can't count on that (it's not the role of ltrace to policy, but to
 * observe).  In any case, we will _at least_ have to deal with
 * removal of vfork return breakpoint (which we have to smuggle back
 * in, so that the parent can see it, too), and introduction of exec*
 * return breakpoint.  Since we already have both breakpoint actions
 * to deal with, we might as well support it all.
 *
 * The gist is that we pretend that the child is in a thread group
 * with its parent, and handle it as a multi-threaded case, with the
 * exception that we know that the parent is blocked, and don't
 * attempt to stop it.  When the child execs, we undo the setup.
 */

struct process_vfork_handler
{
	struct event_handler super;
	void *bp_addr;
};

static Event *
process_vfork_on_event(struct event_handler *super, Event *event)
{
	debug(DEBUG_PROCESS,
	      "process_vfork_on_event: pid %d; event type %d",
	      event->proc->pid, event->type);

	struct process_vfork_handler *self = (void *)super;
	struct breakpoint *sbp;
	assert(self != NULL);

	switch (event->type) {
	case EVENT_BREAKPOINT:
		/* Remember the vfork return breakpoint.  */
		if (self->bp_addr == 0)
			self->bp_addr = event->e_un.brk_addr;
		break;

	case EVENT_EXIT:
	case EVENT_EXIT_SIGNAL:
	case EVENT_EXEC:
		/* Smuggle back in the vfork return breakpoint, so
		 * that our parent can trip over it once again.  */
		if (self->bp_addr != 0) {
			sbp = dict_find_entry(event->proc->leader->breakpoints,
					      self->bp_addr);
			if (sbp != NULL)
				assert(sbp->libsym == NULL);
			/* We don't mind failing that, it's not a big
			 * deal to not display one extra vfork return.  */
			insert_breakpoint(event->proc->parent,
					  self->bp_addr, NULL);
		}

		continue_process(event->proc->parent->pid);

		/* Remove the leader that we artificially set up
		 * earlier.  */
		change_process_leader(event->proc, event->proc);
		destroy_event_handler(event->proc);

	default:
		;
	}

	return event;
}

void
continue_after_vfork(struct Process *proc)
{
	debug(DEBUG_PROCESS, "continue_after_vfork: pid=%d", proc->pid);
	struct process_vfork_handler *handler = calloc(sizeof(*handler), 1);
	if (handler == NULL) {
		perror("malloc vfork handler");
		/* Carry on not bothering to treat the process as
		 * necessary.  */
		continue_process(proc->parent->pid);
		return;
	}

	/* We must set up custom event handler, so that we see
	 * exec/exit events for the task itself.  */
	handler->super.on_event = process_vfork_on_event;
	install_event_handler(proc, &handler->super);

	/* Make sure that the child is sole thread.  */
	assert(proc->leader == proc);
	assert(proc->next == NULL || proc->next->leader != proc);

	/* Make sure that the child's parent is properly set up.  */
	assert(proc->parent != NULL);
	assert(proc->parent->leader != NULL);

	change_process_leader(proc, proc->parent->leader);
}

static int
is_mid_stopping(Process *proc)
{
	return proc != NULL
		&& proc->event_handler != NULL
		&& proc->event_handler->on_event == &process_stopping_on_event;
}

void
continue_after_syscall(struct Process *proc, int sysnum, int ret_p)
{
	/* Don't continue if we are mid-stopping.  */
	if (ret_p && (is_mid_stopping(proc) || is_mid_stopping(proc->leader))) {
		debug(DEBUG_PROCESS,
		      "continue_after_syscall: don't continue %d",
		      proc->pid);
		return;
	}
	continue_process(proc->pid);
}

/* If ltrace gets SIGINT, the processes directly or indirectly run by
 * ltrace get it too.  We just have to wait long enough for the signal
 * to be delivered and the process terminated, which we notice and
 * exit ltrace, too.  So there's not much we need to do there.  We
 * want to keep tracing those processes as usual, in case they just
 * SIG_IGN the SIGINT to do their shutdown etc.
 *
 * For processes ran on the background, we want to install an exit
 * handler that stops all the threads, removes all breakpoints, and
 * detaches.
 */
void
os_ltrace_exiting(void)
{
	struct opt_p_t *it;
	for (it = opt_p; it != NULL; it = it->next) {
		struct Process *proc = pid2proc(it->pid);
		if (proc == NULL || proc->leader == NULL)
			continue;
		if (ltrace_exiting_install_handler(proc->leader) < 0)
			fprintf(stderr,
				"Couldn't install exiting handler for %d.\n",
				proc->pid);
	}
}

int
os_ltrace_exiting_sighandler(void)
{
	extern int linux_in_waitpid;
	if (linux_in_waitpid) {
		os_ltrace_exiting();
		return 1;
	}
	return 0;
}

size_t
umovebytes(Process *proc, void *addr, void *laddr, size_t len) {

	union {
		long a;
		char c[sizeof(long)];
	} a;
	int started = 0;
	size_t offset = 0, bytes_read = 0;

	while (offset < len) {
		a.a = ptrace(PTRACE_PEEKTEXT, proc->pid, addr + offset, 0);
		if (a.a == -1 && errno) {
			if (started && errno == EIO)
				return bytes_read;
			else
				return -1;
		}
		started = 1;

		if (len - offset >= sizeof(long)) {
			memcpy(laddr + offset, &a.c[0], sizeof(long));
			bytes_read += sizeof(long);
		}
		else {
			memcpy(laddr + offset, &a.c[0], len - offset);
			bytes_read += (len - offset);
		}
		offset += sizeof(long);
	}

	return bytes_read;
}
