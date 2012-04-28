/*
 * This file is part of ltrace.
 * Copyright (C) 2011,2012 Petr Machata, Red Hat Inc.
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

#ifndef _LTRACE_LINUX_TRACE_H_
#define _LTRACE_LINUX_TRACE_H_

#include "proc.h"

/* This publishes some Linux-specific data structures used for process
 * handling.  */

/**
 * This is used for bookkeeping related to PIDs that the event
 * handlers work with.
 */
struct pid_task {
	pid_t pid;	/* This may be 0 for tasks that exited
			 * mid-handling.  */
	int sigstopped : 1;
	int got_event : 1;
	int delivered : 1;
	int vforked : 1;
	int sysret : 1;
};

struct pid_set {
	struct pid_task *tasks;
	size_t count;
	size_t alloc;
};

/**
 * Breakpoint re-enablement.  When we hit a breakpoint, we must
 * disable it, single-step, and re-enable it.  That single-step can be
 * done only by one task in a task group, while others are stopped,
 * otherwise the processes would race for who sees the breakpoint
 * disabled and who doesn't.  The following is to keep track of it
 * all.
 */
struct process_stopping_handler
{
	struct event_handler super;

	/* The task that is doing the re-enablement.  */
	struct Process *task_enabling_breakpoint;

	/* The pointer being re-enabled.  */
	struct breakpoint *breakpoint_being_enabled;

	/* Artificial atomic skip breakpoint, if any needed.  */
	void *atomic_skip_bp_addrs[2];

	/* When all tasks are stopped, this callback gets called.  */
	void (*on_all_stopped)(struct process_stopping_handler *);

	/* When we get a singlestep event, this is called to decide
	 * whether to stop stepping, or whether to enable the
	 * brakpoint, sink remaining signals, and continue
	 * everyone.  */
	enum callback_status (*keep_stepping_p)
		(struct process_stopping_handler *);

	/* Whether we need to use ugly workaround to get around
	 * various problems with singlestepping.  */
	enum callback_status (*ugly_workaround_p)
		(struct process_stopping_handler *);

	enum {
		/* We are waiting for everyone to land in t/T.  */
		psh_stopping = 0,

		/* We are doing the PTRACE_SINGLESTEP.  */
		psh_singlestep,

		/* We are waiting for all the SIGSTOPs to arrive so
		 * that we can sink them.  */
		psh_sinking,

		/* This is for tracking the ugly workaround.  */
		psh_ugly_workaround,
	} state;

	int exiting;

	struct pid_set pids;
};

/* Allocate a process stopping handler, initialize it and install it.
 * Return 0 on success or a negative value on failure.  Pass NULL for
 * each callback to use a default instead.  The default for
 * ON_ALL_STOPPED is LINUX_PTRACE_DISABLE_AND_SINGLESTEP, the default
 * for KEEP_STEPPING_P and UGLY_WORKAROUND_P is "no".  */
int process_install_stopping_handler
	(struct Process *proc, struct breakpoint *sbp,
	 void (*on_all_stopped)(struct process_stopping_handler *),
	 enum callback_status (*keep_stepping_p)
		 (struct process_stopping_handler *),
	 enum callback_status (*ugly_workaround_p)
		(struct process_stopping_handler *));

void linux_ptrace_disable_and_singlestep(struct process_stopping_handler *self);
void linux_ptrace_disable_and_continue(struct process_stopping_handler *self);

#endif /* _LTRACE_LINUX_TRACE_H_ */
