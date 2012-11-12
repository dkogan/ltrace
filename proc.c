/*
 * This file is part of ltrace.
 * Copyright (C) 2011,2012 Petr Machata, Red Hat Inc.
 * Copyright (C) 2010 Joe Damato
 * Copyright (C) 1998,2009 Juan Cespedes
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
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(HAVE_LIBUNWIND)
#include <libunwind.h>
#include <libunwind-ptrace.h>
#endif /* defined(HAVE_LIBUNWIND) */

#include "backend.h"
#include "breakpoint.h"
#include "debug.h"
#include "fetch.h"
#include "proc.h"
#include "value_dict.h"

#ifndef ARCH_HAVE_PROCESS_DATA
int
arch_process_init(struct Process *proc)
{
	return 0;
}

void
arch_process_destroy(struct Process *proc)
{
}

int
arch_process_clone(struct Process *retp, struct Process *proc)
{
	return 0;
}

int
arch_process_exec(struct Process *proc)
{
	return 0;
}
#endif

#ifndef OS_HAVE_PROCESS_DATA
int
os_process_init(struct Process *proc)
{
	return 0;
}

void
os_process_destroy(struct Process *proc)
{
}

int
os_process_clone(struct Process *retp, struct Process *proc)
{
	return 0;
}

int
os_process_exec(struct Process *proc)
{
	return 0;
}
#endif

#ifndef ARCH_HAVE_DYNLINK_DONE
void
arch_dynlink_done(struct Process *proc)
{
}
#endif

static void add_process(struct Process *proc, int was_exec);
static void unlist_process(struct Process *proc);

static void
destroy_unwind(struct Process *proc)
{
#if defined(HAVE_LIBUNWIND)
	_UPT_destroy(proc->unwind_priv);
	unw_destroy_addr_space(proc->unwind_as);
#endif /* defined(HAVE_LIBUNWIND) */
}

static int
process_bare_init(struct Process *proc, const char *filename,
		  pid_t pid, int was_exec)
{
	if (!was_exec) {
		memset(proc, 0, sizeof(*proc));

		proc->filename = strdup(filename);
		if (proc->filename == NULL) {
		fail:
			free(proc->filename);
			if (proc->breakpoints != NULL)
				dict_clear(proc->breakpoints);
			return -1;
		}
	}

	/* Add process so that we know who the leader is.  */
	proc->pid = pid;
	add_process(proc, was_exec);
	if (proc->leader == NULL)
		goto fail;

	if (proc->leader == proc) {
		proc->breakpoints = dict_init(target_address_hash,
					      target_address_cmp);
		if (proc->breakpoints == NULL)
			goto fail;
	} else {
		proc->breakpoints = NULL;
	}

#if defined(HAVE_LIBUNWIND)
	proc->unwind_priv = _UPT_create(pid);
	proc->unwind_as = unw_create_addr_space(&_UPT_accessors, 0);
#endif /* defined(HAVE_LIBUNWIND) */

	return 0;
}

static void
process_bare_destroy(struct Process *proc, int was_exec)
{
	dict_clear(proc->breakpoints);
	if (!was_exec) {
		free(proc->filename);
		unlist_process(proc);
		destroy_unwind(proc);
	}
}

static int
process_init_main(struct Process *proc)
{
	if (breakpoints_init(proc) < 0) {
		fprintf(stderr, "failed to init breakpoints %d\n",
			proc->pid);
		return -1;
	}

	return 0;
}

int
process_init(struct Process *proc, const char *filename, pid_t pid)
{
	if (process_bare_init(proc, filename, pid, 0) < 0) {
	fail:
		fprintf(stderr, "failed to initialize process %d: %s\n",
			pid, strerror(errno));
		return -1;
	}

	if (os_process_init(proc) < 0) {
		process_bare_destroy(proc, 0);
		goto fail;
	}

	if (arch_process_init(proc) < 0) {
		os_process_destroy(proc);
		process_bare_destroy(proc, 0);
		goto fail;
	}

	if (proc->leader != proc)
		return 0;
	if (process_init_main(proc) < 0) {
		process_bare_destroy(proc, 0);
		goto fail;
	}
	return 0;
}

static enum callback_status
destroy_breakpoint_cb(struct Process *proc, struct breakpoint *bp, void *data)
{
	breakpoint_destroy(bp);
	free(bp);
	return CBS_CONT;
}

// XXX see comment in handle_event.c
void callstack_pop(struct Process *proc);

static void
private_process_destroy(struct Process *proc, int was_exec)
{
	/* Pop remaining stack elements.  */
	while (proc->callstack_depth > 0) {
		/* When this is called just before a process is
		 * destroyed, the breakpoints should either have been
		 * retracted by now, or were killed by exec.  In any
		 * case, it's safe to pretend that there are no
		 * breakpoints associated with the stack elements, so
		 * that stack_pop doesn't attempt to destroy them.  */
		size_t i = proc->callstack_depth - 1;
		if (!proc->callstack[i].is_syscall)
			proc->callstack[i].return_addr = 0;

		callstack_pop(proc);
	}

	if (!was_exec)
		free(proc->filename);

	/* Libraries and symbols.  This is only relevant in
	 * leader.  */
	struct library *lib;
	for (lib = proc->libraries; lib != NULL; ) {
		struct library *next = lib->next;
		library_destroy(lib);
		free(lib);
		lib = next;
	}
	proc->libraries = NULL;

	/* Breakpoints.  */
	if (proc->breakpoints != NULL) {
		proc_each_breakpoint(proc, NULL, destroy_breakpoint_cb, NULL);
		dict_clear(proc->breakpoints);
		proc->breakpoints = NULL;
	}

	destroy_unwind(proc);
}

void
process_destroy(struct Process *proc)
{
	arch_process_destroy(proc);
	os_process_destroy(proc);
	private_process_destroy(proc, 0);
}

int
process_exec(struct Process *proc)
{
	/* Call exec handlers first, before we destroy the main
	 * state.  */
	if (arch_process_exec(proc) < 0
	    || os_process_exec(proc) < 0)
		return -1;

	private_process_destroy(proc, 1);

	if (process_bare_init(proc, NULL, proc->pid, 1) < 0)
		return -1;
	if (process_init_main(proc) < 0) {
		process_bare_destroy(proc, 1);
		return -1;
	}
	return 0;
}

struct Process *
open_program(const char *filename, pid_t pid)
{
	assert(pid != 0);
	struct Process *proc = malloc(sizeof(*proc));
	if (proc == NULL || process_init(proc, filename, pid) < 0) {
		free(proc);
		return NULL;
	}
	return proc;
}

struct clone_single_bp_data {
	struct Process *old_proc;
	struct Process *new_proc;
	int error;
};

static void
clone_single_bp(void *key, void *value, void *u)
{
	struct breakpoint *bp = value;
	struct clone_single_bp_data *data = u;

	/* Don't bother if there were errors anyway.  */
	if (data->error != 0)
		return;

	struct breakpoint *clone = malloc(sizeof(*clone));
	if (clone == NULL
	    || breakpoint_clone(clone, data->new_proc,
				bp, data->old_proc) < 0) {
	fail:
		free(clone);
		data->error = -1;
	}
	if (proc_add_breakpoint(data->new_proc->leader, clone) < 0) {
		breakpoint_destroy(clone);
		goto fail;
	}
}

int
process_clone(struct Process *retp, struct Process *proc, pid_t pid)
{
	if (process_bare_init(retp, proc->filename, pid, 0) < 0) {
	fail1:
		fprintf(stderr, "failed to clone process %d->%d : %s\n",
			proc->pid, pid, strerror(errno));
		return -1;
	}

	retp->tracesysgood = proc->tracesysgood;
	retp->e_machine = proc->e_machine;
	retp->e_class = proc->e_class;

	/* For non-leader processes, that's all we need to do.  */
	if (retp->leader != retp)
		return 0;

	/* Clone symbols first so that we can clone and relink
	 * breakpoints.  */
	struct library *lib;
	struct library **nlibp = &retp->libraries;
	for (lib = proc->leader->libraries; lib != NULL; lib = lib->next) {
		*nlibp = malloc(sizeof(**nlibp));
		if (*nlibp == NULL
		    || library_clone(*nlibp, lib) < 0) {
		fail2:
			process_bare_destroy(retp, 0);

			/* Error when cloning.  Unroll what was done.  */
			for (lib = retp->libraries; lib != NULL; ) {
				struct library *next = lib->next;
				library_destroy(lib);
				free(lib);
				lib = next;
			}
			goto fail1;
		}

		nlibp = &(*nlibp)->next;
	}

	/* Now clone breakpoints.  Symbol relinking is done in
	 * clone_single_bp.  */
	struct clone_single_bp_data data = {
		.old_proc = proc,
		.new_proc = retp,
		.error = 0,
	};
	dict_apply_to_all(proc->leader->breakpoints, &clone_single_bp, &data);
	if (data.error < 0)
		goto fail2;

	/* And finally the call stack.  */
	/* XXX clearly the callstack handling should be moved to a
	 * separate module and this whole business extracted to
	 * callstack_clone, or callstack_element_clone.  */
	memcpy(retp->callstack, proc->callstack, sizeof(retp->callstack));
	retp->callstack_depth = proc->callstack_depth;

	size_t i;
	for (i = 0; i < retp->callstack_depth; ++i) {
		struct callstack_element *elem = &retp->callstack[i];
		struct fetch_context *ctx = elem->fetch_context;
		if (ctx != NULL) {
			struct fetch_context *nctx = fetch_arg_clone(retp, ctx);
			if (nctx == NULL) {
				size_t j;
			fail3:
				for (j = 0; j < i; ++j) {
					nctx = elem->fetch_context;
					fetch_arg_done(nctx);
					elem->fetch_context = NULL;
				}
				goto fail2;
			}
			elem->fetch_context = nctx;
		}

		struct value_dict *args = elem->arguments;
		if (args != NULL) {
			struct value_dict *nargs = malloc(sizeof(*nargs));
			if (nargs == NULL
			    || val_dict_clone(nargs, args) < 0) {
				size_t j;
				for (j = 0; j < i; ++j) {
					nargs = elem->arguments;
					val_dict_destroy(nargs);
					free(nargs);
					elem->arguments = NULL;
				}

				/* Pretend that this round went well,
				 * so that fail3 frees I-th
				 * fetch_context.  */
				++i;
				goto fail3;
			}
			elem->arguments = nargs;
		}

		/* If it's not a syscall, we need to find the
		 * corresponding library symbol in the cloned
		 * library.  */
		if (!elem->is_syscall && elem->c_un.libfunc != NULL) {
			struct library_symbol *libfunc = elem->c_un.libfunc;
			int rc = proc_find_symbol(retp, libfunc,
						  NULL, &elem->c_un.libfunc);
			assert(rc == 0);
		}
	}

	/* At this point, retp is fully initialized, except for OS and
	 * arch parts, and we can call private_process_destroy.  */
	if (os_process_clone(retp, proc) < 0) {
		private_process_destroy(retp, 0);
		return -1;
	}
	if (arch_process_clone(retp, proc) < 0) {
		os_process_destroy(retp);
		private_process_destroy(retp, 0);
		return -1;
	}

	return 0;
}

static int
open_one_pid(pid_t pid)
{
	Process *proc;
	char *filename;
	debug(DEBUG_PROCESS, "open_one_pid(pid=%d)", pid);

	/* Get the filename first.  Should the trace_pid fail, we can
	 * easily free it, untracing is more work.  */
	if ((filename = pid2name(pid)) == NULL
	    || trace_pid(pid) < 0) {
	fail:
		free(filename);
		return -1;
	}

	proc = open_program(filename, pid);
	if (proc == NULL)
		goto fail;
	free(filename);
	trace_set_options(proc);

	return 0;
}

static enum callback_status
start_one_pid(Process * proc, void * data)
{
	continue_process(proc->pid);
	return CBS_CONT;
}

void
open_pid(pid_t pid)
{
	debug(DEBUG_PROCESS, "open_pid(pid=%d)", pid);
	/* If we are already tracing this guy, we should be seeing all
	 * his children via normal tracing route.  */
	if (pid2proc(pid) != NULL)
		return;

	/* First, see if we can attach the requested PID itself.  */
	if (open_one_pid(pid)) {
		fprintf(stderr, "Cannot attach to pid %u: %s\n",
			pid, strerror(errno));
		trace_fail_warning(pid);
		return;
	}

	/* Now attach to all tasks that belong to that PID.  There's a
	 * race between process_tasks and open_one_pid.  So when we
	 * fail in open_one_pid below, we just do another round.
	 * Chances are that by then that PID will have gone away, and
	 * that's why we have seen the failure.  The processes that we
	 * manage to open_one_pid are stopped, so we should eventually
	 * reach a point where process_tasks doesn't give any new
	 * processes (because there's nobody left to produce
	 * them).  */
	size_t old_ntasks = 0;
	int have_all;
	while (1) {
		pid_t *tasks;
		size_t ntasks;
		size_t i;

		if (process_tasks(pid, &tasks, &ntasks) < 0) {
			fprintf(stderr, "Cannot obtain tasks of pid %u: %s\n",
				pid, strerror(errno));
			break;
		}

		have_all = 1;
		for (i = 0; i < ntasks; ++i)
			if (pid2proc(tasks[i]) == NULL
			    && open_one_pid(tasks[i]))
				have_all = 0;

		free(tasks);

		if (have_all && old_ntasks == ntasks)
			break;
		old_ntasks = ntasks;
	}

	struct Process *leader = pid2proc(pid)->leader;

	/* XXX Is there a way to figure out whether _start has
	 * actually already been hit?  */
	arch_dynlink_done(leader);

	/* Done.  Continue everyone.  */
	each_task(leader, NULL, start_one_pid, NULL);
}

static enum callback_status
find_proc(Process * proc, void * data)
{
	pid_t pid = (pid_t)(uintptr_t)data;
	return proc->pid == pid ? CBS_STOP : CBS_CONT;
}

Process *
pid2proc(pid_t pid) {
	return each_process(NULL, &find_proc, (void *)(uintptr_t)pid);
}

static Process * list_of_processes = NULL;

static void
unlist_process(Process * proc)
{
	Process *tmp;

	if (list_of_processes == proc) {
		list_of_processes = list_of_processes->next;
		return;
	}

	for (tmp = list_of_processes; ; tmp = tmp->next) {
		/* If the following assert fails, the process wasn't
		 * in the list.  */
		assert(tmp->next != NULL);

		if (tmp->next == proc) {
			tmp->next = tmp->next->next;
			return;
		}
	}
}

struct Process *
each_process(struct Process *start_after,
	     enum callback_status(*cb)(struct Process *proc, void *data),
	     void *data)
{
	struct Process *it = start_after == NULL ? list_of_processes
		: start_after->next;

	while (it != NULL) {
		/* Callback might call remove_process.  */
		struct Process *next = it->next;
		switch ((*cb)(it, data)) {
		case CBS_FAIL:
			/* XXX handle me */
		case CBS_STOP:
			return it;
		case CBS_CONT:
			break;
		}
		it = next;
	}
	return NULL;
}

Process *
each_task(struct Process *proc, struct Process *start_after,
	  enum callback_status(*cb)(struct Process *proc, void *data),
	  void *data)
{
	assert(proc != NULL);
	struct Process *it = start_after == NULL ? proc->leader
		: start_after->next;

	if (it != NULL) {
		struct Process *leader = it->leader;
		while (it != NULL && it->leader == leader) {
			/* Callback might call remove_process.  */
			struct Process *next = it->next;
			switch ((*cb)(it, data)) {
			case CBS_FAIL:
				/* XXX handle me */
			case CBS_STOP:
				return it;
			case CBS_CONT:
				break;
			}
			it = next;
		}
	}
	return NULL;
}

static void
add_process(struct Process *proc, int was_exec)
{
	Process ** leaderp = &list_of_processes;
	if (proc->pid) {
		pid_t tgid = process_leader(proc->pid);
		if (tgid == 0)
			/* Must have been terminated before we managed
			 * to fully attach.  */
			return;
		if (tgid == proc->pid)
			proc->leader = proc;
		else {
			Process * leader = pid2proc(tgid);
			proc->leader = leader;
			if (leader != NULL)
				leaderp = &leader->next;
		}
	}

	if (!was_exec) {
		proc->next = *leaderp;
		*leaderp = proc;
	}
}

void
change_process_leader(Process * proc, Process * leader)
{
	Process ** leaderp = &list_of_processes;
	if (proc->leader == leader)
		return;

	assert(leader != NULL);
	unlist_process(proc);
	if (proc != leader)
		leaderp = &leader->next;

	proc->leader = leader;
	proc->next = *leaderp;
	*leaderp = proc;
}

static enum callback_status
clear_leader(struct Process *proc, void *data)
{
	debug(DEBUG_FUNCTION, "detach_task %d from leader %d",
	      proc->pid, proc->leader->pid);
	proc->leader = NULL;
	return CBS_CONT;
}

void
remove_process(Process *proc)
{
	debug(DEBUG_FUNCTION, "remove_proc(pid=%d)", proc->pid);

	if (proc->leader == proc)
		each_task(proc, NULL, &clear_leader, NULL);

	unlist_process(proc);
	process_removed(proc);
	process_destroy(proc);
	free(proc);
}

void
install_event_handler(Process *proc, struct event_handler *handler)
{
	debug(DEBUG_FUNCTION, "install_event_handler(pid=%d, %p)", proc->pid, handler);
	assert(proc->event_handler == NULL);
	proc->event_handler = handler;
}

void
destroy_event_handler(Process * proc)
{
	struct event_handler *handler = proc->event_handler;
	debug(DEBUG_FUNCTION, "destroy_event_handler(pid=%d, %p)", proc->pid, handler);
	assert(handler != NULL);
	if (handler->destroy != NULL)
		handler->destroy(handler);
	free(handler);
	proc->event_handler = NULL;
}

static int
breakpoint_for_symbol(struct library_symbol *libsym, struct Process *proc)
{
	arch_addr_t bp_addr;
	assert(proc->leader == proc);

	/* Don't enable latent or delayed symbols.  */
	if (libsym->latent || libsym->delayed) {
		debug(DEBUG_FUNCTION,
		      "delayed and/or latent breakpoint pid=%d, %s@%p",
		      proc->pid, libsym->name, libsym->enter_addr);
		return 0;
	}

	bp_addr = sym2addr(proc, libsym);

	/* If there is an artificial breakpoint on the same address,
	 * its libsym will be NULL, and we can smuggle our libsym
	 * there.  That artificial breakpoint is there presumably for
	 * the callbacks, which we don't touch.  If there is a real
	 * breakpoint, then this is a bug.  ltrace-elf.c should filter
	 * symbols and ignore extra symbol aliases.
	 *
	 * The other direction is more complicated and currently not
	 * supported.  If a breakpoint has custom callbacks, it might
	 * be also custom-allocated, and we would really need to swap
	 * the two: delete the one now in the dictionary, swap values
	 * around, and put the new breakpoint back in.  */
	struct breakpoint *bp = dict_find_entry(proc->breakpoints,
						bp_addr);
	if (bp != NULL) {
		/* MIPS backend makes duplicate requests.  This is
		 * likely a bug in the backend.  Currently there's no
		 * point assigning more than one symbol to a
		 * breakpoint, because when it hits, we won't know
		 * what to print out.  But it's easier to fix it here
		 * before someone who understands MIPS has the time to
		 * look into it.  So turn the sanity check off on
		 * MIPS.  References:
		 *
		 *   http://lists.alioth.debian.org/pipermail/ltrace-devel/2012-November/000764.html
		 *   http://lists.alioth.debian.org/pipermail/ltrace-devel/2012-November/000770.html
		 */
#ifndef __mips__
		assert(bp->libsym == NULL);
		bp->libsym = libsym;
#endif
		return 0;
	}

	bp = malloc(sizeof(*bp));
	if (bp == NULL
	    || breakpoint_init(bp, proc, bp_addr, libsym) < 0) {
	fail:
		free(bp);
		return -1;
	}
	if (proc_add_breakpoint(proc, bp) < 0) {
		breakpoint_destroy(bp);
		goto fail;
	}

	if (breakpoint_turn_on(bp, proc) < 0) {
		proc_remove_breakpoint(proc, bp);
		breakpoint_destroy(bp);
		goto fail;
	}

	return 0;
}

static enum callback_status
cb_breakpoint_for_symbol(struct library_symbol *libsym, void *data)
{
	return breakpoint_for_symbol(libsym, data) < 0 ? CBS_FAIL : CBS_CONT;
}

static int
proc_activate_latent_symbol(struct Process *proc,
			    struct library_symbol *libsym)
{
	assert(libsym->latent);
	libsym->latent = 0;
	debug(DEBUG_FUNCTION, "activated latent symbol");
	return breakpoint_for_symbol(libsym, proc);
}

int
proc_activate_delayed_symbol(struct Process *proc,
			     struct library_symbol *libsym)
{
	assert(libsym->delayed);
	libsym->delayed = 0;
	debug(DEBUG_FUNCTION, "activated delayed symbol");
	return breakpoint_for_symbol(libsym, proc);
}

static enum callback_status
activate_latent_in(struct Process *proc, struct library *lib, void *data)
{
	struct library_exported_name *exported;
	for (exported = data; exported != NULL; exported = exported->next) {
		struct library_symbol *libsym = NULL;
		while ((libsym = library_each_symbol(lib, libsym,
						     library_symbol_named_cb,
						     (void *)exported->name))
		       != NULL)
			if (libsym->latent
			    && proc_activate_latent_symbol(proc, libsym) < 0)
				return CBS_FAIL;
	}
	return CBS_CONT;
}

void
proc_add_library(struct Process *proc, struct library *lib)
{
	assert(lib->next == NULL);
	lib->next = proc->libraries;
	proc->libraries = lib;
	debug(DEBUG_PROCESS, "added library %s@%p (%s) to %d",
	      lib->soname, lib->base, lib->pathname, proc->pid);

	/* Insert breakpoints for all active (non-latent) symbols.  */
	struct library_symbol *libsym = NULL;
	while ((libsym = library_each_symbol(lib, libsym,
					     cb_breakpoint_for_symbol,
					     proc)) != NULL)
		fprintf(stderr, "Couldn't insert breakpoint for %s to %d: %s.",
			libsym->name, proc->pid, strerror(errno));

	/* Look through export list of the new library and compare it
	 * with latent symbols of all libraries (including this
	 * library itself).  */
	struct library *lib2 = NULL;
	while ((lib2 = proc_each_library(proc, lib2, activate_latent_in,
					 lib->exported_names)) != NULL)
		fprintf(stderr,
			"Couldn't activate latent symbols for %s in %d: %s.",
			libsym->name, proc->pid, strerror(errno));
}

int
proc_remove_library(struct Process *proc, struct library *lib)
{
	struct library **libp;
	for (libp = &proc->libraries; *libp != NULL; libp = &(*libp)->next)
		if (*libp == lib) {
			*libp = lib->next;
			return 0;
		}
	return -1;
}

struct library *
proc_each_library(struct Process *proc, struct library *it,
		  enum callback_status (*cb)(struct Process *proc,
					     struct library *lib, void *data),
		  void *data)
{
	if (it == NULL)
		it = proc->libraries;

	while (it != NULL) {
		struct library *next = it->next;

		switch (cb(proc, it, data)) {
		case CBS_FAIL:
			/* XXX handle me */
		case CBS_STOP:
			return it;
		case CBS_CONT:
			break;
		}

		it = next;
	}

	return NULL;
}

static void
check_leader(struct Process *proc)
{
	/* Only the group leader should be getting the breakpoints and
	 * thus have ->breakpoint initialized.  */
	assert(proc->leader != NULL);
	assert(proc->leader == proc);
	assert(proc->breakpoints != NULL);
}

int
proc_add_breakpoint(struct Process *proc, struct breakpoint *bp)
{
	debug(DEBUG_FUNCTION, "proc_add_breakpoint(pid=%d, %s@%p)",
	      proc->pid, breakpoint_name(bp), bp->addr);
	check_leader(proc);

	/* XXX We might merge bp->libsym instead of the following
	 * assert, but that's not necessary right now.  Read the
	 * comment in breakpoint_for_symbol.  */
	assert(dict_find_entry(proc->breakpoints, bp->addr) == NULL);

	if (dict_enter(proc->breakpoints, bp->addr, bp) < 0) {
		fprintf(stderr,
			"couldn't enter breakpoint %s@%p to dictionary: %s\n",
			breakpoint_name(bp), bp->addr, strerror(errno));
		return -1;
	}

	return 0;
}

void
proc_remove_breakpoint(struct Process *proc, struct breakpoint *bp)
{
	debug(DEBUG_FUNCTION, "proc_remove_breakpoint(pid=%d, %s@%p)",
	      proc->pid, breakpoint_name(bp), bp->addr);
	check_leader(proc);
	struct breakpoint *removed = dict_remove(proc->breakpoints, bp->addr);
	assert(removed == bp);
}

/* Dict doesn't support iteration restarts, so here's this contraption
 * for now.  XXX add restarts to dict.  */
struct each_breakpoint_data
{
	void *start;
	void *end;
	struct Process *proc;
	enum callback_status (*cb)(struct Process *proc,
				   struct breakpoint *bp,
				   void *data);
	void *cb_data;
};

static void
each_breakpoint_cb(void *key, void *value, void *d)
{
	struct each_breakpoint_data *data = d;
	if (data->end != NULL)
		return;
	if (data->start == key)
		data->start = NULL;

	if (data->start == NULL) {
		switch (data->cb(data->proc, value, data->cb_data)) {
		case CBS_FAIL:
			/* XXX handle me */
		case CBS_STOP:
			data->end = key;
		case CBS_CONT:
			return;
		}
	}
}

void *
proc_each_breakpoint(struct Process *proc, void *start,
		     enum callback_status (*cb)(struct Process *proc,
						struct breakpoint *bp,
						void *data), void *data)
{
	struct each_breakpoint_data dd = {
		.start = start,
		.proc = proc,
		.cb = cb,
		.cb_data = data,
	};
	dict_apply_to_all(proc->breakpoints, &each_breakpoint_cb, &dd);
	return dd.end;
}

int
proc_find_symbol(struct Process *proc, struct library_symbol *sym,
		 struct library **retlib, struct library_symbol **retsym)
{
	struct library *lib = sym->lib;
	assert(lib != NULL);

	struct library *flib
		= proc_each_library(proc, NULL, library_with_key_cb, &lib->key);
	if (flib == NULL)
		return -1;

	struct library_symbol *fsym
		= library_each_symbol(flib, NULL, library_symbol_named_cb,
				      (char *)sym->name);
	if (fsym == NULL)
		return -1;

	if (retlib != NULL)
		*retlib = flib;
	if (retsym != NULL)
		*retsym = fsym;

	return 0;
}

struct library_symbol *
proc_each_symbol(struct Process *proc, struct library_symbol *start_after,
		 enum callback_status (*cb)(struct library_symbol *, void *),
		 void *data)
{
	struct library *lib;
	for (lib = start_after != NULL ? start_after->lib : proc->libraries;
	     lib != NULL; lib = lib->next) {
		start_after = library_each_symbol(lib, start_after, cb, data);
		if (start_after != NULL)
			return start_after;
	}

	return NULL;
}
