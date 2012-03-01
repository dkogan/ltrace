#include "config.h"

#if defined(HAVE_LIBUNWIND)
#include <libunwind.h>
#include <libunwind-ptrace.h>
#endif /* defined(HAVE_LIBUNWIND) */

#include <sys/types.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <assert.h>
#include <error.h>

#include "common.h"
#include "breakpoint.h"
#include "proc.h"

static int
process_bare_init(struct Process *proc, const char *filename, pid_t pid)
{
	fprintf(stderr, "process_bare_init %s %d\n", filename, pid);
	memset(proc, 0, sizeof(*proc));

	proc->filename = strdup(filename);
	if (proc->filename == NULL) {
	fail:
		free(proc->filename);
		if (proc->breakpoints != NULL)
			dict_clear(proc->breakpoints);
		return -1;
	}

	/* Add process so that we know who the leader is.  */
	proc->pid = pid;
	add_process(proc);
	if (proc->leader == NULL)
		goto fail;

	if (proc->leader == proc) {
		proc->breakpoints = dict_init(dict_key2hash_int,
					      dict_key_cmp_int);
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
process_bare_destroy(struct Process *proc)
{
	free(proc->filename);
	dict_clear(proc->breakpoints);
	remove_process(proc);
}

int
process_init(struct Process *proc, const char *filename, pid_t pid, int enable)
{
	fprintf(stderr, "process_init %s %d enable=%d\n", filename, pid, enable);
	if (process_bare_init(proc, filename, pid) < 0) {
		error(0, errno, "init process %d", pid);
		return -1;
	}

	if (proc->leader == proc && breakpoints_init(proc, enable) < 0) {
		fprintf(stderr, "failed to init breakpoints %d\n",
			proc->pid);
		process_bare_destroy(proc);
		return -1;
	}

	return 0;
}

struct Process *
open_program(const char *filename, pid_t pid, int enable)
{
	fprintf(stderr, "open_program %s %d enable=%d\n",
		filename, pid, enable);
	assert(pid != 0);
	struct Process *proc = malloc(sizeof(*proc));
	if (proc == NULL
	    || process_init(proc, filename, pid, enable) < 0) {
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

struct find_symbol_data {
	struct library_symbol *old_libsym;
	struct library_symbol *found_libsym;
};

static enum callback_status
find_sym_in_lib(struct Process *proc, struct library *lib, void *u)
{
	struct find_symbol_data *fs = u;
	fs->found_libsym
		= library_each_symbol(lib, NULL, library_symbol_equal_cb,
				      fs->old_libsym);
	return fs->found_libsym != NULL ? CBS_STOP : CBS_CONT;
}

static void
clone_single_bp(void *key, void *value, void *u)
{
	target_address_t addr = (target_address_t)key;
	struct breakpoint *bp = value;
	struct clone_single_bp_data *data = u;

	/* Find library and symbol that this symbol was linked to.  */
	struct library_symbol *libsym = bp->libsym;
	struct library *lib = NULL;
	if (libsym != NULL) {
		struct find_symbol_data f_data = {
			.old_libsym = libsym,
		};
		lib = proc_each_library(data->old_proc, NULL,
					find_sym_in_lib, &f_data);
		assert(lib != NULL);
		libsym = f_data.found_libsym;
	}

	/* LIB and LIBSYM now hold the new library and symbol that
	 * correspond to the original breakpoint.  Now we can do the
	 * clone itself.  */
	struct breakpoint *clone = malloc(sizeof(*clone));
	if (clone == NULL
	    || breakpoint_init(clone, data->new_proc, addr,
			       libsym, bp->cbs) < 0) {
		data->error = -1;
		return;
	}
}

int
process_clone(struct Process *retp, struct Process *proc, pid_t pid)
{
	if (process_bare_init(retp, proc->filename, pid) < 0) {
	fail:
		error(0, errno, "clone process %d->%d", proc->pid, pid);
		return -1;
	}

	/* For non-leader processes, that's all we need to do.  */
	if (proc->leader != proc)
		return 0;

	/* Clone symbols first so that we can clone and relink
	 * breakpoints.  */
	struct library *lib;
	struct library **nlibp = &retp->libraries;
	for (lib = proc->libraries; lib != NULL; lib = lib->next) {
		*nlibp = malloc(sizeof(**nlibp));
		if (*nlibp == NULL
		    || library_clone(*nlibp, lib) < 0) {
		fail2:
			process_bare_destroy(retp);

			/* Error when cloning.  Unroll what was done.  */
			for (lib = retp->libraries; lib != NULL; ) {
				struct library *next = lib->next;
				library_destroy(lib);
				free(lib);
				lib = next;
			}
			goto fail;
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
	dict_apply_to_all(proc->breakpoints, &clone_single_bp, &data);

	if (data.error < 0)
		goto fail2;

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
		free(filename);
		return -1;
	}

	proc = open_program(filename, pid, 0);
	if (proc == NULL)
		return -1;
	trace_set_options(proc, pid);

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

	/* Done.  Now initialize breakpoints and then continue
	 * everyone.  */
	Process * leader;
	leader = pid2proc(pid)->leader;
	enable_all_breakpoints(leader);

	each_task(pid2proc(pid)->leader, start_one_pid, NULL);
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
each_process(struct Process *it,
	     enum callback_status(*cb)(struct Process *proc, void *data),
	     void *data)
{
	if (it == NULL)
		it = list_of_processes;
	for (; it != NULL; ) {
		/* Callback might call remove_process.  */
		Process * next = it->next;
		switch ((*cb)(it, data)) {
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
each_task(struct Process *it,
	  enum callback_status(*cb)(struct Process *proc, void *data),
	  void *data)
{
	if (it != NULL) {
		Process * leader = it->leader;
		for (; it != NULL && it->leader == leader; ) {
			/* Callback might call remove_process.  */
			Process * next = it->next;
			switch ((*cb)(it, data)) {
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

void
add_process(Process * proc)
{
	fprintf(stderr, "add_process %d\n", proc->pid);
	Process ** leaderp = &list_of_processes;
	if (proc->pid) {
		pid_t tgid = process_leader(proc->pid);
		fprintf(stderr, " + leader is %d\n", tgid);
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
	proc->next = *leaderp;
	*leaderp = proc;
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

static enum ecb_status
event_for_proc(Event * event, void * data)
{
	if (event->proc == data)
		return ecb_deque;
	else
		return ecb_cont;
}

static void
delete_events_for(Process * proc)
{
	Event * event;
	while ((event = each_qd_event(&event_for_proc, proc)) != NULL)
		free(event);
}

void
remove_process(Process *proc)
{
	debug(DEBUG_FUNCTION, "remove_proc(pid=%d)", proc->pid);

	if (proc->leader == proc)
		each_task(proc, &clear_leader, NULL);

	unlist_process(proc);
	delete_events_for(proc);
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

static enum callback_status
breakpoint_for_symbol(struct library_symbol *libsym, void *data)
{
	struct Process *proc = data;
	fprintf(stderr, "  %s@%p\n", libsym->name, libsym->enter_addr);

	if (insert_breakpoint(proc, libsym->enter_addr, libsym, 1) == NULL)
		return CBS_STOP;

	return CBS_CONT;
}

void
proc_add_library(struct Process *proc, struct library *lib)
{
	assert(lib->next == NULL);
	lib->next = proc->libraries;
	proc->libraries = lib;
	fprintf(stderr, "=== Added library %s@%p to %d:\n",
		lib->name, lib->base, proc->pid);

	struct library_symbol *libsym = NULL;
	while ((libsym = library_each_symbol(lib, libsym, breakpoint_for_symbol,
					     proc)) != NULL) {
		error(0, errno, "insert breakpoint for %s", libsym->name);
		libsym = libsym->next;
	}
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
		case CBS_STOP:
			return it;
		case CBS_CONT:
			break;
		}

		it = next;
	}

	return NULL;
}
