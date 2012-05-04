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

#include "common.h"
#include "breakpoint.h"
#include "proc.h"

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

#ifndef ARCH_HAVE_DYNLINK_DONE
void
arch_dynlink_done(struct Process *proc)
{
}
#endif

static void add_process(struct Process *proc, int was_exec);
static void unlist_process(struct Process *proc);

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

	if (arch_process_init(proc) < 0) {
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

static void
private_process_destroy(struct Process *proc, int keep_filename)
{
	if (!keep_filename)
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
}

void
process_destroy(struct Process *proc)
{
	private_process_destroy(proc, 0);
	arch_process_destroy(proc);
}

int
process_exec(struct Process *proc)
{
	/* Call exec first, before we destroy the main state.  */
	if (arch_process_exec(proc) < 0)
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

	data->error = 0;
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
	fail:
		fprintf(stderr, "failed to clone process %d->%d : %s\n",
			proc->pid, pid, strerror(errno));
		return -1;
	}

	retp->tracesysgood = proc->tracesysgood;
	retp->e_machine = proc->e_machine;

	/* For non-leader processes, that's all we need to do.  */
	if (retp->leader != retp)
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
			process_bare_destroy(retp, 0);

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

	/* And finally the call stack.  */
	memcpy(retp->callstack, proc->callstack, sizeof(retp->callstack));
	retp->callstack_depth = proc->callstack_depth;

	if (data.error < 0)
		goto fail2;

	if (arch_process_clone(retp, proc) < 0)
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

	proc = open_program(filename, pid);
	if (proc == NULL)
		return -1;
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
		each_task(proc, NULL, &clear_leader, NULL);

	unlist_process(proc);
	delete_events_for(proc);
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

static enum callback_status
breakpoint_for_symbol(struct library_symbol *libsym, void *data)
{
	struct Process *proc = data;
	assert(proc->leader == proc);

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
						libsym->enter_addr);
	if (bp != NULL) {
		assert(bp->libsym == NULL);
		bp->libsym = libsym;
		return CBS_CONT;
	}

	bp = malloc(sizeof(*bp));
	if (bp == NULL
	    || breakpoint_init(bp, proc, libsym->enter_addr, libsym) < 0) {
	fail:
		free(bp);
		return CBS_FAIL;
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

	struct library_symbol *libsym = NULL;
	while ((libsym = library_each_symbol(lib, libsym, breakpoint_for_symbol,
					     proc)) != NULL)
		fprintf(stderr, "couldn't insert breakpoint for %s to %d: %s",
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
