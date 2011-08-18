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

Process *
open_program(char *filename, pid_t pid, int enable) {
	Process *proc;
	assert(pid != 0);
	proc = calloc(sizeof(Process), 1);
	if (!proc) {
		perror("malloc");
		exit(1);
	}
	proc->filename = strdup(filename);
	proc->breakpoints_enabled = -1;
	proc->pid = pid;
#if defined(HAVE_LIBUNWIND)
	proc->unwind_priv = _UPT_create(pid);
	proc->unwind_as = unw_create_addr_space(&_UPT_accessors, 0);
#endif /* defined(HAVE_LIBUNWIND) */

	add_process(proc);
	assert(proc->leader != NULL);

	if (proc->leader == proc)
		breakpoints_init(proc, enable);

	return proc;
}

static int
open_one_pid(pid_t pid)
{
	Process *proc;
	char *filename;
	debug(DEBUG_PROCESS, "open_one_pid(pid=%d)", pid);

	if (trace_pid(pid) < 0)
		return 0;

	filename = pid2name(pid);
	if (filename == NULL)
		return 0;

	proc = open_program(filename, pid, 1);
	trace_set_options(proc, pid);
	continue_process(pid);
	proc->breakpoints_enabled = 1;

	return 1;
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
	if (!open_one_pid(pid)) {
		fprintf(stderr, "Cannot attach to pid %u: %s\n",
			pid, strerror(errno));
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
	int have_all;
	do {
		pid_t *tasks;
		size_t ntasks;
		size_t i;
		if (process_tasks(pid, &tasks, &ntasks) < 0) {
			fprintf(stderr, "Cannot obtain tasks of pid %u: %s\n",
				pid, strerror(errno));
			return;
		}

		have_all = 1;
		for (i = 0; i < ntasks; ++i)
			if (pid2proc(tasks[i]) == NULL
			    && !open_one_pid(tasks[i]))
				have_all = 0;

		free(tasks);

	} while (have_all == 0);
}

static enum pcb_status
find_proc(Process * proc, void * data)
{
	pid_t pid = (pid_t)(uintptr_t)data;
	return proc->pid == pid ? pcb_stop : pcb_cont;
}

Process *
pid2proc(pid_t pid) {
	return each_process(NULL, &find_proc, (void *)(uintptr_t)pid);
}


static Process * list_of_processes = NULL;

Process *
each_process(Process * proc,
	     enum pcb_status (* cb)(Process * proc, void * data),
	     void * data)
{
	Process * it = proc ?: list_of_processes;
	for (; it != NULL; ) {
		/* Callback might call remove_process.  */
		Process * next = it->next;
		if ((*cb) (it, data) == pcb_stop)
			return it;
		it = next;
	}
	return NULL;
}

Process *
each_task(Process * it, enum pcb_status (* cb)(Process * proc, void * data),
	  void * data)
{
	if (it != NULL) {
		Process * leader = it->leader;
		for (; it != NULL && it->leader == leader; ) {
			/* Callback might call remove_process.  */
			Process * next = it->next;
			if ((*cb) (it, data) == pcb_stop)
				return it;
			it = next;
		}
	}
	return NULL;
}

void
add_process(Process * proc)
{
	Process ** leaderp = &list_of_processes;
	if (proc->pid) {
		pid_t tgid = process_leader(proc->pid);
		if (tgid == proc->pid)
			proc->leader = proc;
		else {
			Process * leader = pid2proc(tgid);
			proc->leader = leader;
			if (leader != NULL)
				// NULL: sub-task added before leader?
				leaderp = &leader->next;
		}
	}
	proc->next = *leaderp;
	*leaderp = proc;
}

static enum pcb_status
clear_leader(Process * proc, void * data)
{
	debug(DEBUG_FUNCTION, "detach_task %d from leader %d",
	      proc->pid, proc->leader->pid);
	proc->leader = NULL;
	return pcb_cont;
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
	Process *tmp, *tmp2;

	debug(DEBUG_FUNCTION, "remove_proc(pid=%d)", proc->pid);

	if (proc->leader == proc)
		each_task(proc, &clear_leader, NULL);

	if (list_of_processes == proc) {
		tmp = list_of_processes;
		list_of_processes = list_of_processes->next;
		delete_events_for(tmp);
		free(tmp);
		return;
	}
	tmp = list_of_processes;
	while (tmp->next) {
		if (tmp->next == proc) {
			tmp2 = tmp->next;
			tmp->next = tmp->next->next;
			delete_events_for(tmp2);
			free(tmp2);
			return;
		}
		tmp = tmp->next;
	}
}

void
install_event_handler(Process * proc, Event_Handler * handler)
{
	debug(DEBUG_FUNCTION, "install_event_handler(pid=%d, %p)", proc->pid, handler);
	assert(proc->event_handler == NULL);
	proc->event_handler = handler;
}

void
destroy_event_handler(Process * proc)
{
	Event_Handler * handler = proc->event_handler;
	debug(DEBUG_FUNCTION, "destroy_event_handler(pid=%d, %p)", proc->pid, handler);
	assert(handler != NULL);
	handler->destroy(handler);
	free(handler);
	proc->event_handler = NULL;
}
