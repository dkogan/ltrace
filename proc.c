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
	if (proc->leader == NULL) {
		free(proc);
		return NULL;
	}

	if (proc->leader == proc)
		if (breakpoints_init(proc, enable)) {
			fprintf(stderr, "failed to init breakpoints %d\n",
				proc->pid);
			remove_process(proc);
			return NULL;
		}

	return proc;
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

enum pcb_status
start_one_pid(Process * proc, void * data)
{
	continue_process(proc->pid);
	proc->breakpoints_enabled = 1;
	return pcb_cont;
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
			goto start;
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
start:
	leader = pid2proc(pid)->leader;
	enable_all_breakpoints(leader);

	each_task(pid2proc(pid)->leader, start_one_pid, NULL);
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
	debug(DEBUG_FUNCTION, "remove_proc(pid=%d)", proc->pid);

	if (proc->leader == proc)
		each_task(proc, &clear_leader, NULL);

	unlist_process(proc);
	delete_events_for(proc);
	free(proc);
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
	if (handler->destroy != NULL)
		handler->destroy(handler);
	free(handler);
	proc->event_handler = NULL;
}
