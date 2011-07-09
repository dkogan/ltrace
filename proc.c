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

	breakpoints_init(proc, enable);

	return proc;
}

void
open_pid(pid_t pid) {
	Process *proc;
	char *filename;

	if (trace_pid(pid) < 0) {
		fprintf(stderr, "Cannot attach to pid %u: %s\n", pid,
			strerror(errno));
		return;
	}

	filename = pid2name(pid);

	if (!filename) {
		fprintf(stderr, "Cannot trace pid %u: %s\n", pid,
				strerror(errno));
		return;
	}

	proc = open_program(filename, pid, 1);
	continue_process(pid);
	proc->breakpoints_enabled = 1;
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
void
add_process(Process * proc)
{
	proc->next = list_of_processes;
	list_of_processes = proc;
}

void
remove_process(Process *proc)
{
	Process *tmp, *tmp2;

	debug(DEBUG_FUNCTION, "remove_proc(pid=%d)", proc->pid);

	if (list_of_processes == proc) {
		tmp = list_of_processes;
		list_of_processes = list_of_processes->next;
		free(tmp);
		return;
	}
	tmp = list_of_processes;
	while (tmp->next) {
		if (tmp->next == proc) {
			tmp2 = tmp->next;
			tmp->next = tmp->next->next;
			free(tmp2);
			return;
		}
		tmp = tmp->next;
	}
}
