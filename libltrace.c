#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/param.h>
#include <signal.h>
#include <sys/wait.h>

#include "common.h"

char *command = NULL;

int exiting = 0;		/* =1 if a SIGINT or SIGTERM has been received */

static enum pcb_status
stop_non_p_processes (Process * proc, void * data)
{
	int stop = 1;

	struct opt_p_t *it;
	for (it = opt_p; it != NULL; it = it->next) {
		Process * p_proc = pid2proc(it->pid);
		if (p_proc == NULL) {
			printf("stop_non_p_processes: %d terminated?\n", it->pid);
			continue;
		}
		if (p_proc == proc || p_proc->leader == proc->leader) {
			stop = 0;
			break;
		}
	}

	if (stop) {
		debug(2, "Sending SIGSTOP to process %u", proc->pid);
		kill(proc->pid, SIGSTOP);
	}

	return pcb_cont;
}

static void
signal_alarm(int sig) {
	signal(SIGALRM, SIG_DFL);
	each_process(NULL, &stop_non_p_processes, NULL);
}

static void
signal_exit(int sig) {
	exiting = 1;
	debug(1, "Received interrupt signal; exiting...");
	signal(SIGINT, SIG_IGN);
	signal(SIGTERM, SIG_IGN);
	signal(SIGALRM, signal_alarm);
	//alarm(1);
}

static void
normal_exit(void) {
	output_line(0, 0);
	if (options.summary) {
		show_summary();
	}
	if (options.output) {
		fclose(options.output);
		options.output = NULL;
	}
}

void
ltrace_init(int argc, char **argv) {
	struct opt_p_t *opt_p_tmp;

	atexit(normal_exit);
	signal(SIGINT, signal_exit);	/* Detach processes when interrupted */
	signal(SIGTERM, signal_exit);	/*  ... or killed */

	argv = process_options(argc, argv);
	while (opt_F) {
		/* If filename begins with ~, expand it to the user's home */
		/* directory. This does not correctly handle ~yoda, but that */
		/* isn't as bad as it seems because the shell will normally */
		/* be doing the expansion for us; only the hardcoded */
		/* ~/.ltrace.conf should ever use this code. */
		if (opt_F->filename[0] == '~') {
			char path[PATH_MAX];
			char *home_dir = getenv("HOME");
			if (home_dir) {
				strncpy(path, home_dir, PATH_MAX - 1);
				path[PATH_MAX - 1] = '\0';
				strncat(path, opt_F->filename + 1,
						PATH_MAX - strlen(path) - 1);
				read_config_file(path);
			}
		} else {
			read_config_file(opt_F->filename);
		}
		opt_F = opt_F->next;
	}
	if (opt_e) {
		struct opt_e_t *tmp = opt_e;
		while (tmp) {
			debug(1, "Option -e: %s\n", tmp->name);
			tmp = tmp->next;
		}
	}
	if (command) {
		open_program(command, execute_program(command, argv), 0);
	}
	opt_p_tmp = opt_p;
	while (opt_p_tmp) {
		open_pid(opt_p_tmp->pid);
		opt_p_tmp = opt_p_tmp->next;
	}
}

static int num_ltrace_callbacks[EVENT_MAX];
static callback_func * ltrace_callbacks[EVENT_MAX];

void
ltrace_add_callback(callback_func func, Event_type type) {
	ltrace_callbacks[type] = realloc(ltrace_callbacks[type], (num_ltrace_callbacks[type]+1)*sizeof(callback_func));
	ltrace_callbacks[type][num_ltrace_callbacks[type]++] = func;
}

static void
dispatch_callbacks(Event * ev) {
	int i;
	/* Ignoring case 1: signal into a dying tracer */
	if (ev->type==EVENT_SIGNAL && 
			exiting && ev->e_un.signum == SIGSTOP) {
		return;
	}
	/* Ignoring case 2: process being born before a clone event */
	if (ev->proc && ev->proc->state == STATE_IGNORED) {
		return;
	}
	for (i=0; i<num_ltrace_callbacks[ev->type]; i++) {
		ltrace_callbacks[ev->type][i](ev);
	}
}

void
ltrace_main(void) {
	Event * ev;
	while (1) {
		ev = next_event();
		dispatch_callbacks(ev);
		handle_event(ev);
	}
}
