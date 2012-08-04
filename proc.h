/*
 * This file is part of ltrace.
 * Copyright (C) 2010,2011,2012 Petr Machata, Red Hat Inc.
 * Copyright (C) 2010 Joe Damato
 * Copyright (C) 1998,2001,2008,2009 Juan Cespedes
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

#ifndef _PROC_H_
#define _PROC_H_

#include "config.h"

#include <sys/time.h>

#if defined(HAVE_LIBUNWIND)
# include <libunwind.h>
#endif /* defined(HAVE_LIBUNWIND) */

#include "ltrace.h"
#include "dict.h"
#include "sysdep.h"

struct library;
struct breakpoint;

/* XXX Move this somewhere where it makes sense.  When the mess in
 * common.h is disentangled, that would actually be a good place for
 * this.  */
enum callback_status {
	CBS_STOP, /* The iteration should stop.  */
	CBS_CONT, /* The iteration should continue.  */
	CBS_FAIL, /* There was an error.  The iteration should stop
		   * and return error.  */
};

struct event_handler {
	/* Event handler that overrides the default one.  Should
	 * return NULL if the event was handled, otherwise the
	 * returned event is passed to the default handler.  */
	Event *(*on_event)(struct event_handler *self, Event *event);

	/* Called when the event handler removal is requested.  */
	void (*destroy)(struct event_handler *self);
};

enum process_state {
	STATE_ATTACHED = 0,
	STATE_BEING_CREATED,
	STATE_IGNORED  /* ignore this process (it's a fork and no -f was used) */
};

struct callstack_element {
	union {
		int syscall;
		struct library_symbol * libfunc;
	} c_un;
	int is_syscall;
	void * return_addr;
	struct timeval time_spent;
	void * arch_ptr;
};

/* XXX We should get rid of this.  */
#define MAX_CALLDEPTH 64

/* XXX We would rather have this all organized a little differently,
 * have Process for the whole group and Task for what's there for
 * per-thread stuff.  But for now this is the less invasive way of
 * structuring it.  */
typedef struct Process Process;
struct Process {
	enum process_state state;
	Process * parent;         /* needed by STATE_BEING_CREATED */
	char * filename;
	pid_t pid;

	/* Dictionary of breakpoints (which is a mapping
	 * address->breakpoint).  This is NULL for non-leader
	 * processes.  XXX note that we store addresses (keys) by
	 * value.  That assumes that target_address_t fits in host
	 * pointer.  */
	Dict * breakpoints;

	int mask_32bit;           /* 1 if 64-bit ltrace is tracing 32-bit process */
	unsigned int personality;
	int tracesysgood;         /* signal indicating a PTRACE_SYSCALL trap */

	int callstack_depth;
	struct callstack_element callstack[MAX_CALLDEPTH];

	/* Linked list of libraries in backwards order of mapping.
	 * The last element is the executed binary itself.  */
	struct library *libraries;

	/* Arch-dependent: */
	void *debug;	/* arch-dep process debug struct XXX move to
			 * os_process_data after it's invented.  */
	void * instruction_pointer;
	void * stack_pointer;      /* To get return addr, args... */
	void * return_addr;
	void * arch_ptr;
	short e_machine;
#ifdef __arm__
	int thumb_mode;           /* ARM execution mode: 0: ARM, 1: Thumb */
#endif

#if defined(HAVE_LIBUNWIND)
	/* libunwind address space */
	unw_addr_space_t unwind_as;
	void *unwind_priv;
#endif /* defined(HAVE_LIBUNWIND) */

	/* Set in leader.  */
	struct event_handler *event_handler;

	/**
	 * Process chaining.
	 **/
	Process * next;

	/* LEADER points to the leader thread of the POSIX.1 process.
	   If X->LEADER == X, then X is the leader thread and the
	   Process structures chained by NEXT represent other threads,
	   up until, but not including, the next leader thread.
	   LEADER may be NULL after the leader has already exited.  In
	   that case this process is waiting to be collected.  */
	Process * leader;

	struct arch_process_data arch;
};

/* Initialize a process given a path to binary FILENAME, with a PID,
 * and add the process to an internal chain of traced processes.  */
int process_init(struct Process *proc, const char *filename, pid_t pid);

/* PROC underwent an exec.  This is a bit like process_destroy
 * followed by process_init, except that some state is kept and the
 * process doesn't lose it's place in the list of processes.  */
int process_exec(struct Process *proc);

/* Release any memory allocated for PROC (but not PROC itself).  Does
 * NOT remove PROC from internal chain.
 *
 * XXX clearly this init/destroy pair is different than others and
 * should be fixed.  process_init should presumably be separate from
 * process_add.  */
void process_destroy(struct Process *proc);

struct Process *open_program(const char *filename, pid_t pid);
void open_pid(pid_t pid);
Process * pid2proc(pid_t pid);

/* Clone the contents of PROC into the memory referenced by RETP.
 * Returns 0 on success or a negative value on failure.  */
int process_clone(struct Process *retp, struct Process *proc, pid_t pid);

/* Iterate through the processes that ltrace currently traces.  CB is
 * called for each process.  Tasks are considered to be processes for
 * the purpose of this iterator.
 *
 * Notes on this iteration interface: The iteration starts after the
 * process designated by START_AFTER, or at the first process if
 * START_AFTER is NULL.  DATA is passed verbatim to CB.  If CB returns
 * CBS_STOP, the iteration stops and the current iterator is returned.
 * That iterator can then be used to restart the iteration.  NULL is
 * returned when iteration ends.
 *
 * There's no provision for returning error states.  Errors need to be
 * signaled to the caller via DATA, together with any other data that
 * the callback needs.  */
Process *each_process(Process *start_after,
		      enum callback_status (*cb)(struct Process *proc,
						 void *data),
		      void *data);

/* Iterate through list of tasks of given process PROC.  Restarts are
 * supported via START_AFTER (see each_process for details of
 * iteration interface).  */
Process *each_task(struct Process *proc, struct Process *start_after,
		   enum callback_status (*cb)(struct Process *proc,
					      void *data),
		   void *data);

void change_process_leader(Process *proc, Process *leader);

/* Remove process from the list of traced processes, drop any events
 * in the event queue, destroy it and free memory.  */
void remove_process(struct Process *proc);

void install_event_handler(Process *proc, struct event_handler *handler);
void destroy_event_handler(Process *proc);

/* Add a library LIB to the list of PROC's libraries.  */
void proc_add_library(struct Process *proc, struct library *lib);

/* Remove LIB from list of PROC's libraries.  Returns 0 if the library
 * was found and unlinked, otherwise returns a negative value.  */
int proc_remove_library(struct Process *proc, struct library *lib);

/* Iterate through the libraries of PROC.  See each_process for
 * detailed description of the iteration interface.  */
struct library *proc_each_library(struct Process *proc, struct library *start,
				  enum callback_status (*cb)(struct Process *p,
							     struct library *l,
							     void *data),
				  void *data);

/* Insert BP into PROC.  */
int proc_add_breakpoint(struct Process *proc, struct breakpoint *bp);

/* Remove BP from PROC.  This has no reason to fail in runtime.  If it
 * does not find BP in PROC, it's hard error guarded by assertion.  */
void proc_remove_breakpoint(struct Process *proc, struct breakpoint *bp);

/* Iterate through the libraries of PROC.  See each_process for
 * detailed description of the iteration interface.  */
void *proc_each_breakpoint(struct Process *proc, void *start,
			   enum callback_status (*cb)(struct Process *proc,
						      struct breakpoint *bp,
						      void *data),
			   void *data);

#endif /* _PROC_H_ */
