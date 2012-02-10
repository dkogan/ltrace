#ifndef _PROC_H_
#define _PROC_H_

#if defined(HAVE_LIBUNWIND)
# include <libunwind.h>
#endif /* defined(HAVE_LIBUNWIND) */

#include "ltrace.h"
#include "dict.h"

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

enum pcb_status {
	pcb_stop, /* The iteration should stop.  */
	pcb_cont, /* The iteration should continue.  */
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
	 * processes.  */
	Dict * breakpoints;

	int mask_32bit;           /* 1 if 64-bit ltrace is tracing 32-bit process */
	unsigned int personality;
	int tracesysgood;         /* signal indicating a PTRACE_SYSCALL trap */

	int callstack_depth;
	struct callstack_element callstack[MAX_CALLDEPTH];
	struct library_symbol * list_of_symbols;

	int libdl_hooked;
	/* Arch-dependent: */
	void * debug;	/* arch-dep process debug struct */
	long debug_state; /* arch-dep debug state */
	void * instruction_pointer;
	void * stack_pointer;      /* To get return addr, args... */
	void * return_addr;
	void * arch_ptr;
	short e_machine;
	short need_to_reinitialize_breakpoints;
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
};

Process * open_program(char *filename, pid_t pid, int init_breakpoints);
void open_pid(pid_t pid);
Process * pid2proc(pid_t pid);
Process *each_process(Process *start,
		      enum pcb_status (* cb)(Process *proc, void *data),
		      void *data);
Process *each_task(Process *start,
		   enum pcb_status (* cb)(Process *proc, void *data),
		   void *data);
void add_process(Process *proc);
void change_process_leader(Process *proc, Process *leader);
void remove_process(Process *proc);
void install_event_handler(Process *proc, struct event_handler *handler);
void destroy_event_handler(Process *proc);

#endif /* _PROC_H_ */
