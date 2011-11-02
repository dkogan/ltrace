#include "config.h"

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <assert.h>
#include <sys/time.h>
#include <errno.h>

#include "common.h"

#ifdef __powerpc__
#include <sys/ptrace.h>
#endif

static void handle_signal(Event *event);
static void handle_exit(Event *event);
static void handle_exit_signal(Event *event);
static void handle_syscall(Event *event);
static void handle_arch_syscall(Event *event);
static void handle_sysret(Event *event);
static void handle_arch_sysret(Event *event);
static void handle_clone(Event *event);
static void handle_exec(Event *event);
static void handle_breakpoint(Event *event);
static void handle_new(Event *event);

static void callstack_push_syscall(Process *proc, int sysnum);
static void callstack_push_symfunc(Process *proc,
				   struct library_symbol *sym);
static void callstack_pop(Process *proc);

static char * shortsignal(Process *proc, int signum);
static char * sysname(Process *proc, int sysnum);
static char * arch_sysname(Process *proc, int sysnum);

static Event *
call_handler(Process * proc, Event * event)
{
	assert(proc != NULL);

	Event_Handler * handler = proc->event_handler;
	if (handler == NULL)
		return event;

	return (*handler->on_event) (handler, event);
}

void
handle_event(Event *event) {
	if (exiting == 1) {
		exiting = 2;
		debug(1, "ltrace about to exit");
		ltrace_exiting();
	}
	debug(DEBUG_FUNCTION, "handle_event(pid=%d, type=%d)",
	      event->proc ? event->proc->pid : -1, event->type);

	/* If the thread group or an individual task define an
	   overriding event handler, give them a chance to kick in.
	   We will end up calling both handlers, if the first one
	   doesn't sink the event.  */
	if (event->proc != NULL) {
		event = call_handler(event->proc, event);
		if (event == NULL)
			/* It was handled.  */
			return;

		/* Note: the previous handler has a chance to alter
		 * the event.  */
		if (event->proc != NULL
		    && event->proc->leader != NULL
		    && event->proc != event->proc->leader) {
			event = call_handler(event->proc->leader, event);
			if (event == NULL)
				return;
		}
	}

	switch (event->type) {
	case EVENT_NONE:
		debug(1, "event: none");
		return;
	case EVENT_SIGNAL:
		debug(1, "event: signal (%s [%d])",
		      shortsignal(event->proc, event->e_un.signum),
		      event->e_un.signum);
		handle_signal(event);
		return;
	case EVENT_EXIT:
		debug(1, "event: exit (%d)", event->e_un.ret_val);
		handle_exit(event);
		return;
	case EVENT_EXIT_SIGNAL:
		debug(1, "event: exit signal (%s [%d])",
		      shortsignal(event->proc, event->e_un.signum),
		      event->e_un.signum);
		handle_exit_signal(event);
		return;
	case EVENT_SYSCALL:
		debug(1, "event: syscall (%s [%d])",
		      sysname(event->proc, event->e_un.sysnum),
		      event->e_un.sysnum);
		handle_syscall(event);
		return;
	case EVENT_SYSRET:
		debug(1, "event: sysret (%s [%d])",
		      sysname(event->proc, event->e_un.sysnum),
		      event->e_un.sysnum);
		handle_sysret(event);
		return;
	case EVENT_ARCH_SYSCALL:
		debug(1, "event: arch_syscall (%s [%d])",
				arch_sysname(event->proc, event->e_un.sysnum),
				event->e_un.sysnum);
		handle_arch_syscall(event);
		return;
	case EVENT_ARCH_SYSRET:
		debug(1, "event: arch_sysret (%s [%d])",
				arch_sysname(event->proc, event->e_un.sysnum),
				event->e_un.sysnum);
		handle_arch_sysret(event);
		return;
	case EVENT_CLONE:
	case EVENT_VFORK:
		debug(1, "event: clone (%u)", event->e_un.newpid);
		handle_clone(event);
		return;
	case EVENT_EXEC:
		debug(1, "event: exec()");
		handle_exec(event);
		return;
	case EVENT_BREAKPOINT:
		debug(1, "event: breakpoint");
		handle_breakpoint(event);
		return;
	case EVENT_NEW:
		debug(1, "event: new process");
		handle_new(event);
		return;
	default:
		fprintf(stderr, "Error! unknown event?\n");
		exit(1);
	}
}

/* TODO */
static void *
address_clone(void * addr, void * data)
{
	debug(DEBUG_FUNCTION, "address_clone(%p)", addr);
	return addr;
}

static void *
breakpoint_clone(void * bp, void * data)
{
	Breakpoint * b;
	Dict * map = data;
	debug(DEBUG_FUNCTION, "breakpoint_clone(%p)", bp);
	b = malloc(sizeof(Breakpoint));
	if (!b) {
		perror("malloc()");
		exit(1);
	}
	memcpy(b, bp, sizeof(Breakpoint));
	if (b->libsym != NULL) {
		struct library_symbol * sym = dict_find_entry(map, b->libsym);
		if (b->libsym == NULL) {
			fprintf(stderr, "Can't find cloned symbol %s.\n",
				b->libsym->name);
			return NULL;
		}
		b->libsym = sym;
	}
	return b;
}

typedef struct Pending_New Pending_New;
struct Pending_New {
	pid_t pid;
	Pending_New * next;
};
static Pending_New * pending_news = NULL;

static int
pending_new(pid_t pid) {
	Pending_New * p;

	debug(DEBUG_FUNCTION, "pending_new(%d)", pid);

	p = pending_news;
	while (p) {
		if (p->pid == pid) {
			return 1;
		}
		p = p->next;
	}
	return 0;
}

static void
pending_new_insert(pid_t pid) {
	Pending_New * p;

	debug(DEBUG_FUNCTION, "pending_new_insert(%d)", pid);

	p = malloc(sizeof(Pending_New));
	if (!p) {
		perror("malloc()");
		exit(1);
	}
	p->pid = pid;
	p->next = pending_news;
	pending_news = p;
}

static void
pending_new_remove(pid_t pid) {
	Pending_New *p, *pred;

	debug(DEBUG_FUNCTION, "pending_new_remove(%d)", pid);

	p = pending_news;
	if (p->pid == pid) {
		pending_news = p->next;
		free(p);
	} else {
		while (p) {
			if (p->pid == pid) {
				pred->next = p->next;
				free(p);
			}
			pred = p;
			p = p->next;
		}
	}
}

static int
clone_breakpoints(Process * proc, Process * orig_proc)
{
	/* When copying breakpoints, we also have to copy the
	 * referenced symbols, and link them properly.  */
	Dict * map = dict_init(&dict_key2hash_int, &dict_key_cmp_int);
	struct library_symbol * it = proc->list_of_symbols;
	proc->list_of_symbols = NULL;
	for (; it != NULL; it = it->next) {
		struct library_symbol * libsym = clone_library_symbol(it);
		if (libsym == NULL) {
			int save_errno;
		err:
			save_errno = errno;
			destroy_library_symbol_chain(proc->list_of_symbols);
			dict_clear(map);
			errno = save_errno;
			return -1;
		}
		libsym->next = proc->list_of_symbols;
		proc->list_of_symbols = libsym;
		if (dict_enter(map, it, libsym) != 0)
			goto err;
	}

	proc->breakpoints = dict_clone2(orig_proc->breakpoints,
					address_clone, breakpoint_clone, map);
	if (proc->breakpoints == NULL)
		goto err;

	dict_clear(map);
	return 0;
}

static void
handle_clone(Event * event) {
	Process *p;

	debug(DEBUG_FUNCTION, "handle_clone(pid=%d)", event->proc->pid);

	p = malloc(sizeof(Process));
	if (!p) {
		perror("malloc()");
		exit(1);
	}
	memcpy(p, event->proc, sizeof(Process));
	p->pid = event->e_un.newpid;
	p->parent = event->proc;

	/* We save register values to the arch pointer, and these need
	   to be per-thread.  */
	p->arch_ptr = NULL;

	if (pending_new(p->pid)) {
		pending_new_remove(p->pid);
		if (p->event_handler != NULL)
			destroy_event_handler(p);
		if (event->proc->state == STATE_ATTACHED && options.follow) {
			p->state = STATE_ATTACHED;
		} else {
			p->state = STATE_IGNORED;
		}
		continue_process(p->pid);
		add_process(p);
	} else {
		p->state = STATE_BEING_CREATED;
		add_process(p);
	}

	if (p->leader == p)
		clone_breakpoints(p, event->proc->leader);
	else
		/* Thread groups share breakpoints.  */
		p->breakpoints = NULL;

	if (event->type == EVENT_VFORK)
		continue_after_vfork(p);
	else
		continue_process(event->proc->pid);
}

static void
handle_new(Event * event) {
	Process * proc;

	debug(DEBUG_FUNCTION, "handle_new(pid=%d)", event->e_un.newpid);

	proc = pid2proc(event->e_un.newpid);
	if (!proc) {
		pending_new_insert(event->e_un.newpid);
	} else {
		assert(proc->state == STATE_BEING_CREATED);
		if (options.follow) {
			proc->state = STATE_ATTACHED;
		} else {
			proc->state = STATE_IGNORED;
		}
		continue_process(proc->pid);
	}
}

static char *
shortsignal(Process *proc, int signum) {
	static char *signalent0[] = {
#include "signalent.h"
	};
	static char *signalent1[] = {
#include "signalent1.h"
	};
	static char **signalents[] = { signalent0, signalent1 };
	int nsignals[] = { sizeof signalent0 / sizeof signalent0[0],
		sizeof signalent1 / sizeof signalent1[0]
	};

	debug(DEBUG_FUNCTION, "shortsignal(pid=%d, signum=%d)", proc->pid, signum);

	if (proc->personality > sizeof signalents / sizeof signalents[0])
		abort();
	if (signum < 0 || signum >= nsignals[proc->personality]) {
		return "UNKNOWN_SIGNAL";
	} else {
		return signalents[proc->personality][signum];
	}
}

static char *
sysname(Process *proc, int sysnum) {
	static char result[128];
	static char *syscalent0[] = {
#include "syscallent.h"
	};
	static char *syscalent1[] = {
#include "syscallent1.h"
	};
	static char **syscalents[] = { syscalent0, syscalent1 };
	int nsyscals[] = { sizeof syscalent0 / sizeof syscalent0[0],
		sizeof syscalent1 / sizeof syscalent1[0]
	};

	debug(DEBUG_FUNCTION, "sysname(pid=%d, sysnum=%d)", proc->pid, sysnum);

	if (proc->personality > sizeof syscalents / sizeof syscalents[0])
		abort();
	if (sysnum < 0 || sysnum >= nsyscals[proc->personality]) {
		sprintf(result, "SYS_%d", sysnum);
		return result;
	} else {
		sprintf(result, "SYS_%s",
			syscalents[proc->personality][sysnum]);
		return result;
	}
}

static char *
arch_sysname(Process *proc, int sysnum) {
	static char result[128];
	static char *arch_syscalent[] = {
#include "arch_syscallent.h"
	};
	int nsyscals = sizeof arch_syscalent / sizeof arch_syscalent[0];

	debug(DEBUG_FUNCTION, "arch_sysname(pid=%d, sysnum=%d)", proc->pid, sysnum);

	if (sysnum < 0 || sysnum >= nsyscals) {
		sprintf(result, "ARCH_%d", sysnum);
		return result;
	} else {
		sprintf(result, "ARCH_%s",
				arch_syscalent[sysnum]);
		return result;
	}
}

static void
handle_signal(Event *event) {
	debug(DEBUG_FUNCTION, "handle_signal(pid=%d, signum=%d)", event->proc->pid, event->e_un.signum);
	if (event->proc->state != STATE_IGNORED && !options.no_signals) {
		output_line(event->proc, "--- %s (%s) ---",
				shortsignal(event->proc, event->e_un.signum),
				strsignal(event->e_un.signum));
	}
	continue_after_signal(event->proc->pid, event->e_un.signum);
}

static void
handle_exit(Event *event) {
	debug(DEBUG_FUNCTION, "handle_exit(pid=%d, status=%d)", event->proc->pid, event->e_un.ret_val);
	if (event->proc->state != STATE_IGNORED) {
		output_line(event->proc, "+++ exited (status %d) +++",
				event->e_un.ret_val);
	}
	remove_process(event->proc);
}

static void
handle_exit_signal(Event *event) {
	debug(DEBUG_FUNCTION, "handle_exit_signal(pid=%d, signum=%d)", event->proc->pid, event->e_un.signum);
	if (event->proc->state != STATE_IGNORED) {
		output_line(event->proc, "+++ killed by %s +++",
				shortsignal(event->proc, event->e_un.signum));
	}
	remove_process(event->proc);
}

static void
handle_syscall(Event *event) {
	debug(DEBUG_FUNCTION, "handle_syscall(pid=%d, sysnum=%d)", event->proc->pid, event->e_un.sysnum);
	if (event->proc->state != STATE_IGNORED) {
		callstack_push_syscall(event->proc, event->e_un.sysnum);
		if (options.syscalls) {
			output_left(LT_TOF_SYSCALL, event->proc,
				    sysname(event->proc, event->e_un.sysnum));
		}
		if (event->proc->breakpoints_enabled == 0) {
			enable_all_breakpoints(event->proc);
		}
	}
	continue_after_syscall(event->proc, event->e_un.sysnum, 0);
}

static void
handle_exec(Event * event) {
	Process * proc = event->proc;
	pid_t saved_pid;

	debug(DEBUG_FUNCTION, "handle_exec(pid=%d)", proc->pid);
	if (proc->state == STATE_IGNORED) {
		untrace_pid(proc->pid);
		remove_process(proc);
		return;
	}
	output_line(proc, "--- Called exec() ---");
	proc->mask_32bit = 0;
	proc->personality = 0;
	proc->arch_ptr = NULL;
	free(proc->filename);
	proc->filename = pid2name(proc->pid);
	saved_pid = proc->pid;
	proc->pid = 0;
	breakpoints_init(proc, 0);
	proc->pid = saved_pid;
	proc->callstack_depth = 0;
	continue_process(proc->pid);
}

static void
handle_arch_syscall(Event *event) {
	debug(DEBUG_FUNCTION, "handle_arch_syscall(pid=%d, sysnum=%d)", event->proc->pid, event->e_un.sysnum);
	if (event->proc->state != STATE_IGNORED) {
		callstack_push_syscall(event->proc, 0xf0000 + event->e_un.sysnum);
		if (options.syscalls) {
			output_left(LT_TOF_SYSCALL, event->proc,
					arch_sysname(event->proc, event->e_un.sysnum));
		}
		if (event->proc->breakpoints_enabled == 0) {
			enable_all_breakpoints(event->proc);
		}
	}
	continue_process(event->proc->pid);
}

struct timeval current_time_spent;

static void
calc_time_spent(Process *proc) {
	struct timeval tv;
	struct timezone tz;
	struct timeval diff;
	struct callstack_element *elem;

	debug(DEBUG_FUNCTION, "calc_time_spent(pid=%d)", proc->pid);
	elem = &proc->callstack[proc->callstack_depth - 1];

	gettimeofday(&tv, &tz);

	diff.tv_sec = tv.tv_sec - elem->time_spent.tv_sec;
	if (tv.tv_usec >= elem->time_spent.tv_usec) {
		diff.tv_usec = tv.tv_usec - elem->time_spent.tv_usec;
	} else {
		diff.tv_sec++;
		diff.tv_usec = 1000000 + tv.tv_usec - elem->time_spent.tv_usec;
	}
	current_time_spent = diff;
}

static void
handle_sysret(Event *event) {
	debug(DEBUG_FUNCTION, "handle_sysret(pid=%d, sysnum=%d)", event->proc->pid, event->e_un.sysnum);
	if (event->proc->state != STATE_IGNORED) {
		if (opt_T || options.summary) {
			calc_time_spent(event->proc);
		}
		if (options.syscalls) {
			output_right(LT_TOF_SYSCALLR, event->proc,
					sysname(event->proc, event->e_un.sysnum));
		}
		assert(event->proc->callstack_depth > 0);
		unsigned d = event->proc->callstack_depth - 1;
		assert(event->proc->callstack[d].is_syscall);
		callstack_pop(event->proc);
	}
	continue_after_syscall(event->proc, event->e_un.sysnum, 1);
}

static void
handle_arch_sysret(Event *event) {
	debug(DEBUG_FUNCTION, "handle_arch_sysret(pid=%d, sysnum=%d)", event->proc->pid, event->e_un.sysnum);
	if (event->proc->state != STATE_IGNORED) {
		if (opt_T || options.summary) {
			calc_time_spent(event->proc);
		}
		if (options.syscalls) {
			output_right(LT_TOF_SYSCALLR, event->proc,
					arch_sysname(event->proc, event->e_un.sysnum));
		}
		callstack_pop(event->proc);
	}
	continue_process(event->proc->pid);
}

#ifdef __powerpc__
void *get_count_register (Process *proc);
#endif

static void
handle_breakpoint(Event *event) {
	int i, j;
	Breakpoint *sbp;
	Process *leader = event->proc->leader;

	/* The leader has terminated.  */
	if (leader == NULL) {
		continue_process(event->proc->pid);
		return;
	}

	debug(DEBUG_FUNCTION, "handle_breakpoint(pid=%d, addr=%p)", event->proc->pid, event->e_un.brk_addr);
	debug(2, "event: breakpoint (%p)", event->e_un.brk_addr);

#ifdef __powerpc__
	/* Need to skip following NOP's to prevent a fake function from being stacked.  */
	long stub_addr = (long) get_count_register(event->proc);
	Breakpoint *stub_bp = NULL;
	char nop_instruction[] = PPC_NOP;

	stub_bp = address2bpstruct(leader, event->e_un.brk_addr);

	if (stub_bp) {
		unsigned char *bp_instruction = stub_bp->orig_value;

		if (memcmp(bp_instruction, nop_instruction,
			    PPC_NOP_LENGTH) == 0) {
			if (stub_addr != (long) event->e_un.brk_addr) {
				set_instruction_pointer (event->proc, event->e_un.brk_addr + 4);
				continue_process(event->proc->pid);
				return;
			}
		}
	}
#endif

	for (i = event->proc->callstack_depth - 1; i >= 0; i--) {
		if (event->e_un.brk_addr ==
		    event->proc->callstack[i].return_addr) {
#ifdef __powerpc__
			/*
			 * PPC HACK! (XXX FIXME TODO)
			 * The PLT gets modified during the first call,
			 * so be sure to re-enable the breakpoint.
			 */
			unsigned long a;
			struct library_symbol *libsym =
			    event->proc->callstack[i].c_un.libfunc;
			void *addr = sym2addr(event->proc, libsym);

			if (libsym->plt_type != LS_TOPLT_POINT) {
				unsigned char break_insn[] = BREAKPOINT_VALUE;

				sbp = address2bpstruct(leader, addr);
				assert(sbp);
				a = ptrace(PTRACE_PEEKTEXT, event->proc->pid,
					   addr);

				if (memcmp(&a, break_insn, BREAKPOINT_LENGTH)) {
					sbp->enabled--;
					insert_breakpoint(event->proc, addr,
							  libsym, 1);
				}
			} else {
				sbp = dict_find_entry(leader->breakpoints, addr);
				/* On powerpc, the breakpoint address
				   may end up being actual entry point
				   of the library symbol, not the PLT
				   address we computed.  In that case,
				   sbp is NULL.  */
				if (sbp == NULL || addr != sbp->addr) {
					insert_breakpoint(event->proc, addr,
							  libsym, 1);
				}
			}
#elif defined(__mips__)
			void *addr = NULL;
			struct library_symbol *sym= event->proc->callstack[i].c_un.libfunc;
			struct library_symbol *new_sym;
			assert(sym);
			addr = sym2addr(leader, sym);
			sbp = dict_find_entry(leader->breakpoints, addr);
			if (sbp) {
				if (addr != sbp->addr) {
					insert_breakpoint(event->proc, addr, sym, 1);
				}
			} else {
				new_sym=malloc(sizeof(*new_sym) + strlen(sym->name) + 1);
				memcpy(new_sym,sym,sizeof(*new_sym) + strlen(sym->name) + 1);
				new_sym->next = leader->list_of_symbols;
				leader->list_of_symbols = new_sym;
				insert_breakpoint(event->proc, addr, new_sym, 1);
			}
#endif
			for (j = event->proc->callstack_depth - 1; j > i; j--) {
				callstack_pop(event->proc);
			}
			if (event->proc->state != STATE_IGNORED) {
				if (opt_T || options.summary) {
					calc_time_spent(event->proc);
				}
			}
			event->proc->return_addr = event->e_un.brk_addr;
			if (event->proc->state != STATE_IGNORED) {
				output_right(LT_TOF_FUNCTIONR, event->proc,
						event->proc->callstack[i].c_un.libfunc->name);
			}
			callstack_pop(event->proc);
			sbp = address2bpstruct(leader, event->e_un.brk_addr);
			continue_after_breakpoint(event->proc, sbp);
			return;
		}
	}

	if ((sbp = address2bpstruct(leader, event->e_un.brk_addr))) {
		if (sbp->libsym == NULL) {
			continue_after_breakpoint(event->proc, sbp);
			return;
		}

		if (strcmp(sbp->libsym->name, "") == 0) {
			debug(DEBUG_PROCESS, "Hit _dl_debug_state breakpoint!\n");
			arch_check_dbg(leader);
		}

		if (event->proc->state != STATE_IGNORED) {
			event->proc->stack_pointer = get_stack_pointer(event->proc);
			event->proc->return_addr =
				get_return_addr(event->proc, event->proc->stack_pointer);
			callstack_push_symfunc(event->proc, sbp->libsym);
			output_left(LT_TOF_FUNCTION, event->proc, sbp->libsym->name);
		}
#ifdef PLT_REINITALISATION_BP
		if (event->proc->need_to_reinitialize_breakpoints
		    && (strcmp(sbp->libsym->name, PLTs_initialized_by_here) ==
			0))
			reinitialize_breakpoints(leader);
#endif

		continue_after_breakpoint(event->proc, sbp);
		return;
	}

	if (event->proc->state != STATE_IGNORED && !options.no_plt) {
		output_line(event->proc, "unexpected breakpoint at %p",
				(void *)event->e_un.brk_addr);
	}
	continue_process(event->proc->pid);
}

static void
callstack_push_syscall(Process *proc, int sysnum) {
	struct callstack_element *elem;

	debug(DEBUG_FUNCTION, "callstack_push_syscall(pid=%d, sysnum=%d)", proc->pid, sysnum);
	/* FIXME: not good -- should use dynamic allocation. 19990703 mortene. */
	if (proc->callstack_depth == MAX_CALLDEPTH - 1) {
		fprintf(stderr, "%s: Error: call nesting too deep!\n", __func__);
		abort();
		return;
	}

	elem = &proc->callstack[proc->callstack_depth];
	elem->is_syscall = 1;
	elem->c_un.syscall = sysnum;
	elem->return_addr = NULL;

	proc->callstack_depth++;
	if (opt_T || options.summary) {
		struct timezone tz;
		gettimeofday(&elem->time_spent, &tz);
	}
}

static void
callstack_push_symfunc(Process *proc, struct library_symbol *sym) {
	struct callstack_element *elem, *prev;

	debug(DEBUG_FUNCTION, "callstack_push_symfunc(pid=%d, symbol=%s)", proc->pid, sym->name);
	/* FIXME: not good -- should use dynamic allocation. 19990703 mortene. */
	if (proc->callstack_depth == MAX_CALLDEPTH - 1) {
		fprintf(stderr, "%s: Error: call nesting too deep!\n", __func__);
		abort();
		return;
	}

	prev = &proc->callstack[proc->callstack_depth-1];
	elem = &proc->callstack[proc->callstack_depth];
	elem->is_syscall = 0;
	elem->c_un.libfunc = sym;

	elem->return_addr = proc->return_addr;
	if (elem->return_addr) {
		insert_breakpoint(proc, elem->return_addr, NULL, 1);
	}

	/* handle functions like atexit() on mips which have no return */
	if (elem->return_addr != prev->return_addr)
		proc->callstack_depth++;
	if (opt_T || options.summary) {
		struct timezone tz;
		gettimeofday(&elem->time_spent, &tz);
	}
}

static void
callstack_pop(Process *proc) {
	struct callstack_element *elem;
	assert(proc->callstack_depth > 0);

	debug(DEBUG_FUNCTION, "callstack_pop(pid=%d)", proc->pid);
	elem = &proc->callstack[proc->callstack_depth - 1];
	if (!elem->is_syscall && elem->return_addr) {
		assert(proc->leader != NULL);
		delete_breakpoint(proc, elem->return_addr);
	}
	if (elem->arch_ptr != NULL) {
		free(elem->arch_ptr);
		elem->arch_ptr = NULL;
	}
	proc->callstack_depth--;
}
