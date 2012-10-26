/*
 * This file is part of ltrace.
 * Copyright (C) 2012 Petr Machata, Red Hat Inc.
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

#ifndef BACKEND_H
#define BACKEND_H

#include "forward.h"
#include "sysdep.h"

#include <gelf.h>

enum process_status {
	ps_invalid,	/* Failure.  */
	ps_stop,	/* Job-control stop.  */
	ps_tracing_stop,
	ps_sleeping,
	ps_zombie,
	ps_other,	/* Necessary other states can be added as needed.  */
};

/*
 * This file contains documentation of back end interface.  Some of
 * these may be implemented on an OS level (i.e. they are the same
 * e.g. on all Linux architectures), some may differ per architecture
 * on the same OS (e.g. a way to insert a breakpoint into the process
 * image is a likely candidate).
 */

/* Convert a PID to a path to the corresponding binary.  */
char *pid2name(pid_t pid);

/* Given a PID, find a leader of thread group.  */
pid_t process_leader(pid_t pid);

/* Given a PID of leader thread, fill in PIDs of all the tasks.  The
 * function will initialize the pointer *RET_TASKS to a
 * newly-allocated array, and will store number of elements in that
 * array to *RET_N.  You have to free that buffer when you don't need
 * it anymore.  */
int process_tasks(pid_t pid, pid_t **ret_tasks, size_t *ret_n);

/* Answer whether the process PID is stopped.  Returns 0 when not
 * stopped, 1 when stopped, or -1 when there was an error.  */
int process_stopped(pid_t pid);

/* Answer a status of the task PID.  See enum process_status.  */
enum process_status process_status(pid_t pid);

/* Wait for PID to be ready for tracing.  */
int wait_for_proc(pid_t pid);

/* Send a signal SIG to the task PID.  */
int task_kill(pid_t pid, int sig);

/* Called after PID is attached, but before it is continued.  */
void trace_set_options(struct Process *proc);

/* Called after ltrace forks.  Should attach the newly created child,
 * in whose context this function is called.  */
void trace_me(void);

/* Called when ltrace needs to attach to PID, such as when it attaches
 * to a running process, whose PID is given on the command line.  */
int trace_pid(pid_t pid);

/* Stop tracing PID.  */
void untrace_pid(pid_t pid);

/* The back end may need to store arbitrary data to a process.  This
 * is a place where it can initialize PROC->arch_dep.  XXX this should
 * be dropped in favor of arhc_process_init on pmachata/libs.  */
void get_arch_dep(struct Process *proc);

/* Return current instruction pointer of PROC.
 *
 * XXX note that the IP must fit into an arch pointer.  This prevents
 * us to use 32-bit ltrace to trace 64-bit process, even on arches
 * that would otherwise support this.  Above we have a definition of
 * arch_addr_t.  This should be converted to an integral type and
 * used for target addresses throughout.  */
void *get_instruction_pointer(struct Process *proc);

/* Set instruction pointer of PROC to ADDR.  XXX see above.  */
void set_instruction_pointer(struct Process *proc, void *addr);

/* Return current stack pointer of PROC.  XXX see above.  */
void *get_stack_pointer(struct Process *proc);

/* Find and return caller address, i.e. the address where the current
 * function returns.  */
void *get_return_addr(struct Process *proc, void *stack_pointer);

/* Adjust PROC so that when the current function returns, it returns
 * to ADDR.  */
void set_return_addr(struct Process *proc, void *addr);

/* Enable breakpoint SBP in process PROC.  */
void enable_breakpoint(struct Process *proc, struct breakpoint *sbp);

/* Disable breakpoint SBP in process PROC.  */
void disable_breakpoint(struct Process *proc, struct breakpoint *sbp);

/* Determine whether the event that we have just seen (and that is
 * recorded in STATUS) was a syscall.  If it was, return 1.  If it was
 * a return from syscall, return 2.  In both cases, set *SYSNUM to the
 * number of said syscall.  If it wasn't a syscall, return 0.  If
 * there was an error, return -1.  */
int syscall_p(struct Process *proc, int status, int *sysnum);

/* Continue execution of the process with given PID.  */
void continue_process(pid_t pid);

/* Called after we received a signal SIGNUM.  Should do whatever
 * book-keeping is necessary and continue the process if
 * necessary.  */
void continue_after_signal(pid_t pid, int signum);

/* Called after we received a system call SYSNUM.  RET_P is 0 if this
 * is system call, otherwise it's return from a system call.  The
 * callback should do whatever book-keeping is necessary and continue
 * the process if necessary.  */
void continue_after_syscall(struct Process *proc, int sysnum, int ret_p);

/* Called after we hit a breakpoint SBP.  Should do whatever
 * book-keeping is necessary and then continue the process.  */
void continue_after_breakpoint(struct Process *proc, struct breakpoint *sbp);

/* Called after we received a vfork.  Should do whatever book-keeping
 * is necessary and continue the process if necessary.  N.B. right
 * now, with Linux/GNU the only back end, this is not necessary.  I
 * imagine other systems may be different.  */
void continue_after_vfork(struct Process *proc);

/* Called when trace_me or primary trace_pid fail.  This may plug in
 * any platform-specific knowledge of why it could be so.  */
void trace_fail_warning(pid_t pid);

/* A pair of functions called to initiate a detachment request when
 * ltrace is about to exit.  Their job is to undo any effects that
 * tracing had and eventually detach process, perhaps by way of
 * installing a process handler.
 *
 * OS_LTRACE_EXITING_SIGHANDLER is called from a signal handler
 * context right after the signal was captured.  It returns 1 if the
 * request was handled or 0 if it wasn't.
 *
 * If the call to OS_LTRACE_EXITING_SIGHANDLER didn't handle the
 * request, OS_LTRACE_EXITING is called when the next event is
 * generated.  Therefore it's called in "safe" context, without
 * re-entrancy concerns, but it's only called after an even is
 * generated.  */
int os_ltrace_exiting_sighandler(void);
void os_ltrace_exiting(void);

/* Should copy COUNT bytes from address ADDR of process PROC to local
 * buffer BUF.  */
size_t umovebytes (struct Process *proc, void *addr, void *buf, size_t count);

/* Find out an address of symbol SYM in process PROC, and return.
 * Returning NULL delays breakpoint insertion and enables heaps of
 * arch-specific black magic that we should clean up some day.
 *
 * XXX the same points as for get_instruction_pointer apply. */
void *sym2addr(struct Process *proc, struct library_symbol *sym);

/* Obtain address of PLT entry corresponding to relocation RELA in
 * file LTE.  This is NDX-th PLT entry in the file.
 *
 * XXX should this return arch_addr_t?  */
GElf_Addr arch_plt_sym_val(struct ltelf *lte, size_t ndx, GElf_Rela *rela);

/* Called at some point after we have attached to PROC.  This callback
 * should insert an introspection breakpoint for handling dynamic
 * linker library loads.  */
int linkmap_init(struct Process *proc, arch_addr_t dyn_addr);

/* This should produce and return the next event of one of the traced
 * processes.  The returned pointer will not be freed by the core and
 * should be either statically allocated, or the management should be
 * done some other way.  */
struct Event *next_event(void);

/* Called when process PROC was removed.  */
void process_removed(struct Process *proc);

/* This should extract entry point address and interpreter (dynamic
 * linker) bias if possible.  Returns 0 if there were no errors, -1
 * otherwise.  Sets *ENTRYP and *INTERP_BIASP to non-zero values if
 * the corresponding value is known, or zero otherwise; this is not
 * done for pointers that are NULL.  */
int process_get_entry(struct Process *proc,
		      arch_addr_t *entryp,
		      arch_addr_t *interp_biasp);


/* Optional callbacks
 *
 * Some callbacks are only available if backend (arch.h) has a certain
 * define.  If such a define is not present, default implementation
 * (most often doing nothing at all) us used instead.  This is used
 * for gradual extensions of ltrace, so that backends that are not
 * fully up to date, or that don't need certain functionality, keep
 * working, while other backends take advantage of the optional
 * features.  */

/* The following callbacks have to be implemented in backend if arch.h
 * defines ARCH_HAVE_LTELF_DATA.  Those are used to init and destroy
 * LTE->arch.  arch_elf_init returns 0 on success or a negative value
 * on failure.  */
int arch_elf_init(struct ltelf *lte, struct library *lib);
void arch_elf_destroy(struct ltelf *lte);

/* The following callbacks have to be implemented in backend if arch.h
 * defines ARCH_HAVE_BREAKPOINT_DATA.  Those are used to init,
 * destroy, and clone SBP->arch.  arch_breakpoint_init and
 * arch_breakpoint_clone return 0 on success or a negative value on
 * failure.  */
int arch_breakpoint_init(struct Process *proc, struct breakpoint *sbp);
void arch_breakpoint_destroy(struct breakpoint *sbp);
int arch_breakpoint_clone(struct breakpoint *retp, struct breakpoint *sbp);

/* The following callbacks have to be implemented in backend if arch.h
 * defines ARCH_HAVE_LIBRARY_DATA.  Those are used to init, destroy
 * and clone LIB->arch.  */
void arch_library_init(struct library *lib);
void arch_library_destroy(struct library *lib);
void arch_library_clone(struct library *retp, struct library *lib);

/* The following callbacks have to be implemented in backend if arch.h
 * defines ARCH_HAVE_LIBRARY_SYMBOL_DATA.  Those are used to init,
 * destroy and clone LIBSYM->arch.  arch_library_symbol_init and
 * arch_library_symbol_clone return 0 on success or a negative value
 * on failure.  */
int arch_library_symbol_init(struct library_symbol *libsym);
void arch_library_symbol_destroy(struct library_symbol *libsym);
int arch_library_symbol_clone(struct library_symbol *retp,
			      struct library_symbol *libsym);

/* The following callbacks have to be implemented in backend if arch.h
 * defines ARCH_HAVE_PROCESS_DATA.  Those are used to init, destroy
 * and clone PROC->arch.  arch_process_exec is called to update
 * PROC->arch in case that PROC underwent an exec.  See notes at
 * process_init, process_destroy, process_clone and process_exec in
 * proc.h.  */
int arch_process_init(struct Process *proc);
void arch_process_destroy(struct Process *proc);
int arch_process_clone(struct Process *retp, struct Process *proc);
int arch_process_exec(struct Process *proc);

/* The following callbacks have to be implemented in OS backend if
 * os.h defines OS_HAVE_PROCESS_DATA.  The protocol is same as for,
 * respectively, arch_process_init, arch_process_destroy,
 * arch_process_clone and arch_process_exec.  */
int os_process_init(struct Process *proc);
void os_process_destroy(struct Process *proc);
int os_process_clone(struct Process *retp, struct Process *proc);
int os_process_exec(struct Process *proc);

/* The following callback has to be implemented in backend if arch.h
 * defines ARCH_HAVE_GET_SYM_INFO.
 *
 * This is called for every PLT relocation R in ELF file LTE, that
 * ltrace is about to add to it's internal representation of the
 * program under trace.
 * The corresponding PLT entry is for SYM_INDEX-th relocation in the file.
 *
 * The callback is responsible for initializing RELA and SYM.
 *
 * Return 0 if OK.
 * Return a negative value if this symbol (SYM_INDEX) should be ignored.  */
int arch_get_sym_info(struct ltelf *lte, const char *filename,
		      size_t sym_index, GElf_Rela *rela, GElf_Sym *sym);

enum plt_status {
	plt_fail,
	plt_ok,
	plt_default,
};

/* The following callback has to be implemented in backend if arch.h
 * defines ARCH_HAVE_ADD_PLT_ENTRY.
 *
 * This is called for every PLT relocation R in ELF file LTE, that
 * ltrace is about to add to a library constructed in process PROC.
 * The corresponding PLT entry is for symbol called NAME, and it's
 * I-th relocation in the file.
 *
 * If this function returns plt_default, PLT address is obtained by
 * calling arch_plt_sym_val, and symbol is allocated.  If plt_ok or
 * plt_default are returned, the chain of symbols passed back in RET
 * is added to library under construction.  */
enum plt_status arch_elf_add_plt_entry(struct Process *proc, struct ltelf *lte,
				       const char *name, GElf_Rela *rela,
				       size_t i, struct library_symbol **ret);

/* This callback needs to be implemented if arch.h defines
 * ARCH_HAVE_DYNLINK_DONE.  It is called after the dynamic linker is
 * done with the process startup.  */
void arch_dynlink_done(struct Process *proc);

/* This callback needs to be implemented if arch.h defines
 * ARCH_HAVE_SYMBOL_RET.  It is called after a traced call returns.  */
void arch_symbol_ret(struct Process *proc, struct library_symbol *libsym);


/* This callback needs to be implemented if arch.h defines
 * ARCH_HAVE_FIND_DL_DEBUG.
 * It is called by generic code to find the address of the dynamic
 * linkers debug structure.
 * DYN_ADDR holds the address of the dynamic section.
 * If the debug area is found, return 0 and fill in the address in *RET.
 * If the debug area is not found, return a negative value.  */
int arch_find_dl_debug(struct Process *proc, arch_addr_t dyn_addr,
		       arch_addr_t *ret);

/* If arch.h defines ARCH_HAVE_FETCH_ARG, the following callbacks have
 * to be implemented: arch_fetch_arg_init, arch_fetch_arg_clone,
 * arch_fetch_arg_done, arch_fetch_arg_next and arch_fetch_retval.
 * See fetch.h for details.  */

/* If arch.h defines both ARCH_HAVE_FETCH_ARG and
 * ARCH_HAVE_FETCH_PACK, the following callbacks have to be
 * implemented: arch_fetch_param_pack_start,
 * arch_fetch_param_pack_end.  See fetch.h for details.  */

#endif /* BACKEND_H */
