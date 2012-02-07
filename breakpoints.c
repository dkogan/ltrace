#include "config.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#ifdef __powerpc__
#include <sys/ptrace.h>
#endif

#include "breakpoint.h"
#include "common.h"

void
breakpoint_on_hit(struct breakpoint *bp, struct Process *proc)
{
	assert(bp != NULL);
	if (bp->cbs != NULL && bp->cbs->on_hit != NULL)
		(bp->cbs->on_hit) (bp, proc);
}

void
breakpoint_on_destroy(struct breakpoint *bp)
{
	assert(bp != NULL);
	if (bp->cbs != NULL && bp->cbs->on_destroy != NULL)
		(bp->cbs->on_destroy) (bp);
}

/*****************************************************************************/

struct breakpoint *
address2bpstruct(Process *proc, void *addr)
{
	assert(proc != NULL);
	assert(proc->breakpoints != NULL);
	assert(proc->leader == proc);
	debug(DEBUG_FUNCTION, "address2bpstruct(pid=%d, addr=%p)", proc->pid, addr);
	return dict_find_entry(proc->breakpoints, addr);
}

struct breakpoint *
insert_breakpoint(Process *proc, void *addr,
		  struct library_symbol *libsym, int enable)
{
	struct breakpoint *sbp;

	Process * leader = proc->leader;

	/* Only the group leader should be getting the breakpoints and
	 * thus have ->breakpoint initialized.  */
	assert(leader != NULL);
	assert(leader->breakpoints != NULL);

#ifdef __arm__
	int thumb_mode = (int)addr & 1;
	if (thumb_mode)
		addr = (void *)((int)addr & ~1);
#endif

	debug(DEBUG_FUNCTION, "insert_breakpoint(pid=%d, addr=%p, symbol=%s)", proc->pid, addr, libsym ? libsym->name : "NULL");
	debug(1, "symbol=%s, addr=%p", libsym?libsym->name:"(nil)", addr);

	if (!addr)
		return NULL;

	if (libsym)
		libsym->needs_init = 0;

	sbp = dict_find_entry(leader->breakpoints, addr);
	if (sbp == NULL) {
		sbp = calloc(1, sizeof(*sbp));
		if (sbp == NULL) {
			return NULL;	/* TODO FIXME XXX: error_mem */
		}
		dict_enter(leader->breakpoints, addr, sbp);
		sbp->addr = addr;
		sbp->libsym = libsym;
	}
#ifdef __arm__
	sbp->thumb_mode = thumb_mode | proc->thumb_mode;
	proc->thumb_mode = 0;
#endif
	sbp->enabled++;
	if (sbp->enabled == 1 && enable) {
		assert(proc->pid != 0);
		enable_breakpoint(proc, sbp);
	}

	return sbp;
}

void
delete_breakpoint(Process *proc, void *addr)
{
	struct breakpoint *sbp;

	debug(DEBUG_FUNCTION, "delete_breakpoint(pid=%d, addr=%p)", proc->pid, addr);

	Process * leader = proc->leader;
	assert(leader != NULL);

	sbp = dict_find_entry(leader->breakpoints, addr);
	assert(sbp);		/* FIXME: remove after debugging has been done. */
	/* This should only happen on out-of-memory conditions. */
	if (sbp == NULL)
		return;

	sbp->enabled--;
	if (sbp->enabled == 0)
		disable_breakpoint(proc, sbp);
	assert(sbp->enabled >= 0);
}

static void
enable_bp_cb(void *addr, void *sbp, void *proc)
{
	debug(DEBUG_FUNCTION, "enable_bp_cb(pid=%d)", ((Process *)proc)->pid);
	if (((Breakpoint *)sbp)->enabled) {
		enable_breakpoint(proc, sbp);
	}
}

void
enable_all_breakpoints(Process *proc) {
	debug(DEBUG_FUNCTION, "enable_all_breakpoints(pid=%d)", proc->pid);
	if (proc->breakpoints_enabled <= 0) {
#ifdef __powerpc__
		unsigned long a;

		/*
		 * PPC HACK! (XXX FIXME TODO)
		 * If the dynamic linker hasn't populated the PLT then
		 * dont enable the breakpoints
		 */
		if (options.libcalls) {
			a = ptrace(PTRACE_PEEKTEXT, proc->pid,
				   sym2addr(proc, proc->list_of_symbols),
				   0);
			if (a == 0x0)
				return;
		}
#endif

		debug(1, "Enabling breakpoints for pid %u...", proc->pid);
		if (proc->breakpoints) {
			dict_apply_to_all(proc->breakpoints, enable_bp_cb,
					  proc);
		}
#ifdef __mips__
		{
			/*
			 * I'm sure there is a nicer way to do this. We need to
			 * insert breakpoints _after_ the child has been started.
			 */
			struct library_symbol *sym;
			struct library_symbol *new_sym;
			sym=proc->list_of_symbols;
			while(sym){
				void *addr= sym2addr(proc,sym);
				if(!addr){
					sym=sym->next;
					continue;
				}
				if(dict_find_entry(proc->breakpoints,addr)){
					sym=sym->next;
					continue;
				}
				debug(2,"inserting bp %p %s",addr,sym->name);
				new_sym=malloc(sizeof(*new_sym) + strlen(sym->name) + 1);
				memcpy(new_sym,sym,sizeof(*new_sym) + strlen(sym->name) + 1);
				new_sym->next=proc->list_of_symbols;
				proc->list_of_symbols=new_sym;
				insert_breakpoint(proc, addr, new_sym);
				sym=sym->next;
			}
		}
#endif
	}
	proc->breakpoints_enabled = 1;
}

static void
disable_bp_cb(void *addr, void *sbp, void *proc)
{
	debug(DEBUG_FUNCTION, "disable_bp_cb(pid=%d)", ((Process *)proc)->pid);
	if (((Breakpoint *)sbp)->enabled) {
		disable_breakpoint(proc, sbp);
	}
}

void
disable_all_breakpoints(Process *proc) {
	debug(DEBUG_FUNCTION, "disable_all_breakpoints(pid=%d)", proc->pid);
	assert(proc->leader == proc);
	if (proc->breakpoints_enabled) {
		debug(1, "Disabling breakpoints for pid %u...", proc->pid);
		dict_apply_to_all(proc->breakpoints, disable_bp_cb, proc);
	}
	proc->breakpoints_enabled = 0;
}

static void
free_bp_cb(void *addr, void *sbp, void *data) {
	debug(DEBUG_FUNCTION, "free_bp_cb(sbp=%p)", sbp);
	assert(sbp);
	free(sbp);
}

int
breakpoints_init(Process *proc, int enable)
{
	struct library_symbol *sym;

	debug(DEBUG_FUNCTION, "breakpoints_init(pid=%d)", proc->pid);
	if (proc->breakpoints) {	/* let's remove that struct */
		dict_apply_to_all(proc->breakpoints, free_bp_cb, NULL);
		dict_clear(proc->breakpoints);
		proc->breakpoints = NULL;
	}

	/* Only the thread group leader should hold the breakpoints.
	 * (N.B. PID may be set to 0 temporarily when called by
	 * handle_exec).  */
	assert(proc->leader == proc);

	proc->breakpoints = dict_init(dict_key2hash_int,
				      dict_key_cmp_int);

	destroy_library_symbol_chain(proc->list_of_symbols);
	proc->list_of_symbols = NULL;

	if (options.libcalls && proc->filename) {
		proc->list_of_symbols = read_elf(proc);
		if (proc->list_of_symbols == NULL) {
			/* XXX leak breakpoints */
			return -1;
		}

		if (opt_e) {
			struct library_symbol **tmp1 = &proc->list_of_symbols;
			while (*tmp1) {
				struct opt_e_t *tmp2 = opt_e;
				int keep = !opt_e_enable;

				while (tmp2) {
					if (!strcmp((*tmp1)->name,
						    tmp2->name)) {
						keep = opt_e_enable;
					}
					tmp2 = tmp2->next;
				}
				if (!keep) {
					*tmp1 = (*tmp1)->next;
				} else {
					tmp1 = &((*tmp1)->next);
				}
			}
		}
	}

	for (sym = proc->list_of_symbols; sym; sym = sym->next)
		insert_breakpoint(proc, sym2addr(proc, sym), sym, enable);

	proc->callstack_depth = 0;
	proc->breakpoints_enabled = -1;
	return 0;
}

void
reinitialize_breakpoints(Process *proc) {
	struct library_symbol *sym;

	debug(DEBUG_FUNCTION, "reinitialize_breakpoints(pid=%d)", proc->pid);

	sym = proc->list_of_symbols;

	while (sym) {
		if (sym->needs_init) {
			insert_breakpoint(proc, sym2addr(proc, sym), sym, 1);
			if (sym->needs_init && !sym->is_weak) {
				fprintf(stderr,
					"could not re-initialize breakpoint for \"%s\" in file \"%s\"\n",
					sym->name, proc->filename);
				exit(1);
			}
		}
		sym = sym->next;
	}
}
