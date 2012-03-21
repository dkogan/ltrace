#include "config.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <error.h>
#include <errno.h>

#ifdef __powerpc__
#include <sys/ptrace.h>
#endif

#include "breakpoint.h"
#include "common.h"
#include "proc.h"
#include "library.h"

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

#ifdef ARCH_HAVE_BREAKPOINT_DATA
int arch_breakpoint_init(struct Process *proc, struct breakpoint *sbp);
#else
int
arch_breakpoint_init(struct Process *proc, struct breakpoint *sbp)
{
	return 0;
}
#endif

int
breakpoint_init(struct breakpoint *bp, struct Process *proc,
		target_address_t addr, struct library_symbol *libsym,
		struct bp_callbacks *cbs)
{
	bp->cbs = cbs;
	bp->addr = addr;
	memset(bp->orig_value, 0, sizeof(bp->orig_value));
	bp->enabled = 0;
	bp->libsym = libsym;
	return arch_breakpoint_init(proc, bp);
}

struct breakpoint *
insert_breakpoint(Process *proc, void *addr,
		  struct library_symbol *libsym, int enable)
{
	Process * leader = proc->leader;

	/* Only the group leader should be getting the breakpoints and
	 * thus have ->breakpoint initialized.  */
	assert(leader != NULL);
	assert(leader->breakpoints != NULL);

	debug(DEBUG_FUNCTION, "insert_breakpoint(pid=%d, addr=%p, symbol=%s)", proc->pid, addr, libsym ? libsym->name : "NULL");
	debug(1, "symbol=%s, addr=%p", libsym?libsym->name:"(nil)", addr);

	if (addr == 0) {
		/* XXX we need a better way to deal with this.  For
		 * now, just abuse errno to carry the error
		 * information.  */
		errno = EINVAL;
		return NULL;
	}

	if (libsym)
		libsym->needs_init = 0;

	struct breakpoint *sbp = dict_find_entry(leader->breakpoints, addr);
	if (sbp == NULL) {
		sbp = malloc(sizeof(*sbp));
		if (sbp == NULL
		    || breakpoint_init(sbp, proc, addr, libsym, NULL) < 0
		    || dict_enter(leader->breakpoints, addr, sbp) < 0) {
			free(sbp);
			return NULL;
		}
	}

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
	if (((struct breakpoint *)sbp)->enabled)
		enable_breakpoint(proc, sbp);
}

void
enable_all_breakpoints(Process *proc)
{
	debug(DEBUG_FUNCTION, "enable_all_breakpoints(pid=%d)", proc->pid);

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

static void
disable_bp_cb(void *addr, void *sbp, void *proc)
{
	debug(DEBUG_FUNCTION, "disable_bp_cb(pid=%d)", ((Process *)proc)->pid);
	if (((struct breakpoint *)sbp)->enabled)
		disable_breakpoint(proc, sbp);
}

void
disable_all_breakpoints(Process *proc) {
	debug(DEBUG_FUNCTION, "disable_all_breakpoints(pid=%d)", proc->pid);
	assert(proc->leader == proc);
	dict_apply_to_all(proc->breakpoints, disable_bp_cb, proc);
}

static enum callback_status
reinitialize_breakpoints(struct Process *proc, struct library *library,
			 void *data)
{
	debug(DEBUG_FUNCTION, "reinitialize_breakpoints_in(pid=%d, %s)",
	      proc->pid, library->name);

	struct library_symbol *sym;
	for (sym = library->symbols; sym != NULL; sym = sym->next)
		if (sym->needs_init) {
			target_address_t addr = sym2addr(proc, sym);
			if (insert_breakpoint(proc, addr, sym, 1) == NULL
			    || (sym->needs_init && !sym->is_weak))
				fprintf(stderr,
					"could not re-initialize breakpoint "
					"for \"%s\" in file \"%s\"\n",
					sym->name, proc->filename);
		}

	return CBS_CONT;
}

static void
entry_callback_hit(struct breakpoint *bp, struct Process *proc)
{
	fprintf(stderr, "entry_callback_hit\n");
	if (proc == NULL || proc->leader == NULL)
		return;
	delete_breakpoint(proc, bp->addr); // xxx

	linkmap_init(proc);
	proc_each_library(proc->leader, NULL, reinitialize_breakpoints, NULL);
}

int
breakpoints_init(Process *proc, int enable)
{
	fprintf(stderr, "breakpoints_init %d enable=%d\n", proc->pid, enable);
	debug(DEBUG_FUNCTION, "breakpoints_init(pid=%d)", proc->pid);

	/* XXX breakpoint dictionary should be initialized
	 * outside.  Here we just put in breakpoints.  */
	assert(proc->breakpoints != NULL);

	/* Only the thread group leader should hold the breakpoints.  */
	assert(proc->leader == proc);

	if (options.libcalls && proc->filename) {
		struct library *lib = ltelf_read_main_binary(proc, proc->filename);
		switch (lib != NULL) {
		fail:
			proc_remove_library(proc, lib);
			library_destroy(lib);
		case 0:
			return -1;
		}
		proc_add_library(proc, lib);
		fprintf(stderr, "note: symbols in %s were not filtered.\n",
			lib->name);

		struct breakpoint *entry_bp
			= insert_breakpoint(proc, lib->entry, NULL, 1);
		if (entry_bp == NULL) {
			error(0, errno, "couldn't insert entry breakpoint");
			goto fail;
		}

		fprintf(stderr, "setting entry_callbacks by hand, fix it\n");
		static struct bp_callbacks entry_callbacks = {
			.on_hit = entry_callback_hit,
		};
		entry_bp->cbs = &entry_callbacks;
	}

	proc->callstack_depth = 0;
	return 0;
}
