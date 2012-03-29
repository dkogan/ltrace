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

#ifndef ARCH_HAVE_TRANSLATE_ADDRESS
int
arch_translate_address(struct Process *proc,
		       target_address_t addr, target_address_t *ret)
{
	*ret = addr;
	return 0;
}
#endif

void
breakpoint_on_hit(struct breakpoint *bp, struct Process *proc)
{
	assert(bp != NULL);
	if (bp->cbs != NULL && bp->cbs->on_hit != NULL)
		(bp->cbs->on_hit)(bp, proc);
}

void
breakpoint_on_continue(struct breakpoint *bp, struct Process *proc)
{
	assert(bp != NULL);
	if (bp->cbs != NULL && bp->cbs->on_continue != NULL)
		(bp->cbs->on_continue)(bp, proc);
	else
		continue_after_breakpoint(proc, bp);
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

#ifndef ARCH_HAVE_BREAKPOINT_DATA
int
arch_breakpoint_init(struct Process *proc, struct breakpoint *sbp)
{
	return 0;
}

void
arch_breakpoint_destroy(struct breakpoint *sbp)
{
}
#endif

/* On second thought, I don't think we need PROC.  All the translation
 * (arch_translate_address in particular) should be doable using
 * static lookups of various sections in the ELF file.  We shouldn't
 * need process for anything.  */
int
breakpoint_init(struct breakpoint *bp, struct Process *proc,
		target_address_t addr, struct library_symbol *libsym)
{
	bp->cbs = NULL;
	bp->proc = NULL;
	bp->addr = addr;
	memset(bp->orig_value, 0, sizeof(bp->orig_value));
	bp->enabled = 0;
	bp->libsym = libsym;
	return arch_breakpoint_init(proc, bp);
}

void
breakpoint_set_callbacks(struct breakpoint *bp, struct bp_callbacks *cbs)
{
	if (bp->cbs != NULL)
		assert(bp->cbs == NULL);
	bp->cbs = cbs;
}

void
breakpoint_destroy(struct breakpoint *bp)
{
	if (bp == NULL)
		return;

	/* XXX I'm not convinced that we need on_destroy.  We already
	 * have arch_breakpoint_destroy, which is necessary as a
	 * counterpart of arch_breakpoint_init in any case.  */
	if (bp->cbs != NULL && bp->cbs->on_destroy != NULL)
		(bp->cbs->on_destroy) (bp);

	arch_breakpoint_destroy(bp);
}

int
breakpoint_turn_on(struct breakpoint *bp)
{
	/* Make sure it was inserted.  XXX In a clean world, we would
	 * have breakpoint_site representing a place and breakpoint
	 * representing inserted breakpoint.  */
	assert(bp->proc != NULL);
	bp->enabled++;
	if (bp->enabled == 1) {
		assert(bp->proc->pid != 0);
		enable_breakpoint(bp->proc, bp);
	}
	return 0;
}

int
breakpoint_turn_off(struct breakpoint *bp)
{
	assert(bp->proc != NULL);
	bp->enabled--;
	if (bp->enabled == 0)
		disable_breakpoint(bp->proc, bp);
	assert(bp->enabled >= 0);
	return 0;
}

struct breakpoint *
insert_breakpoint(struct Process *proc, void *addr,
		  struct library_symbol *libsym)
{
	Process *leader = proc->leader;

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

	/* XXX what we need to do instead is have a list of
	 * breakpoints that are enabled at this address.  The
	 * following works if every breakpoint is the same and there's
	 * no extra data, but that doesn't hold anymore.  For now it
	 * will suffice, about the only realistic case where we need
	 * to have more than one breakpoint per address is return from
	 * a recursive library call.  */
	struct breakpoint *sbp = dict_find_entry(leader->breakpoints, addr);
	if (sbp == NULL) {
		sbp = malloc(sizeof(*sbp));
		if (sbp == NULL
		    || breakpoint_init(sbp, proc, addr, libsym) < 0) {
			free(sbp);
			return NULL;
		}
		if (proc_add_breakpoint(proc, sbp) < 0) {
		fail:
			breakpoint_destroy(sbp);
			free(sbp);
			return NULL;
		}
	}

	if (breakpoint_turn_on(sbp) < 0)
		goto fail;

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

	if (breakpoint_turn_off(sbp) < 0) {
		fprintf(stderr, "Couldn't turn off the breakpoint %s@%p\n",
			breakpoint_name(sbp), sbp->addr);
		return;
	}
}

const char *
breakpoint_name(const struct breakpoint *bp)
{
	assert(bp != NULL);
	return bp->libsym != NULL ? bp->libsym->name : NULL;
}

struct library *
breakpoint_library(const struct breakpoint *bp)
{
	assert(bp != NULL);
	return bp->libsym != NULL ? bp->libsym->lib : NULL;
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

struct entry_breakpoint {
	struct breakpoint super;
	target_address_t dyn_addr;
};

static void
entry_callback_hit(struct breakpoint *a, struct Process *proc)
{
	struct entry_breakpoint *bp = (void *)a;
	fprintf(stderr, "entry_callback_hit\n");
	if (proc == NULL || proc->leader == NULL)
		return;
	delete_breakpoint(proc, bp->super.addr); // xxx
	//enable_all_breakpoints(proc);

	linkmap_init(proc, bp->dyn_addr);
}

int
entry_breakpoint_init(struct Process *proc,
		      struct entry_breakpoint *bp, target_address_t addr)
{
	int err;
	if ((err = breakpoint_init(&bp->super, proc, addr, NULL)) < 0)
		return err;

	static struct bp_callbacks entry_callbacks = {
		.on_hit = entry_callback_hit,
	};
	bp->super.cbs = &entry_callbacks;
	return 0;
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
		struct library *lib = ltelf_read_main_binary(proc,
							     proc->filename);
		struct entry_breakpoint *entry_bp = NULL;
		int bp_state = 0;
		int result = -1;
		switch (lib != NULL) {
		fail:
			proc_remove_library(proc, lib);
			library_destroy(lib);
			switch (bp_state) {
			case 2:
				proc_remove_breakpoint(proc, &entry_bp->super);
			case 1:
				breakpoint_destroy(&entry_bp->super);
			}
			free(entry_bp);
		case 0:
			return result;
		}

		proc_add_library(proc, lib);
		fprintf(stderr, "note: symbols in %s were not filtered.\n",
			lib->name);

		entry_bp = malloc(sizeof(*entry_bp));
		if (entry_bp == NULL
		    || (result = entry_breakpoint_init(proc, entry_bp,
						       lib->entry)) < 0)
			goto fail;

		++bp_state;
		if ((result = proc_add_breakpoint(proc, &entry_bp->super)) < 0)
			goto fail;

		++bp_state;
		if ((result = breakpoint_turn_on(&entry_bp->super)) < 0)
			goto fail;
	}

	proc->callstack_depth = 0;
	return 0;
}
