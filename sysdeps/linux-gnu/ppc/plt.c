#include <gelf.h>
#include <sys/ptrace.h>
#include <errno.h>
#include <error.h>
#include <inttypes.h>
#include <assert.h>
#include <string.h>

#include "proc.h"
#include "common.h"
#include "library.h"
#include "breakpoint.h"

/* There are two PLT types on 32-bit PPC: old-style, BSS PLT, and
 * new-style "secure" PLT.  We can tell one from the other by the
 * flags on the .plt section.  If it's +X (executable), it's BSS PLT,
 * otherwise it's secure.
 *
 * BSS PLT works the same way as most architectures: the .plt section
 * contains trampolines and we put breakpoints to those.  With secure
 * PLT, the .plt section doesn't contain instructions but addresses.
 * The real PLT table is stored in .text.  Addresses of those PLT
 * entries can be computed, and it fact that's what the glink deal
 * below does.
 *
 * If not prelinked, BSS PLT entries in the .plt section contain
 * zeroes that are overwritten by the dynamic linker during start-up.
 * For that reason, ltrace realizes those breakpoints only after
 * .start is hit.
 *
 * 64-bit PPC is more involved.  Program linker creates for each
 * library call a _stub_ symbol named xxxxxxxx.plt_call.<callee>
 * (where xxxxxxxx is a hexadecimal number).  That stub does the call
 * dispatch: it loads an address of a function to call from the
 * section .plt, and branches.  PLT entries themselves are essentially
 * a curried call to the resolver.  When the symbol is resolved, the
 * resolver updates the value stored in .plt, and the next time
 * around, the stub calls the library function directly.  So we make
 * at most one trip (none if the binary is prelinked) through each PLT
 * entry, and correspondingly that is useless as a breakpoint site.
 *
 * Note the three confusing terms: stubs (that play the role of PLT
 * entries), PLT entries, .plt section.
 *
 * We first check symbol tables and see if we happen to have stub
 * symbols available.  If yes we just put breakpoints to those, and
 * treat them as usual breakpoints.  The only tricky part is realizing
 * that there can be more than one breakpoint per symbol.
 *
 * The case that we don't have the stub symbols available is harder.
 * The following scheme uses two kinds of PLT breakpoints: unresolved
 * and resolved (to some address).  When the process starts (or when
 * we attach), we distribute unresolved PLT breakpoints to the PLT
 * entries (not stubs).  Then we look in .plt, and for each entry
 * whose value is different than the corresponding PLT entry address,
 * we assume it was already resolved, and convert the breakpoint to
 * resolved.  We also rewrite the resolved value in .plt back to the
 * PLT address.
 *
 * When a PLT entry hits a resolved breakpoint (which happens because
 * we put back the unresolved addresses to .plt), we move the
 * instruction pointer to the corresponding address and continue the
 * process as if nothing happened.
 *
 * When unresolved PLT entry is called for the first time, we need to
 * catch the new value that the resolver will write to a .plt slot.
 * We also need to prevent another thread from racing through and
 * taking the branch without ltrace noticing.  So when unresolved PLT
 * entry hits, we have to stop all threads.  We then single-step
 * through the resolver, until the .plt slot changes.  When it does,
 * we treat it the same way as above: convert the PLT breakpoint to
 * resolved, and rewrite the .plt value back to PLT address.  We then
 * start all threads again.
 *
 * In theory we might find the exact instruction that will update the
 * .plt slot, and emulate it, updating the PLT breakpoint immediately,
 * and then just skip it.  But that's even messier than the thread
 * stopping business and single stepping that needs to be done.
 */

#define PPC_PLT_STUB_SIZE 16
#define PPC64_PLT_STUB_SIZE 8 //xxx

static inline int
host_powerpc64()
{
#ifdef __powerpc64__
	return 1;
#else
	return 0;
#endif
}

GElf_Addr
arch_plt_sym_val(struct ltelf *lte, size_t ndx, GElf_Rela *rela)
{
	if (lte->ehdr.e_machine == EM_PPC && lte->arch.secure_plt) {
		assert(lte->arch.plt_stub_vma != 0);
		return lte->arch.plt_stub_vma + PPC_PLT_STUB_SIZE * ndx;

	} else if (lte->ehdr.e_machine == EM_PPC) {
		return rela->r_offset;

	} else {
		/* If we get here, we don't have stub symbols.  In
		 * that case we put brakpoints to PLT entries the same
		 * as the PPC32 secure PLT case does.  */
		assert(lte->arch.plt_stub_vma != 0);
		return lte->arch.plt_stub_vma + PPC64_PLT_STUB_SIZE * ndx;
	}
}

int
arch_translate_address(struct Process *proc,
		       target_address_t addr, target_address_t *ret)
{
	if (proc->e_machine == EM_PPC64) {
		assert(host_powerpc64());
		long l = ptrace(PTRACE_PEEKTEXT, proc->pid, addr, 0);
		fprintf(stderr, "arch_translate_address %p->%#lx\n",
			addr, l);
		if (l == -1 && errno) {
			error(0, errno, ".opd translation of %p", addr);
			return -1;
		}
		*ret = (target_address_t)l;
		return 0;
	}

	*ret = addr;
	return 0;
}

/* XXX Apparently PPC64 doesn't support PLT breakpoints.  */
void *
sym2addr(Process *proc, struct library_symbol *sym) {
	void *addr = sym->enter_addr;
	long pt_ret;

	debug(3, 0);

	if (sym->plt_type != LS_TOPLT_POINT) {
		return addr;
	}

	if (proc->pid == 0) {
		return 0;
	}

	if (options.debug >= 3) {
		xinfdump(proc->pid, (void *)(((long)addr-32)&0xfffffff0),
			 sizeof(void*)*8);
	}

	// On a PowerPC-64 system, a plt is three 64-bit words: the first is the
	// 64-bit address of the routine.  Before the PLT has been initialized,
	// this will be 0x0. In fact, the symbol table won't have the plt's
	// address even.  Ater the PLT has been initialized, but before it has
	// been resolved, the first word will be the address of the function in
	// the dynamic linker that will reslove the PLT.  After the PLT is
	// resolved, this will will be the address of the routine whose symbol
	// is in the symbol table.

	// On a PowerPC-32 system, there are two types of PLTs: secure (new) and
	// non-secure (old).  For the secure case, the PLT is simply a pointer
	// and we can treat it much as we do for the PowerPC-64 case.  For the
	// non-secure case, the PLT is executable code and we can put the
	// break-point right in the PLT.

	pt_ret = ptrace(PTRACE_PEEKTEXT, proc->pid, addr, 0);

#if SIZEOF_LONG == 8
	if (proc->mask_32bit) {
		// Assume big-endian.
		addr = (void *)((pt_ret >> 32) & 0xffffffff);
	} else {
		addr = (void *)pt_ret;
	}
#else
	/* XXX Um, so where exactly are we dealing with the non-secure
	   PLT thing?  */
	addr = (void *)pt_ret;
#endif

	return addr;
}

static GElf_Addr
get_glink_vma(struct ltelf *lte, GElf_Addr ppcgot, Elf_Data *plt_data)
{
	Elf_Scn *ppcgot_sec = NULL;
	GElf_Shdr ppcgot_shdr;
	if (ppcgot != 0
	    && elf_get_section_covering(lte, ppcgot,
					&ppcgot_sec, &ppcgot_shdr) < 0)
		// xxx should be the log out
		fprintf(stderr,
			"DT_PPC_GOT=%#" PRIx64 ", but no such section found.\n",
			ppcgot);

	if (ppcgot_sec != NULL) {
		Elf_Data *data = elf_loaddata(ppcgot_sec, &ppcgot_shdr);
		if (data == NULL || data->d_size < 8 ) {
			fprintf(stderr, "Couldn't read GOT data.\n");
		} else {
			// where PPCGOT begins in .got
			size_t offset = ppcgot - ppcgot_shdr.sh_addr;
			assert(offset % 4 == 0);
			uint32_t glink_vma;
			if (elf_read_u32(data, offset + 4, &glink_vma) < 0) {
				fprintf(stderr,
					"Couldn't read glink VMA address"
					" at %zd@GOT\n", offset);
				return 0;
			}
			if (glink_vma != 0) {
				debug(1, "PPC GOT glink_vma address: %#" PRIx32,
				      glink_vma);
				fprintf(stderr, "PPC GOT glink_vma "
					"address: %#"PRIx32"\n", glink_vma);
				return (GElf_Addr)glink_vma;
			}
		}
	}

	if (plt_data != NULL) {
		uint32_t glink_vma;
		if (elf_read_u32(plt_data, 0, &glink_vma) < 0) {
			fprintf(stderr,
				"Couldn't read glink VMA address at 0@.plt\n");
			return 0;
		}
		debug(1, ".plt glink_vma address: %#" PRIx32, glink_vma);
		fprintf(stderr, ".plt glink_vma address: "
			"%#"PRIx32"\n", glink_vma);
		return (GElf_Addr)glink_vma;
	}

	return 0;
}

static int
load_dynamic_entry(struct ltelf *lte, int tag, GElf_Addr *valuep)
{
	Elf_Scn *scn;
	GElf_Shdr shdr;
	if (elf_get_section_type(lte, SHT_DYNAMIC, &scn, &shdr) < 0
	    || scn == NULL) {
	fail:
		error(0, 0, "Couldn't get SHT_DYNAMIC: %s",
		      elf_errmsg(-1));
		return -1;
	}

	Elf_Data *data = elf_loaddata(scn, &shdr);
	if (data == NULL)
		goto fail;

	size_t j;
	for (j = 0; j < shdr.sh_size / shdr.sh_entsize; ++j) {
		GElf_Dyn dyn;
		if (gelf_getdyn(data, j, &dyn) == NULL)
			goto fail;

		if(dyn.d_tag == tag) {
			*valuep = dyn.d_un.d_ptr;
			return 0;
		}
	}

	return -1;
}

static int
load_ppcgot(struct ltelf *lte, GElf_Addr *ppcgotp)
{
	return load_dynamic_entry(lte, DT_PPC_GOT, ppcgotp);
}

static int
load_ppc64_glink(struct ltelf *lte, GElf_Addr *glinkp)
{
	return load_dynamic_entry(lte, DT_PPC64_GLINK, glinkp);
}

int
arch_elf_init(struct ltelf *lte)
{
	lte->arch.secure_plt = !(lte->lte_flags & LTE_PLT_EXECUTABLE);
	if (lte->ehdr.e_machine == EM_PPC && lte->arch.secure_plt) {
		GElf_Addr ppcgot;
		if (load_ppcgot(lte, &ppcgot) < 0) {
			fprintf(stderr, "Couldn't find DT_PPC_GOT.\n");
			return -1;
		}
		GElf_Addr glink_vma = get_glink_vma(lte, ppcgot, lte->plt_data);

		assert (lte->relplt_size % 12 == 0);
		size_t count = lte->relplt_size / 12; // size of RELA entry
		lte->arch.plt_stub_vma = glink_vma
			- (GElf_Addr)count * PPC_PLT_STUB_SIZE;
		debug(1, "stub_vma is %#" PRIx64, lte->arch.plt_stub_vma);

	} else if (lte->ehdr.e_machine == EM_PPC64) {
		GElf_Addr glink_vma;
		if (load_ppc64_glink(lte, &glink_vma) < 0) {
			fprintf(stderr, "Couldn't find DT_PPC64_GLINK.\n");
			return -1;
		}

		/* The first glink stub starts at offset 32.  */
		lte->arch.plt_stub_vma = glink_vma + 32;
	}

	/* Override the value that we gleaned from flags on the .plt
	 * section.  The PLT entries are in fact executable, they are
	 * just not in .plt.  */
	lte->lte_flags |= LTE_PLT_EXECUTABLE;

	/* On PPC64, look for stub symbols in symbol table.  These are
	 * called: xxxxxxxx.plt_call.callee_name@version+addend.  */
	if (lte->ehdr.e_machine == EM_PPC64
	    && lte->symtab != NULL && lte->strtab != NULL) {

		/* N.B. We can't simply skip the symbols that we fail
		 * to read or malloc.  There may be more than one stub
		 * per symbol name, and if we failed in one but
		 * succeeded in another, the PLT enabling code would
		 * have no way to tell that something is missing.  We
		 * could work around that, of course, but it doesn't
		 * seem worth the trouble.  So if anything fails, we
		 * just pretend that we don't have stub symbols at
		 * all, as if the binary is stripped.  */

		size_t i;
		for (i = 0; i < lte->symtab_count; ++i) {
			GElf_Sym sym;
			if (gelf_getsym(lte->symtab, i, &sym) == NULL) {
				struct library_symbol *sym, *next;
			fail:
				for (sym = lte->arch.stubs; sym != NULL; ) {
					next = sym->next;
					library_symbol_destroy(sym);
					free(sym);
					sym = next;
				}
				lte->arch.stubs = NULL;
				break;
			}

			const char *name = lte->strtab + sym.st_name;

#define STUBN ".plt_call."
			if ((name = strstr(name, STUBN)) == NULL)
				continue;
			name += sizeof(STUBN) - 1;
#undef STUBN

			size_t len;
			const char *ver = strchr(name, '@');
			if (ver != NULL) {
				len = ver - name;

			} else {
				/* If there is "+" at all, check that
				 * the symbol name ends in "+0".  */
				const char *add = strrchr(name, '+');
				if (add != NULL) {
					assert(strcmp(add, "+0") == 0);
					len = add - name;
				} else {
					len = strlen(name);
				}
			}

			char *sym_name = strndup(name, len);
			struct library_symbol *libsym = malloc(sizeof(*libsym));
			if (sym_name == NULL || libsym == NULL) {
				free(sym_name);
				free(libsym);
				goto fail;
			}

			target_address_t addr
				= (target_address_t)sym.st_value + lte->bias;
			library_symbol_init(libsym, addr, sym_name, 1,
					    LS_TOPLT_EXEC);
			libsym->arch.type = PPC64PLT_STUB;
			libsym->next = lte->arch.stubs;
			lte->arch.stubs = libsym;
		}
	}

	return 0;
}

enum plt_status
arch_elf_add_plt_entry(struct Process *proc, struct ltelf *lte,
		       const char *a_name, GElf_Rela *rela, size_t ndx,
		       struct library_symbol **ret)
{
	if (lte->ehdr.e_machine == EM_PPC)
		return plt_default;

	/* PPC64.  If we have stubs, we return a chain of breakpoint
	 * sites, one for each stub that corresponds to this PLT
	 * entry.  */
	struct library_symbol *chain = NULL;
	struct library_symbol **symp;
	for (symp = &lte->arch.stubs; *symp != NULL; ) {
		struct library_symbol *sym = *symp;
		if (strcmp(sym->name, a_name) != 0) {
			symp = &(*symp)->next;
			continue;
		}

		/* Re-chain the symbol from stubs to CHAIN.  */
		*symp = sym->next;
		sym->next = chain;
		chain = sym;
	}

	if (chain != NULL) {
		struct library_symbol *sym;
		for (sym = chain; sym != NULL; sym = sym->next)
			fprintf(stderr, "match %s --> %p\n",
				sym->name, sym->enter_addr);
		for (sym = lte->arch.stubs; sym != NULL; sym = sym->next)
			fprintf(stderr, "remains %s --> %p\n",
				sym->name, sym->enter_addr);

		*ret = chain;
		return plt_ok;
	}

	/* We don't have stub symbols.  Find corresponding .plt slot,
	 * and check whether it contains the corresponding PLT address
	 * (or 0 if the dynamic linker hasn't run yet).  N.B. we don't
	 * want read this from ELF file, but from process image.  That
	 * makes a difference if we are attaching to a running
	 * process.  */

	GElf_Addr plt_entry_addr = arch_plt_sym_val(lte, ndx, rela);
	GElf_Addr plt_slot_addr = rela->r_offset;
	assert(plt_slot_addr >= lte->plt_addr
	       || plt_slot_addr < lte->plt_addr + lte->plt_size);

	long plt_slot_value = ptrace(PTRACE_PEEKTEXT, proc->pid,
				     plt_slot_addr, 0);
	if (plt_slot_value == -1 && errno != 0) {
		error(0, errno, "ptrace .plt slot value @%#" PRIx64,
		      plt_slot_addr);
		return plt_fail;
	}

	char *name = strdup(a_name);
	struct library_symbol *libsym = malloc(sizeof(*libsym));
	if (name == NULL || libsym == NULL) {
		error(0, errno, "allocation for .plt slot");
	fail:
		free(name);
		free(libsym);
		return plt_fail;
	}

	library_symbol_init(libsym, (target_address_t)plt_entry_addr,
			    name, 1, LS_TOPLT_EXEC);
	if ((GElf_Addr)plt_slot_value == plt_entry_addr
	    || plt_slot_value == 0) {
		libsym->arch.type = PPC64PLT_UNRESOLVED;
		libsym->arch.orig_addr = 0;
	} else {
		/* Unresolve the .plt slot.  If the binary was
		 * prelinked, this makes the code invalid, because in
		 * case of prelinked binary, the dynamic linker
		 * doesn't update .plt[0] and .plt[1] with addresses
		 * of the resover.  But we don't care, we will never
		 * need to enter the resolver.  That just means that
		 * we have to un-un-resolve this back before we
		 * detach, which is nothing new: we already need to
		 * retract breakpoints.  */
		/* We only modify plt_entry[0], which holds the
		 * resolved address of the routine.  We keep the TOC
		 * and environment pointers intact.  Hence the only
		 * adjustment that we need to do is to IP.  */
		if (ptrace(PTRACE_POKETEXT, proc->pid,
			   plt_slot_addr, plt_entry_addr) < 0) {
			error(0, errno, "unresolve .plt slot");
			goto fail;
		}
		libsym->arch.type = PPC64PLT_RESOLVED;
		libsym->arch.orig_addr = plt_slot_value;
	}

	*ret = libsym;
	return plt_ok;
}

void
arch_elf_destroy(struct ltelf *lte)
{
	struct library_symbol *sym;
	for (sym = lte->arch.stubs; sym != NULL; ) {
		struct library_symbol *next = sym->next;
		library_symbol_destroy(sym);
		free(sym);
		sym = next;
	}
}

static void
ppc64_resolved_bp_continue(struct breakpoint *bp, struct Process *proc)
{
	fprintf(stderr, "ppc64_resolved_bp_continue\n");
	set_instruction_pointer(proc,
				(target_address_t)bp->libsym->arch.orig_addr);
	continue_process(proc->pid);
}

int
arch_breakpoint_init(struct Process *proc, struct breakpoint *bp)
{
	if (proc->e_machine == EM_PPC
	    || bp->libsym == NULL
	    || bp->libsym->arch.type == PPC64PLT_STUB)
		return 0;

	if (bp->libsym->arch.type == PPC64PLT_RESOLVED) {
		fprintf(stderr, "arch_breakpoint_init RESOLVED\n");
		static struct bp_callbacks resolved_cbs = {
			.on_continue = ppc64_resolved_bp_continue,
		};
		breakpoint_set_callbacks(bp, &resolved_cbs);

	} else {
		fprintf(stderr, "arch_breakpoint_init UNRESOLVED\n");
		fprintf(stderr, "a.k.a the insane case\n");
		abort();
	}

	return 0;
}

void
arch_breakpoint_destroy(struct breakpoint *bp)
{
}
