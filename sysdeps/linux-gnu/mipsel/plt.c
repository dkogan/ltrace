#include <string.h>
#include <error.h>
#include <errno.h>
#include <gelf.h>
#include <sys/ptrace.h>

#include "common.h"
#include "debug.h"
#include "proc.h"
#include "library.h"
#include "breakpoint.h"
#include "backend.h"

/**
   \addtogroup mipsel
   @{
 */

/**
   \param lte Structure containing link table entry information
   \param ndx Index into .dynsym
   \param rela Not used.
   \return Address of GOT table entry

   MIPS ABI Supplement:

   DT_PLTGOT This member holds the address of the .got section.

   DT_MIPS_SYMTABNO This member holds the number of entries in the
   .dynsym section.

   DT_MIPS_LOCAL_GOTNO This member holds the number of local global
   offset table entries.

   DT_MIPS_GOTSYM This member holds the index of the first dyamic
   symbol table entry that corresponds to an entry in the gobal offset
   table.

   Called by read_elf when building the symbol table.

 */
GElf_Addr
arch_plt_sym_val(struct ltelf *lte, size_t ndx, GElf_Rela *rela)
{
    debug(1,"plt_addr %zx ndx %#zx",lte->arch.pltgot_addr, ndx);
    return lte->arch.pltgot_addr +
	    sizeof(void *) * (lte->arch.mips_local_gotno
			      + (ndx - lte->arch.mips_gotsym));
}
/**
   \param proc The process to work on.
   \param sym The library symbol.
   \return What is at the got table address

   The return value should be the address to put the breakpoint at.

   On the mips the library_symbol.enter_addr is the .got addr for the
   symbol and the breakpoint.addr is the actual breakpoint address.

   Other processors use a plt, the mips is "special" in that is uses
   the .got for both function and data relocations. Prior to program
   startup, return 0.

   \warning MIPS relocations are lazy. This means that the breakpoint
   may move after the first call. Ltrace dictionary routines don't
   have a delete and symbol is one to one with breakpoint, so if the
   breakpoint changes I just add a new breakpoint for the new address.
 */
void *
sym2addr(Process *proc, struct library_symbol *sym) {
    long ret;

    if (sym->plt_type == LS_TOPLT_NONE) {
        return sym->enter_addr;
    }

    if(!proc->pid){
        return 0;
    }
    ret=ptrace(PTRACE_PEEKTEXT, proc->pid, sym->enter_addr, 0);
    if(ret==-1){
        ret =0;
    }
    return (void *)ret;;
}

/*
 * MIPS doesn't have traditional got.plt entries with corresponding
 * relocations.
 *
 * sym_index is an offset into the external GOT entries. Filter out
 * stuff that are not functions.
 */
int
arch_get_sym_info(struct ltelf *lte, const char *filename,
		  size_t sym_index, GElf_Rela *rela, GElf_Sym *sym)
{
	const char *name;

	/* Fixup the offset.  */
	sym_index += lte->arch.mips_gotsym;

	if (gelf_getsym(lte->dynsym, sym_index, sym) == NULL){
		error(EXIT_FAILURE, 0,
			"Couldn't get relocation from \"%s\"", filename);
	}

	name = lte->dynstr + sym->st_name;
	if (ELF64_ST_TYPE(sym->st_info) != STT_FUNC) {
		debug(2, "sym %s not a function", name);
		return -1;
	}

	return 0;
}

/**
  MIPS ABI Supplement:

  DT_PLTGOT This member holds the address of the .got section.

  DT_MIPS_SYMTABNO This member holds the number of entries in the
  .dynsym section.

  DT_MIPS_LOCAL_GOTNO This member holds the number of local global
  offset table entries.

  DT_MIPS_GOTSYM This member holds the index of the first dyamic
  symbol table entry that corresponds to an entry in the gobal offset
  table.

 */
int
arch_elf_init(struct ltelf *lte, struct library *lib)
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

		if(dyn.d_tag == DT_PLTGOT) {
			lte->arch.pltgot_addr = dyn.d_un.d_ptr;
		}
		if(dyn.d_tag == DT_MIPS_LOCAL_GOTNO){
			lte->arch.mips_local_gotno = dyn.d_un.d_val;
		}
		if(dyn.d_tag == DT_MIPS_GOTSYM){
			lte->arch.mips_gotsym = dyn.d_un.d_val;
		}
	}

	/* Tell the generic code how many dynamic trace:able symbols
	 * we've got.  */
	lte->relplt_count = lte->dynsym_count - lte->arch.mips_gotsym;
	return 0;
}

void
arch_elf_destroy(struct ltelf *lte)
{
}

/* When functions return we check if the symbol needs an updated
   breakpoint with the resolved address.  */
void arch_symbol_ret(struct Process *proc, struct library_symbol *libsym)
{
	struct breakpoint *bp;
	arch_addr_t resolved_addr;

	/* Only deal with unresolved symbols.  */
	if (libsym->arch.type != MIPS_PLT_UNRESOLVED)
		return;

	resolved_addr = sym2addr(proc, libsym);
	libsym->arch.resolved_addr = (uintptr_t) resolved_addr;
	libsym->arch.type = MIPS_PLT_RESOLVED;

	if (libsym->arch.stub_addr == libsym->arch.resolved_addr) {
		/* Prelinked symbol. No need to add new breakpoint.  */
		return;
	}

	bp = malloc(sizeof (*bp));
	if (bp == NULL) {
		fprintf(stderr, "Failed to allocate bp for %s\n",
			libsym->name);
		return;
	}

	if (breakpoint_init(bp, proc, resolved_addr, libsym) < 0)
		goto err;

	if (proc_add_breakpoint(proc, bp) < 0) {
		breakpoint_destroy(bp);
		goto err;
	}

	if (breakpoint_turn_on(bp, proc) < 0) {
		proc_remove_breakpoint(proc, bp);
		breakpoint_destroy(bp);
		goto err;
	}
	return;
err:
	free(bp);
}

static enum callback_status
cb_enable_breakpoint_sym(struct library_symbol *libsym, void *data)
{
	struct Process *proc = data;
	struct breakpoint *bp;
	arch_addr_t bp_addr;

	if (libsym->plt_type != LS_TOPLT_GOTONLY)
		return CBS_CONT;

	/* Update state.  */
	bp_addr = sym2addr(proc, libsym);
	/* XXX The cast to uintptr_t should be removed when
	 * arch_addr_t becomes integral type.  keywords: double cast.  */
	libsym->arch.resolved_addr = (uintptr_t) bp_addr;

	if (libsym->arch.resolved_addr == 0)
		/* FIXME: What does this mean?  */
		return CBS_CONT;

	libsym->arch.type = MIPS_PLT_RESOLVED;

	/* Add breakpoint.  */
	bp = malloc(sizeof *bp);
	if (bp == NULL
	    || breakpoint_init(bp, proc, bp_addr, libsym) < 0) {
		goto fail;
	}

	if (proc_add_breakpoint(proc, bp) < 0) {
		breakpoint_destroy(bp);
		goto fail;
	}

	if (breakpoint_turn_on(bp, proc) < 0) {
		proc_remove_breakpoint(proc, bp);
		breakpoint_destroy(bp);
		goto fail;
	}

	return CBS_CONT;
fail:
	free(bp);
	fprintf(stderr, "Failed to add breakpoint for %s\n", libsym->name);
	return CBS_CONT;
}

static enum callback_status
cb_enable_breakpoint_lib(struct Process *proc, struct library *lib, void *data)
{
	library_each_symbol(lib, NULL, cb_enable_breakpoint_sym, proc);
	return CBS_CONT;
}

void arch_dynlink_done(struct Process *proc)
{
	proc_each_library(proc, NULL, cb_enable_breakpoint_lib, NULL);
}

enum plt_status
arch_elf_add_plt_entry(struct Process *proc, struct ltelf *lte,
                       const char *a_name, GElf_Rela *rela, size_t ndx,
                       struct library_symbol **ret)
{
	char *name = NULL;
	int sym_index = ndx + lte->arch.mips_gotsym;

	struct library_symbol *libsym = malloc(sizeof(*libsym));
	if (libsym == NULL)
		return plt_fail;

	GElf_Addr addr = arch_plt_sym_val(lte, sym_index, 0);

	name = strdup(a_name);
	if (name == NULL) {
		fprintf(stderr, "%s: failed %s(%#llx): %s\n", __func__,
			name, addr, strerror(errno));
		goto fail;
	}

	/* XXX The double cast should be removed when
	 * arch_addr_t becomes integral type.  */
	if (library_symbol_init(libsym,
				(arch_addr_t) (uintptr_t) addr,
				name, 1, LS_TOPLT_EXEC) < 0) {
		fprintf(stderr, "%s: failed %s : %llx\n", __func__, name, addr);
		goto fail;
	}

	arch_addr_t bp_addr = sym2addr(proc, libsym);
	/* XXX This cast should be removed when
	 * arch_addr_t becomes integral type.  keywords: double cast. */
	libsym->arch.stub_addr = (uintptr_t) bp_addr;

	if (bp_addr == 0) {
		/* Function pointers without PLT entries.  */
		libsym->plt_type = LS_TOPLT_GOTONLY;
		libsym->arch.type = MIPS_PLT_UNRESOLVED;
	}

	*ret = libsym;
	return plt_ok;

fail:
	free(name);
	free(libsym);
	return plt_fail;
}

int
arch_library_symbol_init(struct library_symbol *libsym)
{
	libsym->arch.type = MIPS_PLT_UNRESOLVED;
	if (libsym->plt_type == LS_TOPLT_NONE) {
		libsym->arch.type = MIPS_PLT_RESOLVED;
	}
	return 0;
}

void
arch_library_symbol_destroy(struct library_symbol *libsym)
{
}

int
arch_library_symbol_clone(struct library_symbol *retp,
                          struct library_symbol *libsym)
{
	retp->arch = libsym->arch;
	return 0;
}

/**@}*/
