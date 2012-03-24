#include <gelf.h>
#include <sys/ptrace.h>
#include <errno.h>
#include <error.h>
#include <inttypes.h>
#include <assert.h>

#include "proc.h"
#include "common.h"
#include "library.h"

#define PPC_PLT_STUB_SIZE 16

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
		assert(lte->ehdr.e_machine == EM_PPC64);
		fprintf(stderr, "PPC64\n");
		abort();
		return rela->r_offset;
	}
}

int
arch_translate_address(struct Process *proc,
		       target_address_t addr, target_address_t *ret)
{
	if (host_powerpc64() && proc->e_machine == EM_PPC64) {
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
load_ppcgot(struct ltelf *lte, GElf_Addr *ppcgotp)
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

		if(dyn.d_tag == DT_PPC_GOT) {
			*ppcgotp = dyn.d_un.d_ptr;
			return 0;
		}
	}

	return -1;
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
	}

	/* Override the value that we gleaned from flags on the .plt
	 * section.  The PLT entries are in fact executable, they are
	 * just not in .plt.  */
	lte->lte_flags |= LTE_PLT_EXECUTABLE;
	return 0;
}
