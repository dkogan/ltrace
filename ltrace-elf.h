#ifndef LTRACE_ELF_H
#define LTRACE_ELF_H

#include <gelf.h>
#include <stdlib.h>

struct Process;
struct library;

/* XXX Ok, the original idea was to separate the low-level ELF data
 * from the abstract "struct library" object, but we use some of the
 * following extensively in the back end.  Not all though.  So what we
 * use should be move to struct library, and the rest of this
 * structure maybe could be safely hidden in .c.  How to integrate the
 * arch-specific bits into struct library is unclear as of now.  */
struct ltelf {
	int fd;
	Elf *elf;
	GElf_Ehdr ehdr;
	Elf_Data *dynsym;
	size_t dynsym_count;
	const char *dynstr;
	GElf_Addr plt_addr;
	size_t plt_size;
	Elf_Data *relplt;
	size_t relplt_count;
	Elf_Data *symtab;
	const char *strtab;
	const char *soname;
	size_t symtab_count;
	Elf_Data *opd;
	GElf_Addr *opd_addr;
	size_t opd_size;
	int lte_flags;
	GElf_Addr dyn_addr;
	size_t dyn_sz;
	GElf_Addr base_addr;
	GElf_Addr entry_addr;
#ifdef __mips__
	size_t pltgot_addr;
	size_t mips_local_gotno;
	size_t mips_gotsym;
#endif // __mips__
	GElf_Addr plt_stub_vma;
};

#define ELF_MAX_SEGMENTS  50
#define LTE_PLT_EXECUTABLE 2

#define PLTS_ARE_EXECUTABLE(lte) (((lte)->lte_flags & LTE_PLT_EXECUTABLE) != 0)

int open_elf(struct ltelf *lte, const char *filename);

/* XXX is it possible to put breakpoints in VDSO and VSYSCALL
 * pseudo-libraries?  For now we assume that all libraries can be
 * opened via a filesystem.  BASE is ignored for ET_EXEC files.  */
struct library *ltelf_read_library(const char *filename, GElf_Addr base);

/* Create a library object representing the main binary.  The entry
 * point address is stored to *ENTRYP.  */
struct library *ltelf_read_main_binary(struct Process *proc, const char *path);

GElf_Addr arch_plt_sym_val(struct ltelf *, size_t, GElf_Rela *);

#if __WORDSIZE == 32
#define PRI_ELF_ADDR		PRIx32
#define GELF_ADDR_CAST(x)	(void *)(uint32_t)(x)
#else
#define PRI_ELF_ADDR		PRIx64
#define GELF_ADDR_CAST(x)	(void *)(x)
#endif

#endif
