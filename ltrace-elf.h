#ifndef LTRACE_ELF_H
#define LTRACE_ELF_H

#include <gelf.h>
#include <stdlib.h>

#define DEFINING_LTELF
#include "arch.h"
#undef DEFINING_LTELF

#ifndef ARCH_HAVE_LTELF_DATA
struct arch_ltelf_data {
};
#endif

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
	Elf_Data *plt_data;
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
	size_t relplt_size;
	GElf_Addr bias;
	GElf_Addr entry_addr;
	GElf_Addr base_addr;
	struct arch_ltelf_data arch;
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

Elf_Data *elf_loaddata(Elf_Scn *scn, GElf_Shdr *shdr);
int elf_get_section_covering(struct ltelf *lte, GElf_Addr addr,
			     Elf_Scn **tgt_sec, GElf_Shdr *tgt_shdr);

/* Read, respectively, 2, 4, or 8 bytes from Elf data at given OFFSET,
 * and store it in *RETP.  Returns 0 on success or a negative value if
 * there's not enough data.  */
int elf_read_u16(Elf_Data *data, size_t offset, uint16_t *retp);
int elf_read_u32(Elf_Data *data, size_t offset, uint32_t *retp);
int elf_read_u64(Elf_Data *data, size_t offset, uint64_t *retp);


#if __WORDSIZE == 32
#define PRI_ELF_ADDR		PRIx32
#define GELF_ADDR_CAST(x)	(void *)(uint32_t)(x)
#else
#define PRI_ELF_ADDR		PRIx64
#define GELF_ADDR_CAST(x)	(void *)(x)
#endif

#endif
