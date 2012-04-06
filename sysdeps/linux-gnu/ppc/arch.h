#ifndef LTRACE_PPC_ARCH_H
#define LTRACE_PPC_ARCH_H

#include <gelf.h>

#define BREAKPOINT_VALUE { 0x7f, 0xe0, 0x00, 0x08 }
#define BREAKPOINT_LENGTH 4
#define DECR_PC_AFTER_BREAK 0

#define LT_ELFCLASS	ELFCLASS32
#define LT_ELF_MACHINE	EM_PPC

#ifdef __powerpc64__ // Says 'ltrace' is 64 bits, says nothing about target.
#define LT_ELFCLASS2	ELFCLASS64
#define LT_ELF_MACHINE2	EM_PPC64
#define ARCH_SUPPORTS_OPD
#endif

#define PLT_REINITALISATION_BP    "_start"

#define ARCH_HAVE_UMOVELONG
#define ARCH_HAVE_ATOMIC_SINGLESTEP
#define ARCH_HAVE_ADD_PLT_ENTRY
#define ARCH_HAVE_LTELF_DATA
#define ARCH_HAVE_BREAKPOINT_DATA
#define ARCH_HAVE_LIBRARY_SYMBOL_DATA
#define ARCH_HAVE_TRANSLATE_ADDRESS

struct library_symbol;
struct arch_ltelf_data {
	GElf_Addr plt_stub_vma;
	int secure_plt;
	struct library_symbol *stubs;
};

enum ppc64_plt_type {
	/* STUB, never resolved.  */
	PPC64PLT_STUB,

	/* Unresolved PLT symbol (.plt contains PLT address).  */
	PPC64PLT_UNRESOLVED,

	/* Resolved PLT symbol.  The corresponding .plt slot contained
	 * target address, which was changed to the address of
	 * corresponding PLT entry.  The original is now saved in
	 * RESOLVED_VALUE.  */
	PPC64PLT_RESOLVED,
};

struct arch_library_symbol_data {
	enum ppc64_plt_type type;
	GElf_Addr resolved_value;

	/* Address of corresponding slot in .plt.  */
	GElf_Addr plt_slot_addr;
};

struct arch_breakpoint_data {
};

#endif /* LTRACE_PPC_ARCH_H */
