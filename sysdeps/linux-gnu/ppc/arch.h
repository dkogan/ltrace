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

struct library_symbol;
struct arch_ltelf_data {
	GElf_Addr plt_stub_vma;
	int secure_plt;
	struct library_symbol *stubs;
};

#endif /* LTRACE_PPC_ARCH_H */
