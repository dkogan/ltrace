#ifndef LTRACE_MIPS_ARCH_H
#define LTRACE_MIPS_ARCH_H

#include <stddef.h>

#define BREAKPOINT_VALUE { 0x0d, 0x00, 0x00, 0x00 }
#define BREAKPOINT_LENGTH 4
#define DECR_PC_AFTER_BREAK 0

#define LT_ELFCLASS	ELFCLASS32
#define LT_ELF_MACHINE	EM_MIPS

#define PLTs_INIT_BY_HERE "_start"
#define E_ENTRY_NAME    "_start"

#define ARCH_HAVE_LTELF_DATA
struct arch_ltelf_data {
	size_t pltgot_addr;
	size_t mips_local_gotno;
	size_t mips_gotsym;
};

#endif /* LTRACE_MIPS_ARCH_H */
