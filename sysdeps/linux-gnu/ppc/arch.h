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
#define ARCH_HAVE_TRANSLATE_ADDRESS
#define ARCH_HAVE_DYNLINK_DONE

struct library_symbol;

#define ARCH_HAVE_LTELF_DATA
struct arch_ltelf_data {
	GElf_Addr plt_stub_vma;
	struct library_symbol *stubs;
	int secure_plt;
};

#define ARCH_HAVE_LIBRARY_DATA
struct arch_library_data {
	int bss_plt_prelinked;
};

enum ppc64_plt_type {
	/* Either a non-PLT symbol, or PPC32 symbol.  */
	PPC_DEFAULT = 0,

	/* PPC64 STUB, never resolved.  */
	PPC64_PLT_STUB,

	/* Unresolved PLT symbol (.plt contains PLT address).  */
	PPC_PLT_UNRESOLVED,

	/* Resolved PLT symbol.  The corresponding .plt slot contained
	 * target address, which was changed to the address of
	 * corresponding PLT entry.  The original is now saved in
	 * RESOLVED_VALUE.  */
	PPC_PLT_RESOLVED,
};

#define ARCH_HAVE_LIBRARY_SYMBOL_DATA
struct arch_library_symbol_data {
	enum ppc64_plt_type type;
	GElf_Addr resolved_value;

	/* Address of corresponding slot in .plt.  */
	GElf_Addr plt_slot_addr;
};

#define ARCH_HAVE_BREAKPOINT_DATA
struct arch_breakpoint_data {
	/* We need this just for arch_breakpoint_init.  */
};

#define ARCH_HAVE_PROCESS_DATA
struct arch_process_data {
	/* Breakpoint that hits when the dynamic linker is about to
	 * update a .plt slot.  NULL before that address is known.  */
	struct breakpoint *dl_plt_update_bp;

	/* PLT update breakpoint looks here for the handler.  */
	struct process_stopping_handler *handler;
};

#endif /* LTRACE_PPC_ARCH_H */
