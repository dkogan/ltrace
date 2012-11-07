/*
 * This file is part of ltrace.
 * Copyright (C) 2012 Petr Machata
 * Copyright (C) 2006 Paul Gilliam
 * Copyright (C) 2002,2004 Juan Cespedes
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */
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

#define ARCH_HAVE_ATOMIC_SINGLESTEP
#define ARCH_HAVE_ADD_PLT_ENTRY
#define ARCH_HAVE_TRANSLATE_ADDRESS
#define ARCH_HAVE_DYNLINK_DONE
#define ARCH_HAVE_FETCH_ARG
#define ARCH_ENDIAN_BIG
#define ARCH_HAVE_SIZEOF
#define ARCH_HAVE_ALIGNOF

struct library_symbol;

#define ARCH_HAVE_LTELF_DATA
struct arch_ltelf_data {
	GElf_Addr plt_stub_vma;
	struct library_symbol *stubs;
	Elf_Data *opd_data;
	GElf_Addr opd_base;
	GElf_Xword opd_size;
	int secure_plt;
};

#define ARCH_HAVE_LIBRARY_DATA
struct arch_library_data {
	GElf_Addr pltgot_addr;
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
