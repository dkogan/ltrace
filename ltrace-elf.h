/*
 * This file is part of ltrace.
 * Copyright (C) 2006,2010,2012 Petr Machata, Red Hat Inc.
 * Copyright (C) 2010 Zachary T Welch
 * Copyright (C) 2001,2004,2007,2009 Juan Cespedes
 * Copyright (C) 2006 Ian Wienand
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

#ifndef LTRACE_ELF_H
#define LTRACE_ELF_H

#include <gelf.h>
#include <stdlib.h>
#include "sysdep.h"

struct Process;
struct library;
struct library_symbol;

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
	GElf_Word plt_flags;
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
	GElf_Addr dyn_addr;
	size_t dyn_sz;
	size_t relplt_size;
	GElf_Addr bias;
	GElf_Addr entry_addr;
	GElf_Addr base_addr;
	struct arch_ltelf_data arch;
};

int open_elf(struct ltelf *lte, const char *filename);
void do_close_elf(struct ltelf *lte);

/* XXX is it possible to put breakpoints in VDSO and VSYSCALL
 * pseudo-libraries?  For now we assume that all libraries can be
 * opened via a filesystem.  BASE is ignored for ET_EXEC files.  */
int ltelf_read_library(struct library *lib, struct Process *proc,
		       const char *filename, GElf_Addr bias);

/* Create a library object representing the main binary.  The entry
 * point address is stored to *ENTRYP.  */
struct library *ltelf_read_main_binary(struct Process *proc, const char *path);

/* Create a default PLT entry.  This can be used instead (or in
 * addition to) returning plt_default from arch_elf_add_plt_entry.
 * RET shall be initialized, the created symbol will be added to the
 * beginning of the linked list at *RET.  This function doesn't add
 * the symbol to LTE.  arch_elf_add_plt_entry has the chance to adjust
 * symbol internals to its liking, and then return either plt_default
 * or plt_ok.  */
int default_elf_add_plt_entry(struct Process *proc, struct ltelf *lte,
			      const char *a_name, GElf_Rela *rela, size_t ndx,
			      struct library_symbol **ret);

/* The base implementation of backend.h (arch_get_sym_info).
 * See backend.h for details.  */
int elf_get_sym_info(struct ltelf *lte, const char *filename,
		     size_t sym_index, GElf_Rela *rela, GElf_Sym *sym);

Elf_Data *elf_loaddata(Elf_Scn *scn, GElf_Shdr *shdr);
int elf_get_section_covering(struct ltelf *lte, GElf_Addr addr,
			     Elf_Scn **tgt_sec, GElf_Shdr *tgt_shdr);
int elf_get_section_type(struct ltelf *lte, GElf_Word type,
			 Elf_Scn **tgt_sec, GElf_Shdr *tgt_shdr);
int elf_get_section_named(struct ltelf *lte, const char *name,
			  Elf_Scn **tgt_sec, GElf_Shdr *tgt_shdr);

/* Read, respectively, 2, 4, or 8 bytes from Elf data at given OFFSET,
 * and store it in *RETP.  Returns 0 on success or a negative value if
 * there's not enough data.  */
int elf_read_u16(Elf_Data *data, GElf_Xword offset, uint16_t *retp);
int elf_read_u32(Elf_Data *data, GElf_Xword offset, uint32_t *retp);
int elf_read_u64(Elf_Data *data, GElf_Xword offset, uint64_t *retp);

#if __WORDSIZE == 32
#define PRI_ELF_ADDR		PRIx32
#define GELF_ADDR_CAST(x)	(void *)(uint32_t)(x)
#else
#define PRI_ELF_ADDR		PRIx64
#define GELF_ADDR_CAST(x)	(void *)(x)
#endif

#endif
