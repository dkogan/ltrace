/*
 * This file is part of ltrace.
 * Copyright (C) 2010 Zach Welch, CodeSourcery
 * Copyright (C) 2004,2008,2009 Juan Cespedes
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

#include <gelf.h>

#include "proc.h"
#include "library.h"
#include "ltrace-elf.h"

static int
arch_plt_entry_has_stub(struct ltelf *lte, size_t off) {
	uint16_t op = *(uint16_t *)((char *)lte->relplt->d_buf + off);
	return op == 0x4778;
}

GElf_Addr
arch_plt_sym_val(struct ltelf *lte, size_t ndx, GElf_Rela * rela) {
	size_t start = lte->relplt->d_size + 12;
	size_t off = start + 20, i;
	for (i = 0; i < ndx; i++)
		off += arch_plt_entry_has_stub(lte, off) ? 16 : 12;
	if (arch_plt_entry_has_stub(lte, off))
		off += 4;
	return lte->plt_addr + off - start;
}

void *
sym2addr(Process *proc, struct library_symbol *sym) {
	return sym->enter_addr;
}
