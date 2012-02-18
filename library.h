/*
 * This file is part of ltrace.
 * Copyright (C) 2012 Petr Machata, Red Hat Inc.
 * Copyright (C) 2006 Paul Gilliam
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

#ifndef _LIBRARY_H_
#define _LIBRARY_H_

#include <stdint.h>
#include <gelf.h> // XXX 

struct Process;
struct library;

enum toplt {
	LS_TOPLT_NONE = 0,	/* PLT not used for this symbol. */
	LS_TOPLT_EXEC,		/* PLT for this symbol is executable. */
	LS_TOPLT_POINT		/* PLT for this symbol is a non-executable. */
};

/* We should in general be able to trace 64-bit processes with 32-bit
 * ltrace.  (At least PPC has several PTRACE requests related to
 * tracing 64-on-32, so presumably it should be possible.)  But ltrace
 * is currently hopelessly infested with using void* for host address.
 * So keep with it, for now.  */
typedef void *target_address_t;

struct library_symbol {
	struct library_symbol *next;
	struct library *lib;
	const char *name;
	target_address_t enter_addr;
	enum toplt plt_type;
	char needs_init;
	char is_weak;
	char own_name;
};

/* Init LIBSYM.  NAME will be freed when LIBSYM is destroyed if
 * OWN_NAME.  */
/* XXX note that we shouldn't use GElf_Addr for ADDR either.  The fact
 * that Elf is used is a back-end detail.  At least ltrace pretends
 * that it would like to be cross-platform like that one day.  */
void library_symbol_init(struct library_symbol *libsym, struct library *lib,
			 GElf_Addr addr, const char *name, int own_name,
			 enum toplt type_of_plt, int is_weak);

/* Copy library symbol SYM into the area pointed-to by RETP.  Return 0
 * on success or a negative value on failure.  */
int library_symbol_clone(struct library_symbol *retp,
			 struct library_symbol *sym);

/* Destroy library symbol.  This essentially just frees name if it's
 * owned.  It doesn't free the memory associated with SYM pointer
 * itself.  Returns 0 on success or a negative value in case of an
 * error (which would be an out of memory condition).  */
void library_symbol_destroy(struct library_symbol *sym);

/* Compare two library symbols.  Returns a negative value, 0, or a
 * positive value, much like strcmp.  The function compares symbol
 * addresses, and if those are equal, it compares symbol names.  If
 * those are equal, too, the symbols are considered equal.  */
int library_symbol_cmp(struct library_symbol *a, struct library_symbol *b);

/* A function that can be used as library_each_symbol callback.  Looks
 * for a symbol SYM for which library_symbol_cmp(SYM, STANDARD)
 * returns 0.  */
enum callback_status library_symbol_equal_cb(struct library_symbol *libsym,
					     void *standard);

/* XXX we might consider sharing libraries across processes.  Things
 * like libc will be opened by every single process, no point cloning
 * these everywhere.  But for now, keep the ownership structure
 * simple.  */
struct library {
	struct library *next;

	/* Address where the library is mapped.  Two library objects
	 * are considered equal, if they have the same base.  */
	target_address_t base;

	/* Absolute address of the entry point.  Useful for main
	 * binary, though I the value might be useful for the dynamic
	 * linker, too (in case we ever want to do early process
	 * tracing).  */
	target_address_t entry;

	/* Symbols associated with the library.  */
	struct library_symbol *symbols;
	const char *name;
	char own_name;
};

/* Init LIB.  NAME will be freed when LIB is destroyed if
 * OWN_NAME.  */
void library_init(struct library *lib, const char *name, int own_name);

/* Initialize RETP to a library identical to LIB.  Symbols are not
 * shared, but copied over.  Returns 0 on success and a negative value
 * in case of failure.  */
int library_clone(struct library *retp, struct library *lib);

/* Destroy library.  Doesn't free LIB itself.  */
void library_destroy(struct library *lib);

/* Set library name.  Frees the old name if necessary.  */
void library_set_name(struct library *lib, const char *new_name, int own_name);

/* Iterate through list of symbols of library LIB.  Restarts are
 * supported via START (see each_process for details of iteration
 * interface).  */
struct library_symbol *library_each_symbol
	(struct library *lib, struct library_symbol *start,
	 enum callback_status (*cb)(struct library_symbol *, void *),
	 void *data);

/* Add a new symbol SYM to LIB.  SYM is assumed owned, we need to
 * overwrite SYM->next.  */
void library_add_symbol(struct library *lib, struct library_symbol *sym);

/* A function that can be used as proc_each_library callback.  Looks
 * for a library with the name passed in DATA.  PROC is ignored.  */
enum callback_status library_named_cb(struct Process *proc,
				      struct library *lib, void *name);

/* A function that can be used as proc_each_library callback.  Looks
 * for a library with given base.
 *
 * NOTE: The base is passed as a POINTER to target_address_t (that
 * because in general, target_address_t doesn't fit in void*). */
enum callback_status library_with_base_cb(struct Process *proc,
					  struct library *lib, void *basep);

#endif /* _LIBRARY_H_ */
