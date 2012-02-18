/*
 * This file is part of ltrace.
 * Copyright (C) 2011,2012 Petr Machata, Red Hat Inc.
 * Copyright (C) 2001,2009 Juan Cespedes
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

#include <stdlib.h>
#include <string.h>
#include "library.h"
#include "proc.h" // for enum callback_status
#include "debug.h"

/* If the other symbol owns the name, we need to make the copy, so
 * that the life-times of the two symbols are not dependent on each
 * other.  */
static int
strdup_if_owned(const char **retp, const char *str, int owned)
{
	if (!owned || str == NULL) {
		*retp = str;
		return 0;
	} else {
		*retp = strdup(str);
		return *retp != NULL ? 0 : -1;
	}
}

void
library_symbol_init(struct library_symbol *libsym, struct library *lib,
		    GElf_Addr addr, const char *name, int own_name,
		    enum toplt type_of_plt, int is_weak)
{
	libsym->next = NULL;
	libsym->lib = lib;
	libsym->needs_init = 0;
	libsym->is_weak = is_weak;
	libsym->plt_type = type_of_plt;
	libsym->name = name;
	libsym->own_name = own_name;
	libsym->enter_addr = (void *)(uintptr_t)addr;
}

void
library_symbol_destroy(struct library_symbol *libsym)
{
	if (libsym != NULL && libsym->own_name)
		free((char *)libsym->name);
}

int
library_symbol_clone(struct library_symbol *retp, struct library_symbol *libsym)
{
	const char *name;
	if (strdup_if_owned(&name, libsym->name, libsym->own_name) < 0)
		return -1;

	library_symbol_init(retp, libsym->lib, (GElf_Addr)libsym->enter_addr,
			    name, libsym->own_name, libsym->plt_type,
			    libsym->is_weak);
	retp->needs_init = libsym->needs_init;
	return 0;
}

int
library_symbol_cmp(struct library_symbol *a, struct library_symbol *b)
{
	if (a->enter_addr < b->enter_addr)
		return -1;
	if (a->enter_addr > b->enter_addr)
		return 1;
	if (a->name != NULL && b->name != NULL)
		return strcmp(a->name, b->name);
	if (a->name == NULL) {
		if (b->name == NULL)
			return 0;
		return -1;
	}
	return 1;
}

enum callback_status
library_symbol_equal_cb(struct library_symbol *libsym, void *u)
{
	struct library_symbol *standard = u;
	return library_symbol_cmp(libsym, standard) == 0 ? CBS_STOP : CBS_CONT;
}

void
library_init(struct library *lib, const char *name, int own_name)
{
	lib->next = NULL;
	lib->name = name;
	lib->own_name = own_name;
	lib->symbols = NULL;
}

int
library_clone(struct library *retp, struct library *lib)
{
	const char *name;
	if (strdup_if_owned(&name, lib->name, lib->own_name) < 0)
		return -1;

	library_init(retp, lib->name, lib->own_name);

	struct library_symbol *it;
	struct library_symbol **nsymp = &retp->symbols;
	for (it = lib->symbols; it != NULL; it = it->next) {
		*nsymp = malloc(sizeof(**nsymp));
		if (*nsymp == NULL
		    || library_symbol_clone(*nsymp, it) < 0) {
			/* Release what we managed to allocate.  */
			library_destroy(retp);
			return -1;
		}

		(*nsymp)->lib = retp;
		nsymp = &(*nsymp)->next;
	}
	return 0;
}

void
library_destroy(struct library *lib)
{
	if (lib == NULL)
		return;
	library_set_name(lib, NULL, 0);

	struct library_symbol *sym;
	for (sym = lib->symbols; sym != NULL; ) {
		struct library_symbol *next = sym->next;
		library_symbol_destroy(sym);
		free(sym);
		sym = next;
	}
}

void
library_set_name(struct library *lib, const char *new_name, int own_name)
{
	if (lib->own_name)
		free((char *)lib->name);
	lib->name = new_name;
	lib->own_name = own_name;
}

struct library_symbol *
library_each_symbol(struct library *lib, struct library_symbol *it,
		    enum callback_status (*cb)(struct library_symbol *, void *),
		    void *data)
{
	if (it == NULL)
		it = lib->symbols;

	while (it != NULL) {
		struct library_symbol *next = it->next;

		switch ((*cb)(it, data)) {
		case CBS_STOP:
			return it;
		case CBS_CONT:
			break;
		}

		it = next;
	}

	return NULL;
}

void
library_add_symbol(struct library *lib, struct library_symbol *sym)
{
	sym->next = lib->symbols;
	lib->symbols = sym;
}

enum callback_status
library_named_cb(struct Process *proc, struct library *lib, void *name)
{
	if (name == lib->name
	    || strcmp(lib->name, (char *)name) == 0)
		return CBS_STOP;
	else
		return CBS_CONT;
}

enum callback_status
library_with_base_cb(struct Process *proc, struct library *lib, void *basep)
{
	return lib->base == *(target_address_t *)basep ? CBS_STOP : CBS_CONT;
}
