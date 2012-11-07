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
#include <assert.h>
#include <stdio.h>

#include "library.h"
#include "callback.h"
#include "debug.h"
#include "dict.h"
#include "backend.h" // for arch_library_symbol_init, arch_library_init

#ifndef ARCH_HAVE_LIBRARY_DATA
void
arch_library_init(struct library *lib)
{
}

void
arch_library_destroy(struct library *lib)
{
}

void
arch_library_clone(struct library *retp, struct library *lib)
{
}
#endif

#ifndef ARCH_HAVE_LIBRARY_SYMBOL_DATA
int
arch_library_symbol_init(struct library_symbol *libsym)
{
	return 0;
}

void
arch_library_symbol_destroy(struct library_symbol *libsym)
{
}

int
arch_library_symbol_clone(struct library_symbol *retp,
			  struct library_symbol *libsym)
{
	return 0;
}
#endif

unsigned int
target_address_hash(const void *key)
{
	/* XXX this assumes that key is passed by value.  */
	union {
		arch_addr_t addr;
		unsigned int ints[sizeof(arch_addr_t)
				  / sizeof(unsigned int)];
	} u = { .addr = (arch_addr_t)key };

	size_t i;
	unsigned int h = 0;
	for (i = 0; i < sizeof(u.ints) / sizeof(*u.ints); ++i)
		h ^= dict_key2hash_int((void *)(uintptr_t)u.ints[i]);
	return h;
}

int
target_address_cmp(const void *key1, const void *key2)
{
	/* XXX this assumes that key is passed by value.  */
	arch_addr_t addr1 = (arch_addr_t)key1;
	arch_addr_t addr2 = (arch_addr_t)key2;
	return addr1 < addr2 ? 1
	     : addr1 > addr2 ? -1 : 0;
}

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

static void
private_library_symbol_init(struct library_symbol *libsym,
			    arch_addr_t addr,
			    const char *name, int own_name,
			    enum toplt type_of_plt,
			    int latent, int delayed)
{
	libsym->next = NULL;
	libsym->lib = NULL;
	libsym->plt_type = type_of_plt;
	libsym->name = name;
	libsym->own_name = own_name;
	libsym->latent = latent;
	libsym->delayed = delayed;
	libsym->enter_addr = (void *)(uintptr_t)addr;
}

static void
private_library_symbol_destroy(struct library_symbol *libsym)
{
	library_symbol_set_name(libsym, NULL, 0);
}

int
library_symbol_init(struct library_symbol *libsym,
		    arch_addr_t addr, const char *name, int own_name,
		    enum toplt type_of_plt)
{
	private_library_symbol_init(libsym, addr, name, own_name,
				    type_of_plt, 0, 0);

	/* If arch init fails, we've already set libsym->name and
	 * own_name.  But we return failure, and the client code isn't
	 * supposed to call library_symbol_destroy in such a case.  */
	return arch_library_symbol_init(libsym);
}

void
library_symbol_destroy(struct library_symbol *libsym)
{
	if (libsym != NULL) {
		private_library_symbol_destroy(libsym);
		arch_library_symbol_destroy(libsym);
	}
}

int
library_symbol_clone(struct library_symbol *retp, struct library_symbol *libsym)
{
	const char *name;
	if (strdup_if_owned(&name, libsym->name, libsym->own_name) < 0)
		return -1;

	private_library_symbol_init(retp, libsym->enter_addr,
				    name, libsym->own_name, libsym->plt_type,
				    libsym->latent, libsym->delayed);

	if (arch_library_symbol_clone(retp, libsym) < 0) {
		private_library_symbol_destroy(retp);
		return -1;
	}

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

void
library_symbol_set_name(struct library_symbol *libsym,
			const char *name, int own_name)
{
	if (libsym->own_name)
		free((char *)libsym->name);
	libsym->name = name;
	libsym->own_name = own_name;
}

enum callback_status
library_symbol_equal_cb(struct library_symbol *libsym, void *u)
{
	struct library_symbol *standard = u;
	return library_symbol_cmp(libsym, standard) == 0 ? CBS_STOP : CBS_CONT;
}

enum callback_status
library_symbol_named_cb(struct library_symbol *libsym, void *name)
{
	return strcmp(libsym->name, name) == 0 ? CBS_STOP : CBS_CONT;
}

enum callback_status
library_symbol_delayed_cb(struct library_symbol *libsym, void *unused)
{
	return libsym->delayed ? CBS_STOP : CBS_CONT;
}

static void
private_library_init(struct library *lib, enum library_type type)
{
	lib->next = NULL;

	lib->key = 0;
	lib->base = 0;
	lib->entry = 0;
	lib->dyn_addr = 0;

	lib->soname = NULL;
	lib->own_soname = 0;

	lib->pathname = NULL;
	lib->own_pathname = 0;

	lib->symbols = NULL;
	lib->exported_names = NULL;
	lib->type = type;
}

void
library_init(struct library *lib, enum library_type type)
{
	private_library_init(lib, type);
	arch_library_init(lib);
}

static int
library_exported_name_clone(struct library_exported_name *retp,
			    struct library_exported_name *exnm)
{
	char *name = exnm->own_name ? strdup(exnm->name) : (char *)exnm->name;
	if (name == NULL)
		return -1;
	retp->name = name;
	retp->own_name = exnm->own_name;
	return 0;
}

int
library_clone(struct library *retp, struct library *lib)
{
	const char *soname = NULL;
	const char *pathname;
	if (strdup_if_owned(&soname, lib->soname, lib->own_soname) < 0
	     || strdup_if_owned(&pathname,
				lib->pathname, lib->own_pathname) < 0) {
		if (lib->own_soname)
			free((char *)soname);
		return -1;
	}

	private_library_init(retp, lib->type);
	library_set_soname(retp, soname, lib->own_soname);
	library_set_pathname(retp, pathname, lib->own_pathname);
	arch_library_clone(retp, lib);

	retp->key = lib->key;

	/* Clone symbols.  */
	{
		struct library_symbol *it;
		struct library_symbol **nsymp = &retp->symbols;
		for (it = lib->symbols; it != NULL; it = it->next) {
			*nsymp = malloc(sizeof(**nsymp));
			if (*nsymp == NULL
			    || library_symbol_clone(*nsymp, it) < 0) {
				free(*nsymp);
			fail:
				/* Release what we managed to allocate.  */
				library_destroy(retp);
				return -1;
			}

			(*nsymp)->lib = retp;
			nsymp = &(*nsymp)->next;
		}
		*nsymp = NULL;
	}

	/* Clone exported names.  */
	{
		struct library_exported_name *it;
		struct library_exported_name **nnamep = &retp->exported_names;
		for (it = lib->exported_names; it != NULL; it = it->next) {
			*nnamep = malloc(sizeof(**nnamep));
			if (*nnamep == NULL
			    || library_exported_name_clone(*nnamep, it) < 0) {
				free(*nnamep);
				goto fail;
			}
			nnamep = &(*nnamep)->next;
		}
		*nnamep = NULL;
	}

	return 0;
}

void
library_destroy(struct library *lib)
{
	if (lib == NULL)
		return;

	arch_library_destroy(lib);
	library_set_soname(lib, NULL, 0);
	library_set_pathname(lib, NULL, 0);

	struct library_symbol *sym;
	for (sym = lib->symbols; sym != NULL; ) {
		struct library_symbol *next = sym->next;
		library_symbol_destroy(sym);
		free(sym);
		sym = next;
	}

	/* Release exported names.  */
	struct library_exported_name *it;
	for (it = lib->exported_names; it != NULL; ) {
		struct library_exported_name *next = it->next;
		if (it->own_name)
			free((char *)it->name);
		free(it);
		it = next;
	}
}

void
library_set_soname(struct library *lib, const char *new_name, int own_name)
{
	if (lib->own_soname)
		free((char *)lib->soname);
	lib->soname = new_name;
	lib->own_soname = own_name;
}

void
library_set_pathname(struct library *lib, const char *new_name, int own_name)
{
	if (lib->own_pathname)
		free((char *)lib->pathname);
	lib->pathname = new_name;
	lib->own_pathname = own_name;
}

struct library_symbol *
library_each_symbol(struct library *lib, struct library_symbol *start_after,
		    enum callback_status (*cb)(struct library_symbol *, void *),
		    void *data)
{
	struct library_symbol *it = start_after == NULL ? lib->symbols
		: start_after->next;

	while (it != NULL) {
		struct library_symbol *next = it->next;

		switch ((*cb)(it, data)) {
		case CBS_FAIL:
			/* XXX handle me  */
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
library_add_symbol(struct library *lib, struct library_symbol *first)
{
	struct library_symbol *last;
	for (last = first; last != NULL; ) {
		last->lib = lib;
		if (last->next != NULL)
			last = last->next;
		else
			break;
	}

	assert(last->next == NULL);
	last->next = lib->symbols;
	lib->symbols = first;
}

enum callback_status
library_named_cb(struct Process *proc, struct library *lib, void *name)
{
	if (name == lib->soname
	    || strcmp(lib->soname, (char *)name) == 0)
		return CBS_STOP;
	else
		return CBS_CONT;
}

enum callback_status
library_with_key_cb(struct Process *proc, struct library *lib, void *keyp)
{
	return lib->key == *(arch_addr_t *)keyp ? CBS_STOP : CBS_CONT;
}
