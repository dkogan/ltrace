/*
 * This file is part of ltrace.
 * Copyright (C) 2011,2012 Petr Machata
 * Copyright (C) 2003,2004,2008,2009 Juan Cespedes
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "common.h"

/*
 * Dictionary based on code by Morten Eriksen <mortene@sim.no>.
 */

struct dict_entry {
	unsigned int hash;
	void *key;
	void *value;
	struct dict_entry *next;
};

/* #define DICTTABLESIZE 97 */
#define DICTTABLESIZE 997	/* Semi-randomly selected prime number. */
/* #define DICTTABLESIZE 9973 */
/* #define DICTTABLESIZE 99991 */
/* #define DICTTABLESIZE 999983 */

struct dict {
	struct dict_entry *buckets[DICTTABLESIZE];
	unsigned int (*key2hash) (const void *);
	int (*key_cmp) (const void *, const void *);
};

Dict *
dict_init(unsigned int (*key2hash) (const void *),
	  int (*key_cmp) (const void *, const void *))
{
	Dict *d;
	int i;

	debug(DEBUG_FUNCTION, "dict_init()");

	d = malloc(sizeof(Dict));
	if (!d) {
		perror("malloc()");
		exit(1);
	}
	for (i = 0; i < DICTTABLESIZE; i++) {	/* better use memset()? */
		d->buckets[i] = NULL;
	}
	d->key2hash = key2hash;
	d->key_cmp = key_cmp;
	return d;
}

void
dict_clear(Dict *d) {
	int i;
	struct dict_entry *entry, *nextentry;

	debug(DEBUG_FUNCTION, "dict_clear()");
	assert(d);
	for (i = 0; i < DICTTABLESIZE; i++) {
		for (entry = d->buckets[i]; entry != NULL; entry = nextentry) {
			nextentry = entry->next;
			free(entry);
		}
		d->buckets[i] = NULL;
	}
	free(d);
}

int
dict_enter(Dict *d, void *key, void *value) {
	struct dict_entry *entry, *newentry;
	unsigned int hash;
	unsigned int bucketpos;

	debug(DEBUG_FUNCTION, "dict_enter()");

	hash = d->key2hash(key);
	bucketpos = hash % DICTTABLESIZE;

	assert(d);
	newentry = malloc(sizeof(struct dict_entry));
	if (!newentry) {
		perror("malloc");
		exit(1);
	}

	newentry->hash = hash;
	newentry->key = key;
	newentry->value = value;
	newentry->next = NULL;

	entry = d->buckets[bucketpos];
	while (entry && entry->next)
		entry = entry->next;

	if (entry)
		entry->next = newentry;
	else
		d->buckets[bucketpos] = newentry;

	debug(3, "new dict entry at %p[%d]: (%p,%p)", d, bucketpos, key, value);
	return 0;
}

void *
dict_remove(Dict *d, void *key)
{
	assert(d != NULL);
	debug(DEBUG_FUNCTION, "dict_remove(%p)", key);

	unsigned int hash = d->key2hash(key);
	unsigned int bucketpos = hash % DICTTABLESIZE;

	struct dict_entry **entryp;
	for (entryp = &d->buckets[bucketpos]; (*entryp) != NULL;
	     entryp = &(*entryp)->next) {
		struct dict_entry *entry = *entryp;
		if (hash != entry->hash)
			continue;
		if (d->key_cmp(key, entry->key) == 0) {
			*entryp = entry->next;
			void *value = entry->value;
			free(entry);
			return value;
		}
	}
	return NULL;
}

void *
dict_find_entry(Dict *d, const void *key)
{
	unsigned int hash;
	unsigned int bucketpos;
	struct dict_entry *entry;

	debug(DEBUG_FUNCTION, "dict_find_entry()");

	hash = d->key2hash(key);
	bucketpos = hash % DICTTABLESIZE;

	assert(d);
	for (entry = d->buckets[bucketpos]; entry; entry = entry->next) {
		if (hash != entry->hash) {
			continue;
		}
		if (!d->key_cmp(key, entry->key)) {
			break;
		}
	}
	return entry ? entry->value : NULL;
}

void
dict_apply_to_all(Dict *d,
		  void (*func) (void *key, void *value, void *data), void *data) {
	int i;

	debug(DEBUG_FUNCTION, "dict_apply_to_all()");

	if (!d) {
		return;
	}
	for (i = 0; i < DICTTABLESIZE; i++) {
		struct dict_entry *entry = d->buckets[i];
		while (entry) {
			func(entry->key, entry->value, data);
			entry = entry->next;
		}
	}
}

/*****************************************************************************/

unsigned int
dict_key2hash_string(const void *key)
{
	const char *s = (const char *)key;
	unsigned int total = 0, shift = 0;

	assert(key);
	while (*s) {
		total = total ^ ((*s) << shift);
		shift += 5;
		if (shift > 24)
			shift -= 24;
		s++;
	}
	return total;
}

int
dict_key_cmp_string(const void *key1, const void *key2)
{
	assert(key1);
	assert(key2);
	return strcmp((const char *)key1, (const char *)key2);
}

unsigned int
dict_key2hash_int(const void *key)
{
	return (unsigned long)key;
}

int
dict_key_cmp_int(const void *key1, const void *key2)
{
	return key1 - key2;
}

Dict *
dict_clone2(Dict * old, void * (*key_clone)(void *, void *),
	    void * (*value_clone)(void *, void *), void * data)
{
	Dict *d;
	int i;

	debug(DEBUG_FUNCTION, "dict_clone()");

	d = malloc(sizeof(Dict));
	if (!d) {
		perror("malloc()");
		exit(1);
	}
	memcpy(d, old, sizeof(Dict));
	for (i = 0; i < DICTTABLESIZE; i++) {	/* better use memset()? */
		struct dict_entry *de_old;
		struct dict_entry **de_new;

		de_old = old->buckets[i];
		de_new = &d->buckets[i];
		while (de_old) {
			void * nkey, * nval;
			*de_new = malloc(sizeof(struct dict_entry));
			if (!*de_new) {
				perror("malloc()");
				exit(1);
			}
			memcpy(*de_new, de_old, sizeof(struct dict_entry));

			/* The error detection is rather weak :-/ */
			nkey = key_clone(de_old->key, data);
			if (nkey == NULL && de_old->key != NULL) {
				perror("key_clone");
			err:
				/* XXX Will this actually work?  We
				 * simply memcpy the old dictionary
				 * over up there.  */
				dict_clear(d);
				free(de_new);
				return NULL;
			}

			nval = value_clone(de_old->value, data);
			if (nval == NULL && de_old->value != NULL) {
				perror("value_clone");
				goto err;
			}

			(*de_new)->key = nkey;
			(*de_new)->value = nval;
			de_new = &(*de_new)->next;
			de_old = de_old->next;
		}
	}
	return d;
}

struct wrap_clone_cb
{
	void * (*key_clone)(void *);
	void * (*value_clone)(void *);
};

static void *
value_clone_1(void * arg, void * data)
{
	return ((struct wrap_clone_cb *)data)->value_clone(arg);
}

static void *
key_clone_1(void * arg, void * data)
{
	return ((struct wrap_clone_cb *)data)->key_clone(arg);
}

Dict *
dict_clone(Dict * old, void * (*key_clone)(void *),
	   void * (*value_clone)(void *))
{
	struct wrap_clone_cb cb = { key_clone, value_clone };
	return dict_clone2(old, &key_clone_1, &value_clone_1, &cb);
}
