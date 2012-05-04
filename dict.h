/*
 * This file is part of ltrace.
 * Copyright (C) 2011,2012 Petr Machata
 * Copyright (C) 2003,2004,2008,2009 Juan Cespedes
 * Copyright (C) 2006 Ian Wienand
 * Copyright (C) ???? Morten Eriksen <mortene@sim.no>
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

#ifndef _DICT_H_
#define _DICT_H_

/*
 * Dictionary based on code by Morten Eriksen <mortene@sim.no>.
 */

typedef struct dict Dict;

extern Dict *dict_init(unsigned int (*key2hash) (const void *),
		       int (*key_cmp) (const void *, const void *));
extern void dict_clear(Dict *d);
extern int dict_enter(Dict *d, void *key, void *value);
extern void *dict_remove(Dict *d, void *key);
extern void *dict_find_entry(Dict *d, const void *key);
extern void dict_apply_to_all(Dict *d,
			      void (*func) (void *key, void *value, void *data),
			      void *data);

extern unsigned int dict_key2hash_string(const void *key);
extern int dict_key_cmp_string(const void *key1, const void *key2);

extern unsigned int dict_key2hash_int(const void *key);
extern int dict_key_cmp_int(const void *key1, const void *key2);

extern Dict * dict_clone(Dict *old, void * (*key_clone)(void*), void * (*value_clone)(void*));
extern Dict * dict_clone2(Dict * old,
			  void * (* key_clone)(void * key, void * data),
			  void * (* value_clone)(void * value, void * data),
			  void * data);

#endif /* _DICT_H_ */
