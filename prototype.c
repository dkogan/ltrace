/*
 * This file is part of ltrace.
 * Copyright (C) 2012 Petr Machata, Red Hat Inc.
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

#include "prototype.h"
#include "callback.h"
#include "param.h"
#include "type.h"

struct protolib g_prototypes;

void
prototype_init(struct prototype *proto)
{
	VECT_INIT(&proto->params, struct param);

	proto->return_info = NULL;
	proto->own_return_info = 0;
}

static void
param_destroy_cb(struct param *param, void *data)
{
	param_destroy(param);
}

void
prototype_destroy(struct prototype *proto)
{
	if (proto == NULL)
		return;
	if (proto->own_return_info) {
		type_destroy(proto->return_info);
		free(proto->return_info);
	}

	VECT_DESTROY(&proto->params, struct param, &param_destroy_cb, NULL);
}

int
prototype_push_param(struct prototype *proto, struct param *param)
{
	return VECT_PUSHBACK(&proto->params, param);
}

size_t
prototype_num_params(struct prototype *proto)
{
	return vect_size(&proto->params);
}

void
prototype_destroy_nth_param(struct prototype *proto, size_t n)
{
	assert(n < prototype_num_params(proto));
	VECT_ERASE(&proto->params, struct param, n, n+1,
		   &param_destroy_cb, NULL);
}

struct param *
prototype_get_nth_param(struct prototype *proto, size_t n)
{
	assert(n < prototype_num_params(proto));
	return VECT_ELEMENT(&proto->params, struct param, n);
}

struct each_param_data {
	struct prototype *proto;
	enum callback_status (*cb)(struct prototype *, struct param *, void *);
	void *data;
};

static enum callback_status
each_param_cb(struct param *param, void *data)
{
	struct each_param_data *cb_data = data;
	return (cb_data->cb)(cb_data->proto, param, cb_data->data);
}

struct param *
prototype_each_param(struct prototype *proto, struct param *start_after,
		     enum callback_status (*cb)(struct prototype *,
						struct param *, void *),
		     void *data)
{
	struct each_param_data cb_data = { proto, cb, data };
	return VECT_EACH(&proto->params, struct param, start_after,
			 &each_param_cb, &cb_data);
}

void
named_type_init(struct named_type *named,
		struct arg_type_info *info, int own_type)
{
	named->info = info;
	named->own_type = own_type;
	named->forward = 0;
}

void
named_type_destroy(struct named_type *named)
{
	if (named->own_type) {
		type_destroy(named->info);
		free(named->info);
	}
}

int
protolib_init(struct protolib *plib)
{
	plib->prototypes = dict_init(&dict_key2hash_string,
				     &dict_key_cmp_string);
	if (plib->prototypes == NULL)
		return -1;

	plib->named_types = dict_init(&dict_key2hash_string,
				      &dict_key_cmp_string);
	if (plib->named_types == NULL) {
		dict_clear(plib->prototypes);
		return -1;
	}

	VECT_INIT(&plib->imports, struct protolib *);
	return 0;
}

static void
prototype_entry_destroy(void *key, void *val, void *data)
{
	char *name = key;
	struct prototype *proto = val;
	free(name);
	prototype_destroy(proto);
}

static void
named_type_entry_destroy(void *key, void *val, void *data)
{
	char *name = key;
	struct named_type *named = val;
	free(name);
	named_type_destroy(named);
}

void
protolib_destroy(struct protolib *plib)
{
	VECT_DESTROY(&plib->imports, struct prototype *, NULL, NULL);

	dict_apply_to_all(plib->prototypes, prototype_entry_destroy, NULL);
	dict_clear(plib->prototypes);

	dict_apply_to_all(plib->named_types, named_type_entry_destroy, NULL);
	dict_clear(plib->named_types);
}

static struct protolib **
each_import(struct protolib *plib, struct protolib **start_after,
	    enum callback_status (*cb)(struct protolib **, void *), void *data)
{
	return VECT_EACH(&plib->imports, struct protolib *,
			 start_after, cb, data);
}

static enum callback_status
is_or_imports(struct protolib **plibp, void *data)
{
	struct protolib *import = data;
	if (*plibp == import
	    || each_import(*plibp, NULL, &is_or_imports, import) != NULL)
		return CBS_STOP;
	else
		return CBS_CONT;
}

int
protolib_add_import(struct protolib *plib, struct protolib *import)
{
	if (is_or_imports(&plib, import) == CBS_STOP)
		return -2;

	return VECT_PUSHBACK(&plib->imports, import) < 0 ? -1 : 0;
}

static int
enroll(struct dict *dict, const char *name, int own_name, void *value)
{
	assert(name != NULL);

	if (!own_name) {
		name = strdup(name);
		if (name == NULL)
			return -1;
	}

	if (dict_enter(dict, (void *)name, value) < 0) {
		if (own_name)
			free((void *)name);
		return -1;
	}
	return 0;
}

int
protolib_add_prototype(struct protolib *plib, const char *name, int own_name,
		       struct prototype *proto)
{
	return enroll(plib->prototypes, name, own_name, proto);
}

int
protolib_add_named_type(struct protolib *plib, const char *name, int own_name,
			struct named_type *named)
{
	return enroll(plib->named_types, name, own_name, named);
}

struct lookup {
	const char *name;
	void *result;
	struct dict *(*getter)(struct protolib *plib);
};

static struct dict *
get_prototypes(struct protolib *plib)
{
	return plib->prototypes;
}

static struct dict *
get_named_types(struct protolib *plib)
{
	return plib->named_types;
}

static enum callback_status
protolib_lookup_rec(struct protolib **plibp, void *data)
{
	struct lookup *lookup = data;
	struct dict *dict = (*lookup->getter)(*plibp);

	lookup->result = dict_find_entry(dict, lookup->name);
	if (lookup->result != NULL)
		return CBS_STOP;

	if (each_import(*plibp, NULL, &protolib_lookup_rec, lookup) != NULL) {
		assert(lookup->result != NULL);
		return CBS_STOP;
	}

	return CBS_CONT;
}

static void *
protolib_lookup(struct protolib *plib, const char *name,
		struct dict *(*getter)(struct protolib *))
{
	struct lookup lookup = { name, NULL, getter };
	if (protolib_lookup_rec(&plib, &lookup) == CBS_STOP)
		assert(lookup.result != NULL);
	else
		assert(lookup.result == NULL);
	return lookup.result;
}

struct prototype *
protolib_lookup_prototype(struct protolib *plib, const char *name)
{
	return protolib_lookup(plib, name, &get_prototypes);
}

struct named_type *
protolib_lookup_type(struct protolib *plib, const char *name)
{
	return protolib_lookup(plib, name, &get_named_types);
}
