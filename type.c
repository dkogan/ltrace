/*
 * This file is part of ltrace.
 * Copyright (C) 2011,2012 Petr Machata, Red Hat Inc.
 * Copyright (C) 2007,2008 Juan Cespedes
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

#include <assert.h>
#include <stdlib.h>

#include "type.h"
#include "sysdep.h"
#include "expr.h"

struct arg_type_info *
type_get_simple(enum arg_type type)
{
#define HANDLE(T) {					\
		static struct arg_type_info t = { T };	\
	case T:						\
		return &t;				\
	}

	switch (type) {
	HANDLE(ARGTYPE_UNKNOWN)
	HANDLE(ARGTYPE_VOID)
	HANDLE(ARGTYPE_INT)
	HANDLE(ARGTYPE_UINT)
	HANDLE(ARGTYPE_LONG)
	HANDLE(ARGTYPE_ULONG)
	HANDLE(ARGTYPE_OCTAL)
	HANDLE(ARGTYPE_CHAR)
	HANDLE(ARGTYPE_SHORT)
	HANDLE(ARGTYPE_USHORT)
	HANDLE(ARGTYPE_FLOAT)
	HANDLE(ARGTYPE_DOUBLE)

	  HANDLE(ARGTYPE_FORMAT)

#undef HANDLE

	case ARGTYPE_STRING_N:
	case ARGTYPE_COUNT:

	case ARGTYPE_ARRAY:
	case ARGTYPE_ENUM:
	case ARGTYPE_STRUCT:
	case ARGTYPE_POINTER:
		assert(!"Not a simple type!");
	};
	abort();
}

struct enum_entry {
	char *key;
	int own_key;
	int value;
};

void
type_init_enum(struct arg_type_info *info)
{
	info->type = ARGTYPE_ENUM;
	VECT_INIT(&info->u.entries, struct enum_entry);
}

int
type_enum_add(struct arg_type_info *info,
	      const char *key, int own_key, int value)
{
	assert(info->type == ARGTYPE_ENUM);
	struct enum_entry entry = { (char *)key, own_key, value };
	return VECT_PUSHBACK(&info->u.entries, &entry);
}

size_t
type_enum_size(struct arg_type_info *info)
{
	assert(info->type == ARGTYPE_ENUM);
	return vect_size(&info->u.entries);
}

const char *
type_enum_get(struct arg_type_info *info, int value)
{
	assert(info->type == ARGTYPE_ENUM);
	size_t i;
	for (i = 0; i < vect_size(&info->u.entries); ++i) {
		struct enum_entry *entry = VECT_ELEMENT(&info->u.entries,
							struct enum_entry, i);
		if (value == entry->value)
			return entry->key;
	}
	return NULL;
}

static void
enum_entry_dtor(struct enum_entry *entry, void *data)
{
	if (entry->own_key)
		free(entry->key);
}

static void
type_enum_destroy(struct arg_type_info *info)
{
	VECT_DESTROY(&info->u.entries, struct enum_entry,
		     enum_entry_dtor, NULL);
}

struct struct_field {
	struct arg_type_info *info;
	int own_info;
};

void
type_init_struct(struct arg_type_info *info)
{
	info->type = ARGTYPE_STRUCT;
	VECT_INIT(&info->u.entries, struct struct_field);
}

int
type_struct_add(struct arg_type_info *info,
		struct arg_type_info *field_info, int own)
{
	assert(info->type == ARGTYPE_STRUCT);
	struct struct_field field = { field_info, own };
	return VECT_PUSHBACK(&info->u.entries, &field);
}

struct arg_type_info *
type_struct_get(struct arg_type_info *info, size_t idx)
{
	assert(info->type == ARGTYPE_STRUCT);
	struct struct_field *field = VECT_ELEMENT(&info->u.entries,
						  struct struct_field, idx);
	if (field == NULL)
		return NULL;
	return field->info;
}

size_t
type_struct_size(struct arg_type_info *info)
{
	assert(info->type == ARGTYPE_STRUCT);
	return vect_size(&info->u.entries);
}

static void
struct_field_dtor(struct struct_field *field, void *data)
{
	if (field->own_info) {
		type_destroy(field->info);
		free(field->info);
	}
}

static void
type_struct_destroy(struct arg_type_info *info)
{
	VECT_DESTROY(&info->u.entries, struct struct_field,
		     struct_field_dtor, NULL);
}

static int
layout_struct(struct Process *proc, struct arg_type_info *info,
	      size_t *sizep, size_t *alignmentp, size_t *offsetofp)
{
	size_t sz = 0;
	size_t max_alignment = 0;
	size_t i;
	size_t offsetof_field = (size_t)-1;
	if (offsetofp != NULL)
		offsetof_field = *offsetofp;

	assert(info->type == ARGTYPE_STRUCT);
	for (i = 0; i < vect_size(&info->u.entries); ++i) {
		struct struct_field *field
			= VECT_ELEMENT(&info->u.entries,
				       struct struct_field, i);

		size_t alignment = type_alignof(proc, field->info);
		if (alignment == (size_t)-1)
			return -1;

		/* Add padding to SZ to align the next element.  */
		sz = align(sz, alignment);
		if (i == offsetof_field) {
			*offsetofp = sz;
			if (sizep == NULL && alignmentp == NULL)
				return 0;
		}

		size_t size = type_sizeof(proc, field->info);
		if (size == (size_t)-1)
			return -1;
		sz += size;

		if (alignment > max_alignment)
			max_alignment = alignment;
	}

	if (max_alignment > 0)
		sz = align(sz, max_alignment);

	if (sizep != NULL)
		*sizep = sz;

	if (alignmentp != NULL)
		*alignmentp = max_alignment;

	return 0;
}

void
type_init_array(struct arg_type_info *info,
		struct arg_type_info *element_info, int own_info,
		struct expr_node *length, int own_length)
{
	info->type = ARGTYPE_ARRAY;
	info->u.array_info.elt_type = element_info;
	info->u.array_info.own_info = own_info;
	info->u.array_info.length = length;
	info->u.array_info.own_length = own_length;
}

void
type_init_string(struct arg_type_info *info,
		 struct expr_node *length, int own_length)
{
	info->type = ARGTYPE_STRING_N;
	info->u.string_n_info.length = length;
	info->u.string_n_info.own_length = own_length;
}

static void
type_array_destroy(struct arg_type_info *info)
{
	if (info->u.array_info.own_info) {
		type_destroy(info->u.array_info.elt_type);
		free(info->u.array_info.elt_type);
	}
	if (info->u.array_info.own_length) {
		expr_destroy(info->u.array_info.length);
		free(info->u.array_info.length);
	}
}

static void
type_string_n_destroy(struct arg_type_info *info)
{
	if (info->u.array_info.own_length) {
		expr_destroy(info->u.string_n_info.length);
		free(info->u.string_n_info.length);
	}
}

void
type_init_pointer(struct arg_type_info *info,
		  struct arg_type_info *pointee_info, int own_info)
{
	info->type = ARGTYPE_POINTER;
	info->u.ptr_info.info = pointee_info;
	info->u.ptr_info.own_info = own_info;
}

static void
type_pointer_destroy(struct arg_type_info *info)
{
	if (info->u.ptr_info.own_info) {
		type_destroy(info->u.ptr_info.info);
		free(info->u.ptr_info.info);
	}
}

void
type_destroy(struct arg_type_info *info)
{
	if (info == NULL)
		return;

	switch (info->type) {
	case ARGTYPE_ENUM:
		return type_enum_destroy(info);

	case ARGTYPE_STRUCT:
		type_struct_destroy(info);
		break;

	case ARGTYPE_ARRAY:
		type_array_destroy(info);
		break;

	case ARGTYPE_POINTER:
		type_pointer_destroy(info);
		break;

	case ARGTYPE_STRING_N:
		type_string_n_destroy(info);

	case ARGTYPE_UNKNOWN:
	case ARGTYPE_VOID:
	case ARGTYPE_INT:
	case ARGTYPE_UINT:
	case ARGTYPE_LONG:
	case ARGTYPE_ULONG:
	case ARGTYPE_OCTAL:
	case ARGTYPE_CHAR:
	case ARGTYPE_SHORT:
	case ARGTYPE_USHORT:
	case ARGTYPE_FLOAT:
	case ARGTYPE_DOUBLE:
		break;

	case ARGTYPE_FORMAT:
	case ARGTYPE_COUNT:
		break;
	}
}

#ifdef ARCH_HAVE_SIZEOF
size_t arch_type_sizeof(struct Process *proc, struct arg_type_info * arg);
#else
size_t
arch_type_sizeof(struct Process *proc, struct arg_type_info * arg)
{
	/* Use default value.  */
	return (size_t)-2;
}
#endif

#ifdef ARCH_HAVE_ALIGNOF
size_t arch_type_alignof(struct Process *proc, struct arg_type_info * arg);
#else
size_t
arch_type_alignof(struct Process *proc, struct arg_type_info * arg)
{
	/* Use default value.  */
	return (size_t)-2;
}
#endif

/* We need to support alignments that are not power of two.  E.g. long
 * double on x86 has alignment of 12.  */
size_t
align(size_t sz, size_t alignment)
{
	assert(alignment != 0);

	if ((sz % alignment) != 0)
		sz = ((sz / alignment) + 1) * alignment;

	return sz;
}

size_t
type_sizeof(struct Process *proc, struct arg_type_info *type)
{
	size_t arch_size = arch_type_sizeof(proc, type);
	if (arch_size != (size_t)-2)
		return arch_size;

	switch (type->type) {
		size_t size;
	case ARGTYPE_CHAR:
		return sizeof(char);

	case ARGTYPE_SHORT:
	case ARGTYPE_USHORT:
		return sizeof(short);

	case ARGTYPE_INT:
	case ARGTYPE_UINT:
	case ARGTYPE_ENUM:
		return sizeof(int);

	case ARGTYPE_LONG:
	case ARGTYPE_ULONG:
		return sizeof(long);

	case ARGTYPE_FLOAT:
		return sizeof(float);

	case ARGTYPE_DOUBLE:
		return sizeof(double);

	case ARGTYPE_STRUCT:
		if (layout_struct(proc, type, &size, NULL, NULL) < 0)
			return (size_t)-1;
		return size;

	case ARGTYPE_POINTER:
		return sizeof(void *);

	case ARGTYPE_ARRAY:
		if (expr_is_compile_constant(type->u.array_info.length)) {
			long l;
			if (expr_eval_constant(type->u.array_info.length,
					       &l) < 0)
				return -1;

			struct arg_type_info *elt_ti
				= type->u.array_info.elt_type;

			size_t elt_size = type_sizeof(proc, elt_ti);
			if (elt_size == (size_t)-1)
				return (size_t)-1;

			return ((size_t)l) * elt_size;

		} else {
			/* Flexible arrays don't count into the
			 * sizeof.  */
			return 0;
		}

	case ARGTYPE_VOID:
		return 0;

	/* XXX these are in fact formatting conventions, not
	 * data types.  They should be handled differently.  */
	case ARGTYPE_OCTAL:
	case ARGTYPE_UNKNOWN:
		return sizeof(long);

	case ARGTYPE_FORMAT:
	case ARGTYPE_STRING_N:
	case ARGTYPE_COUNT:
		return -1;
	}

	abort();
}

#undef alignof
#define alignof(field,st) ((size_t) ((char*) &st.field - (char*) &st))

size_t
type_alignof(struct Process *proc, struct arg_type_info *type)
{
	size_t arch_alignment = arch_type_alignof(proc, type);
	if (arch_alignment != (size_t)-2)
		return arch_alignment;

	struct { char c; char C; } cC;
	struct { char c; short s; } cs;
	struct { char c; int i; } ci;
	struct { char c; long l; } cl;
	struct { char c; void* p; } cp;
	struct { char c; float f; } cf;
	struct { char c; double d; } cd;

	static size_t char_alignment = alignof(C, cC);
	static size_t short_alignment = alignof(s, cs);
	static size_t int_alignment = alignof(i, ci);
	static size_t long_alignment = alignof(l, cl);
	static size_t ptr_alignment = alignof(p, cp);
	static size_t float_alignment = alignof(f, cf);
	static size_t double_alignment = alignof(d, cd);

	switch (type->type) {
		size_t alignment;
	case ARGTYPE_LONG:
	case ARGTYPE_ULONG:
		return long_alignment;
	case ARGTYPE_CHAR:
		return char_alignment;
	case ARGTYPE_SHORT:
	case ARGTYPE_USHORT:
		return short_alignment;
	case ARGTYPE_FLOAT:
		return float_alignment;
	case ARGTYPE_DOUBLE:
		return double_alignment;
	case ARGTYPE_POINTER:
		return ptr_alignment;

	case ARGTYPE_ARRAY:
		return type_alignof(proc, type->u.array_info.elt_type);

	case ARGTYPE_STRUCT:
		if (layout_struct(proc, type, NULL, &alignment, NULL) < 0)
			return (size_t)-1;
		return alignment;

	default:
		return int_alignment;
	}
}

size_t
type_offsetof(struct Process *proc, struct arg_type_info *type, size_t emt)
{
	assert(type->type == ARGTYPE_STRUCT
	       || type->type == ARGTYPE_ARRAY
	       /* XXX Temporary, this will be removed.  */
	       || type->type == ARGTYPE_STRING_N);

	switch (type->type) {
		size_t alignment;
		size_t size;
	case ARGTYPE_ARRAY:
		alignment = type_alignof(proc, type->u.array_info.elt_type);
		if (alignment == (size_t)-1)
			return (size_t)-1;

		size = type_sizeof(proc, type->u.array_info.elt_type);
		if (size == (size_t)-1)
			return (size_t)-1;

		return emt * align(size, alignment);

	case ARGTYPE_STRING_N:
		return emt;

	case ARGTYPE_STRUCT:
		if (layout_struct(proc, type, NULL, NULL, &emt) < 0)
			return (size_t)-1;
		return emt;

	default:
		abort ();
	}
}

struct arg_type_info *
type_element(struct arg_type_info *info, size_t emt)
{
	assert(info->type == ARGTYPE_STRUCT
	       || info->type == ARGTYPE_ARRAY
	       /* XXX Temporary, this will be removed.  */
	       || info->type == ARGTYPE_STRING_N);

	switch (info->type) {
	case ARGTYPE_ARRAY:
		return info->u.array_info.elt_type;

	case ARGTYPE_STRUCT:
		assert(emt < type_struct_size(info));
		return type_struct_get(info, emt);

	case ARGTYPE_STRING_N:
		return type_get_simple(ARGTYPE_CHAR);

	default:
		abort ();
	}
}
