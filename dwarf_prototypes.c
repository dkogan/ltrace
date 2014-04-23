/* Copyright Dima Kogan <dima@secretsauce.net>
 *
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of version 2 of the GNU General Public License as published by the
 * Free Software Foundation.
 *
 */
#include <stdio.h>
#include <elfutils/libdwfl.h>
#include <dwarf.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include "config.h"
#include "prototype.h"
#include "type.h"
#include "param.h"
#include "dict.h"
#include "lens.h"
#include "lens_enum.h"
#include "value.h"
#include "expr.h"
#include "library.h"
#include "options.h"
#include "filter.h"


//#define DUMP_PROTOTYPES

#if 1
#define complain( die, format, ... )							\
	fprintf(stderr, "%s() die '%s' @ 0x%lx: " format "\n",		\
			__func__, dwarf_diename(die), dwarf_dieoffset(die),	\
			##__VA_ARGS__ )
#else
#define complain( die, format, ... )
#endif

#define NEXT_SIBLING(die)								\
	int res = dwarf_siblingof(die, die);				\
	if (res == 0) continue;     /* sibling exists    */	\
	if (res < 0)  return false; /* error             */	\
	break                       /* no sibling exists */

// A map from DIE addresses (Dwarf_Off) to type structures (struct
// arg_type_info*). This is created and filled in at the start of each import,
// and deleted when the import is complete
static struct dict type_hash;


static bool get_type(struct arg_type_info** info, Dwarf_Die* type_die);


#if 0
static bool _dump_dwarf_tree(Dwarf_Die* die, int indent)
{
    while (1) {
        fprintf(stderr, "%*sprocessing unit: 0x%02x/'%s'\n", indent*4, "",
               dwarf_tag(die), dwarf_diename(die));

        Dwarf_Die child;
        if (dwarf_child(die, &child) == 0) {
			if (!_dump_dwarf_tree(&child, indent+1))
				return false;
        }

        SIBLING(die);
    }

    return true;
}

static bool dump_dwarf_tree(Dwarf_Die* die)
{
    return _dump_dwarf_tree( die, 0 );
}
#endif

#ifdef DUMP_PROTOTYPES
static bool _dump_ltrace_tree(const struct arg_type_info* info, int indent)
{
	if (indent > 7) {
		fprintf(stderr, "%*s%p ...\n", indent*4, "", (void*)info);
		return true;
	}

	if (info == NULL) {
		fprintf(stderr, "%*s%p NULL\n", indent*4, "", (void*)info);
		return true;
	}

	switch (info->type) {
	case ARGTYPE_VOID:
		fprintf(stderr, "%*s%p void\n", indent*4, "", (void*)info);
		break;

	case ARGTYPE_INT:
	case ARGTYPE_UINT:
	case ARGTYPE_LONG:
	case ARGTYPE_ULONG:
	case ARGTYPE_CHAR:
	case ARGTYPE_SHORT:
	case ARGTYPE_USHORT:
	case ARGTYPE_FLOAT:
	case ARGTYPE_DOUBLE:
		fprintf(stderr, "%*s%p base\n", indent*4, "", (void*)info);
		break;

	case ARGTYPE_ARRAY:
		fprintf(stderr, "%*s%p array. elements not printed\n", indent*4, "",
				(void*)info);
		break;

	case ARGTYPE_POINTER:
		fprintf(stderr, "%*s%p pointer to...\n", indent*4, "", (void*)info);
		_dump_ltrace_tree( info->u.ptr_info.info, indent+1 );
		break;

	case ARGTYPE_STRUCT:
		fprintf(stderr, "%*s%p struct...\n", indent*4, "", (void*)info);
		struct struct_field
		{
			struct arg_type_info *info;
			int own_info;
		}* elements = (struct struct_field*)info->u.entries.data;
		unsigned int i;
		for(i=0; i<info->u.entries.size; i++)
			_dump_ltrace_tree( elements[i].info, indent+1 );
		break;

	default:
		fprintf(stderr, "%*s%p unknown type\n", indent*4, "", (void*)info);
		return false;;
	}

	return true;
}

static bool dump_ltrace_tree(const struct arg_type_info* info)
{
	return _dump_ltrace_tree( info, 0 );
}
#endif


// pulls a numerical value out of a particular attribute in a die. Returns true
// if successful. The result is returned in *result. Note that this is cast to
// (uint64_t), regardless of the actual type of the input
static bool get_die_numeric(uint64_t* result,
							Dwarf_Die *die, unsigned int attr_name)
{
	Dwarf_Attribute attr ;

	union {
		Dwarf_Word		udata;
		Dwarf_Sword     sdata;
		Dwarf_Addr		addr;
		bool			flag;
	} u;

	if (dwarf_attr(die, attr_name, &attr) == NULL)
		return false;

	unsigned int form = dwarf_whatform(&attr);

#define PROCESS_NUMERIC(type)						\
	if (dwarf_form ## type(&attr, &u.type) != 0)	\
		return false;								\
	*result = (uint64_t)u.type;						\
	return true


	switch (form) {
	case DW_FORM_addr:
		PROCESS_NUMERIC(addr);

	case DW_FORM_data1:
	case DW_FORM_data2:
	case DW_FORM_data4:
	case DW_FORM_data8:
	case DW_FORM_udata:
		PROCESS_NUMERIC(udata);

	case DW_FORM_sdata:
		PROCESS_NUMERIC(sdata);

	case DW_FORM_flag:
		PROCESS_NUMERIC(flag);

	default:
		complain(die, "Unknown numeric form %d for attr_name: %d", form, attr_name);
		return false;
	}
#undef PROCESS_NUMERIC
}

static bool get_integer_base_type(enum arg_type* type, int byte_size, bool is_signed)
{
	switch (byte_size) {
	case sizeof(char):
		*type = ARGTYPE_CHAR;
		return true;

	case sizeof(short):
		*type = is_signed ? ARGTYPE_SHORT : ARGTYPE_USHORT;
		return true;

	case sizeof(int):
		*type = is_signed ? ARGTYPE_INT : ARGTYPE_UINT;
		return true;

	case sizeof(long):
		*type = is_signed ? ARGTYPE_LONG : ARGTYPE_ULONG;
		return true;

	default:
		return false;
	}
}

static enum arg_type get_base_type(Dwarf_Die* die)
{
	int64_t encoding;
	if( !get_die_numeric((uint64_t*)&encoding, die, DW_AT_encoding))
		return ARGTYPE_VOID;

	if (encoding == DW_ATE_void)
		return ARGTYPE_VOID;

	if (encoding == DW_ATE_signed_char || encoding == DW_ATE_unsigned_char)
		return ARGTYPE_CHAR;

		uint64_t byte_size;
		if (!get_die_numeric(&byte_size, die, DW_AT_byte_size))
			return ARGTYPE_VOID;

	if (encoding == DW_ATE_signed   ||
		encoding == DW_ATE_unsigned ||
		encoding == DW_ATE_boolean) {

		bool is_signed = (encoding == DW_ATE_signed);

		enum arg_type type;
		if(!get_integer_base_type(&type, (int)byte_size, is_signed)) {
			complain(die, "Unknown integer base type. Using 'void'");
			return ARGTYPE_VOID;
		}
		return type;
	}

	if (encoding == DW_ATE_float) {
		switch (byte_size) {
		case sizeof(float):
			return ARGTYPE_FLOAT;

		case sizeof(double):
			return ARGTYPE_DOUBLE;

		default:
			// things like long doubles. ltrace has no support yet, so I just
			// say "void"
			return ARGTYPE_VOID;
		}
	}

#if 0
	if (encoding == DW_ATE_complex_float) {
		switch (byte_size) {
		case 2*sizeof(float):
			return ARGTYPE_FLOAT;

		case 2*sizeof(double):
			return ARGTYPE_DOUBLE;

		default:
			// things like long doubles. ltrace has no support yet, so I just
			// say "void"
			return ARGTYPE_VOID;
		}
	}
#endif

	// Unknown encoding. I just say void
	complain(die, "Unknown base type. Returning 'void'");
	return ARGTYPE_VOID;
}

static bool get_type_die(Dwarf_Die* type_die, Dwarf_Die* die)
{
	Dwarf_Attribute attr;
	return
		dwarf_attr(die, DW_AT_type, &attr) != NULL &&
		dwarf_formref_die(&attr, type_die) != NULL;
}

static size_t dwarf_die_hash(const void* x)
{
	return *(const Dwarf_Off*)x;
}
static int dwarf_die_eq(const void* a, const void* b)
{
	return *(const Dwarf_Off*)a == *(const Dwarf_Off*)b;
}

static bool get_enum(struct arg_type_info* enum_info, Dwarf_Die* parent)
{
	uint64_t byte_size;
	if (!get_die_numeric(&byte_size, parent, DW_AT_byte_size)) {
		// No byte size given, assume 'int'
		enum_info->type = ARGTYPE_INT;
	} else {
		if(!get_integer_base_type(&enum_info->type, (int)byte_size, true)) {
			complain(parent, "Unknown integer base type. Using 'int'");
			enum_info->type = ARGTYPE_INT;
		}
	}

	struct enum_lens *lens = calloc(1, sizeof(struct enum_lens));
	if (lens == NULL) {
		complain(parent, "alloc error");
		return false;
	}
	lens_init_enum(lens);
	enum_info->lens = &lens->super;

	Dwarf_Die die;
	if (dwarf_child(parent, &die) != 0) {
		// empty enum. we're done
		return true;
	}

	while(1) {
		complain(&die, "enum element: 0x%02x/'%s'", dwarf_tag(&die),
				 dwarf_diename(&die));

		if (dwarf_tag(&die) != DW_TAG_enumerator) {
			complain(&die, "Enums can have ONLY DW_TAG_enumerator elements");
			return false;
		}

		if (!dwarf_hasattr(&die, DW_AT_const_value)) {
			complain(&die, "Enums MUST have DW_AT_const_value values");
			return false;
		}

		const char* key = dwarf_diename(&die);
		if (key == NULL) {
			complain(&die, "Enums must have a DW_AT_name key");
			return false;
		}
		const char* dupkey = strdup(key);
		if (dupkey == NULL) {
			complain(&die, "Couldn't duplicate enum key");
			return false;
		}

		struct value* value = calloc( 1, sizeof(struct value));
		if (value == NULL) {
			complain(&die, "Couldn't alloc enum value");
			return false;
		}

		value_init_detached(value, NULL, type_get_simple( enum_info->type ), 0);
		uint64_t enum_value;
		if (!get_die_numeric(&enum_value, &die, DW_AT_const_value)) {
			complain(&die, "Couldn't get enum value");
			return false;
		}

		value_set_word(value, (long)enum_value);

		if (lens_enum_add( lens, dupkey, 0, value, 0 )) {
			complain(&die, "Couldn't add enum element");
			return false;
		}

		NEXT_SIBLING(&die);
	}

	return true;
}

static bool get_array(struct arg_type_info* array_info, Dwarf_Die* parent)
{
	Dwarf_Die type_die;
	if (!get_type_die( &type_die, parent )) {
		complain( parent, "Array has unknown type" );
		return false;
	}

	struct arg_type_info* info;
	if (!get_type( &info, &type_die )) {
		complain( parent, "Couldn't figure out array's type" );
		return false;
	}

	Dwarf_Die subrange;
	if (dwarf_child(parent, &subrange) != 0) {
		complain(parent,
				 "Array must have a DW_TAG_subrange_type child, but has none");
		return false;
	}

	Dwarf_Die next_subrange;
	if (dwarf_siblingof(&subrange, &next_subrange) <= 0) {
		complain(parent,
				 "Array must have exactly one DW_TAG_subrange_type child");
		return false;
	}

	if (dwarf_hasattr(&subrange, DW_AT_lower_bound)) {
		uint64_t lower_bound;
		if (!get_die_numeric(&lower_bound, &subrange, DW_AT_lower_bound)) {
			complain( parent, "Couldn't read lower bound");
			return false;
		}

		if (lower_bound != 0) {
			complain( parent,
					  "Array subrange has a nonzero lower bound. Don't know what to do");
			return false;
		}
	}

	uint64_t N;
	if (!dwarf_hasattr(&subrange, DW_AT_upper_bound)) {
		// no upper bound is defined. This is probably a variable-width array,
		// and I don't know how long it is. Let's say 0 to be safe
		N = 0;
	}
	else
	{
		if (!get_die_numeric(&N, &subrange, DW_AT_upper_bound)) {
			complain( parent, "Couldn't read upper bound");
			return false;
		}
		N++;
	}

	// I'm not checking the subrange type. It should be some sort of integer,
	// and I don't know what it would mean for it to be something else

	struct value* value = calloc( 1, sizeof(struct value));
	if (value == NULL) {
		complain(&subrange, "Couldn't alloc length value");
		return false;
	}
	value_init_detached(value, NULL, type_get_simple( ARGTYPE_INT ), 0);
	value_set_word(value, N );

	struct expr_node* length = calloc( 1, sizeof(struct expr_node));
	if (length == NULL) {
		complain(&subrange, "Couldn't alloc length expr");
		return false;
	}
	expr_init_const(length, value);

	type_init_array(array_info, info, 0, length, 0 );

	return true;
}

static bool get_structure(struct arg_type_info* struct_info, Dwarf_Die* parent)
{
	type_init_struct(struct_info);

	Dwarf_Die die;
	if (dwarf_child(parent, &die) != 0) {
		// no elements; we're done
		return true;
	}

	while(1) {
		complain(&die, "member: 0x%02x", dwarf_tag(&die));

		if (dwarf_tag(&die) != DW_TAG_member) {
			complain(&die, "Structure can have ONLY DW_TAG_member");
			return false;
		}

		Dwarf_Die type_die;
		if (!get_type_die( &type_die, &die )) {
			complain( &die, "Couldn't get type of element");
			return false;
		}

		struct arg_type_info* member_info = NULL;
		if (!get_type( &member_info, &type_die )) {
			complain(&die, "Couldn't parse type from DWARF data");
			return false;
		}
		type_struct_add( struct_info, member_info, 0 );

		NEXT_SIBLING(&die);
	}

	return true;
}

// Reads the type in the die into the given structure
// Returns true on sucess
static bool get_type(struct arg_type_info** info, Dwarf_Die* type_die)
{
	Dwarf_Off die_offset = dwarf_dieoffset(type_die);
	struct arg_type_info** found_type = dict_find(&type_hash, &die_offset );
	if (found_type != NULL) {
		*info = *found_type;
		complain(type_die, "Read pre-computed type: %p", *info);
		return true;
	}

	Dwarf_Die next_die;

	switch (dwarf_tag(type_die)) {
	case DW_TAG_base_type:
		*info = type_get_simple( get_base_type( type_die ));
		complain(type_die, "Storing base type: %p", *info);
		dict_insert( &type_hash, &die_offset, info );
		return true;

	case DW_TAG_subroutine_type:
	case DW_TAG_inlined_subroutine:
		// function pointers are stored as void*. If ltrace tries to dereference
		// these, it'll get a segfault
		*info = type_get_simple( ARGTYPE_VOID );
		complain(type_die, "Storing subroutine type: %p", *info);
		dict_insert( &type_hash, &die_offset, info );
		return true;

	case DW_TAG_pointer_type:

		if (!get_type_die(&next_die, type_die )) {
			// the pointed-to type isn't defined, so I report a void*
			*info = type_get_simple( ARGTYPE_VOID );
			complain(type_die, "Storing void-pointer type: %p", *info);
			dict_insert( &type_hash, &die_offset, info );
			return true;
		}

		*info = calloc( 1, sizeof(struct arg_type_info));
		if (*info == NULL) {
			complain(type_die, "alloc error");
			return false;
		}
		type_init_pointer(*info, NULL, 0);

		complain(type_die, "Storing pointer type: %p", *info);
		dict_insert( &type_hash, &die_offset, info );
		return get_type( &(*info)->u.ptr_info.info, &next_die );

	case DW_TAG_structure_type:
		*info = calloc( 1, sizeof(struct arg_type_info));
		if (*info == NULL) {
			complain(type_die, "alloc error");
			return false;
		}

		complain(type_die, "Storing struct type: %p", *info);
		dict_insert( &type_hash, &die_offset, info );
		return get_structure( *info, type_die );


	case DW_TAG_typedef:
	case DW_TAG_const_type:
	case DW_TAG_volatile_type: {
		// Various tags are simply pass-through, so I just keep going
		bool res = true;
		if (get_type_die(&next_die, type_die )) {
			complain(type_die, "Storing const/typedef type: %p", *info);
			res = get_type( info, &next_die );
		} else {
			// no type. Use 'void'. Normally I'd think this is bogus, but stdio
			// typedefs something to void
			*info = type_get_simple( ARGTYPE_VOID );
			complain(type_die, "Storing void type: %p", *info);
		}
		if (res)
			dict_insert( &type_hash, &die_offset, info );
		return res;
	}

	case DW_TAG_enumeration_type:
		// We have an enumeration. This has type "int", but has a particular
		// lens to handle the enum
		*info = calloc( 1, sizeof(struct arg_type_info));
		if (*info == NULL) {
			complain(type_die, "alloc error");
			return false;
		}

		complain(type_die, "Storing enum int: %p", *info);
		dict_insert( &type_hash, &die_offset, info );
		return get_enum( *info, type_die );

	case DW_TAG_array_type:
		*info = calloc( 1, sizeof(struct arg_type_info));
		if (*info == NULL) {
			complain(type_die, "alloc error");
			return false;
		}

		complain(type_die, "Storing array: %p", *info);
		dict_insert( &type_hash, &die_offset, info );
		return get_array( *info, type_die );

	case DW_TAG_union_type:
		*info = type_get_simple( ARGTYPE_VOID );
		complain(type_die, "Storing union-as-void type: %p", *info);
		return true;

	default:
		complain(type_die, "Unknown type tag 0x%x", dwarf_tag(type_die));
		break;
	}

	return false;
}

static bool get_prototype(struct prototype* proto, Dwarf_Die* subroutine)
{
	// First, look at the return type. This is stored in a DW_AT_type tag in the
	// subroutine DIE. If there is no such tag, this function returns void
	Dwarf_Die return_type_die;
	if (!get_type_die(&return_type_die, subroutine )) {
		proto->return_info = type_get_simple( ARGTYPE_VOID );
		proto->own_return_info = 0;
	} else {
		proto->return_info = calloc( 1, sizeof( struct arg_type_info ));
		if (proto->return_info == NULL) {
			complain(subroutine, "Couldn't alloc return type");
			return false;
		}
		proto->own_return_info = 0;

		if (!get_type( &proto->return_info, &return_type_die )) {
			complain(subroutine, "Couldn't get return type");
			return false;
		}
	}


	// Now look at the arguments
	Dwarf_Die arg_die;
	if (dwarf_child(subroutine, &arg_die) != 0) {
		// no args. We're done
		return true;
	}

	while(1) {
		if (dwarf_tag(&arg_die) == DW_TAG_formal_parameter) {

			complain(&arg_die, "arg: 0x%02x", dwarf_tag(&arg_die));

			Dwarf_Die type_die;
			if (!get_type_die(&type_die, &arg_die )) {
				complain(&arg_die, "Couldn't get the argument type die");
				return false;
			}

			struct arg_type_info* arg_type_info = NULL;
			if (!get_type( &arg_type_info, &type_die )) {
				complain(&arg_die, "Couldn't parse arg type from DWARF data");
				return false;
			}

			struct param param;
			param_init_type(&param, arg_type_info, 0);
			if (prototype_push_param(proto, &param) <0) {
				complain(&arg_die, "couldn't add argument to the prototype");
				return false;
			}

#ifdef DUMP_PROTOTYPES
			fprintf(stderr, "Adding argument:\n");
			dump_ltrace_tree(arg_type_info);
#endif
		}

		NEXT_SIBLING(&arg_die);
	}

	return true;
}

static bool import_subprogram(struct protolib* plib, struct library* lib,
							  Dwarf_Die* die)
{
	// I use the linkage function name if there is one, otherwise the
	// plain name
	const char* function_name = NULL;
	Dwarf_Attribute attr;
	if (dwarf_attr(die, DW_AT_linkage_name, &attr) != NULL)
		function_name = dwarf_formstring(&attr);
	if (function_name == NULL)
		function_name = dwarf_diename(die);
	if (function_name == NULL) {
		complain(die, "Function has no name. Not importing" );
		return true;
	}


	complain(die, "subroutine_type: 0x%02x; function '%s'",
			 dwarf_tag(die), function_name);

	struct prototype* proto =
		protolib_lookup_prototype(plib, function_name, false );

	if (proto != NULL) {
		complain(die, "Prototype already exists. Skipping");
		return true;
	}

	if (!filter_matches_symbol(options.plt_filter,    function_name, lib) &&
		!filter_matches_symbol(options.static_filter, function_name, lib) &&
		!filter_matches_symbol(options.export_filter, function_name, lib)) {
		complain(die, "Prototype not requested by any filter");
		return true;
	}

	proto = malloc(sizeof(struct prototype));
	if (proto == NULL) {
		complain(die, "couldn't alloc prototype");
		return false;
	}
	prototype_init( proto );

	if (!get_prototype(proto, die )) {
		complain(die, "couldn't get prototype");
		return false;
	}

	protolib_add_prototype(plib, function_name, 0, proto);
	return true;
}

static bool process_die_compileunit(struct protolib* plib, struct library* lib,
									Dwarf_Die* parent)
{
	Dwarf_Die die;
	if (dwarf_child(parent, &die) != 0) {
		// no child nodes, so nothing to do
		return true;
	}

	while (1) {
		if (dwarf_tag(&die) == DW_TAG_subprogram)
			if(!import_subprogram(plib, lib, &die))
				return false;

		NEXT_SIBLING(&die);
	}

	return true;
}

static bool import(struct protolib* plib, struct library* lib, Dwfl* dwfl)
{
	dict_init(&type_hash, sizeof(Dwarf_Off), sizeof(struct arg_type_info*),
			  dwarf_die_hash, dwarf_die_eq, NULL );

	Dwarf_Addr bias;
    Dwarf_Die* die = NULL;
    while ((die = dwfl_nextcu(dwfl, die, &bias)) != NULL) {
        if (dwarf_tag(die) == DW_TAG_compile_unit) {
            if (!process_die_compileunit(plib, lib, die)) {
                complain(die, "Error reading compile unit");
				exit(1);
				return false;
            }
        } else {
            complain(die, "DW_TAG_compile_unit expected");
			exit(1);
            return false;
        }
    }

	dict_destroy( &type_hash, NULL, NULL, NULL );
	return true;
}

bool import_DWARF_prototypes(struct library* lib)
{
	struct protolib*	plib = lib->protolib;
	Dwfl*				dwfl = lib->dwfl;

	if (plib == NULL) {
		plib = protolib_cache_default(&g_protocache, lib->soname, 0);
		if (plib == NULL) {
			fprintf(stderr, "Error loading protolib %s: %s.\n",
					lib->soname, strerror(errno));
		}
	}

	if (import(plib, lib, dwfl)) {
		lib->protolib = plib;
		return true;
	}
	return false;
}

/*
- I handle static functions now. Should I? Those do not have DW_AT_external==1

- should process existing prototypes to make sure they match

- what do function pointers look like? I'm doing void*

- unions

- all my *allocs leak


*/
