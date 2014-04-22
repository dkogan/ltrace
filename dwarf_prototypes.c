/* Most of this is Copyright Dima Kogan <dima@secretsauce.net>
 *
 * Pieces of this were taken from dwarf_prototypes.c in the dwarves project.
 * Those are Copyright (C) 2008 Arnaldo Carvalho de Melo <acme@redhat.com>.
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

// A map from DIE addresses (Dwarf_Off) to type structures (struct
// arg_type_info*). This is created and filled in at the start of each import,
// and deleted when the import is complete
static struct dict type_hash;


static bool getType( struct arg_type_info** info, Dwarf_Die* type_die);


#if 0
static bool _dump_dwarf_tree(Dwarf_Die* die, int indent)
{
    while(1)
    {
        fprintf(stderr, "%*sprocessing unit: 0x%02x/'%s'\n", indent*4, "",
               dwarf_tag(die), dwarf_diename(die) );

        Dwarf_Die child;
        if (dwarf_child(die, &child) == 0)
        {
			if( !_dump_dwarf_tree(&child, indent+1) )
				return false;
        }

        int res = dwarf_siblingof(die, die);
        if( res == 0 ) continue;     // sibling exists
        if( res < 0 )  return false; // error
        break;                       // no sibling exists
    }

    return true;
}

static bool dump_dwarf_tree(Dwarf_Die* die)
{
    return _dump_dwarf_tree( die, 0 );
}
#endif

#ifdef DUMP_PROTOTYPES
static bool _dump_ltrace_tree( const struct arg_type_info* info, int indent )
{
	if( indent > 7 )
	{
		fprintf(stderr, "%*s%p ...\n", indent*4, "", (void*)info);
		return true;
	}

	if( info == NULL )
	{
		fprintf(stderr, "%*s%p NULL\n", indent*4, "", (void*)info);
		return true;
	}

	switch(info->type)
	{
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
		fprintf(stderr, "%*s%p array. elements not printed\n", indent*4, "", (void*)info);
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

static bool dump_ltrace_tree( const struct arg_type_info* info )
{
	return _dump_ltrace_tree( info, 0 );
}
#endif



static uint64_t attr_numeric(Dwarf_Die *die, uint32_t name)
{
	Dwarf_Attribute attr;
	uint32_t form;

	if (dwarf_attr(die, name, &attr) == NULL)
		return 0;

	form = dwarf_whatform(&attr);

	switch (form) {
	case DW_FORM_addr: {
		Dwarf_Addr addr;
		if (dwarf_formaddr(&attr, &addr) == 0)
			return addr;
	}
		break;
	case DW_FORM_data1:
	case DW_FORM_data2:
	case DW_FORM_data4:
	case DW_FORM_data8:
	case DW_FORM_sdata:
	case DW_FORM_udata: {
		Dwarf_Word value;
		if (dwarf_formudata(&attr, &value) == 0)
			return value;
	}
		break;
	case DW_FORM_flag:
	case DW_FORM_flag_present: {
		bool value;
		if (dwarf_formflag(&attr, &value) == 0)
			return value;
	}
		break;
	default:
		complain(die, "DW_AT_<0x%x>=0x%x", name, form);
		break;
	}

	return 0;
}

static enum arg_type getBaseType( Dwarf_Die* die )
{
	int encoding = attr_numeric(die, DW_AT_encoding);

	if( encoding == DW_ATE_void )
		return ARGTYPE_VOID;

	if( encoding == DW_ATE_signed_char || encoding == DW_ATE_unsigned_char )
		return ARGTYPE_CHAR;

	if( encoding == DW_ATE_signed   ||
		encoding == DW_ATE_unsigned ||
		encoding == DW_ATE_boolean )
	{
		bool is_signed = (encoding == DW_ATE_signed);
		switch( attr_numeric(die, DW_AT_byte_size) )
		{
		case sizeof(char):
			return ARGTYPE_CHAR;

		case sizeof(short):
			return is_signed ? ARGTYPE_SHORT : ARGTYPE_USHORT;

		case sizeof(int):
			return is_signed ? ARGTYPE_INT : ARGTYPE_UINT;

		case sizeof(long):
			return is_signed ? ARGTYPE_LONG : ARGTYPE_ULONG;

		default:
			complain(die, "");
			exit(1);
		}
	}

	if( encoding == DW_ATE_float )
	{
		switch( attr_numeric(die, DW_AT_byte_size) )
		{
		case sizeof(float):
			return ARGTYPE_FLOAT;

		case sizeof(double):
			return ARGTYPE_DOUBLE;

		default:
			// things like long doubles. ltrace has no support yet, so I just say "void"
			return ARGTYPE_VOID;
		}
	}

	// Unknown encoding. I just say void
	return ARGTYPE_VOID;
}

static bool getTypeDie( Dwarf_Die* type_die, Dwarf_Die* die )
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

static bool getEnum(struct arg_type_info* enum_info, Dwarf_Die* parent)
{
	enum_info->type = ARGTYPE_INT;

	struct enum_lens *lens = calloc(1, sizeof(struct enum_lens));
	if (lens == NULL)
	{
		complain(parent, "alloc error");
		return false;
	}
	lens_init_enum(lens);
	enum_info->lens = &lens->super;

	Dwarf_Die die;
	if( dwarf_child(parent, &die) != 0 )
	{
		// empty enum. we're done
		return true;
	}

	while(1) {
		complain(&die, "enum element: 0x%02x/'%s'", dwarf_tag(&die), dwarf_diename(&die) );

		if( dwarf_tag(&die) != DW_TAG_enumerator )
		{
			complain(&die, "Enums can have ONLY DW_TAG_enumerator elements");
			return false;
		}

		if( !dwarf_hasattr(&die, DW_AT_const_value) )
		{
			complain(&die, "Enums MUST have DW_AT_const_value values");
			return false;
		}

		const char* key = dwarf_diename(&die);
		if( key == NULL )
		{
			complain(&die, "Enums must have a DW_AT_name key");
			return false;
		}
		const char* dupkey = strdup(key);
		if( dupkey == NULL )
		{
			complain(&die, "Couldn't duplicate enum key");
			return false;
		}

		struct value* value = calloc( 1, sizeof(struct value) );
		if( value == NULL )
		{
			complain(&die, "Couldn't alloc enum value");
			return false;
		}

		value_init_detached(value, NULL, type_get_simple( ARGTYPE_INT ), 0);
		value_set_word(value, attr_numeric(&die, DW_AT_const_value) );

		if( lens_enum_add( lens, dupkey, 0, value, 0 ) )
		{
			complain(&die, "Couldn't add enum element");
			return false;
		}

		int res = dwarf_siblingof(&die, &die);
		if( res == 0 ) continue;     /* sibling exists    */
		if( res < 0 )  return false; /* error             */
		break;                       /* no sibling exists */
	}

	return true;
}

static bool getArray(struct arg_type_info* array_info, Dwarf_Die* parent)
{
	Dwarf_Die type_die;
	if( !getTypeDie( &type_die, parent ) )
	{
		complain( parent, "Array has unknown type" );
		return false;
	}

	struct arg_type_info* info;
	if( !getType( &info, &type_die ) )
	{
		complain( parent, "Couldn't figure out array's type" );
		return false;
	}

	Dwarf_Die subrange;
	if( dwarf_child(parent, &subrange) != 0 )
	{
		complain( parent, "Array must have a DW_TAG_subrange_type child, but has none" );
		return false;
	}

	Dwarf_Die next_subrange;
	if( dwarf_siblingof(&subrange, &next_subrange) <= 0 )
	{
		complain( parent, "Array must have exactly one DW_TAG_subrange_type child" );
		return false;
	}

	if( dwarf_hasattr(&subrange, DW_AT_lower_bound) )
	{
		if( attr_numeric(&subrange, DW_AT_lower_bound) != 0 )
		{
			complain( parent, "Array subrange has a nonzero lower bound. Don't know what to do");
			return false;
		}
	}

	int N;
	if( !dwarf_hasattr(&subrange, DW_AT_upper_bound) )
	{
		// no upper bound is defined. This is probably a variable-width array,
		// and I don't know how long it is. Let's say 0 to be safe
		N = 0;
	}
	else
		N = attr_numeric(&subrange, DW_AT_upper_bound)+1;

	// I'm not checking the subrange type. It should be some sort of integer,
	// and I don't know what it would mean for it to be something else

	struct value* value = calloc( 1, sizeof(struct value) );
	if( value == NULL )
	{
		complain(&subrange, "Couldn't alloc length value");
		return false;
	}
	value_init_detached(value, NULL, type_get_simple( ARGTYPE_INT ), 0);
	value_set_word(value, N );

	struct expr_node* length = calloc( 1, sizeof(struct expr_node) );
	if( length == NULL )
	{
		complain(&subrange, "Couldn't alloc length expr");
		return false;
	}
	expr_init_const(length, value);

	type_init_array(array_info, info, 0, length, 0 );

	return true;
}

static bool getStructure(struct arg_type_info* struct_info, Dwarf_Die* parent)
{
	type_init_struct(struct_info);

	Dwarf_Die die;
	if( dwarf_child(parent, &die) != 0 )
	{
		// no elements; we're done
		return true;
	}

	while(1) {
		complain(&die, "member: 0x%02x", dwarf_tag(&die) );

		if( dwarf_tag(&die) != DW_TAG_member )
		{
			complain(&die, "Structure can have ONLY DW_TAG_member");
			return false;
		}

		Dwarf_Die type_die;
		if( !getTypeDie( &type_die, &die ) )
		{
			complain( &die, "Couldn't get type of element");
			return false;
		}

		struct arg_type_info* member_info = NULL;
		if( !getType( &member_info, &type_die ) )
		{
			complain(&die, "Couldn't parse type from DWARF data");
			return false;
		}
		type_struct_add( struct_info, member_info, 0 );

		int res = dwarf_siblingof(&die, &die);
		if( res == 0 ) continue;     /* sibling exists    */
		if( res < 0 )  return false; /* error             */
		break;                       /* no sibling exists */
	}

	return true;
}

// Reads the type in the die into the given structure
// Returns true on sucess
static bool getType( struct arg_type_info** info, Dwarf_Die* type_die)
{
	Dwarf_Off die_offset = dwarf_dieoffset(type_die);
	struct arg_type_info** found_type = dict_find(&type_hash, &die_offset );
	if(found_type != NULL)
	{
		*info = *found_type;
		complain(type_die, "Read pre-computed type: %p", *info);
		return true;
	}

	Dwarf_Die next_die;

	switch( dwarf_tag(type_die) )
	{
	case DW_TAG_base_type:
		*info = type_get_simple( getBaseType( type_die ) );
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

		if( !getTypeDie(&next_die, type_die ) )
		{
			// the pointed-to type isn't defined, so I report a void*
			*info = type_get_simple( ARGTYPE_VOID );
			complain(type_die, "Storing void-pointer type: %p", *info);
			dict_insert( &type_hash, &die_offset, info );
			return true;
		}

		*info = calloc( 1, sizeof(struct arg_type_info) );
		if( *info == NULL )
		{
			complain(type_die, "alloc error");
			return false;
		}
		type_init_pointer(*info, NULL, 0);

		complain(type_die, "Storing pointer type: %p", *info);
		dict_insert( &type_hash, &die_offset, info );
		return getType( &(*info)->u.ptr_info.info, &next_die );

	case DW_TAG_structure_type:
		*info = calloc( 1, sizeof(struct arg_type_info) );
		if( *info == NULL )
		{
			complain(type_die, "alloc error");
			return false;
		}

		complain(type_die, "Storing struct type: %p", *info);
		dict_insert( &type_hash, &die_offset, info );
		return getStructure( *info, type_die );


	case DW_TAG_typedef: ;
	case DW_TAG_const_type: ;
	case DW_TAG_volatile_type: ;
		// Various tags are simply pass-through, so I just keep going
		bool res = true;
		if( getTypeDie(&next_die, type_die ) )
		{
			complain(type_die, "Storing const/typedef type: %p", *info);
			res = getType( info, &next_die );
		}
		else
		{
			// no type. Use 'void'. Normally I'd think this is bogus, but stdio
			// typedefs something to void
			*info = type_get_simple( ARGTYPE_VOID );
			complain(type_die, "Storing void type: %p", *info);
		}
		if( res )
			dict_insert( &type_hash, &die_offset, info );
		return res;

	case DW_TAG_enumeration_type:
		// We have an enumeration. This has type "int", but has a particular
		// lens to handle the enum
		*info = calloc( 1, sizeof(struct arg_type_info) );
		if( *info == NULL )
		{
			complain(type_die, "alloc error");
			return false;
		}

		complain(type_die, "Storing enum int: %p", *info);
		dict_insert( &type_hash, &die_offset, info );
		return getEnum( *info, type_die );

	case DW_TAG_array_type:
		*info = calloc( 1, sizeof(struct arg_type_info) );
		if( *info == NULL )
		{
			complain(type_die, "alloc error");
			return false;
		}

		complain(type_die, "Storing array: %p", *info);
		dict_insert( &type_hash, &die_offset, info );
		return getArray( *info, type_die );

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

static bool getPrototype(struct prototype* proto, Dwarf_Die* subroutine)
{
	// First, look at the return type. This is stored in a DW_AT_type tag in the
	// subroutine DIE. If there is no such tag, this function returns void
	Dwarf_Die return_type_die;
	if( !getTypeDie(&return_type_die, subroutine ) )
	{
		proto->return_info = type_get_simple( ARGTYPE_VOID );
		proto->own_return_info = 0;
	}
	else
	{
		proto->return_info = calloc( 1, sizeof( struct arg_type_info ) );
		if( proto->return_info == NULL )
		{
			complain(subroutine, "Couldn't alloc return type");
			return false;
		}
		proto->own_return_info = 0;

		if( !getType( &proto->return_info, &return_type_die ) )
		{
			complain(subroutine, "Couldn't get return type");
			return false;
		}
	}


	// Now look at the arguments
	Dwarf_Die arg_die;
	if( dwarf_child(subroutine, &arg_die) != 0 )
	{
		// no args. We're done
		return true;
	}

	while(1) {
		if( dwarf_tag(&arg_die) != DW_TAG_formal_parameter )
			goto next_prototype_argument;

		complain(&arg_die, "arg: 0x%02x", dwarf_tag(&arg_die));

		Dwarf_Die type_die;
		if( !getTypeDie(&type_die, &arg_die ) )
		{
			complain(&arg_die, "Couldn't get the argument type die");
			return false;
		}

		struct arg_type_info* arg_type_info = NULL;
		if( !getType( &arg_type_info, &type_die ) )
		{
			complain(&arg_die, "Couldn't parse arg type from DWARF data");
			return false;
		}

		struct param param;
		param_init_type(&param, arg_type_info, 0);
		if( prototype_push_param(proto, &param) <0 )
		{
			complain(&arg_die, "couldn't add argument to the prototype");
			return false;
		}

#ifdef DUMP_PROTOTYPES
		fprintf(stderr, "Adding argument:\n");
		dump_ltrace_tree(arg_type_info);
#endif

	next_prototype_argument: ;
		int res = dwarf_siblingof(&arg_die, &arg_die);
		if( res == 0 ) continue;     /* sibling exists    */
		if( res < 0 )  return false; /* error             */
		break;                       /* no sibling exists */
	}

	return true;
}

static bool process_die_compileunit(struct protolib* plib, struct library* lib, Dwarf_Die* parent)
{
	Dwarf_Die die;
	if( dwarf_child(parent, &die) != 0 )
	{
		// no child nodes, so nothing to do
		return true;
	}

	while(1)
	{
		if( dwarf_tag(&die) == DW_TAG_subprogram )
		{
			const char* function_name = dwarf_diename(&die);

			complain(&die, "subroutine_type: 0x%02x; function '%s'", dwarf_tag(&die), function_name);

			struct prototype* proto =
				protolib_lookup_prototype(plib, function_name, true );

			if( proto != NULL )
			{
				complain(&die, "Prototype already exists. Skipping");
				goto next_prototype;
			}

			if( !filter_matches_symbol(options.plt_filter,    function_name, lib) &&
				!filter_matches_symbol(options.static_filter, function_name, lib) &&
				!filter_matches_symbol(options.export_filter, function_name, lib) )
			{
				complain(&die, "Prototype not requested by any filter");
				goto next_prototype;
			}

			proto = malloc(sizeof(struct prototype));
			if( proto == NULL )
			{
				complain(&die, "couldn't alloc prototype");
				return false;
			}
			prototype_init( proto );

			if( !getPrototype(proto, &die ) )
			{
				complain(&die, "couldn't get prototype");
				return false;
			}

			protolib_add_prototype(plib, function_name, 0, proto);
		}

		next_prototype:;
		int res = dwarf_siblingof(&die, &die);
		if( res == 0 ) continue;     /* sibling exists    */
		if( res < 0 )  return false; /* error             */
		break;                       /* no sibling exists */
	}

	return true;
}

static bool import( struct protolib* plib, struct library* lib, Dwfl* dwfl )
{
	dict_init(&type_hash, sizeof(Dwarf_Off), sizeof(struct arg_type_info*),
			  dwarf_die_hash, dwarf_die_eq, NULL );

	Dwarf_Addr bias;
    Dwarf_Die* die = NULL;
    while( (die = dwfl_nextcu(dwfl, die, &bias)) != NULL )
    {
        if( dwarf_tag(die) == DW_TAG_compile_unit )
        {
            if( !process_die_compileunit(plib, lib, die) )
            {
                complain(die, "Error reading compile unit");
				exit(1);
				return false;
            }
        }
        else
        {
            complain(die, "DW_TAG_compile_unit expected");
			exit(1);
            return false;
        }
    }

	dict_destroy( &type_hash, NULL, NULL, NULL );
	return true;
}

bool import_DWARF_prototypes( struct protolib* plib, struct library* lib,
							  Dwfl *dwfl )
{
	if( plib == NULL )
	{
		plib = protolib_cache_default(&g_protocache, lib->soname, 0);
		if (plib == NULL)
		{
			fprintf(stderr, "Error loading protolib %s: %s.\n",
					lib->soname, strerror(errno));
		}
	}

	return import(plib, lib, dwfl);
}

/*
- I handle static functions now. Should I? Those do not have DW_AT_external==1

- should process existing prototypes to make sure they match

- what do function pointers look like? I'm doing void*

- unions

- all my *allocs leak

- protolib_lookup_prototype should look for imports?

*/
