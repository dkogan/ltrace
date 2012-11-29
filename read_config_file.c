/*
 * This file is part of ltrace.
 * Copyright (C) 2011,2012 Petr Machata, Red Hat Inc.
 * Copyright (C) 1998,1999,2003,2007,2008,2009 Juan Cespedes
 * Copyright (C) 2006 Ian Wienand
 * Copyright (C) 2006 Steve Fink
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

#include "config.h"

#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <error.h>
#include <assert.h>

#include "common.h"
#include "output.h"
#include "expr.h"
#include "param.h"
#include "printf.h"
#include "zero.h"
#include "type.h"
#include "lens.h"
#include "lens_default.h"
#include "lens_enum.h"

static int line_no;
static char *filename;
struct typedef_node_t;

static struct arg_type_info *parse_nonpointer_type(char **str,
						   struct param **extra_param,
						   size_t param_num, int *ownp,
						   struct typedef_node_t *td);
static struct arg_type_info *parse_type(char **str, struct param **extra_param,
					size_t param_num, int *ownp,
					struct typedef_node_t *in_typedef);
static struct arg_type_info *parse_lens(char **str, struct param **extra_param,
					size_t param_num, int *ownp,
					struct typedef_node_t *in_typedef);
static int parse_enum(char **str, struct arg_type_info **retp, int *ownp);

Function *list_of_functions = NULL;

static int
parse_arg_type(char **name, enum arg_type *ret)
{
	char *rest = NULL;
	enum arg_type candidate;

#define KEYWORD(KWD, TYPE)						\
	do {								\
		if (strncmp(*name, KWD, sizeof(KWD) - 1) == 0) {	\
			rest = *name + sizeof(KWD) - 1;			\
			candidate = TYPE;				\
			goto ok;					\
		}							\
	} while (0)

	KEYWORD("void", ARGTYPE_VOID);
	KEYWORD("int", ARGTYPE_INT);
	KEYWORD("uint", ARGTYPE_UINT);
	KEYWORD("long", ARGTYPE_LONG);
	KEYWORD("ulong", ARGTYPE_ULONG);
	KEYWORD("char", ARGTYPE_CHAR);
	KEYWORD("short", ARGTYPE_SHORT);
	KEYWORD("ushort", ARGTYPE_USHORT);
	KEYWORD("float", ARGTYPE_FLOAT);
	KEYWORD("double", ARGTYPE_DOUBLE);
	KEYWORD("array", ARGTYPE_ARRAY);
	KEYWORD("struct", ARGTYPE_STRUCT);

	/* Misspelling of int used in ltrace.conf that we used to
	 * ship.  */
	KEYWORD("itn", ARGTYPE_INT);

	assert(rest == NULL);
	return -1;

#undef KEYWORD

ok:
	if (isalnum(*rest))
		return -1;

	*name = rest;
	*ret = candidate;
	return 0;
}

static void
eat_spaces(char **str) {
	while (**str == ' ') {
		(*str)++;
	}
}

static char *
xstrndup(char *str, size_t len) {
	char *ret = (char *) malloc(len + 1);
	if (ret == NULL) {
		report_global_error("malloc: %s", strerror(errno));
		return NULL;
	}
	strncpy(ret, str, len);
	ret[len] = 0;
	return ret;
}

static char *
parse_ident(char **str) {
	char *ident = *str;

	if (!isalpha(**str) && **str != '_') {
		report_error(filename, line_no, "bad identifier");
		return NULL;
	}

	while (**str && (isalnum(**str) || **str == '_')) {
		++(*str);
	}

	return xstrndup(ident, *str - ident);
}

/*
  Returns position in string at the left parenthesis which starts the
  function's argument signature. Returns NULL on error.
*/
static char *
start_of_arg_sig(char *str) {
	char *pos;
	int stacked = 0;

	if (!strlen(str))
		return NULL;

	pos = &str[strlen(str)];
	do {
		pos--;
		if (pos < str)
			return NULL;
		while ((pos > str) && (*pos != ')') && (*pos != '('))
			pos--;

		if (*pos == ')')
			stacked++;
		else if (*pos == '(')
			stacked--;
		else
			return NULL;

	} while (stacked > 0);

	return (stacked == 0) ? pos : NULL;
}

static int
parse_int(char **str, long *ret)
{
	char *end;
	long n = strtol(*str, &end, 0);
	if (end == *str) {
		report_error(filename, line_no, "bad number");
		return -1;
	}

	*str = end;
	if (ret != NULL)
		*ret = n;
	return 0;
}

static int
check_nonnegative(long l)
{
	if (l < 0) {
		report_error(filename, line_no,
			     "expected non-negative value, got %ld", l);
		return -1;
	}
	return 0;
}

static int
check_int(long l)
{
	int i = l;
	if ((long)i != l) {
		report_error(filename, line_no,
			     "Number too large: %ld", l);
		return -1;
	}
	return 0;
}

static int
parse_char(char **str, char expected)
{
	if (**str != expected) {
		report_error(filename, line_no,
			     "expected '%c', got '%c'", expected, **str);
		return -1;
	}

	++*str;
	return 0;
}

static struct expr_node *parse_argnum(char **str, int *ownp, int zero);

static struct expr_node *
parse_zero(char **str, struct expr_node *ret, int *ownp)
{
	eat_spaces(str);
	if (**str == '(') {
		++*str;
		int own;
		struct expr_node *arg = parse_argnum(str, &own, 0);
		if (arg == NULL)
			return NULL;
		if (parse_char(str, ')') < 0) {
		fail:
			expr_destroy(arg);
			free(arg);
			return NULL;
		}

		struct expr_node *ret = build_zero_w_arg(arg, own);
		if (ret == NULL)
			goto fail;
		*ownp = 1;
		return ret;

	} else {
		free(ret);
		*ownp = 0;
		return expr_node_zero();
	}
}

static int
wrap_in_zero(struct expr_node **nodep)
{
	struct expr_node *n = build_zero_w_arg(*nodep, 1);
	if (n == NULL)
		return -1;
	*nodep = n;
	return 0;
}

/*
 * Input:
 *  argN   : The value of argument #N, counting from 1
 *  eltN   : The value of element #N of the containing structure
 *  retval : The return value
 *  N      : The numeric value N
 */
static struct expr_node *
parse_argnum(char **str, int *ownp, int zero)
{
	struct expr_node *expr = malloc(sizeof(*expr));
	if (expr == NULL)
		return NULL;

	if (isdigit(**str)) {
		long l;
		if (parse_int(str, &l) < 0
		    || check_nonnegative(l) < 0
		    || check_int(l) < 0)
			goto fail;

		expr_init_const_word(expr, l, type_get_simple(ARGTYPE_LONG), 0);

		if (zero && wrap_in_zero(&expr) < 0)
			goto fail;

		*ownp = 1;
		return expr;

	} else {
		char *const name = parse_ident(str);
		if (name == NULL) {
		fail_ident:
			free(name);
			goto fail;
		}

		int is_arg = strncmp(name, "arg", 3) == 0;
		if (is_arg || strncmp(name, "elt", 3) == 0) {
			long l;
			char *num = name + 3;
			if (parse_int(&num, &l) < 0 || check_int(l) < 0)
				goto fail_ident;

			if (is_arg) {
				if (l == 0)
					expr_init_named(expr, "retval", 0);
				else
					expr_init_argno(expr, l - 1);
			} else {
				struct expr_node *e_up = malloc(sizeof(*e_up));
				struct expr_node *e_ix = malloc(sizeof(*e_ix));
				if (e_up == NULL || e_ix == NULL) {
					free(e_up);
					free(e_ix);
					goto fail_ident;
				}

				expr_init_up(e_up, expr_self(), 0);
				struct arg_type_info *ti
					= type_get_simple(ARGTYPE_LONG);
				expr_init_const_word(e_ix, l - 1, ti, 0);
				expr_init_index(expr, e_up, 1, e_ix, 1);
			}

		} else if (strcmp(name, "retval") == 0) {
			expr_init_named(expr, "retval", 0);

		} else if (strcmp(name, "zero") == 0) {
			struct expr_node *ret = parse_zero(str, expr, ownp);
			if (ret == NULL)
				goto fail_ident;
			return ret;

		} else {
			report_error(filename, line_no,
				     "Unknown length specifier: '%s'", name);
			goto fail_ident;
		}

		if (zero && wrap_in_zero(&expr) < 0)
			goto fail_ident;

		free(name);
		*ownp = 1;
		return expr;
	}

fail:
	free(expr);
	return NULL;
}

struct typedef_node_t {
	char *name;
	struct arg_type_info *info;
	int own_type;
	int forward : 1;
	struct typedef_node_t *next;
} *typedefs = NULL;

static struct typedef_node_t *
lookup_typedef(const char *name)
{
	struct typedef_node_t *node;
	for (node = typedefs; node != NULL; node = node->next)
		if (strcmp(name, node->name) == 0)
			return node;
	return NULL;
}

static struct arg_type_info *
parse_typedef_name(char **str)
{
	char *end = *str;
	while (*end && (isalnum(*end) || *end == '_'))
		++end;
	if (end == *str)
		return NULL;

	size_t len = end - *str;
	char buf[len + 1];
	memcpy(buf, *str, len);
	*str += len;
	buf[len] = 0;

	struct typedef_node_t *td = lookup_typedef(buf);
	if (td == NULL)
		return NULL;
	return td->info;
}

static void
insert_typedef(struct typedef_node_t *td)
{
	if (td == NULL)
		return;
	td->next = typedefs;
	typedefs = td;
}

static struct typedef_node_t *
new_typedef(char *name, struct arg_type_info *info, int own_type)
{
	struct typedef_node_t *binding = malloc(sizeof(*binding));
	binding->name = name;
	binding->info = info;
	binding->own_type = own_type;
	binding->forward = 0;
	binding->next = NULL;
	return binding;
}

static void
parse_typedef(char **str)
{
	(*str) += strlen("typedef");
	eat_spaces(str);
	char *name = parse_ident(str);

	/* Look through the typedef list whether we already have a
	 * forward of this type.  If we do, it must be forward
	 * structure.  */
	struct typedef_node_t *forward = lookup_typedef(name);
	if (forward != NULL
	    && (forward->info->type != ARGTYPE_STRUCT
		|| !forward->forward)) {
		report_error(filename, line_no,
			     "Redefinition of typedef '%s'", name);
		free(name);
		return;
	}

	// Skip = sign
	eat_spaces(str);
	if (parse_char(str, '=') < 0) {
		free(name);
		return;
	}
	eat_spaces(str);

	struct typedef_node_t *this_td = new_typedef(name, NULL, 0);
	this_td->info = parse_lens(str, NULL, 0, &this_td->own_type, this_td);

	if (this_td->info == NULL) {
		free(this_td);
		free(name);
		return;
	}

	if (forward == NULL) {
		insert_typedef(this_td);
		return;
	}

	/* If we are defining a forward, make sure the definition is a
	 * structure as well.  */
	if (this_td->info->type != ARGTYPE_STRUCT) {
		report_error(filename, line_no,
			     "Definition of forward '%s' must be a structure.",
			     name);
		if (this_td->own_type) {
			type_destroy(this_td->info);
			free(this_td->info);
		}
		free(this_td);
		free(name);
		return;
	}

	/* Now move guts of the actual type over to the
	 * forward type.  We can't just move pointers around,
	 * because references to forward must stay intact.  */
	assert(this_td->own_type);
	type_destroy(forward->info);
	*forward->info = *this_td->info;
	forward->forward = 0;
	free(this_td->info);
	free(name);
	free(this_td);
}

static void
destroy_fun(Function *fun)
{
	size_t i;
	if (fun == NULL)
		return;
	if (fun->own_return_info) {
		type_destroy(fun->return_info);
		free(fun->return_info);
	}
	for (i = 0; i < fun->num_params; ++i)
		param_destroy(&fun->params[i]);
	free(fun->params);
}

/* Syntax: struct ( type,type,type,... ) */
static int
parse_struct(char **str, struct arg_type_info *info,
	     struct typedef_node_t *in_typedef)
{
	eat_spaces(str);

	if (**str == ';') {
		if (in_typedef == NULL) {
			report_error(filename, line_no,
				     "Forward struct can be declared only "
				     "directly after a typedef.");
			return -1;
		}

		/* Forward declaration is currently handled as an
		 * empty struct.  */
		type_init_struct(info);
		in_typedef->forward = 1;
		return 0;
	}

	if (parse_char(str, '(') < 0)
		return -1;

	eat_spaces(str); // Empty arg list with whitespace inside

	type_init_struct(info);

	while (1) {
		eat_spaces(str);
		if (**str == 0 || **str == ')') {
			parse_char(str, ')');
			return 0;
		}

		/* Field delimiter.  */
		if (type_struct_size(info) > 0)
			parse_char(str, ',');

		eat_spaces(str);
		int own;
		struct arg_type_info *field = parse_lens(str, NULL, 0, &own,
							 NULL);
		if (field == NULL || type_struct_add(info, field, own)) {
			type_destroy(info);
			return -1;
		}
	}
}

static int
parse_string(char **str, struct arg_type_info **retp, int *ownp)
{
	struct arg_type_info *info = malloc(sizeof(*info) * 2);
	if (info == NULL) {
	fail:
		free(info);
		return -1;
	}

	struct expr_node *length;
	int own_length;
	int with_arg = 0;

	if (isdigit(**str)) {
		/* string0 is string[retval], length is zero(retval)
		 * stringN is string[argN], length is zero(argN) */
		long l;
		if (parse_int(str, &l) < 0
		    || check_int(l) < 0)
			goto fail;

		struct expr_node *length_arg = malloc(sizeof(*length_arg));
		if (length_arg == NULL)
			goto fail;

		if (l == 0)
			expr_init_named(length_arg, "retval", 0);
		else
			expr_init_argno(length_arg, l - 1);

		length = build_zero_w_arg(length_arg, 1);
		if (length == NULL) {
			expr_destroy(length_arg);
			free(length_arg);
			goto fail;
		}
		own_length = 1;

	} else {
		eat_spaces(str);
		if (**str == '[') {
			(*str)++;
			eat_spaces(str);

			length = parse_argnum(str, &own_length, 1);
			if (length == NULL)
				goto fail;

			eat_spaces(str);
			parse_char(str, ']');

		} else if (**str == '(') {
			/* Usage of "string" as lens.  */
			++*str;

			free(info);

			eat_spaces(str);
			info = parse_type(str, NULL, 0, ownp, NULL);
			if (info == NULL)
				goto fail;

			eat_spaces(str);
			parse_char(str, ')');

			with_arg = 1;

		} else {
			/* It was just a simple string after all.  */
			length = expr_node_zero();
			own_length = 0;
		}
	}

	/* String is a pointer to array of chars.  */
	if (!with_arg) {
		type_init_array(&info[1], type_get_simple(ARGTYPE_CHAR), 0,
				length, own_length);

		type_init_pointer(&info[0], &info[1], 0);
		*ownp = 1;
	}

	info->lens = &string_lens;
	info->own_lens = 0;

	*retp = info;
	return 0;
}

static int
build_printf_pack(struct param **packp, size_t param_num)
{
	if (packp == NULL) {
		report_error(filename, line_no,
			     "'format' type in unexpected context");
		return -1;
	}
	if (*packp != NULL) {
		report_error(filename, line_no,
			     "only one 'format' type per function supported");
		return -1;
	}

	*packp = malloc(sizeof(**packp));
	if (*packp == NULL)
		return -1;

	struct expr_node *node = malloc(sizeof(*node));
	if (node == NULL) {
		free(*packp);
		return -1;
	}

	expr_init_argno(node, param_num);

	param_pack_init_printf(*packp, node, 1);

	return 0;
}

/* Match and consume KWD if it's next in stream, and return 0.
 * Otherwise return negative number.  */
static int
try_parse_kwd(char **str, const char *kwd)
{
	size_t len = strlen(kwd);
	if (strncmp(*str, kwd, len) == 0
	    && !isalnum((*str)[len])) {
		(*str) += len;
		return 0;
	}
	return -1;
}

/* Make a copy of INFO and set the *OWN bit if it's not already
 * owned.  */
static int
unshare_type_info(struct arg_type_info **infop, int *ownp)
{
	if (*ownp)
		return 0;

	struct arg_type_info *ninfo = malloc(sizeof(*ninfo));
	if (ninfo == NULL) {
		report_error(filename, line_no,
			     "malloc: %s", strerror(errno));
		return -1;
	}
	*ninfo = **infop;
	*infop = ninfo;
	*ownp = 1;
	return 0;
}

/* XXX extra_param and param_num are a kludge to get in
 * backward-compatible support for "format" parameter type.  The
 * latter is only valid if the former is non-NULL, which is only in
 * top-level context.  */
static int
parse_alias(char **str, struct arg_type_info **retp, int *ownp,
	    struct param **extra_param, size_t param_num)
{
	/* For backward compatibility, we need to support things like
	 * stringN (which is like string[argN], string[N], and also
	 * bare string.  We might, in theory, replace this by
	 * preprocessing configure file sources with M4, but for now,
	 * "string" is syntax.  */
	if (strncmp(*str, "string", 6) == 0) {
		(*str) += 6;
		return parse_string(str, retp, ownp);

	} else if (try_parse_kwd(str, "format") >= 0
		   && extra_param != NULL) {
		/* For backward compatibility, format is parsed as
		 * "string", but it smuggles to the parameter list of
		 * a function a "printf" argument pack with this
		 * parameter as argument.  */
		if (parse_string(str, retp, ownp) < 0)
			return -1;

		return build_printf_pack(extra_param, param_num);

	} else if (try_parse_kwd(str, "enum") >=0) {

		return parse_enum(str, retp, ownp);

	} else {
		*retp = NULL;
		return 0;
	}
}

/* Syntax: array ( type, N|argN ) */
static int
parse_array(char **str, struct arg_type_info *info)
{
	eat_spaces(str);
	if (parse_char(str, '(') < 0)
		return -1;

	eat_spaces(str);
	int own;
	struct arg_type_info *elt_info = parse_lens(str, NULL, 0, &own, NULL);
	if (elt_info == NULL)
		return -1;

	eat_spaces(str);
	parse_char(str, ',');

	eat_spaces(str);
	int own_length;
	struct expr_node *length = parse_argnum(str, &own_length, 0);
	if (length == NULL) {
		if (own) {
			type_destroy(elt_info);
			free(elt_info);
		}
		return -1;
	}

	type_init_array(info, elt_info, own, length, own_length);

	eat_spaces(str);
	parse_char(str, ')');
	return 0;
}

/* Syntax:
 *   enum (keyname[=value],keyname[=value],... )
 *   enum<type> (keyname[=value],keyname[=value],... )
 */
static int
parse_enum(char **str, struct arg_type_info **retp, int *ownp)
{
	/* Optional type argument.  */
	eat_spaces(str);
	if (**str == '[') {
		parse_char(str, '[');
		eat_spaces(str);
		*retp = parse_nonpointer_type(str, NULL, 0, ownp, 0);
		if (*retp == NULL)
			return -1;

		if (!type_is_integral((*retp)->type)) {
			report_error(filename, line_no,
				     "integral type required as enum argument");
		fail:
			if (*ownp) {
				/* This also releases associated lens
				 * if any was set so far.  */
				type_destroy(*retp);
				free(*retp);
			}
			return -1;
		}

		eat_spaces(str);
		if (parse_char(str, ']') < 0)
			goto fail;

	} else {
		*retp = type_get_simple(ARGTYPE_INT);
		*ownp = 0;
	}

	/* We'll need to set the lens, so unshare.  */
	if (unshare_type_info(retp, ownp) < 0)
		goto fail;

	eat_spaces(str);
	if (parse_char(str, '(') < 0)
		goto fail;

	struct enum_lens *lens = malloc(sizeof(*lens));
	if (lens == NULL) {
		report_error(filename, line_no,
			     "malloc enum lens: %s", strerror(errno));
		return -1;
	}

	lens_init_enum(lens);
	(*retp)->lens = &lens->super;
	(*retp)->own_lens = 1;

	long last_val = 0;
	while (1) {
		eat_spaces(str);
		if (**str == 0 || **str == ')') {
			parse_char(str, ')');
			return 0;
		}

		/* Field delimiter.  XXX should we support the C
		 * syntax, where the enumeration can end in pending
		 * comma?  */
		if (lens_enum_size(lens) > 0)
			parse_char(str, ',');

		eat_spaces(str);
		char *key = parse_ident(str);
		if (key == NULL) {
		err:
			free(key);
			goto fail;
		}

		if (**str == '=') {
			++*str;
			eat_spaces(str);
			if (parse_int(str, &last_val) < 0)
				goto err;
		}

		struct value *value = malloc(sizeof(*value));
		if (value == NULL)
			goto err;
		value_init_detached(value, NULL, *retp, 0);
		value_set_word(value, last_val);

		if (lens_enum_add(lens, key, 1, value, 1) < 0)
			goto err;

		last_val++;
	}

	return 0;
}

static struct arg_type_info *
parse_nonpointer_type(char **str, struct param **extra_param, size_t param_num,
		      int *ownp, struct typedef_node_t *in_typedef)
{
	enum arg_type type;
	if (parse_arg_type(str, &type) < 0) {
		struct arg_type_info *simple;
		if (parse_alias(str, &simple, ownp, extra_param, param_num) < 0)
			return NULL;
		if (simple == NULL)
			simple = parse_typedef_name(str);
		if (simple != NULL) {
			*ownp = 0;
			return simple;
		}

		report_error(filename, line_no,
			     "unknown type around '%s'", *str);
		return NULL;
	}

	/* For some types that's all we need.  */
	switch (type) {
	case ARGTYPE_VOID:
	case ARGTYPE_INT:
	case ARGTYPE_UINT:
	case ARGTYPE_LONG:
	case ARGTYPE_ULONG:
	case ARGTYPE_CHAR:
	case ARGTYPE_SHORT:
	case ARGTYPE_USHORT:
	case ARGTYPE_FLOAT:
	case ARGTYPE_DOUBLE:
		*ownp = 0;
		return type_get_simple(type);

	case ARGTYPE_ARRAY:
	case ARGTYPE_STRUCT:
		break;

	case ARGTYPE_POINTER:
		/* Pointer syntax is not based on keyword, so we
		 * should never get this type.  */
		assert(type != ARGTYPE_POINTER);
		abort();
	}

	struct arg_type_info *info = malloc(sizeof(*info));
	if (info == NULL) {
		report_error(filename, line_no,
			     "malloc: %s", strerror(errno));
		return NULL;
	}
	*ownp = 1;

	if (type == ARGTYPE_ARRAY) {
		if (parse_array(str, info) < 0) {
		fail:
			free(info);
			return NULL;
		}
	} else {
		assert(type == ARGTYPE_STRUCT);
		if (parse_struct(str, info, in_typedef) < 0)
			goto fail;
	}

	return info;
}

static struct named_lens {
	const char *name;
	struct lens *lens;
} lenses[] = {
	{ "hide", &blind_lens },
	{ "octal", &octal_lens },
	{ "oct", &octal_lens },
	{ "bitvec", &bitvect_lens },
	{ "hex", &hex_lens },
	{ "bool", &bool_lens },
	{ "guess", &guess_lens },
};

static struct lens *
name2lens(char **str, int *own_lensp)
{
	size_t i;
	for (i = 0; i < sizeof(lenses)/sizeof(*lenses); ++i)
		if (try_parse_kwd(str, lenses[i].name) == 0) {
			*own_lensp = 0;
			return lenses[i].lens;
		}

	return NULL;
}

static struct arg_type_info *
parse_type(char **str, struct param **extra_param, size_t param_num, int *ownp,
	   struct typedef_node_t *in_typedef)
{
	struct arg_type_info *info
		= parse_nonpointer_type(str, extra_param,
					param_num, ownp, in_typedef);
	if (info == NULL)
		return NULL;

	while (1) {
		eat_spaces(str);
		if (**str == '*') {
			struct arg_type_info *outer = malloc(sizeof(*outer));
			if (outer == NULL) {
				if (*ownp) {
					type_destroy(info);
					free(info);
				}
				report_error(filename, line_no,
					     "malloc: %s", strerror(errno));
				return NULL;
			}
			type_init_pointer(outer, info, *ownp);
			*ownp = 1;
			(*str)++;
			info = outer;
		} else
			break;
	}
	return info;
}

static struct arg_type_info *
parse_lens(char **str, struct param **extra_param, size_t param_num, int *ownp,
	   struct typedef_node_t *in_typedef)
{
	int own_lens;
	struct lens *lens = name2lens(str, &own_lens);
	int has_args = 1;
	struct arg_type_info *info;
	if (lens != NULL) {
		eat_spaces(str);

		/* Octal lens gets special treatment, because of
		 * backward compatibility.  */
		if (lens == &octal_lens && **str != '(') {
			has_args = 0;
			info = type_get_simple(ARGTYPE_INT);
			*ownp = 0;
		} else if (parse_char(str, '(') < 0) {
			report_error(filename, line_no,
				     "expected type argument after the lens");
			return NULL;
		}
	}

	if (has_args) {
		eat_spaces(str);
		info = parse_type(str, extra_param, param_num, ownp,
				  in_typedef);
		if (info == NULL) {
		fail:
			if (own_lens && lens != NULL)
				lens_destroy(lens);
			return NULL;
		}
	}

	if (lens != NULL && has_args) {
		eat_spaces(str);
		parse_char(str, ')');
	}

	/* We can't modify shared types.  Make a copy if we have a
	 * lens.  */
	if (lens != NULL && unshare_type_info(&info, ownp) < 0)
		goto fail;

	if (lens != NULL) {
		info->lens = lens;
		info->own_lens = own_lens;
	}

	return info;
}

static int
add_param(Function *fun, size_t *allocdp)
{
	size_t allocd = *allocdp;
	/* XXX +1 is for the extra_param handling hack.  */
	if ((fun->num_params + 1) >= allocd) {
		allocd = allocd > 0 ? 2 * allocd : 8;
		void *na = realloc(fun->params, sizeof(*fun->params) * allocd);
		if (na == NULL)
			return -1;

		fun->params = na;
		*allocdp = allocd;
	}
	return 0;
}

static int
param_is_void(struct param *param)
{
	return param->flavor == PARAM_FLAVOR_TYPE
		&& param->u.type.type->type == ARGTYPE_VOID;
}

static struct arg_type_info *
get_hidden_int(void)
{
	char *str = strdup("hide(int)");
	char *ptr = str;
	assert(str != NULL);
	int own;
	struct arg_type_info *info = parse_lens(&ptr, NULL, 0, &own, NULL);
	assert(info != NULL);
	free(str);
	return info;
}

static Function *
process_line(char *buf) {
	char *str = buf;
	char *tmp;

	line_no++;
	debug(3, "Reading line %d of `%s'", line_no, filename);
	eat_spaces(&str);

	/* A comment or empty line.  */
	if (*str == ';' || *str == 0 || *str == '\n')
		return NULL;

	if (strncmp(str, "typedef", 7) == 0) {
		parse_typedef(&str);
		return NULL;
	}

	Function *fun = calloc(1, sizeof(*fun));
	if (fun == NULL) {
		report_error(filename, line_no,
			     "alloc function: %s", strerror(errno));
		return NULL;
	}

	fun->return_info = parse_lens(&str, NULL, 0,
				      &fun->own_return_info, NULL);
	if (fun->return_info == NULL) {
	err:
		debug(3, " Skipping line %d", line_no);
		destroy_fun(fun);
		return NULL;
	}
	debug(4, " return_type = %d", fun->return_info->type);

	eat_spaces(&str);
	tmp = start_of_arg_sig(str);
	if (tmp == NULL) {
		report_error(filename, line_no, "syntax error");
		goto err;
	}
	*tmp = '\0';
	fun->name = strdup(str);
	str = tmp + 1;
	debug(3, " name = %s", fun->name);

	size_t allocd = 0;
	struct param *extra_param = NULL;

	int have_stop = 0;

	while (1) {
		eat_spaces(&str);
		if (*str == ')')
			break;

		if (str[0] == '+') {
			if (have_stop == 0) {
				if (add_param(fun, &allocd) < 0)
					goto add_err;
				param_init_stop
					(&fun->params[fun->num_params++]);
				have_stop = 1;
			}
			str++;
		}

		if (add_param(fun, &allocd) < 0) {
		add_err:
			report_error(filename, line_no, "(re)alloc params: %s",
				     strerror(errno));
			goto err;
		}

		int own;
		struct arg_type_info *type
			= parse_lens(&str, &extra_param,
				     fun->num_params - have_stop, &own, NULL);
		if (type == NULL) {
			report_error(filename, line_no,
				     "unknown argument type");
			goto err;
		}

		param_init_type(&fun->params[fun->num_params++], type, own);

		eat_spaces(&str);
		if (*str == ',') {
			str++;
			continue;
		} else if (*str == ')') {
			continue;
		} else {
			if (str[strlen(str) - 1] == '\n')
				str[strlen(str) - 1] = '\0';
			report_error(filename, line_no,
				     "syntax error around \"%s\"", str);
			goto err;
		}
	}

	/* We used to allow void parameter as a synonym to an argument
	 * that shouldn't be displayed.  But backends really need to
	 * know the exact type that they are dealing with.  The proper
	 * way to do this these days is to use the hide lens.
	 *
	 * So if there are any voids in the parameter list, show a
	 * warning and assume that they are ints.  If there's a sole
	 * void, assume the function doesn't take any arguments.  The
	 * latter is conservative, we can drop the argument
	 * altogether, instead of fetching and then not showing it,
	 * without breaking any observable behavior.  */
	if (fun->num_params == 1 && param_is_void(&fun->params[0])) {
		if (0)
			/* Don't show this warning.  Pre-0.7.0
			 * ltrace.conf often used this idiom.  This
			 * should be postponed until much later, when
			 * extant uses are likely gone.  */
			report_warning(filename, line_no,
				       "sole void parameter ignored");
		param_destroy(&fun->params[0]);
		fun->num_params = 0;
	} else {
		size_t i;
		for (i = 0; i < fun->num_params; ++i) {
			if (param_is_void(&fun->params[i])) {
				report_warning
					(filename, line_no,
					 "void parameter assumed to be "
					 "'hide(int)'");

				static struct arg_type_info *type = NULL;
				if (type == NULL)
					type = get_hidden_int();
				param_destroy(&fun->params[i]);
				param_init_type(&fun->params[i], type, 0);
			}
		}
	}

	if (extra_param != NULL) {
		assert(fun->num_params < allocd);
		memcpy(&fun->params[fun->num_params++], extra_param,
		       sizeof(*extra_param));
		free(extra_param);
	}

	return fun;
}

void
init_global_config(void)
{
	struct arg_type_info *info = malloc(2 * sizeof(*info));
	if (info == NULL)
		error(1, errno, "malloc in init_global_config");

	memset(info, 0, 2 * sizeof(*info));
	info[0].type = ARGTYPE_POINTER;
	info[0].u.ptr_info.info = &info[1];
	info[1].type = ARGTYPE_VOID;

	insert_typedef(new_typedef(strdup("addr"), info, 0));
	insert_typedef(new_typedef(strdup("file"), info, 1));
}

void
read_config_file(char *file) {
	FILE *stream;
	char buf[1024];

	filename = file;
	stream = fopen(filename, "r");
	if (!stream) {
		return;
	}

	debug(1, "Reading config file `%s'...", filename);

	line_no = 0;
	while (fgets(buf, 1024, stream)) {
		Function *tmp;

		tmp = process_line(buf);

		if (tmp) {
			debug(2, "New function: `%s'", tmp->name);
			tmp->next = list_of_functions;
			list_of_functions = tmp;
		}
	}
	fclose(stream);
}
