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
#include "zero.h"
#include "param.h"
#include "type.h"

static int line_no;
static char *filename;

static struct arg_type_info *parse_type(char **str, int *ownp);

Function *list_of_functions = NULL;

static int
parse_arg_type(char **name, enum arg_type *ret)
{
	char *rest = NULL;
	enum arg_type candidate = ARGTYPE_UNKNOWN;

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
	KEYWORD("octal", ARGTYPE_OCTAL);
	KEYWORD("char", ARGTYPE_CHAR);
	KEYWORD("short", ARGTYPE_SHORT);
	KEYWORD("ushort", ARGTYPE_USHORT);
	KEYWORD("float", ARGTYPE_FLOAT);
	KEYWORD("double", ARGTYPE_DOUBLE);
	KEYWORD("array", ARGTYPE_ARRAY);
	KEYWORD("enum", ARGTYPE_ENUM);
	KEYWORD("struct", ARGTYPE_STRUCT);

	/* XXX temporary.  */
	KEYWORD("format", ARGTYPE_FORMAT);

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

static struct expr_node *parse_argnum(char **str, int zero);

static struct expr_node *
parse_zero(char **str, struct expr_node *ret)
{
	eat_spaces(str);
	if (**str == '(') {
		++*str;
		struct expr_node *arg = parse_argnum(str, 0);
		if (arg == NULL)
			return NULL;
		if (parse_char(str, ')') < 0) {
		fail:
			expr_destroy(arg);
			free(arg);
			return NULL;
		}

		struct expr_node *ret = build_zero_w_arg(arg, 1);
		if (ret == NULL)
			goto fail;
		return ret;

	} else {
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
parse_argnum(char **str, int zero)
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

		return expr;

	} else {
		char *name = parse_ident(str);
		if (name == NULL)
			goto fail;

		int is_arg = strncmp(name, "arg", 3) == 0;
		int is_elt = !is_arg && strncmp(name, "elt", 3) == 0;
		if (is_arg || is_elt) {
			long l;
			name += 3;
			if (parse_int(&name, &l) < 0
			    || check_int(l) < 0)
				goto fail;

			if (is_arg) {
				expr_init_argno(expr, l - 1);
			} else {
				struct expr_node *e_up = malloc(sizeof(*e_up));
				struct expr_node *e_ix = malloc(sizeof(*e_ix));
				if (e_up == NULL || e_ix == NULL) {
					free(e_up);
					free(e_ix);
					goto fail;
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
			struct expr_node *ret = parse_zero(str, expr);
			if (ret == NULL)
				goto fail;
			return ret;

		} else {
			report_error(filename, line_no,
				     "Unknown length specifier: '%s'", name);
			goto fail;
		}

		if (zero && wrap_in_zero(&expr) < 0)
			goto fail;

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
	struct typedef_node_t *next;
} *typedefs = NULL;

static struct arg_type_info *
lookup_typedef(char **str) {
	struct typedef_node_t *node;
	char *end = *str;
	while (*end && (isalnum(*end) || *end == '_'))
		++end;
	if (end == *str)
		return NULL;

	for (node = typedefs; node != NULL; node = node->next) {
		if (strncmp(*str, node->name, end - *str) == 0) {
			(*str) += strlen(node->name);
			return node->info;
		}
	}

	return NULL;
}

static struct typedef_node_t *
insert_typedef(char *name, struct arg_type_info *info, int own_type)
{
	struct typedef_node_t *binding = malloc(sizeof(*binding));
	binding->name = name;
	binding->info = info;
	binding->own_type = own_type;
	binding->next = typedefs;
	typedefs = binding;
	return binding;
}

static void
parse_typedef(char **str) {
	char *name;
	struct arg_type_info *info;

	(*str) += strlen("typedef");
	eat_spaces(str);

	// Grab out the name of the type
	name = parse_ident(str);

	// Skip = sign
	eat_spaces(str);
	if (parse_char(str, '=') < 0)
		return;
	eat_spaces(str);

	// Parse the type
	int own;
	info = parse_type(str, &own);

	insert_typedef(name, info, own);
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
parse_struct(char **str, struct arg_type_info *info)
{
	eat_spaces(str);
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
		struct arg_type_info *field = parse_type(str, &own);
		if (field == NULL || type_struct_add(info, field, own)) {
			type_destroy(info);
			return -1;
		}
	}
}

static int
parse_string(char **str, struct arg_type_info **retp)
{
	struct arg_type_info *info = malloc(sizeof(*info));
	if (info == NULL) {
	fail:
		free(info);
		return -1;
	}

	struct expr_node *length;
	int own_length;

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

			length = parse_argnum(str, 1);
			if (length == NULL)
				goto fail;
			own_length = 1;

			eat_spaces(str);
			parse_char(str, ']');

		} else {
			/* It was just a simple string after all.  */
			length = expr_node_zero();
			own_length = 0;
		}
	}

	/* String is a pointer to array of chars.  */
	type_init_string(info, length, own_length);

	*retp = info;
	return 0;
}

static int
parse_alias(char **str, struct arg_type_info **retp, int *ownp)
{
	/* For backward compatibility, we need to support things like
	 * stringN (which is like string[argN], string[N], and also
	 * bare string.  We might, in theory, replace this by
	 * preprocessing configure file sources with M4, but for now,
	 * "string" is syntax.  */
	if (strncmp(*str, "string", 6) == 0) {
		(*str) += 6;
		return parse_string(str, retp);

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
	struct arg_type_info *elt_info = parse_type(str, &own);
	if (elt_info == NULL)
		return -1;

	eat_spaces(str);
	parse_char(str, ',');

	eat_spaces(str);
	struct expr_node *length = parse_argnum(str, 0);
	if (length == NULL) {
		if (own) {
			type_destroy(elt_info);
			free(elt_info);
		}
		return -1;
	}

	type_init_array(info, elt_info, own, length, 1);

	eat_spaces(str);
	parse_char(str, ')');
	return 0;
}

/* Syntax: enum ( keyname=value,keyname=value,... ) */
static int
parse_enum(char **str, struct arg_type_info *info)
{
	eat_spaces(str);
	if (parse_char(str, '(') < 0)
		return -1;

	type_init_enum(info);

	int last_val = 0;
	while (1) {
		eat_spaces(str);
		if (**str == 0 || **str == ')') {
			parse_char(str, ')');
			return 0;
		}

		/* Field delimiter.  XXX should we support the C
		 * syntax, where the enumeration can end in pending
		 * comma?  */
		if (type_enum_size(info) > 0)
			parse_char(str, ',');

		eat_spaces(str);
		char *key = parse_ident(str);
		if (key == NULL) {
		err:
			free(key);
			return -1;
		}

		if (**str == '=') {
			++*str;
			eat_spaces(str);
			long l;
			if (parse_int(str, &l) < 0 || check_int(l) < 0)
				goto err;
			last_val = l;

		} else {
			last_val++;
		}

		if (type_enum_add(info, key, 1, last_val) < 0)
			goto err;
	}

	return 0;
}

static struct arg_type_info *
parse_nonpointer_type(char **str, int *ownp)
{
	enum arg_type type;
	if (parse_arg_type(str, &type) < 0) {
		struct arg_type_info *simple;
		if (parse_alias(str, &simple, ownp) < 0)
			return NULL;
		if (simple == NULL)
			simple = lookup_typedef(str);
		if (simple != NULL) {
			*ownp = 0;
			return simple;
		}
		report_error(filename, line_no,
			     "unknown type around '%s'", *str);
		return NULL;
	}

	int (*parser) (char **, struct arg_type_info *) = NULL;
	/* For some types that's all we need.  */
	switch (type) {
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
	case ARGTYPE_FORMAT:
		*ownp = 0;
		return type_get_simple(type);

	case ARGTYPE_ARRAY:
		parser = parse_array;
		break;

	case ARGTYPE_ENUM:
		parser = parse_enum;
		break;

	case ARGTYPE_STRUCT:
		parser = parse_struct;
		break;

	case ARGTYPE_STRING_N:
		/* Strings are handled in aliases, to support
		 * "stringN" syntax cleanly.  */
		assert(type != ARGTYPE_STRING_N);
		abort();

	case ARGTYPE_POINTER:
		/* Pointer syntax is not based on keyword, so we
		 * should never get this type.  */
		assert(type != ARGTYPE_POINTER);
	case ARGTYPE_COUNT:
		abort();
	}

	struct arg_type_info *info = malloc(sizeof(*info));
	if (info == NULL) {
		report_error(filename, line_no,
			     "malloc: %s", strerror(errno));
		return NULL;
	}
	*ownp = 1;

	if (parser(str, info) < 0) {
		free(info);
		return NULL;
	}

	return info;
}

static struct arg_type_info *
parse_type(char **str, int *ownp)
{
	struct arg_type_info *info = parse_nonpointer_type(str, ownp);
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

static Function *
process_line(char *buf) {
	char *str = buf;
	char *tmp;

	line_no++;
	debug(3, "Reading line %d of `%s'", line_no, filename);
	eat_spaces(&str);

	/* A comment or empty line.  */
	if (*str == ';' || *str == 0)
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

	fun->return_info = parse_type(&str, &fun->own_return_info);
	if (fun->return_info == NULL
	    || fun->return_info->type == ARGTYPE_UNKNOWN) {
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
	fun->num_params = 0;
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
		struct arg_type_info *type = parse_type(&str, &own);
		if (type == NULL) {
			report_error(filename, line_no,
				     "unknown argument type");
			goto err;
		}

		/* XXX We used to allow void parameter as a synonym to
		 * an argument that shouldn't be displayed.  We may
		 * wish to re-introduce this when lenses are
		 * implemented, as a synonym, but backends generally
		 * need to know the type, so disallow bare void for
		 * now.  */
		if (type->type == ARGTYPE_VOID) {
			report_warning(filename, line_no,
				       "void parameter assumed to be 'int'");
			if (own) {
				type_destroy(type);
				free(type);
			}
			type = type_get_simple(ARGTYPE_INT);
			own = 0;
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

	if (extra_param != NULL) {
		assert(fun->num_params < allocd);
		memcpy(&fun->params[fun->num_params++], extra_param,
		       sizeof(*extra_param));
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

	insert_typedef(strdup("addr"), info, 0);
	insert_typedef(strdup("file"), info, 1);
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
