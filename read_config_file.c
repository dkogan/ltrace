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

#include "common.h"
#include "type.h"
#include "expr.h"
#include "errno.h"

static int line_no;
static char *filename;
static int error_count = 0;

static struct arg_type_info *parse_type(char **str);

Function *list_of_functions = NULL;

/* Map of strings to type names. These do not need to be in any
 * particular order */
static struct list_of_pt_t {
	char *name;
	enum arg_type pt;
} list_of_pt[] = {
	{
	"void", ARGTYPE_VOID}, {
	"int", ARGTYPE_INT}, {
	"uint", ARGTYPE_UINT}, {
	"long", ARGTYPE_LONG}, {
	"ulong", ARGTYPE_ULONG}, {
	"octal", ARGTYPE_OCTAL}, {
	"char", ARGTYPE_CHAR}, {
	"short", ARGTYPE_SHORT}, {
	"ushort", ARGTYPE_USHORT}, {
	"float", ARGTYPE_FLOAT}, {
	"double", ARGTYPE_DOUBLE}, {
	"addr", ARGTYPE_ADDR}, {
	"file", ARGTYPE_FILE}, {
	"format", ARGTYPE_FORMAT}, {
	"string", ARGTYPE_STRING}, {
	"array", ARGTYPE_ARRAY}, {
	"struct", ARGTYPE_STRUCT}, {
	"enum", ARGTYPE_ENUM}, {
	NULL, ARGTYPE_UNKNOWN}	/* Must finish with NULL */
};

/* Array of prototype objects for each of the types. The order in this
 * array must exactly match the list of enumerated values in
 * common.h */
static struct arg_type_info arg_type_prototypes[] = {
	{ ARGTYPE_VOID },
	{ ARGTYPE_INT },
	{ ARGTYPE_UINT },
	{ ARGTYPE_LONG },
	{ ARGTYPE_ULONG },
	{ ARGTYPE_OCTAL },
	{ ARGTYPE_CHAR },
	{ ARGTYPE_SHORT },
	{ ARGTYPE_USHORT },
	{ ARGTYPE_FLOAT },
	{ ARGTYPE_DOUBLE },
	{ ARGTYPE_ADDR },
	{ ARGTYPE_FILE },
	{ ARGTYPE_FORMAT },
	{ ARGTYPE_STRING },
	{ ARGTYPE_STRING_N },
	{ ARGTYPE_ARRAY },
	{ ARGTYPE_ENUM },
	{ ARGTYPE_STRUCT },
	{ ARGTYPE_POINTER },
	{ ARGTYPE_UNKNOWN }
};

struct arg_type_info *
lookup_prototype(enum arg_type at) {
	if (at >= 0 && at <= ARGTYPE_COUNT)
		return &arg_type_prototypes[at];
	else
		return &arg_type_prototypes[ARGTYPE_COUNT]; /* UNKNOWN */
}

static struct arg_type_info *
str2type(char **str) {
	struct list_of_pt_t *tmp = &list_of_pt[0];

	while (tmp->name) {
		if (!strncmp(*str, tmp->name, strlen(tmp->name))
				&& index(" ,()#*;012345[", *(*str + strlen(tmp->name)))) {
			*str += strlen(tmp->name);
			return lookup_prototype(tmp->pt);
		}
		tmp++;
	}
	return lookup_prototype(ARGTYPE_UNKNOWN);
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
parse_int(char **str) {
	char *end;
	long n = strtol(*str, &end, 0);
	if (end == *str) {
		report_error(filename, line_no, "bad number");
		return -1;
	}

	*str = end;
	return n;
}

/*
 * Input:
 *  argN   : The value of argument #N, counting from 1
 *  eltN   : The value of element #N of the containing structure
 *  retval : The return value
 *  N      : The numeric value N
 */
static struct expr_node *
parse_argnum(char **str)
{
	struct expr_node *expr = malloc(sizeof(*expr));
	if (expr == NULL)
		return NULL;

	if (isdigit(**str)) {
		expr_init_const_word(expr, parse_int(str),
				     type_get_simple(ARGTYPE_LONG), 0);

		return expr;

	} else {
		char *name = parse_ident(str);
		if (name == NULL)
			goto fail;

		int is_arg = strncmp(name, "arg", 3) == 0;
		int is_elt = !is_arg && strncmp(name, "elt", 3) == 0;
		if (is_arg || is_elt) {
			name += 3;
			int l = parse_int(&name);
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

		} else {
			report_error(filename, line_no,
				     "Unknown length specifier: '%s'", name);
			goto fail;
		}
		return expr;
	}

fail:
	free(expr);
	return NULL;
}

struct typedef_node_t {
	char *name;
	struct arg_type_info *info;
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

static void
parse_typedef(char **str) {
	char *name;
	struct arg_type_info *info;
	struct typedef_node_t *binding;

	(*str) += strlen("typedef");
	eat_spaces(str);

	// Grab out the name of the type
	name = parse_ident(str);

	// Skip = sign
	eat_spaces(str);
	if (**str != '=') {
		output_line(0,
				"Syntax error in `%s', line %d: expected '=', got '%c'",
				filename, line_no, **str);
		error_count++;
		return;
	}
	(*str)++;
	eat_spaces(str);

	// Parse the type
	info = parse_type(str);

	// Insert onto beginning of linked list
	binding = malloc(sizeof(*binding));
	binding->name = name;
	binding->info = info;
	binding->next = typedefs;
	typedefs = binding;
}

/* Syntax: struct ( type,type,type,... ) */
static int
parse_struct(char **str, struct arg_type_info *info)
{
	eat_spaces(str);
	if (**str != '(')
		return -1;
	++*str;

	eat_spaces(str); // Empty arg list with whitespace inside

	type_init_struct(info);

	while (1) {
		eat_spaces(str);
		if (**str == 0 || **str == ')') {
			++*str;
			return 0;
		}

		/* Field delimiter.  */
		if (type_struct_size(info) > 0)
			++*str;

		eat_spaces(str);
		int own = 0;
		struct arg_type_info *field = parse_type(str);
		if (field == NULL || type_struct_add(info, field, own)) {
			type_destroy(info);
			return -1;
		}
	}
}

static struct arg_type_info *
parse_nonpointer_type(char **str) {
	struct arg_type_info *simple;
	struct arg_type_info *info;

	if (strncmp(*str, "typedef", 7) == 0) {
		parse_typedef(str);
		return lookup_prototype(ARGTYPE_UNKNOWN);
	}

	simple = str2type(str);
	if (simple->type == ARGTYPE_UNKNOWN) {
		info = lookup_typedef(str);
		if (info)
			return info;
		else
			return simple;		// UNKNOWN
	}

	info = malloc(sizeof(*info));
	info->type = simple->type;

	/* Code to parse parameterized types will go into the following
	   switch statement. */

	switch (info->type) {

	/* Syntax: array ( type, N|argN ) */
	case ARGTYPE_ARRAY:
		(*str)++;		// Get past open paren
		eat_spaces(str);
		if ((info->u.array_info.elt_type = parse_type(str)) == NULL)
			return NULL;
		(*str)++;		// Get past comma
		eat_spaces(str);
		info->u.array_info.length = parse_argnum(str);
		(*str)++;		// Get past close paren
		return info;

	/* Syntax: enum ( keyname=value,keyname=value,... ) */
	case ARGTYPE_ENUM:{
		struct enum_opt {
			char *key;
			int value;
			struct enum_opt *next;
		};
		struct enum_opt *list = NULL;
		struct enum_opt *p;
		int entries = 0;
		int ii;

		eat_spaces(str);
		(*str)++;		// Get past open paren
		eat_spaces(str);

		while (**str && **str != ')') {
			p = (struct enum_opt *) malloc(sizeof(*p));
			eat_spaces(str);
			p->key = parse_ident(str);
			if (error_count) {
				free(p);
				return NULL;
			}
			eat_spaces(str);
			if (**str != '=') {
				free(p->key);
				free(p);
				output_line(0,
						"Syntax error in `%s', line %d: expected '=', got '%c'",
						filename, line_no, **str);
				error_count++;
				return NULL;
			}
			++(*str);
			eat_spaces(str);
			p->value = parse_int(str);
			p->next = list;
			list = p;
			++entries;

			// Skip comma
			eat_spaces(str);
			if (**str == ',') {
				(*str)++;
				eat_spaces(str);
			}
		}

		info->u.enum_info.entries = entries;
		info->u.enum_info.keys =
			(char **) malloc(entries * sizeof(char *));
		info->u.enum_info.values =
			(int *) malloc(entries * sizeof(int));
		for (ii = 0, p = NULL; list; ++ii, list = list->next) {
			if (p)
				free(p);
			info->u.enum_info.keys[ii] = list->key;
			info->u.enum_info.values[ii] = list->value;
			p = list;
		}
		if (p)
			free(p);

		return info;
	}

	case ARGTYPE_STRING:
		if (!isdigit(**str) && **str != '[') {
			/* Oops, was just a simple string after all */
			free(info);
			return simple;
		}

		info->type = ARGTYPE_STRING_N;

		/* Backwards compatibility for string0, string1, ... */
		if (isdigit(**str)) {
			info->u.string_n_info.length = parse_argnum(str);
			return info;
		}

		(*str)++;		// Skip past opening [
		eat_spaces(str);
		info->u.string_n_info.length = parse_argnum(str);
		eat_spaces(str);
		(*str)++;		// Skip past closing ]
		return info;

	// Syntax: struct ( type,type,type,... )
	case ARGTYPE_STRUCT:{
		if (parse_struct(str, info) < 0) {
			free(info);
			output_line(0, "Parse error in `%s', line %d",
				    filename, line_no);
			error_count++;
			return NULL;
		}
		return info;
	}

	default:
		if (info->type == ARGTYPE_UNKNOWN) {
			output_line(0, "Syntax error in `%s', line %d: "
					"Unknown type encountered",
					filename, line_no);
			free(info);
			error_count++;
			return NULL;
		} else {
			return info;
		}
	}
}

static struct arg_type_info *
parse_type(char **str) {
	struct arg_type_info *info = parse_nonpointer_type(str);
	while (**str == '*') {
		struct arg_type_info *outer = malloc(sizeof(*info));
		outer->type = ARGTYPE_POINTER;
		outer->u.ptr_info.info = info;
		(*str)++;
		info = outer;
	}
	return info;
}

static Function *
process_line(char *buf) {
	Function fun;
	Function *fun_p;
	char *str = buf;
	char *tmp;
	int i;
	int float_num = 0;

	line_no++;
	debug(3, "Reading line %d of `%s'", line_no, filename);
	eat_spaces(&str);
	fun.return_info = parse_type(&str);
	if (fun.return_info == NULL)
		return NULL;
	if (fun.return_info->type == ARGTYPE_UNKNOWN) {
	err:
		debug(3, " Skipping line %d", line_no);
		return NULL;
	}
	debug(4, " return_type = %d", fun.return_info->type);
	eat_spaces(&str);
	tmp = start_of_arg_sig(str);
	if (tmp == NULL) {
		report_error(filename, line_no, "syntax error");
		goto err;
	}
	*tmp = '\0';
	fun.name = strdup(str);
	str = tmp + 1;
	debug(3, " name = %s", fun.name);
	fun.params_right = 0;
	for (i = 0; i < MAX_ARGS; i++) {
		eat_spaces(&str);
		if (*str == ')') {
			break;
		}
		if (str[0] == '+') {
			fun.params_right++;
			str++;
		} else if (fun.params_right) {
			fun.params_right++;
		}
		fun.arg_info[i] = parse_type(&str);
		if (fun.arg_info[i] == NULL) {
			output_line(0, "Syntax error in `%s', line %d"
					": unknown argument type",
					filename, line_no);
			error_count++;
			return NULL;
		}
		if (fun.arg_info[i]->type == ARGTYPE_FLOAT)
			fun.arg_info[i]->u.float_info.float_index = float_num++;
		else if (fun.arg_info[i]->type == ARGTYPE_DOUBLE)
			fun.arg_info[i]->u.double_info.float_index = float_num++;
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
	fun.num_params = i;
	fun_p = malloc(sizeof(Function));
	if (!fun_p) {
		perror("ltrace: malloc");
		exit(1);
	}
	memcpy(fun_p, &fun, sizeof(Function));
	return fun_p;
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

		error_count = 0;
		tmp = process_line(buf);

		if (tmp) {
			debug(2, "New function: `%s'", tmp->name);
			tmp->next = list_of_functions;
			list_of_functions = tmp;
		}
	}
	fclose(stream);
}
