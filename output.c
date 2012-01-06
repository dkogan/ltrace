/*
 * This file is part of ltrace.
 * Copyright (C) 2011,2012 Petr Machata, Red Hat Inc.
 * Copyright (C) 2010 Joe Damato
 * Copyright (C) 1997,1998,1999,2001,2002,2003,2004,2007,2008,2009 Juan Cespedes
 * Copyright (C) 2006 Paul Gilliam
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

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <unistd.h>

#include "common.h"
#include "proc.h"
#include "library.h"
#include "type.h"
#include "value.h"
#include "value_dict.h"

/* TODO FIXME XXX: include in common.h: */
extern struct timeval current_time_spent;

Dict *dict_opt_c = NULL;

static Process *current_proc = 0;
static int current_depth = 0;
static int current_column = 0;

static void
output_indent(struct Process *proc)
{
	int d = options.indent * (proc->callstack_depth - 1);
	current_column += fprintf(options.output, "%*s", d, "");
}

static void
begin_of_line(enum tof type, Process *proc) {
	current_column = 0;
	if (!proc) {
		return;
	}
	if ((options.output != stderr) && (opt_p || options.follow)) {
		current_column += fprintf(options.output, "%u ", proc->pid);
	} else if (options.follow) {
		current_column += fprintf(options.output, "[pid %u] ", proc->pid);
	}
	if (opt_r) {
		struct timeval tv;
		struct timezone tz;
		static struct timeval old_tv = { 0, 0 };
		struct timeval diff;

		gettimeofday(&tv, &tz);

		if (old_tv.tv_sec == 0 && old_tv.tv_usec == 0) {
			old_tv.tv_sec = tv.tv_sec;
			old_tv.tv_usec = tv.tv_usec;
		}
		diff.tv_sec = tv.tv_sec - old_tv.tv_sec;
		if (tv.tv_usec >= old_tv.tv_usec) {
			diff.tv_usec = tv.tv_usec - old_tv.tv_usec;
		} else {
			diff.tv_sec--;
			diff.tv_usec = 1000000 + tv.tv_usec - old_tv.tv_usec;
		}
		old_tv.tv_sec = tv.tv_sec;
		old_tv.tv_usec = tv.tv_usec;
		current_column += fprintf(options.output, "%3lu.%06d ",
					  diff.tv_sec, (int)diff.tv_usec);
	}
	if (opt_t) {
		struct timeval tv;
		struct timezone tz;

		gettimeofday(&tv, &tz);
		if (opt_t > 2) {
			current_column += fprintf(options.output, "%lu.%06d ",
						  tv.tv_sec, (int)tv.tv_usec);
		} else if (opt_t > 1) {
			struct tm *tmp = localtime(&tv.tv_sec);
			current_column +=
			    fprintf(options.output, "%02d:%02d:%02d.%06d ",
				    tmp->tm_hour, tmp->tm_min, tmp->tm_sec,
				    (int)tv.tv_usec);
		} else {
			struct tm *tmp = localtime(&tv.tv_sec);
			current_column += fprintf(options.output, "%02d:%02d:%02d ",
						  tmp->tm_hour, tmp->tm_min,
						  tmp->tm_sec);
		}
	}
	if (opt_i) {
		if (type == LT_TOF_FUNCTION || type == LT_TOF_FUNCTIONR) {
			current_column += fprintf(options.output, "[%p] ",
						  proc->return_addr);
		} else {
			current_column += fprintf(options.output, "[%p] ",
						  proc->instruction_pointer);
		}
	}
	if (options.indent > 0 && type != LT_TOF_NONE) {
		output_indent(proc);
	}
}

static Function *
name2func(char const *name) {
	Function *tmp;
	const char *str1, *str2;

	tmp = list_of_functions;
	while (tmp) {
#ifdef USE_DEMANGLE
		str1 = options.demangle ? my_demangle(tmp->name) : tmp->name;
		str2 = options.demangle ? my_demangle(name) : name;
#else
		str1 = tmp->name;
		str2 = name;
#endif
		if (!strcmp(str1, str2)) {

			return tmp;
		}
		tmp = tmp->next;
	}
	return NULL;
}

void
output_line(Process *proc, char *fmt, ...) {
	va_list args;

	if (options.summary) {
		return;
	}
	if (current_proc) {
		if (current_proc->callstack[current_depth].return_addr) {
			fprintf(options.output, " <unfinished ...>\n");
		} else {
			fprintf(options.output, " <no return ...>\n");
		}
	}
	current_proc = 0;
	if (!fmt) {
		return;
	}
	begin_of_line(LT_TOF_NONE, proc);

	va_start(args, fmt);
	vfprintf(options.output, fmt, args);
	fprintf(options.output, "\n");
	va_end(args);
	current_column = 0;
}

static void
tabto(int col) {
	if (current_column < col) {
		fprintf(options.output, "%*s", col - current_column, "");
	}
}

void
output_left(enum tof type, struct Process *proc,
	    struct library_symbol *libsym)
{
	const char *function_name = libsym->name;
	Function *func;
	static struct arg_type_info *arg_unknown = NULL;
	if (arg_unknown == NULL)
	    arg_unknown = lookup_prototype(ARGTYPE_UNKNOWN);

	if (options.summary) {
		return;
	}
	if (current_proc) {
		fprintf(options.output, " <unfinished ...>\n");
		current_column = 0;
	}
	current_proc = proc;
	current_depth = proc->callstack_depth;
	begin_of_line(type, proc);
	if (!options.hide_caller && libsym->lib != NULL
	    && libsym->plt_type != LS_TOPLT_NONE)
		current_column += fprintf(options.output, "%s->",
					  libsym->lib->soname);
#ifdef USE_DEMANGLE
	current_column +=
		fprintf(options.output, "%s(",
			(options.demangle
			 ? my_demangle(function_name) : function_name));
#else
	current_column += fprintf(options.output, "%s(", function_name);
#endif

	func = name2func(function_name);

	struct value_dict *arguments = malloc(sizeof(*arguments));
	if (arguments == NULL)
		return;
	val_dict_init(arguments);

	int num, right;
	if (!func) {
		int i;
		for (i = 0; i < 4; i++) {
			long l = gimme_arg(type, proc, i, arg_unknown);
			struct value val;
			value_init(&val, proc, NULL, arg_unknown, 0);
			value_set_long(&val, l);
			val_dict_push_next(arguments, &val);
		}
		right = 0;
		num = 4;
	} else {
		int i;
		for (i = 0; i < func->num_params; i++) {
			long l = gimme_arg(type, proc, i, func->arg_info[i]);
			struct value val;
			value_init(&val, proc, NULL, func->arg_info[i], 0);
			value_set_long(&val, l);
			val_dict_push_next(arguments, &val);
		}
		right = func->params_right;
		num = func->num_params;
	}

	int i;
	for (i = 0; i < num - right - 1; i++) {
		current_column +=
			format_argument(options.output,
					val_dict_get_num(arguments, i),
					arguments);
		current_column += fprintf(options.output, ", ");
	}

	if (num > right) {
		current_column +=
			format_argument(options.output,
					val_dict_get_num(arguments, i),
					arguments);
		if (right) {
			current_column += fprintf(options.output, ", ");
		}
	}

	struct callstack_element *stel
		= &proc->callstack[proc->callstack_depth - 1];
	stel->arguments = arguments;
}

void
output_right(enum tof type, struct Process *proc, struct library_symbol *libsym)
{
	const char *function_name = libsym->name;
	Function *func = name2func(function_name);
	static struct arg_type_info *arg_unknown = NULL;
	if (arg_unknown == NULL)
	    arg_unknown = lookup_prototype(ARGTYPE_UNKNOWN);

	if (options.summary) {
		struct opt_c_struct *st;
		if (!dict_opt_c) {
			dict_opt_c =
			    dict_init(dict_key2hash_string,
				      dict_key_cmp_string);
		}
		st = dict_find_entry(dict_opt_c, function_name);
		if (!st) {
			char *na;
			st = malloc(sizeof(struct opt_c_struct));
			na = strdup(function_name);
			if (!st || !na) {
				perror("malloc()");
				exit(1);
			}
			st->count = 0;
			st->tv.tv_sec = st->tv.tv_usec = 0;
			dict_enter(dict_opt_c, na, st);
		}
		if (st->tv.tv_usec + current_time_spent.tv_usec > 1000000) {
			st->tv.tv_usec += current_time_spent.tv_usec - 1000000;
			st->tv.tv_sec++;
		} else {
			st->tv.tv_usec += current_time_spent.tv_usec;
		}
		st->count++;
		st->tv.tv_sec += current_time_spent.tv_sec;

//              fprintf(options.output, "%s <%lu.%06d>\n", function_name,
//                              current_time_spent.tv_sec, (int)current_time_spent.tv_usec);
		return;
	}
	if (current_proc && (current_proc != proc ||
			    current_depth != proc->callstack_depth)) {
		fprintf(options.output, " <unfinished ...>\n");
		current_proc = 0;
	}
	if (current_proc != proc) {
		begin_of_line(type, proc);
#ifdef USE_DEMANGLE
		current_column +=
		    fprintf(options.output, "<... %s resumed> ",
			    options.demangle ? my_demangle(function_name) : function_name);
#else
		current_column +=
		    fprintf(options.output, "<... %s resumed> ", function_name);
#endif
	}

	struct callstack_element *stel
		= &proc->callstack[proc->callstack_depth - 1];

	struct value retval;
	struct arg_type_info *return_info = arg_unknown;
	if (func != NULL)
		return_info = func->return_info;
	long l = gimme_arg(type, proc, -1, return_info);
	value_init(&retval, proc, NULL, return_info, 0);
	value_set_long(&retval, l);
	val_dict_push_named(stel->arguments, &retval, "retval", 0);

	if (!func) {
		current_column += fprintf(options.output, ") ");
		tabto(options.align - 1);
		fprintf(options.output, "= ");
	} else {
		int i;
		for (i = func->num_params - func->params_right;
		     i < func->num_params - 1; i++) {
			current_column +=
				format_argument(options.output,
						val_dict_get_num
							(stel->arguments, i),
						stel->arguments);
			current_column += fprintf(options.output, ", ");
		}
		if (func->params_right) {
			current_column +=
				format_argument(options.output,
						val_dict_get_num
							(stel->arguments, i),
						stel->arguments);
		}
		current_column += fprintf(options.output, ") ");
		tabto(options.align - 1);
		fprintf(options.output, "= ");
	}

	format_argument(options.output, &retval, stel->arguments);
	val_dict_destroy(stel->arguments);

	if (opt_T) {
		fprintf(options.output, " <%lu.%06d>",
			current_time_spent.tv_sec,
			(int)current_time_spent.tv_usec);
	}
	fprintf(options.output, "\n");

#if defined(HAVE_LIBUNWIND)
	if (options.bt_depth > 0) {
		unw_cursor_t cursor;
		unw_word_t ip, sp;
		int unwind_depth = options.bt_depth;
		char fn_name[100];

		unw_init_remote(&cursor, proc->unwind_as, proc->unwind_priv);
		while (unwind_depth) {
			unw_get_reg(&cursor, UNW_REG_IP, &ip);
			unw_get_reg(&cursor, UNW_REG_SP, &sp);
			unw_get_proc_name(&cursor, fn_name, 100, NULL);
			fprintf(options.output, "\t\t\t%s (ip = 0x%lx)\n", fn_name, (long) ip);
			if (unw_step(&cursor) <= 0)
				break;
			unwind_depth--;
		}
		fprintf(options.output, "\n");
	}
#endif /* defined(HAVE_LIBUNWIND) */

	current_proc = 0;
	current_column = 0;
}

static void
do_report(const char *filename, unsigned line_no, const char *severity,
	  const char *fmt, va_list args)
{
	char buf[128];
	vsnprintf(buf, sizeof(buf), fmt, args);
	buf[sizeof(buf) - 1] = 0;
	if (filename != NULL)
		output_line(0, "%s:%d: %s: %s",
			    filename, line_no, severity, buf);
	else
		output_line(0, "%s: %s", severity, buf);
}

void
report_error(const char *filename, unsigned line_no, char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	do_report(filename, line_no, "error", fmt, args);
	va_end(args);
}

void
report_warning(const char *filename, unsigned line_no, char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	do_report(filename, line_no, "warning", fmt, args);
	va_end(args);
}

void
report_global_error(char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	do_report(NULL, 0, "error", fmt, args);
	va_end(args);
}
