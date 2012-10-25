/*
 * This file is part of ltrace.
 * Copyright (C) 1998,1999,2003,2004,2008,2009 Juan Cespedes
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

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "common.h"

#ifdef USE_DEMANGLE

/*****************************************************************************/

static Dict *d = NULL;

const char *
my_demangle(const char *function_name) {
	const char *tmp, *fn_copy;
#ifdef USE_CXA_DEMANGLE
	extern char *__cxa_demangle(const char *, char *, size_t *, int *);
#endif

	debug(DEBUG_FUNCTION, "my_demangle(name=%s)", function_name);

	if (!d)
		d = dict_init(dict_key2hash_string, dict_key_cmp_string);

	tmp = dict_find_entry(d, (void *)function_name);
	if (!tmp) {
		fn_copy = strdup(function_name);
#ifdef HAVE_LIBIBERTY
		tmp = cplus_demangle(function_name, DMGL_ANSI | DMGL_PARAMS);
#elif defined USE_CXA_DEMANGLE
		int status = 0;
		tmp = __cxa_demangle(function_name, NULL, NULL, &status);
#endif
		if (!tmp)
			tmp = fn_copy;
		if (tmp)
			dict_enter(d, (void *)fn_copy, (void *)tmp);
	}
	return tmp;
}

#endif
