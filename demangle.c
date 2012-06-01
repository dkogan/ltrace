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
