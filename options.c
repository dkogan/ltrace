/*
 * This file is part of ltrace.
 * Copyright (C) 2012, 2013 Petr Machata, Red Hat Inc.
 * Copyright (C) 2009,2010 Joe Damato
 * Copyright (C) 1998,1999,2002,2003,2004,2007,2008,2009 Juan Cespedes
 * Copyright (C) 2006 Ian Wienand
 * Copyright (C) 2006 Steve Fink
 * Copyright (C) 2006 Paul Gilliam, IBM Corporation
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

#include <sys/ioctl.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "common.h"
#include "filter.h"
#include "glob.h"

#ifndef SYSCONFDIR
#define SYSCONFDIR "/etc"
#endif

#define SYSTEM_CONFIG_FILE SYSCONFDIR "/ltrace.conf"
#define USER_CONFIG_FILE "~/.ltrace.conf"

struct options_t options = {
	.align    = DEFAULT_ALIGN,    /* alignment column for results */
	.user     = NULL,             /* username to run command as */
	.syscalls = 0,                /* display syscalls */
#ifdef USE_DEMANGLE
	.demangle = 0,                /* Demangle low-level symbol names */
#endif
	.indent = 0,                  /* indent output according to program flow */
	.output = NULL,               /* output to a specific file */
	.summary = 0,                 /* Report a summary on program exit */
	.debug = 0,                   /* debug */
	.arraylen = DEFAULT_ARRAYLEN, /* maximum # array elements to print */
	.strlen = DEFAULT_STRLEN,     /* maximum # of bytes printed in strings */
	.follow = 0,                  /* trace child processes */
};

static char *progname;		/* Program name (`ltrace') */
int opt_i = 0;			/* instruction pointer */
int opt_r = 0;			/* print relative timestamp */
int opt_t = 0;			/* print absolute timestamp */
int opt_T = 0;			/* show the time spent inside each call */

/* List of pids given to option -p: */
struct opt_p_t *opt_p = NULL;	/* attach to process with a given pid */

/* List of filenames give to option -F: */
struct opt_F_t *opt_F = NULL;	/* alternate configuration file(s) */

static void
err_usage(void) {
	fprintf(stderr, "Try `%s --help' for more information.\n", progname);
	exit(1);
}

static void
usage(void) {
	fprintf(stdout, "Usage: %s [option ...] [command [arg ...]]\n"
		"Trace library calls of a given program.\n\n"
		"  -a, --align=COLUMN  align return values in a secific column.\n"
		"  -A MAXELTS          maximum number of array elements to print.\n"
		"  -b, --no-signals    don't print signals.\n"
		"  -c                  count time and calls, and report a summary on exit.\n"
# ifdef USE_DEMANGLE
		"  -C, --demangle      decode low-level symbol names into user-level names.\n"
# endif
		"  -D, --debug=MASK    enable debugging (see -Dh or --debug=help).\n"
		"  -Dh, --debug=help   show help on debugging.\n"
		"  -e FILTER           modify which library calls to trace.\n"
		"  -f                  trace children (fork() and clone()).\n"
		"  -F, --config=FILE   load alternate configuration file (may be repeated).\n"
		"  -h, --help          display this help and exit.\n"
		"  -i                  print instruction pointer at time of library call.\n"
		"  -l, --library=LIBRARY_PATTERN only trace symbols implemented by this library.\n"
		"  -L                  do NOT display library calls.\n"
		"  -n, --indent=NR     indent output by NR spaces for each call level nesting.\n"
		"  -o, --output=FILENAME write the trace output to file with given name.\n"
		"  -p PID              attach to the process with the process ID pid.\n"
		"  -r                  print relative timestamps.\n"
		"  -s STRSIZE          specify the maximum string size to print.\n"
		"  -S                  trace system calls as well as library calls.\n"
		"  -t, -tt, -ttt       print absolute timestamps.\n"
		"  -T                  show the time spent inside each call.\n"
		"  -u USERNAME         run command with the userid, groupid of username.\n"
		"  -V, --version       output version information and exit.\n"
#if defined(HAVE_LIBUNWIND)
		"  -w, --where=NR      print backtrace showing NR stack frames at most.\n"
#endif /* defined(HAVE_LIBUNWIND) */
		"  -x FILTER           modify which static functions to trace.\n"
		"\nReport bugs to ltrace-devel@lists.alioth.debian.org\n",
		progname);
}

static void
usage_debug(void) {
	fprintf(stdout, "%s debugging option, --debug=<octal> or -D<octal>:\n", progname);
	fprintf(stdout, 
			"\n"
			" number  ref. in source   description\n"
			"      1   general           Generally helpful progress information\n"
			"     10   event             Shows every event received by a traced process\n"
			"     20   process           Shows actions carried upon a traced processes\n"
			"     40   function          Shows every entry to internal functions\n"
			"\n"
			"Debugging options are mixed using bitwise-or.\n"
			"Note that the meanings and values are subject to change.\n"
		   );
}

static char *
search_for_command(char *filename) {
	static char pathname[PATH_MAX];
	char *path;
	int m, n;

	if (strchr(filename, '/')) {
		return filename;
	}
	for (path = getenv("PATH"); path && *path; path += m) {
		if (strchr(path, ':')) {
			n = strchr(path, ':') - path;
			m = n + 1;
		} else {
			m = n = strlen(path);
		}
		if (n + strlen(filename) + 1 >= PATH_MAX) {
			fprintf(stderr, "Error: filename too long.\n");
			exit(1);
		}
		strncpy(pathname, path, n);
		if (n && pathname[n - 1] != '/') {
			pathname[n++] = '/';
		}
		strcpy(pathname + n, filename);
		if (!access(pathname, X_OK)) {
			return pathname;
		}
	}
	return filename;
}

static void
guess_cols(void) {
	struct winsize ws;
	char *c;

	options.align = DEFAULT_ALIGN;
	c = getenv("COLUMNS");
	if (c && *c) {
		char *endptr;
		int cols;
		cols = strtol(c, &endptr, 0);
		if (cols > 0 && !*endptr) {
			options.align = cols * 5 / 8;
		}
	} else if (ioctl(1, TIOCGWINSZ, &ws) != -1 && ws.ws_col > 0) {
		options.align = ws.ws_col * 5 / 8;
	} else if (ioctl(2, TIOCGWINSZ, &ws) != -1 && ws.ws_col > 0) {
		options.align = ws.ws_col * 5 / 8;
	}
}

static int
compile_libname(const char *expr, const char *a_lib, int lib_re_p,
		struct filter_lib_matcher *matcher)
{
	if (strcmp(a_lib, "MAIN") == 0) {
		filter_lib_matcher_main_init(matcher);
	} else {
		/* Add ^ and $ to the library expression as well.  */
		char lib[strlen(a_lib) + 3];
		sprintf(lib, "^%s$", a_lib);

		enum filter_lib_matcher_type type
			= lib[0] == '/' ? FLM_PATHNAME : FLM_SONAME;

		regex_t lib_re;
		int status = (lib_re_p ? regcomp : globcomp)(&lib_re, lib, 0);
		if (status != REG_NOERROR) {
			char buf[100];
			regerror(status, &lib_re, buf, sizeof buf);
			fprintf(stderr, "Rule near '%s' will be ignored: %s.\n",
				expr, buf);
			return -1;
		}
		filter_lib_matcher_name_init(matcher, type, lib_re);
	}
	return 0;
}

static void
add_filter_rule(struct filter *filt, const char *expr,
		enum filter_rule_type type,
		const char *a_sym, int sym_re_p,
		const char *a_lib, int lib_re_p)
{
	struct filter_rule *rule = malloc(sizeof(*rule));
	struct filter_lib_matcher *matcher = malloc(sizeof(*matcher));

	if (rule == NULL || matcher == NULL) {
		fprintf(stderr, "Rule near '%s' will be ignored: %s.\n",
			expr, strerror(errno));
	fail:
		free(rule);
		free(matcher);
		return;
	}

	regex_t symbol_re;
	{
		/* Add ^ to the start of expression and $ to the end, so that
		 * we match the whole symbol name.  Let the user write the "*"
		 * explicitly if they wish.  */
		char sym[strlen(a_sym) + 3];
		sprintf(sym, "^%s$", a_sym);
		int status = (sym_re_p ? regcomp : globcomp)
			(&symbol_re, sym, 0);
		if (status != 0) {
			char buf[100];
			regerror(status, &symbol_re, buf, sizeof buf);
			fprintf(stderr, "Rule near '%s' will be ignored: %s.\n",
				expr, buf);
			goto fail;
		}
	}

	if (compile_libname(expr, a_lib, lib_re_p, matcher) < 0) {
		regfree(&symbol_re);
		goto fail;
	}

	filter_rule_init(rule, type, matcher, symbol_re);
	filter_add_rule(filt, rule);
}

static int
grok_libname_pattern(char **libnamep, char **libendp)
{
	char *libname = *libnamep;
	char *libend = *libendp;

	if (libend[0] != '/')
		return 0;

	*libend-- = 0;
	if (libname != libend && libname[0] == '/')
		++libname;
	else
		fprintf(stderr, "Unmatched '/' in library name.\n");

	*libendp = libend;
	*libnamep = libname;
	return 1;
}

static int
parse_filter(struct filter *filt, char *expr, int operators)
{
	/* Filter is a chain of sym@lib rules separated by '-' or '+'.
	 * If the filter expression starts with '-', the missing
	 * initial rule is implicitly *@*.  */

	enum filter_rule_type type = FR_ADD;

	while (*expr != 0) {
		size_t s = strcspn(expr, &"-+@"[operators ? 0 : 2]);
		char *symname = expr;
		char *libname;
		char *next = expr + s + 1;
		enum filter_rule_type this_type = type;

		if (expr[s] == 0) {
			libname = "*";
			expr = next - 1;

		} else if (expr[s] == '-' || expr[s] == '+') {
			type = expr[s] == '-' ? FR_SUBTRACT : FR_ADD;
			expr[s] = 0;
			libname = "*";
			expr = next;

		} else {
			assert(expr[s] == '@');
			expr[s] = 0;
			s = strcspn(next, &"-+"[operators ? 0 : 2]);
			if (s == 0) {
				libname = "*";
				expr = next;
			} else if (next[s] == 0) {
				expr = next + s;
				libname = next;
			} else {
				assert(next[s] == '-' || next[s] == '+');
				type = next[s] == '-' ? FR_SUBTRACT : FR_ADD;
				next[s] = 0;
				expr = next + s + 1;
				libname = next;
			}
		}

		assert(*libname != 0);
		char *symend = symname + strlen(symname) - 1;
		char *libend = libname + strlen(libname) - 1;
		int sym_is_re = 0;
		int lib_is_re = 0;

		/*
		 * /xxx/@... and ...@/xxx/ means that xxx are regular
		 * expressions.  They are globs otherwise.
		 *
		 * /xxx@yyy/ is the same as /xxx/@/yyy/
		 *
		 * @/xxx matches library path name
		 * @.xxx matches library relative path name
		 */
		if (symname[0] == '/') {
			if (symname != symend && symend[0] == '/') {
				++symname;
				*symend-- = 0;
				sym_is_re = 1;

			} else {
				sym_is_re = 1;
				lib_is_re = 1;
				++symname;

				/* /XXX@YYY/ is the same as
				 * /XXX/@/YYY/.  */
				if (libend[0] != '/')
					fprintf(stderr, "Unmatched '/'"
						" in symbol name.\n");
				else
					*libend-- = 0;
			}
		}

		/* If libname ends in '/', then we expect '/' in the
		 * beginning too.  Otherwise the initial '/' is part
		 * of absolute file name.  */
		if (!lib_is_re)
			lib_is_re = grok_libname_pattern(&libname, &libend);

		if (*symname == 0) /* /@AA/ */
			symname = "*";
		if (*libname == 0) /* /aa@/ */
			libname = "*";

		add_filter_rule(filt, expr, this_type,
				symname, sym_is_re,
				libname, lib_is_re);
	}

	return 0;
}

static struct filter *
recursive_parse_chain(char *expr, int operators)
{
	struct filter *filt = malloc(sizeof(*filt));
	if (filt == NULL) {
		fprintf(stderr, "(Part of) filter will be ignored: '%s': %s.\n",
			expr, strerror(errno));
		return NULL;
	}

	filter_init(filt);
	if (parse_filter(filt, expr, operators) < 0) {
		fprintf(stderr, "Filter '%s' will be ignored.\n", expr);
		free(filt);
		filt = NULL;
	}

	return filt;
}

static struct filter **
slist_chase_end(struct filter **begin)
{
	for (; *begin != NULL; begin = &(*begin)->next)
		;
	return begin;
}

static void
parse_filter_chain(const char *expr, struct filter **retp)
{
	char *str = strdup(expr);
	if (str == NULL) {
		fprintf(stderr, "Filter '%s' will be ignored: %s.\n",
			expr, strerror(errno));
		return;
	}
	/* Support initial '!' for backward compatibility.  */
	if (str[0] == '!')
		str[0] = '-';

	*slist_chase_end(retp) = recursive_parse_chain(str, 1);
	free(str);
}

static int
parse_int(const char *optarg, char opt, int min, int max)
{
	char *endptr;
	long int l = strtol(optarg, &endptr, 0);
	if (l < min || (max != 0 && l > max)
	    || *optarg == 0 || *endptr != 0) {
		const char *fmt = max != 0
			? "Invalid argument to -%c: '%s'.  Use integer %d..%d.\n"
			: "Invalid argument to -%c: '%s'.  Use integer >=%d.\n";
		fprintf(stderr, fmt, opt, optarg, min, max);
		exit(1);
	}
	return (int)l;
}

char **
process_options(int argc, char **argv)
{
	progname = argv[0];
	options.output = stderr;
	options.no_signals = 0;
#if defined(HAVE_LIBUNWIND)
	options.bt_depth = -1;
#endif /* defined(HAVE_LIBUNWIND) */

	guess_cols();

	int libcalls = 1;

	while (1) {
		int c;
		char *p;
		int option_index = 0;
		static struct option long_options[] = {
			{"align", 1, 0, 'a'},
			{"config", 1, 0, 'F'},
			{"debug", 1, 0, 'D'},
# ifdef USE_DEMANGLE
			{"demangle", 0, 0, 'C'},
#endif
			{"indent", 1, 0, 'n'},
			{"help", 0, 0, 'h'},
			{"library", 1, 0, 'l'},
			{"output", 1, 0, 'o'},
			{"version", 0, 0, 'V'},
			{"no-signals", 0, 0, 'b'},
#if defined(HAVE_LIBUNWIND)
			{"where", 1, 0, 'w'},
#endif /* defined(HAVE_LIBUNWIND) */
			{0, 0, 0, 0}
		};
		c = getopt_long(argc, argv, "+cfhiLrStTVb"
# ifdef USE_DEMANGLE
				"C"
# endif
#if defined(HAVE_LIBUNWIND)
				"a:A:D:e:F:l:n:o:p:s:u:x:X:w:", long_options,
#else /* !defined(HAVE_LIBUNWIND) */
				"a:A:D:e:F:l:n:o:p:s:u:x:X:", long_options,
#endif
				&option_index);
		if (c == -1) {
			break;
		}
		switch (c) {
		case 'a':
			options.align = parse_int(optarg, 'a', 0, 0);
			break;
		case 'A':
			options.arraylen = parse_int(optarg, 'A', 0, 0);
			break;
		case 'b':
			options.no_signals = 1;
			break;
		case 'c':
			options.summary++;
			break;
#ifdef USE_DEMANGLE
		case 'C':
			options.demangle++;
			break;
#endif
		case 'D':
			if (optarg[0]=='h') {
				usage_debug();
				exit(0);
			}
			options.debug = strtoul(optarg,&p,8);
			if (*p) {
				fprintf(stderr, "%s: --debug requires an octal argument\n", progname);
				err_usage();
			}
			break;

		case 'e':
			parse_filter_chain(optarg, &options.plt_filter);
			break;

		case 'f':
			options.follow = 1;
			break;
		case 'F':
			{
				struct opt_F_t *tmp = malloc(sizeof(*tmp));
				if (tmp == NULL) {
				fail:
					fprintf(stderr, "%s\n",
						strerror(errno));
					free(tmp);
					exit(1);
				}
				tmp->filename = strdup(optarg);
				if (tmp->filename == NULL)
					goto fail;
				tmp->own_filename = 1;
				tmp->next = opt_F;
				opt_F = tmp;
				break;
			}
		case 'h':
			usage();
			exit(0);
		case 'i':
			opt_i++;
			break;

		case 'l': {
			size_t patlen = strlen(optarg);
			char buf[patlen + 2];
			sprintf(buf, "@%s", optarg);
			*slist_chase_end(&options.export_filter)
				= recursive_parse_chain(buf, 0);
			break;
		}

		case 'L':
			libcalls = 0;
			break;
		case 'n':
			options.indent = parse_int(optarg, 'n', 0, 20);
			break;
		case 'o':
			options.output = fopen(optarg, "w");
			if (!options.output) {
				fprintf(stderr,
					"can't open %s for writing: %s\n",
					optarg, strerror(errno));
				exit(1);
			}
			setvbuf(options.output, (char *)NULL, _IOLBF, 0);
			fcntl(fileno(options.output), F_SETFD, FD_CLOEXEC);
			break;
		case 'p':
			{
				struct opt_p_t *tmp = malloc(sizeof(struct opt_p_t));
				if (!tmp) {
					perror("ltrace: malloc");
					exit(1);
				}
				tmp->pid = parse_int(optarg, 'p', 1, 0);
				tmp->next = opt_p;
				opt_p = tmp;
				break;
			}
		case 'r':
			opt_r++;
			break;
		case 's':
			options.strlen = parse_int(optarg, 's', 0, 0);
			break;
		case 'S':
			options.syscalls = 1;
			break;
		case 't':
			opt_t++;
			break;
		case 'T':
			opt_T++;
			break;
		case 'u':
			options.user = optarg;
			break;
		case 'V':
			printf("ltrace version " PACKAGE_VERSION ".\n"
					"Copyright (C) 1997-2009 Juan Cespedes <cespedes@debian.org>.\n"
					"This is free software; see the GNU General Public Licence\n"
					"version 2 or later for copying conditions.  There is NO warranty.\n");
			exit(0);
			break;
#if defined(HAVE_LIBUNWIND)
		case 'w':
			options.bt_depth = parse_int(optarg, 'w', 1, 0);
			break;
#endif /* defined(HAVE_LIBUNWIND) */

		case 'x':
			parse_filter_chain(optarg, &options.static_filter);
			break;

		default:
			err_usage();
		}
	}
	argc -= optind;
	argv += optind;

	if (!opt_F) {
		opt_F = malloc(sizeof(struct opt_F_t));
		opt_F->next = malloc(sizeof(struct opt_F_t));
		opt_F->next->next = NULL;
		opt_F->filename = USER_CONFIG_FILE;
		opt_F->own_filename = 0;
		opt_F->next->filename = SYSTEM_CONFIG_FILE;
		opt_F->next->own_filename = 0;
	}
	/* Reverse the config file list since it was built by
	 * prepending, and it would make more sense to process the
	 * files in the order they were given. Probably it would make
	 * more sense to keep a tail pointer instead? */
	{
		struct opt_F_t *egg = NULL;
		struct opt_F_t *chicken;
		while (opt_F) {
			chicken = opt_F->next;
			opt_F->next = egg;
			egg = opt_F;
			opt_F = chicken;
		}
		opt_F = egg;
	}

	/* If neither -e, nor -l, nor -L are used, set default -e.
	 * Use @MAIN for now, as that's what ltrace used to have in
	 * the past.  XXX Maybe we should make this "*" instead.  */
	if (libcalls
	    && options.plt_filter == NULL
	    && options.export_filter == NULL) {
		parse_filter_chain("@MAIN", &options.plt_filter);
		options.hide_caller = 1;
	}
	if (!libcalls && options.plt_filter != NULL) {
		fprintf(stderr,
			"%s: Option -L can't be used with -e or -l.\n",
			progname);
		err_usage();
	}

	if (!opt_p && argc < 1) {
		fprintf(stderr, "%s: too few arguments\n", progname);
		err_usage();
	}
	if (opt_r && opt_t) {
		fprintf(stderr,
			"%s: Options -r and -t can't be used together\n",
			progname);
		err_usage();
	}
	if (argc > 0) {
		command = search_for_command(argv[0]);
	}
	return &argv[0];
}
