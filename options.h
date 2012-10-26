/*
 * This file is part of ltrace.
 * Copyright (C) 2009,2010 Joe Damato
 * Copyright (C) 1998,2002,2008 Juan Cespedes
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

#include <stdio.h>
#include <sys/types.h>

#include "forward.h"

struct options_t {
	int align;      /* -a: default alignment column for results */
	char * user;    /* -u: username to run command as */
	int syscalls;   /* -S: display system calls */
	int demangle;   /* -C: demangle low-level names into user-level names */
	int indent;     /* -n: indent trace output according to program flow */
	FILE *output;   /* output to a specific file */
	int summary;    /* count time, calls, and report a summary on program exit */
	int debug;      /* debug */
	size_t arraylen;   /* default maximum # of array elements printed */
	size_t strlen;     /* default maximum # of bytes printed in strings */
	int follow;     /* trace child processes */
	int no_signals; /* don't print signals */
#if defined(HAVE_LIBUNWIND)
	int bt_depth;	 /* how may levels of stack frames to show */
#endif /* defined(HAVE_LIBUNWIND) */
	struct filter *plt_filter;
	struct filter *static_filter;

	/* A filter matching library names of libraries, whose
	 * exported symbols we wish to trace.  */
	struct filter *export_filter;

	int hide_caller; /* Whether caller library should be hidden.  */
};
extern struct options_t options;

extern int opt_i;		/* instruction pointer */
extern int opt_r;		/* print relative timestamp */
extern int opt_t;		/* print absolute timestamp */
extern int opt_T;		/* show the time spent inside each call */

struct opt_p_t {
	pid_t pid;
	struct opt_p_t *next;
};

struct opt_F_t
{
	struct opt_F_t *next;
	char *filename;
	int own_filename : 1;
};

extern struct opt_p_t *opt_p;	/* attach to process with a given pid */

extern struct opt_F_t *opt_F;	/* alternate configuration file(s) */

extern char **process_options(int argc, char **argv);
