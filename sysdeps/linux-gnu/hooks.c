/*
 * This file is part of ltrace.
 * Copyright (C) 2012 Petr Machata
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

#define _POSIX_C_SOURCE 200809L
#include <sys/types.h>
#include <alloca.h>
#include <errno.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "sysdep.h"
#include "vect.h"
#include "dict.h"
#include "options.h"

static char *
append(const char *str1, const char *str2)
{
	char *ret = malloc(strlen(str1) + strlen(str2) + 2);
	if (ret == NULL)
		return ret;
	strcpy(stpcpy(ret, str1), str2);
	return ret;
}

static void
add_dir(struct vect *dirs, const char *str1, const char *str2)
{
	char *dir = append(str1, str2);
	if (dir != NULL
	    && VECT_PUSHBACK(dirs, &dir) < 0)
		fprintf(stderr,
			"Couldn't store candidate config directory %s%s: %s.\n",
			str1, str2, strerror(errno));
}

static enum callback_status
add_dir_component_cb(struct opt_F_t *entry, void *data)
{
	struct vect *dirs = data;
	if (opt_F_get_kind(entry) == OPT_F_DIR)
		add_dir(dirs, entry->pathname, "/ltrace");
	return CBS_CONT;
}

static void
destroy_opt_F_cb(struct opt_F_t *entry, void *data)
{
	opt_F_destroy(entry);
}

int
os_get_config_dirs(int private, const char ***retp)
{
	/* Vector of char *.  Contains first pointers to local paths,
	 * then NULL, then pointers to system paths, then another
	 * NULL.  SYS_START points to the beginning of the second
	 * part.  */
	static struct vect dirs;
	static ssize_t sys_start = 0;

again:
	if (sys_start != 0) {
		if (sys_start == -1)
			return -1;

		if (private)
			*retp = VECT_ELEMENT(&dirs, const char *, 0);
		else
			*retp = VECT_ELEMENT(&dirs, const char *,
					     (size_t)sys_start);
		return 0;
	}

	VECT_INIT(&dirs, char *);

	char *home = getenv("HOME");
	if (home == NULL) {
		struct passwd *pwd = getpwuid(getuid());
		if (pwd != NULL)
			home = pwd->pw_dir;
	}
	/* The values coming from getenv and getpwuid may not be
	 * persistent.  */
	{
		char *tmp = alloca(strlen(home) + 1);
		strcpy(tmp, home);
		home = tmp;
	}

	char *xdg_home = getenv("XDG_CONFIG_HOME");
	if (xdg_home == NULL && home != NULL) {
		xdg_home = alloca(strlen(home) + sizeof "/.config");
		strcpy(stpcpy(xdg_home, home), "/.config");
	}
	if (xdg_home != NULL)
		add_dir(&dirs, xdg_home, "/ltrace");
	if (home != NULL)
		add_dir(&dirs, home, "/.ltrace");

	char *delim = NULL;
	if (VECT_PUSHBACK(&dirs, &delim) < 0) {
	fail:
		/* This can't work :(  */
		fprintf(stderr,
			"Couldn't initialize list of config directories: %s.\n",
			strerror(errno));
		VECT_DESTROY(&dirs, const char *, dict_dtor_string, NULL);
		sys_start = -1;
		return -1;
	}
	sys_start = vect_size(&dirs);

	/* """preference-ordered set of base directories to search for
	 * configuration files in addition to the $XDG_CONFIG_HOME
	 * base directory. The directories in $XDG_CONFIG_DIRS should
	 * be seperated with a colon ':'."""  */
	char *xdg_sys = getenv("XDG_CONFIG_DIRS");
	if (xdg_sys != NULL) {
		struct vect v;
		VECT_INIT(&v, struct opt_F_t);
		if (parse_colon_separated_list(xdg_sys, &v) < 0
		    || VECT_EACH(&v, struct opt_F_t, NULL,
				 add_dir_component_cb, &dirs) != NULL)
			fprintf(stderr,
				"Error processing $XDG_CONFIG_DIRS '%s': %s\n",
				xdg_sys, strerror(errno));
		VECT_DESTROY(&v, struct opt_F_t, destroy_opt_F_cb, NULL);
	}

	/* SYSCONFDIF is passed via -D when compiling.  */
	const char *sysconfdir = SYSCONFDIR;
	if (sysconfdir != NULL)
		add_dir(&dirs, sysconfdir, "");

	if (VECT_PUSHBACK(&dirs, &delim) < 0)
		goto fail;

	goto again;
}
