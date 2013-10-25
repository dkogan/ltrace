/*
 * This file is part of ltrace.
 * Copyright (C) 2012, 2013 Petr Machata
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
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "backend.h"
#include "breakpoint.h"
#include "dict.h"
#include "fetch.h"
#include "library.h"
#include "options.h"
#include "prototype.h"
#include "sysdep.h"
#include "type.h"
#include "value.h"
#include "vect.h"

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

static char *g_home_dir = NULL;

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

		if (retp != NULL) {
			if (private)
				*retp = VECT_ELEMENT(&dirs, const char *, 0);
			else
				*retp = VECT_ELEMENT(&dirs, const char *,
						     (size_t)sys_start);
		}

		return 0;
	}

	VECT_INIT(&dirs, char *);

	char *home = getenv("HOME");
	if (home == NULL) {
		struct passwd *pwd = getpwuid(getuid());
		if (pwd != NULL)
			home = pwd->pw_dir;
	}

	size_t home_len = home != NULL ? strlen(home) : 0;

	/* The values coming from getenv and getpwuid may not be
	 * persistent.  */
	if (home != NULL) {
		g_home_dir = strdup(home);
		if (g_home_dir != NULL) {
			home = g_home_dir;
		} else {
			char *tmp = alloca(home_len + 1);
			strcpy(tmp, home);
			home = tmp;
		}
	}

	char *xdg_home = getenv("XDG_CONFIG_HOME");
	if (xdg_home == NULL && home != NULL) {
		xdg_home = alloca(home_len + sizeof "/.config");
		sprintf(xdg_home, "%s/.config", home);
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

	/* PKGDATADIR is passed via -D when compiling.  */
	const char *pkgdatadir = PKGDATADIR;
	if (pkgdatadir != NULL)
		add_dir(&dirs, pkgdatadir, "");

	if (VECT_PUSHBACK(&dirs, &delim) < 0)
		goto fail;

	goto again;
}

int
os_get_ltrace_conf_filenames(struct vect *retp)
{
	char *homepath = NULL;
	char *syspath = NULL;

#define FN ".ltrace.conf"
	if (g_home_dir == NULL)
		os_get_config_dirs(0, NULL);

	if (g_home_dir != NULL) {
		homepath = malloc(strlen(g_home_dir) + 1 + sizeof FN);
		if (homepath == NULL
		    || sprintf(homepath, "%s/%s", g_home_dir, FN) < 0) {
		fail:
			free(syspath);
			free(homepath);
			return -1;
		}
	}

	/* SYSCONFDIR is passed via -D when compiling.  */
	const char *sysconfdir = SYSCONFDIR;
	if (sysconfdir != NULL && *sysconfdir != '\0') {
		/* No +1, we skip the initial period.  */
		syspath = malloc(strlen(sysconfdir) + sizeof FN);
		if (syspath == NULL
		    || sprintf(syspath, "%s/%s", sysconfdir, FN + 1) < 0)
			goto fail;
	}

	if (VECT_PUSHBACK(retp, &homepath) < 0
	    || VECT_PUSHBACK(retp, &syspath) < 0)
		goto fail;

	return 0;
}

static struct prototype *
void_prototype(void)
{
	static struct prototype ret;
	if (ret.return_info == NULL) {
		prototype_init(&ret);
		ret.return_info = type_get_voidptr();
		ret.own_return_info = 0;
	}
	return &ret;
}

int
os_library_symbol_init(struct library_symbol *libsym)
{
	libsym->os = (struct os_library_symbol_data){};
	return 0;
}

void
os_library_symbol_destroy(struct library_symbol *libsym)
{
}

int
os_library_symbol_clone(struct library_symbol *retp,
			struct library_symbol *libsym)
{
	retp->os = libsym->os;
	return 0;
}

enum plt_status
os_elf_add_func_entry(struct process *proc, struct ltelf *lte,
		      const GElf_Sym *sym,
		      arch_addr_t addr, const char *name,
		      struct library_symbol **ret)
{
	if (GELF_ST_TYPE(sym->st_info) == STT_FUNC)
		return PLT_DEFAULT;

	bool ifunc = false;
#ifdef STT_GNU_IFUNC
	ifunc = GELF_ST_TYPE(sym->st_info) == STT_GNU_IFUNC;
#endif

	if (ifunc) {
#define S ".IFUNC"
		char *tmp_name = malloc(strlen(name) + sizeof S);
		struct library_symbol *tmp = malloc(sizeof *tmp);
		if (tmp_name == NULL || tmp == NULL) {
		fail:
			free(tmp_name);
			free(tmp);
			return PLT_FAIL;
		}
		sprintf(tmp_name, "%s%s", name, S);
#undef S

		if (library_symbol_init(tmp, addr, tmp_name, 1,
					LS_TOPLT_NONE) < 0)
			goto fail;
		tmp->proto = void_prototype();
		tmp->os.is_ifunc = 1;

		*ret = tmp;
		return PLT_OK;
	}

	*ret = NULL;
	return PLT_OK;
}

static enum callback_status
libsym_at_address(struct library_symbol *libsym, void *addrp)
{
	arch_addr_t addr = *(arch_addr_t *)addrp;
	return CBS_STOP_IF(addr == libsym->enter_addr);
}

static void
ifunc_ret_hit(struct breakpoint *bp, struct process *proc)
{
	struct fetch_context *fetch = fetch_arg_init(LT_TOF_FUNCTION, proc,
						     type_get_voidptr());
	if (fetch == NULL)
		return;

	struct breakpoint *nbp = NULL;
	int own_libsym = 0;

	struct value value;
	value_init(&value, proc, NULL, type_get_voidptr(), 0);
	size_t sz = value_size(&value, NULL);
	union {
		uint64_t u64;
		uint32_t u32;
		arch_addr_t a;
	} u;

	if (fetch_retval(fetch, LT_TOF_FUNCTIONR, proc,
			 value.type, &value) < 0
	    || sz > 8 /* Captures failure as well.  */
	    || value_extract_buf(&value, (void *) &u, NULL) < 0) {
	fail:
		fprintf(stderr,
			"Couldn't trace the function "
			"indicated by IFUNC resolver.\n");
		goto done;
	}

	assert(sz == 4 || sz == 8);
	/* XXX double casts below:  */
	if (sz == 4)
		u.a = (arch_addr_t)(uintptr_t)u.u32;
	else
		u.a = (arch_addr_t)(uintptr_t)u.u64;
	if (arch_translate_address_dyn(proc, u.a, &u.a) < 0) {
		fprintf(stderr, "Couldn't OPD-translate the address returned"
			" by the IFUNC resolver.\n");
		goto done;
	}

	assert(bp->os.ret_libsym != NULL);

	struct library *lib = bp->os.ret_libsym->lib;
	assert(lib != NULL);

	/* Look if we already have a symbol with this address.
	 * Otherwise create a new one.  */
	struct library_symbol *libsym
		= library_each_symbol(lib, NULL, libsym_at_address, &u.a);
	if (libsym == NULL) {
		libsym = malloc(sizeof *libsym);
		char *name = strdup(bp->os.ret_libsym->name);

		if (libsym == NULL
		    || name == NULL
		    || library_symbol_init(libsym, u.a, name, 1,
					   LS_TOPLT_NONE) < 0) {
			free(libsym);
			free(name);
			goto fail;
		}

		/* Snip the .IFUNC token.  */
		*strrchr(name, '.') = 0;

		own_libsym = 1;
		library_add_symbol(lib, libsym);
	}

	nbp = malloc(sizeof *bp);
	if (nbp == NULL || breakpoint_init(nbp, proc, u.a, libsym) < 0)
		goto fail;

	/* If there already is a breakpoint at that address, that is
	 * suspicious, but whatever.  */
	struct breakpoint *pre_bp = insert_breakpoint(proc, nbp);
	if (pre_bp == NULL)
		goto fail;
	if (pre_bp == nbp) {
		/* PROC took our breakpoint, so these resources are
		 * not ours anymore.  */
		nbp = NULL;
		own_libsym = 0;
	}

done:
	free(nbp);
	if (own_libsym) {
		library_symbol_destroy(libsym);
		free(libsym);
	}
	fetch_arg_done(fetch);
}

static int
create_ifunc_ret_bp(struct breakpoint **ret,
		    struct breakpoint *bp, struct process *proc)
{
	*ret = create_default_return_bp(proc);
	if (*ret == NULL)
		return -1;
	static struct bp_callbacks cbs = {
		.on_hit = ifunc_ret_hit,
	};
	breakpoint_set_callbacks(*ret, &cbs);

	(*ret)->os.ret_libsym = bp->libsym;

	return 0;
}

int
os_breakpoint_init(struct process *proc, struct breakpoint *bp)
{
	if (bp->libsym != NULL && bp->libsym->os.is_ifunc) {
		static struct bp_callbacks cbs = {
			.get_return_bp = create_ifunc_ret_bp,
		};
		breakpoint_set_callbacks(bp, &cbs);
	}
	return 0;
}

void
os_breakpoint_destroy(struct breakpoint *bp)
{
}

int
os_breakpoint_clone(struct breakpoint *retp, struct breakpoint *bp)
{
	return 0;
}
