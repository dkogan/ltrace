/*
 * This file is part of ltrace.
 * Copyright (C) 2010,2011,2012 Petr Machata
 * Copyright (C) 2004,2008,2009 Juan Cespedes
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

#include <sys/reg.h>
#include <assert.h>
#include <errno.h>
#include <stdlib.h>

#include "backend.h"
#include "debug.h"
#include "proc.h"
#include "ptrace.h"
#include "type.h"

#if (!defined(PTRACE_PEEKUSER) && defined(PTRACE_PEEKUSR))
# define PTRACE_PEEKUSER PTRACE_PEEKUSR
#endif

#if (!defined(PTRACE_POKEUSER) && defined(PTRACE_POKEUSR))
# define PTRACE_POKEUSER PTRACE_POKEUSR
#endif

void
get_arch_dep(struct Process *proc)
{
	long l = ptrace(PTRACE_PEEKUSER, proc->pid, 8 * CS, 0);
	if (l == -1 && errno != 0)
		return;

	if (l == 0x23) {
		proc->mask_32bit = 1;
		proc->personality = 1;
	} else {
		proc->mask_32bit = 0;
		proc->personality = 0;
	}
}

/* Returns 1 if syscall, 2 if sysret, 0 otherwise.
 */
int
syscall_p(struct Process *proc, int status, int *sysnum)
{
	if (WIFSTOPPED(status)
	    && WSTOPSIG(status) == (SIGTRAP | proc->tracesysgood)) {
		struct callstack_element *elem = NULL;
		if (proc->callstack_depth > 0)
			elem = proc->callstack + proc->callstack_depth - 1;

		long int ret = ptrace(PTRACE_PEEKUSER, proc->pid, 8 * ORIG_RAX, 0);
		if (ret == -1) {
			if (errno)
				return -1;
			/* Otherwise, ORIG_RAX == -1 means that the
			 * system call should not be restarted.  In
			 * that case rely on what we have on
			 * stack.  */
			if (elem != NULL && elem->is_syscall)
				ret = elem->c_un.syscall;
		}

		*sysnum = ret;
		debug(DEBUG_FUNCTION, "sysnum=%ld %p %d\n", ret,
		      get_instruction_pointer(proc), errno);
		if (elem != NULL && elem->is_syscall
		    && elem->c_un.syscall == *sysnum)
			return 2;

		if (*sysnum >= 0)
			return 1;
	}
	return 0;
}

size_t
arch_type_sizeof(struct Process *proc, struct arg_type_info *info)
{
	if (proc == NULL || proc->e_machine != EM_386)
		return (size_t)-2;

	switch (info->type) {
	case ARGTYPE_VOID:
	case ARGTYPE_CHAR:
	case ARGTYPE_SHORT:
	case ARGTYPE_USHORT:
	case ARGTYPE_FLOAT:
	case ARGTYPE_DOUBLE:
	case ARGTYPE_ARRAY:
	case ARGTYPE_STRUCT:
		/* Use default value.  */
		return (size_t)-2;

	case ARGTYPE_INT:
	case ARGTYPE_UINT:
	case ARGTYPE_LONG:
	case ARGTYPE_ULONG:
	case ARGTYPE_POINTER:
		return 4;
	}
	abort();
}

size_t
arch_type_alignof(struct Process *proc, struct arg_type_info *info)
{
	if (proc == NULL || proc->e_machine != EM_386)
		return (size_t)-2;

	switch (info->type) {
	case ARGTYPE_ARRAY:
	case ARGTYPE_STRUCT:
		/* Use default value.  */
		return (size_t)-2;

	case ARGTYPE_CHAR:
		return 1;

	case ARGTYPE_SHORT:
	case ARGTYPE_USHORT:
		return 2;

	case ARGTYPE_FLOAT:
	case ARGTYPE_DOUBLE:
	case ARGTYPE_INT:
	case ARGTYPE_UINT:
	case ARGTYPE_LONG:
	case ARGTYPE_ULONG:
	case ARGTYPE_POINTER:
		return 4;

	case ARGTYPE_VOID:
		assert(!"Unexpected i386 alignof type!");
		abort();
	}
	abort();
}
