/*
 * This file is part of ltrace.
 * Copyright (C) 2012 Petr Machata, Red Hat Inc.
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

#include <asm/ptrace.h>
#include <sys/ptrace.h>
#include <sys/ucontext.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "backend.h"
#include "fetch.h"
#include "type.h"
#include "proc.h"
#include "value.h"

struct fetch_context {
	struct user_regs_struct regs;
	arch_addr_t stack_pointer;
	int greg;
	int freg;
};

static int
fp_equivalent(struct arg_type_info *info)
{
	switch (info->type) {
	case ARGTYPE_VOID:
	case ARGTYPE_INT:
	case ARGTYPE_UINT:
	case ARGTYPE_LONG:
	case ARGTYPE_ULONG:
	case ARGTYPE_CHAR:
	case ARGTYPE_SHORT:
	case ARGTYPE_USHORT:
	case ARGTYPE_ARRAY:
	case ARGTYPE_POINTER:
		return 0;

	case ARGTYPE_FLOAT:
	case ARGTYPE_DOUBLE:
		return 1;

	case ARGTYPE_STRUCT:
		if (type_struct_size(info) != 1)
			return 0;
		return fp_equivalent(type_element(info, 0));
	}
	assert(info->type != info->type);
	abort();
}

static int
fetch_register_banks(struct Process *proc, struct fetch_context *ctx)
{
	ptrace_area parea;
	parea.len = sizeof(ctx->regs);
	parea.process_addr = (uintptr_t)&ctx->regs;
	parea.kernel_addr = 0;
	if (ptrace(PTRACE_PEEKUSR_AREA, proc->pid, &parea, NULL) < 0) {
		fprintf(stderr, "fetch_register_banks GPR: %s\n",
			strerror(errno));
		return -1;
	}
	return 0;
}

static int
fetch_context_init(struct Process *proc, struct fetch_context *context)
{
	context->greg = 2;
	context->freg = 0;
	return fetch_register_banks(proc, context);
}

struct fetch_context *
arch_fetch_arg_init(enum tof type, struct Process *proc,
		    struct arg_type_info *ret_info)
{
	struct fetch_context *context = malloc(sizeof(*context));
	if (context == NULL
	    || fetch_context_init(proc, context) < 0) {
		fprintf(stderr, "arch_fetch_arg_init: %s\n",
			strerror(errno));
		free(context);
		return NULL;
	}

	context->stack_pointer = get_stack_pointer(proc) + 160;
	if (ret_info->type == ARGTYPE_STRUCT)
		++context->greg;

	return context;
}

struct fetch_context *
arch_fetch_arg_clone(struct Process *proc,
		     struct fetch_context *context)
{
	struct fetch_context *clone = malloc(sizeof(*context));
	if (clone == NULL)
		return NULL;
	*clone = *context;
	return clone;
}

static int
allocate_stack_slot(struct fetch_context *ctx, struct Process *proc,
		    struct arg_type_info *info, struct value *valuep)
{
	size_t sz = type_sizeof(proc, info);
	if (sz == (size_t)-1)
		return -1;
	size_t a = type_alignof(proc, info);
	if (a < 8)
		a = 8;
	size_t off = sz < a ? a - sz : 0;

	/* XXX Remove the two double casts when arch_addr_t
	 * becomes integral type.  */
	uintptr_t tmp = align((uint64_t)(uintptr_t)ctx->stack_pointer, a);
	ctx->stack_pointer = (arch_addr_t)tmp;

	valuep->where = VAL_LOC_INFERIOR;
	valuep->u.address = ctx->stack_pointer + off;

	ctx->stack_pointer += sz;
	return 0;
}

static void
copy_gpr(struct fetch_context *ctx, struct value *valuep, int regno)
{
	value_set_word(valuep, ctx->regs.gprs[regno]);
}

static int
allocate_gpr(struct fetch_context *ctx, struct Process *proc,
	     struct arg_type_info *info, struct value *valuep)
{
	if (ctx->greg > 6)
		return allocate_stack_slot(ctx, proc, info, valuep);

	copy_gpr(ctx, valuep, ctx->greg++);
	return 0;
}

static int
allocate_fpr(struct fetch_context *ctx, struct Process *proc,
	     struct arg_type_info *info, struct value *valuep)
{
	if (ctx->freg > 6)
		return allocate_stack_slot(ctx, proc, info, valuep);

	size_t sz = type_sizeof(proc, info);
	if (sz == (size_t)-1)
		return -1;

	if (value_reserve(valuep, sz) == NULL)
		return -1;

	memcpy(value_get_raw_data(valuep),
	       &ctx->regs.fp_regs.fprs[ctx->freg], sz);
	ctx->freg += 2;

	return 0;
}

int
arch_fetch_arg_next(struct fetch_context *ctx, enum tof type,
		    struct Process *proc,
		    struct arg_type_info *info, struct value *valuep)
{
	switch (info->type) {
	case ARGTYPE_VOID:
		value_set_word(valuep, 0);
		return 0;

	case ARGTYPE_STRUCT:
		if (fp_equivalent(info))
			/* fall through */

	case ARGTYPE_FLOAT:
	case ARGTYPE_DOUBLE:
			return allocate_fpr(ctx, proc, info, valuep);

		if (type_sizeof(proc, info) < 8)
			return allocate_gpr(ctx, proc, info,valuep);
		/* fall through */

	case ARGTYPE_ARRAY:
		if (value_pass_by_reference(valuep) < 0)
			return -1;
		/* fall through */

	case ARGTYPE_INT:
	case ARGTYPE_UINT:
	case ARGTYPE_LONG:
	case ARGTYPE_ULONG:
	case ARGTYPE_CHAR:
	case ARGTYPE_SHORT:
	case ARGTYPE_USHORT:
	case ARGTYPE_POINTER:
		return allocate_gpr(ctx, proc, info, valuep);
	}
	return -1;
}

int
arch_fetch_retval(struct fetch_context *ctx, enum tof type,
		  struct Process *proc, struct arg_type_info *info,
		  struct value *valuep)
{
	if (info->type == ARGTYPE_STRUCT) {
		if (value_pass_by_reference(valuep) < 0)
			return -1;
		copy_gpr(ctx, valuep, 2);
		return 0;
	}

	if (fetch_context_init(proc, ctx) < 0)
		return -1;
	return arch_fetch_arg_next(ctx, type, proc, info, valuep);
}

void
arch_fetch_arg_done(struct fetch_context *context)
{
	free(context);
}
