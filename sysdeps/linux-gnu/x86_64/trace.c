/*
 * This file is part of ltrace.
 * Copyright (C) 2010,2011 Petr Machata
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
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "ptrace.h"
#include "proc.h"
#include "value.h"
#include "expr.h"
#include "type.h"

#if (!defined(PTRACE_PEEKUSER) && defined(PTRACE_PEEKUSR))
# define PTRACE_PEEKUSER PTRACE_PEEKUSR
#endif

#if (!defined(PTRACE_POKEUSER) && defined(PTRACE_POKEUSR))
# define PTRACE_POKEUSER PTRACE_POKEUSR
#endif

void
get_arch_dep(Process *proc)
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

enum arg_class {
	CLASS_INTEGER,
	CLASS_SSE,
	CLASS_NO,
	CLASS_MEMORY,
	CLASS_X87,
};

enum reg_pool {
	POOL_FUNCALL,
	POOL_SYSCALL,
	/* A common pool for system call and function call return is
	 * enough, the ABI is similar enough.  */
	POOL_RETVAL,
};

struct fetch_context
{
	struct user_regs_struct iregs;
	struct user_fpregs_struct fpregs;
	void *stack_pointer;
	size_t ireg;	/* Used-up integer registers.  */
	size_t freg;	/* Used-up floating registers.  */

	union {
		struct {
			/* Storage classes for return type.  We need
			 * to compute them anyway, so let's keep them
			 * around.  */
			enum arg_class ret_classes[2];
			ssize_t num_ret_classes;
		} x86_64;
		struct {
			struct value retval;
		} i386;
	} u;
};

static int
contains_unaligned_fields(struct arg_type_info *info)
{
	/* XXX currently we don't support structure alignment.  */
	return 0;
}

static int
has_nontrivial_ctor_dtor(struct arg_type_info *info)
{
	/* XXX another unsupported aspect of type info.  We might call
	 * these types "class" instead of "struct" in the config
	 * file.  */
	return 0;
}

static void
copy_int_register(struct fetch_context *context,
		  struct value *valuep, unsigned long val, size_t offset)
{
	if (valuep != NULL) {
		unsigned char *buf = value_get_raw_data(valuep);
		memcpy(buf + offset, &val, sizeof(val));
	}
	context->ireg++;
}

static void
copy_sse_register(struct fetch_context *context, struct value *valuep,
		  int half, size_t sz, size_t offset)
{
	union {
		uint32_t sse[4];
		long halves[2];
	} u;
	size_t off = 4 * context->freg++;
	memcpy(u.sse, context->fpregs.xmm_space + off, sizeof(u.sse));

	if (valuep != NULL) {
		unsigned char *buf = value_get_raw_data(valuep);
		memcpy(buf + offset, u.halves + half, sz);
	}
}

static void
allocate_stack_slot(struct fetch_context *context,
		    struct value *valuep, size_t sz, size_t offset,
		    size_t archw)
{
	size_t a = type_alignof(valuep->inferior, valuep->type);
	if (a < archw)
		a = archw;
	context->stack_pointer
		= (void *)align((unsigned long)context->stack_pointer, a);

	if (valuep != NULL) {
		valuep->where = VAL_LOC_INFERIOR;
		valuep->u.address = context->stack_pointer;
	}
	context->stack_pointer += sz;
}

static enum arg_class
allocate_x87(struct fetch_context *context, struct value *valuep,
	     size_t sz, size_t offset, enum reg_pool pool, size_t archw)
{
	/* Both i386 and x86_64 ABI only ever really use x87 registers
	 * to return values.  Otherwise, the parameter is treated as
	 * if it were CLASS_MEMORY.  On x86_64 x87 registers are only
	 * used for returning long double values, which we currently
	 * don't support.  */

	if (pool != POOL_RETVAL) {
		allocate_stack_slot(context, valuep, sz, offset, archw);
		return CLASS_MEMORY;

	}

	/* If the class is X87, the value is returned on the X87 stack
	 * in %st0 as 80-bit x87 number.
	 *
	 * If the class is X87UP, the value is returned together with
	 * the previous X87 value in %st0.
	 *
	 * If the class is COMPLEX_X87, the real part of the value is
	 * returned in %st0 and the imaginary part in %st1.  */

	if (valuep != NULL) {
		union {
			long double ld;
			double d;
			float f;
			char buf[0];
		} u;

		/* The x87 floating point value is in long double
		 * format, so we need to convert in to the right type.
		 * Alternatively we might just leave it as is and
		 * smuggle the long double type into the value (via
		 * value_set_type), but for that we first need to
		 * support long double in the first place.  */

		unsigned int *reg = &context->fpregs.st_space[0];
		memcpy(&u.ld, reg, sizeof(u));
		if (valuep->type->type == ARGTYPE_FLOAT)
			u.f = (float)u.ld;
		else if (valuep->type->type == ARGTYPE_DOUBLE)
			u.d = (double)u.ld;
		else
			assert(!"Unexpected floating type!"), abort();

		unsigned char *buf = value_get_raw_data(valuep);
		memcpy(buf + offset, u.buf, sz);
	}
	return CLASS_X87;
}

static enum arg_class
allocate_integer(struct fetch_context *context, struct value *valuep,
		 size_t sz, size_t offset, enum reg_pool pool)
{
#define HANDLE(NUM, WHICH)						\
	case NUM:							\
		copy_int_register(context, valuep,			\
				  context->iregs.WHICH, offset);	\
		return CLASS_INTEGER

	switch (pool) {
	case POOL_FUNCALL:
		switch (context->ireg) {
			HANDLE(0, rdi);
			HANDLE(1, rsi);
			HANDLE(2, rdx);
			HANDLE(3, rcx);
			HANDLE(4, r8);
			HANDLE(5, r9);
		default:
			allocate_stack_slot(context, valuep, sz, offset, 8);
			return CLASS_MEMORY;
		}

	case POOL_SYSCALL:
		switch (context->ireg) {
			HANDLE(0, rdi);
			HANDLE(1, rsi);
			HANDLE(2, rdx);
			HANDLE(3, r10);
			HANDLE(4, r8);
			HANDLE(5, r9);
		default:
			assert(!"More than six syscall arguments???");
			abort();
		}

	case POOL_RETVAL:
		switch (context->ireg) {
			HANDLE(0, rax);
			HANDLE(1, rdx);
		default:
			assert(!"More than two return value classes???");
			abort();
		}
	}

	abort();

#undef HANDLE
}

static enum arg_class
allocate_sse(struct fetch_context *context, struct value *valuep,
	     size_t sz, size_t offset, enum reg_pool pool)
{
	size_t num_regs = 0;
	switch (pool) {
	case POOL_FUNCALL:
		num_regs = 8;
	case POOL_SYSCALL:
		break;
	case POOL_RETVAL:
		num_regs = 2;
	}

	if (context->freg >= num_regs) {
		/* We shouldn't see overflow for RETVAL or SYSCALL
		 * pool.  */
		assert(pool == POOL_FUNCALL);
		allocate_stack_slot(context, valuep, sz, offset, 8);
		return CLASS_MEMORY;
	} else {
		copy_sse_register(context, valuep, 0, sz, offset);
		return CLASS_SSE;
	}
}

/* This allocates registers or stack space for another argument of the
 * class CLS.  */
static enum arg_class
allocate_class(enum arg_class cls, struct fetch_context *context,
	       struct value *valuep, size_t sz, size_t offset, enum reg_pool pool)
{
	switch (cls) {
	case CLASS_MEMORY:
		allocate_stack_slot(context, valuep, sz, offset, 8);
	case CLASS_NO:
		return cls;

	case CLASS_INTEGER:
		return allocate_integer(context, valuep, sz, offset, pool);

	case CLASS_SSE:
		return allocate_sse(context, valuep, sz, offset, pool);

	case CLASS_X87:
		return allocate_x87(context, valuep, sz, offset, pool, 8);
	}
	abort();
}

static ssize_t
classify(Process *proc, struct fetch_context *context,
	 struct arg_type_info *info, struct value *valuep, enum arg_class classes[],
	 size_t sz, size_t eightbytes);

/* This classifies one eightbyte part of an array or struct.  */
static ssize_t
classify_eightbyte(Process *proc, struct fetch_context *context,
		   struct arg_type_info *info, struct value *valuep,
		   enum arg_class *classp, size_t start, size_t end,
		   struct arg_type_info *(* getter)(struct arg_type_info *, size_t))
{
	size_t i;
	enum arg_class cls = CLASS_NO;
	for (i = start; i < end; ++i) {
		enum arg_class cls2;
		struct arg_type_info *info2 = getter(info, i);
		size_t sz = type_sizeof(proc, info2);
		if (sz == (size_t)-1)
			return -1;
		if (classify(proc, context, info2, valuep, &cls2, sz, 1) < 0)
			return -1;

		if (cls == CLASS_NO)
			cls = cls2;
		else if (cls2 == CLASS_NO || cls == cls2)
			;
		else if (cls == CLASS_MEMORY || cls2 == CLASS_MEMORY)
			cls = CLASS_MEMORY;
		else if (cls == CLASS_INTEGER || cls2 == CLASS_INTEGER)
			cls = CLASS_INTEGER;
		else
			cls = CLASS_SSE;
	}

	*classp = cls;
	return 1;
}

/* This classifies small arrays and structs.  */
static ssize_t
classify_eightbytes(Process *proc, struct fetch_context *context,
		    struct arg_type_info *info, struct value *valuep,
		    enum arg_class classes[], size_t elements,
		    size_t eightbytes,
		    struct arg_type_info *(* getter)(struct arg_type_info *, size_t))
{
	if (eightbytes > 1) {
		/* Where the second eightbyte starts.  Number of the
		 * first element in the structure that belongs to the
		 * second eightbyte.  */
		size_t start_2nd = 0;
		size_t i;
		for (i = 0; i < elements; ++i)
			if (type_offsetof(proc, info, i) >= 8) {
				start_2nd = i;
				break;
			}

		enum arg_class cls1, cls2;
		if (classify_eightbyte(proc, context, info, valuep, &cls1,
				       0, start_2nd, getter) < 0
		    || classify_eightbyte(proc, context, info, valuep, &cls2,
					  start_2nd, elements, getter) < 0)
			return -1;

		if (cls1 == CLASS_MEMORY || cls2 == CLASS_MEMORY) {
			classes[0] = CLASS_MEMORY;
			return 1;
		}

		classes[0] = cls1;
		classes[1] = cls2;
		return 2;
	}

	return classify_eightbyte(proc, context, info, valuep, classes,
				  0, elements, getter);
}

static struct arg_type_info *
get_array_field(struct arg_type_info *info, size_t emt)
{
	return info->u.array_info.elt_type;
}

static ssize_t
classify(Process *proc, struct fetch_context *context,
	 struct arg_type_info *info, struct value *valuep, enum arg_class classes[],
	 size_t sz, size_t eightbytes)
{
	switch (info->type) {
	case ARGTYPE_VOID:
		return 0;

	case ARGTYPE_CHAR:
	case ARGTYPE_SHORT:
	case ARGTYPE_USHORT:
	case ARGTYPE_INT:
	case ARGTYPE_UINT:
	case ARGTYPE_LONG:
	case ARGTYPE_ULONG:
	case ARGTYPE_ENUM:

	case ARGTYPE_POINTER:
		/* and LONGLONG */
		/* CLASS_INTEGER */
		classes[0] = CLASS_INTEGER;
		return 1;

	case ARGTYPE_FLOAT:
	case ARGTYPE_DOUBLE:
		/* and DECIMAL, and _m64 */
		classes[0] = CLASS_SSE;
		return 1;

	case ARGTYPE_ARRAY:
		/* N.B. this cannot be top-level array, those decay to
		 * pointers.  Therefore, it must be inside structure
		 * that's at most 2 eightbytes long.  */

		/* Structures with flexible array members can't be
		 * passed by value.  */
		assert(expr_is_compile_constant(info->u.array_info.length));

		long l;
		if (expr_eval_constant(info->u.array_info.length, &l) < 0)
			return -1;

		return classify_eightbytes(proc, context, info, valuep, classes,
					   (size_t)l, eightbytes,
					   get_array_field);

	case ARGTYPE_STRUCT:
		/* N.B. "big" structs are dealt with in the
		 * caller.  */

		return classify_eightbytes(proc, context, info, valuep, classes,
					   type_struct_size(info),
					   eightbytes, type_struct_get);
	}
	abort();
}

static ssize_t
pass_by_reference(struct value *valuep, enum arg_class classes[])
{
	if (valuep != NULL) {
		struct arg_type_info *new_info
			= calloc(sizeof(*new_info), 1);
		if (new_info == NULL)
			return -1;

		int own;
		struct arg_type_info *orig;
		value_take_type(valuep, &orig, &own);
		type_init_pointer(new_info, orig, own);
		new_info->lens = orig->lens;
		value_set_type(valuep, new_info, 1);
	}
	classes[0] = CLASS_INTEGER;
	return 1;
}

static ssize_t
classify_argument(Process *proc, struct fetch_context *context,
		  struct arg_type_info *info, struct value *valuep,
		  enum arg_class classes[], size_t *sizep)
{
	size_t sz = type_sizeof(proc, info);
	if (sz == (size_t)-1)
		return -1;
	*sizep = sz;

	size_t eightbytes = (sz + 7) / 8;  /* Round up.  */

	/* Arrays decay into pointers.  */
	assert(info->type != ARGTYPE_ARRAY);

	if (info->type == ARGTYPE_STRUCT) {
		if (eightbytes > 2 || contains_unaligned_fields(info)) {
			classes[0] = CLASS_MEMORY;
			return 1;
		}

		if (has_nontrivial_ctor_dtor(info))
			return pass_by_reference(valuep, classes);
	}

	return classify(proc, context, info, valuep, classes, sz, eightbytes);
}

static int
fetch_register_banks(Process *proc, struct fetch_context *context, int floating)
{
	if (ptrace(PTRACE_GETREGS, proc->pid, 0, &context->iregs) < 0)
		return -1;
	context->ireg = 0;

	if (floating) {
		if (ptrace(PTRACE_GETFPREGS, proc->pid,
			   0, &context->fpregs) < 0)
			return -1;
		context->freg = 0;
	} else {
		context->freg = -1;
	}

	return 0;
}

static int
arch_fetch_arg_next_32(struct fetch_context *context, enum tof type,
		       Process *proc, struct arg_type_info *info,
		       struct value *valuep)
{
	size_t sz = type_sizeof(proc, info);
	if (sz == (size_t)-1)
		return -1;

	allocate_stack_slot(context, valuep, sz, 0, 4);

	return 0;
}

static int
arch_fetch_retval_32(struct fetch_context *context, enum tof type,
		     Process *proc, struct arg_type_info *info,
		     struct value *valuep)
{
	if (fetch_register_banks(proc, context, type == LT_TOF_FUNCTIONR) < 0)
		return -1;

	struct value *retval = &context->u.i386.retval;
	if (retval->type != NULL) {
		/* Struct return value was extracted when in fetch
		 * init.  */
		memcpy(valuep, &context->u.i386.retval, sizeof(*valuep));
		return 0;
	}

	size_t sz = type_sizeof(proc, info);
	if (sz == (size_t)-1)
		return -1;
	if (value_reserve(valuep, sz) == NULL)
		return -1;

	switch (info->type) {
		enum arg_class cls;
	case ARGTYPE_VOID:
		return 0;

	case ARGTYPE_INT:
	case ARGTYPE_UINT:
	case ARGTYPE_LONG:
	case ARGTYPE_ULONG:
	case ARGTYPE_CHAR:
	case ARGTYPE_SHORT:
	case ARGTYPE_USHORT:
	case ARGTYPE_ENUM:
	case ARGTYPE_POINTER:
		cls = allocate_integer(context, valuep, sz, 0, POOL_RETVAL);
		assert(cls == CLASS_INTEGER);
		return 0;

	case ARGTYPE_FLOAT:
	case ARGTYPE_DOUBLE:
		cls = allocate_x87(context, valuep, sz, 0, POOL_RETVAL, 4);
		assert(cls == CLASS_X87);
		return 0;

	case ARGTYPE_ARRAY:
	case ARGTYPE_STRUCT: /* handled above*/
		assert(!"Unexpected i386 retval type!");
		abort();
	}

	abort();
}

struct fetch_context *
arch_fetch_arg_init_32(struct fetch_context *context,
		       enum tof type, Process *proc,
		       struct arg_type_info *ret_info)
{
	context->stack_pointer = (void *)(context->iregs.rsp + 4);

	size_t sz = type_sizeof(proc, ret_info);
	if (sz == (size_t)-1)
		return NULL;

	struct value *retval = &context->u.i386.retval;
	if (ret_info->type == ARGTYPE_STRUCT) {
		value_init(retval, proc, NULL, ret_info, 0);

		enum arg_class dummy[2];
		if (pass_by_reference(retval, dummy) < 0)
			return NULL;
		allocate_stack_slot(context, retval, 4, 0, 4);

	} else {
		value_init_detached(retval, NULL, NULL, 0);
	}

	return context;
}

struct fetch_context *
arch_fetch_arg_init_64(struct fetch_context *ctx, enum tof type, Process *proc,
		       struct arg_type_info *ret_info)
{
	/* The first stack slot holds a return address.  */
	ctx->stack_pointer = (void *)(ctx->iregs.rsp + 8);

	size_t size;
	ctx->u.x86_64.num_ret_classes
		= classify_argument(proc, ctx, ret_info, NULL,
				    ctx->u.x86_64.ret_classes, &size);
	if (ctx->u.x86_64.num_ret_classes == -1)
		return NULL;

	/* If the class is MEMORY, then the first argument is a hidden
	 * pointer to the allocated storage.  */
	if (ctx->u.x86_64.num_ret_classes > 0
	    && ctx->u.x86_64.ret_classes[0] == CLASS_MEMORY) {
		/* MEMORY should be the sole class.  */
		assert(ctx->u.x86_64.num_ret_classes == 1);
		allocate_integer(ctx, NULL, size, 0, POOL_FUNCALL);
	}

	return ctx;
}

struct fetch_context *
arch_fetch_arg_init(enum tof type, Process *proc,
		    struct arg_type_info *ret_info)
{
	struct fetch_context *ctx = malloc(sizeof(*ctx));
	if (ctx == NULL)
		return NULL;

	assert(type != LT_TOF_FUNCTIONR
	       && type != LT_TOF_SYSCALLR);
	if (fetch_register_banks(proc, ctx, type == LT_TOF_FUNCTION) < 0) {
	fail:
		free(ctx);
		return NULL;
	}

	struct fetch_context *ret;
	if (proc->mask_32bit)
		ret = arch_fetch_arg_init_32(ctx, type, proc, ret_info);
	else
		ret = arch_fetch_arg_init_64(ctx, type, proc, ret_info);
	if (ret == NULL)
		goto fail;
	return ret;
}

struct fetch_context *
arch_fetch_arg_clone(Process *proc, struct fetch_context *context)
{
	struct fetch_context *ret = malloc(sizeof(*ret));
	if (ret == NULL)
		return NULL;
	return memcpy(ret, context, sizeof(*ret));
}

static int
arch_fetch_pool_arg_next(struct fetch_context *context, enum tof type,
			 Process *proc, struct arg_type_info *info,
			 struct value *valuep, enum reg_pool pool)
{
	enum arg_class classes[2];
	size_t sz, sz1;
	ssize_t i;
	ssize_t nclasses = classify_argument(proc, context, info, valuep,
					     classes, &sz);
	if (nclasses == -1)
		return -1;
	if (value_reserve(valuep, sz) == NULL)
		return -1;

	/* If there are no registers available for any eightbyte of an
	   argument, the whole argument is passed on the stack.  If
	   registers have already been assigned for some eightbytes of
	   such an argument, the assignments get reverted.  */
	struct fetch_context tmp_context = *context;
	int revert;
	if (nclasses == 1) {
		revert = allocate_class(classes[0], &tmp_context,
					valuep, sz, 0, pool) != classes[0];
	} else {
		revert = 0;
		for (i = 0; i < nclasses; ++i) {
			sz1 = (size_t)(8 * (i + 1)) > sz ? sz - 8 * i : 8;
			if (allocate_class(classes[i], &tmp_context, valuep,
					   sz1, 8 * i, pool) != classes[i])
				revert = 1;
		}
	}

	if (nclasses > 1 && revert)
		allocate_class(CLASS_MEMORY, context, valuep, sz, 0, pool);
	else
		*context = tmp_context; /* commit */

	return 0;
}

int
arch_fetch_fun_retval(struct fetch_context *context, enum tof type,
		      Process *proc, struct arg_type_info *info,
		      struct value *valuep)
{
	assert(type != LT_TOF_FUNCTION
	       && type != LT_TOF_SYSCALL);
	if (value_reserve(valuep, 8 * context->u.x86_64.num_ret_classes) == NULL
	    || fetch_register_banks(proc, context,
				    type == LT_TOF_FUNCTIONR) < 0)
		return -1;

	if (context->u.x86_64.num_ret_classes == 1
	    && context->u.x86_64.ret_classes[0] == CLASS_MEMORY)
		pass_by_reference(valuep, context->u.x86_64.ret_classes);

	size_t sz = type_sizeof(proc, valuep->type);
	if (sz == (size_t)-1)
		return -1;

	ssize_t i;
	size_t sz1 = context->u.x86_64.num_ret_classes == 1 ? sz : 8;
	for (i = 0; i < context->u.x86_64.num_ret_classes; ++i) {
		enum arg_class cls
			= allocate_class(context->u.x86_64.ret_classes[i],
					 context, valuep, sz1,
					 8 * i, POOL_RETVAL);
		assert(cls == context->u.x86_64.ret_classes[i]);
	}
	return 0;
}

int
arch_fetch_arg_next(struct fetch_context *context, enum tof type,
		    Process *proc, struct arg_type_info *info, struct value *valuep)
{
	if (proc->mask_32bit)
		return arch_fetch_arg_next_32(context, type, proc,
					      info, valuep);

	switch (type) {
	case LT_TOF_FUNCTION:
	case LT_TOF_FUNCTIONR:
		return arch_fetch_pool_arg_next(context, type, proc,
						info, valuep, POOL_FUNCALL);

	case LT_TOF_SYSCALL:
	case LT_TOF_SYSCALLR:
		return arch_fetch_pool_arg_next(context, type, proc,
						info, valuep, POOL_SYSCALL);
	}

	abort();
}

int
arch_fetch_retval(struct fetch_context *context, enum tof type,
		  Process *proc, struct arg_type_info *info, struct value *valuep)
{
	if (proc->mask_32bit)
		return arch_fetch_retval_32(context, type, proc, info, valuep);

	return arch_fetch_fun_retval(context, type, proc, info, valuep);
}

void
arch_fetch_arg_done(struct fetch_context *context)
{
	if (context != NULL)
		free(context);
}

size_t
arch_type_sizeof(Process *proc, struct arg_type_info *info)
{
	if (proc == NULL || !proc->mask_32bit)
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
	case ARGTYPE_ENUM:
		return 4;
	}
	abort();
}

size_t
arch_type_alignof(Process *proc, struct arg_type_info *info)
{
	if (proc == NULL || !proc->mask_32bit)
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
	case ARGTYPE_ENUM:
		return 4;

	case ARGTYPE_VOID:
		assert(!"Unexpected i386 alignof type!");
		abort();
	}
	abort();
}
