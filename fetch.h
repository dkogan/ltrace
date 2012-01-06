/*
 * This file is part of ltrace.
 * Copyright (C) 2011,2012 Petr Machata, Red Hat Inc.
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

#ifndef FETCH_H
#define FETCH_H

#include "forward.h"

/* XXX isn't SYSCALL TOF just a different ABI?  Maybe we needed to
 * support variant ABIs all along.  */
enum tof {
	LT_TOF_FUNCTION,	/* A real library function */
	LT_TOF_FUNCTIONR,	/* Return from a real library function */
	LT_TOF_SYSCALL,		/* A syscall */
	LT_TOF_SYSCALLR,	/* Return from a syscall */
};

/* The contents of the structure is defined by the back end.  */
struct fetch_context;

/* Initialize argument fetching.  Returns NULL on failure.  RET_INFO
 * is the return type of the function.  */
struct fetch_context *fetch_arg_init(enum tof type, struct Process *proc,
				     struct arg_type_info *ret_info);

/* Make a clone of context.  */
struct fetch_context *fetch_arg_clone(struct Process *proc,
				      struct fetch_context *context);

/* Load next argument.  The function returns 0 on success or a
 * negative value on failure.  The extracted value is stored in
 * *VALUEP.  */
int fetch_arg_next(struct fetch_context *context, enum tof type,
		   struct Process *proc,
		   struct arg_type_info *info, struct value *valuep);

/* Load return value.  The function returns 0 on success or a negative
 * value on failure.  The extracted value is stored in *VALUEP.  */
int fetch_retval(struct fetch_context *context, enum tof type,
		 struct Process *proc,
		 struct arg_type_info *info, struct value *valuep);

/* Destroy fetch context.  CONTEXT shall be the same memory location
 * that was passed to fetch_arg_next.  */
void fetch_arg_done(struct fetch_context *context);

#endif /* FETCH_H */
