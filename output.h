/*
 * This file is part of ltrace.
 * Copyright (C) 2011 Petr Machata, Red Hat Inc.
 * Copyright (C) 2009 Juan Cespedes
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
#include "fetch.h"

#include "forward.h"

void output_line(struct Process *proc, char *fmt, ...);
void output_left(enum tof type, struct Process *proc,
		 struct library_symbol *libsym);
void output_right(enum tof type, struct Process *proc,
		  struct library_symbol *libsym);

void report_error(char const *file, unsigned line_no, char *fmt, ...);
void report_warning(char const *file, unsigned line_no, char *fmt, ...);
void report_global_error(char *fmt, ...);
