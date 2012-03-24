/*
 * This file is part of ltrace.
 * Copyright (C) 2012 Petr Machata, Red Hat Inc.
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

#ifndef BREAKPOINT_H
#define BREAKPOINT_H

/* XXX This is currently a very weak abstraction.  We would like to
 * much expand this to allow things like breakpoints on SDT probes and
 * such.
 *
 * In particular, we would like to add a tracepoint abstraction.
 * Tracepoint is a traceable feature--e.g. an exact address, a DWARF
 * symbol, an ELF symbol, a PLT entry, or an SDT probe.  Tracepoints
 * are named and the user can configure which of them he wants to
 * enable.  Realized tracepoints enable breakpoints, which are a
 * low-level realization of high-level tracepoint.
 *
 * Tracepoints are provided by the main binary as well as by any
 * opened libraries: every time an ELF file is mapped into the address
 * space, a new set of tracepoints is extracted, and filtered
 * according to user settings.  Those tracepoints that are left are
 * then realized, and the tracing starts.
 *
 * A scheme like this would take care of gradually introducing
 * breakpoints when the library is mapped, and therefore ready, and
 * would avoid certain hacks.  For example on PPC64, we don't actually
 * add breakpoints to PLT.  Instead, we read the PLT (which contains
 * addresses, not code), to figure out where to put the breakpoints.
 * In prelinked code, that address is non-zero, and points to an
 * address that's not yet mapped.  ptrace then fails when we try to
 * add the breakpoint.
 *
 * Ideally, return breakpoints would be just a special kind of
 * tracepoint that has attached some magic.  Or a feature of a
 * tracepoint.  Service breakpoints like the handling of dlopen would
 * be a low-level breakpoint, likely without tracepoint attached.
 *
 * So that's for sometimes.
 */

#include "sysdep.h"
#include "library.h"

struct Process;
struct breakpoint;

struct bp_callbacks {
	void (*on_hit) (struct breakpoint *bp, struct Process *proc);
	void (*on_destroy) (struct breakpoint *bp);
};

struct breakpoint {
	struct bp_callbacks *cbs;
	struct library_symbol *libsym;
	void *addr;
	unsigned char orig_value[BREAKPOINT_LENGTH];
	int enabled;
	struct arch_breakpoint_data arch;
};

/* Call on-hit handler of BP, if any is set.  */
void breakpoint_on_hit(struct breakpoint *bp, struct Process *proc);

/* Call on-destroy handler of BP, if any is set.  */
void breakpoint_on_destroy(struct breakpoint *bp);

/* Initialize a breakpoint structure.  That doesn't actually realize
 * the breakpoint.  The breakpoint is initially assumed to be
 * disabled.  orig_value has to be set separately.  CBS may be
 * NULL.  */
int breakpoint_init(struct breakpoint *bp, struct Process *proc,
		    target_address_t addr, struct library_symbol *libsym,
		    struct bp_callbacks *cbs);

/* This is actually three functions rolled in one:
 *  - breakpoint_init
 *  - proc_insert_breakpoint
 *  - breakpoint_enable
 * XXX I think it should be broken up somehow.  */
struct breakpoint *insert_breakpoint(struct Process *proc, void *addr,
				     struct library_symbol *libsym, int enable);

/* */
void delete_breakpoint(struct Process *proc, void *addr);

/* XXX some of the following belongs to proc.h/proc.c.  */
struct breakpoint *address2bpstruct(struct Process *proc, void *addr);
void enable_all_breakpoints(struct Process *proc);
void disable_all_breakpoints(struct Process *proc);
int breakpoints_init(struct Process *proc, int enable);

#endif /* BREAKPOINT_H */
