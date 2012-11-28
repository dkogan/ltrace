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

#ifndef _PROTOTYPE_H_
#define _PROTOTYPE_H_

#include "forward.h"
#include "dict.h"
#include "vect.h"

/* Function prototype.  */
struct prototype {
	/* Vector of struct param.  */
	struct vect params;

	struct arg_type_info *return_info;
	int own_return_info : 1;
};

/* Initialize a prototype PROTO.  The name will be NAME, and the
 * corresponding string will be owned and freed on destroy if
 * OWN_NAME.  */
void prototype_init(struct prototype *proto);

/* Destroy PROTO (but don't free the memory block pointed-to by
 * PROTO).  */
void prototype_destroy(struct prototype *proto);

/* Add new parameter PARAM to PROTO.  The structure contents are
 * copied and PARAM pointer itself is not owned by PROTO.  */
int prototype_push_param(struct prototype *proto, struct param *param);

/* Return number of parameters of prototype.  */
size_t prototype_num_params(struct prototype *proto);

/* Destroy N-th parameter from PROTO.  N shall be smaller than the
 * number of parameters.  */
void prototype_destroy_nth_param(struct prototype *proto, size_t n);

/* Get N-th parameter of PROTO.  N shall be smaller than the number of
 * parameters.  */
struct param *prototype_get_nth_param(struct prototype *proto, size_t n);

/* Iterate through the parameters of PROTO.  See callback.h for notes
 * on iteration interfaces.  */
struct param *prototype_each_param
	(struct prototype *proto, struct param *start_after,
	 enum callback_status (*cb)(struct prototype *, struct param *, void *),
	 void *data);

/* For storing type aliases.  */
struct named_type {
	struct arg_type_info *info;
	int forward : 1;
	int own_type : 1;
};

/* Initialize a named type INFO, which, if OWN_TYPE, is destroyed when
 * named_type_destroy is called.  */
void named_type_init(struct named_type *named,
		     struct arg_type_info *info, int own_type);

void named_type_destroy(struct named_type *named);

/* One prototype library.  */
struct protolib {
	/* Other libraries to look through if the definition is not
	 * found here.  Note that due to the way imports are stored,
	 * there is no way to distinguish where exactly (at which
	 * place of the config file) the import was made.  */
	struct vect imports;

	/* Dictionary of name->struct prototype.  */
	struct dict prototypes;

	/* Dictionary of name->struct named_type.  */
	struct dict named_types;
};

/* Initialize PLIB.  */
void protolib_init(struct protolib *plib);

/* Destroy PLIB.  */
void protolib_destroy(struct protolib *plib);

/* Push IMPORT to PLIB.  Returns 0 on success or a negative value on
 * failure.  In particular, -2 is returned if mutual import is
 * detected.  */
int protolib_add_import(struct protolib *plib, struct protolib *import);

/* Add a prototype PROTO to PLIB.  Returns 0 on success or a negative
 * value on failure.  NAME is owned and released on PLIB destruction
 * if OWN_NAME.  */
int protolib_add_prototype(struct protolib *plib,
			   const char *name, int own_name,
			   struct prototype *proto);

/* Add a named type NAMED to PLIB.  Returns 0 on success or a negative
 * value on failure.  NAME is owned and released on PLIB destruction
 * if OWN_NAME.  NAMED _pointer_ is copied to PLIB.  */
int protolib_add_named_type(struct protolib *plib,
			    const char *name, int own_name,
			    struct named_type *named);

/* Lookup prototype named NAME in PLIB.  If none is found, look
 * recursively in each of the imports.  Returns the corresponding
 * prototype, or NULL if none was found.  */
struct prototype *protolib_lookup_prototype(struct protolib *plib,
					    const char *name);

/* Add a named type NAMED to PLIB.  Returns 0 on success or a negative
 * value on failure.  */
int protolib_add_type(struct protolib *plib, struct named_type *named);

/* Lookup type named NAME in PLIB.  If none is found, look recursively
 * in each of the imports.  Returns the corresponding type, or NULL if
 * none was found.  */
struct named_type *protolib_lookup_type(struct protolib *plib,
					const char *name);

/* A cache of prototype libraries.  Can load prototype libraries on
 * demand.
 *
 * XXX ltrace should open one config per ABI, which maps long, int,
 * etc. to uint32_t etc.  It would also map char to either of
 * {u,}int8_t.  Other protolibs would have this as implicit import.
 * That would mean that the cache needs ABI tagging--each ABI should
 * have a separate prototype cache, because the types will potentially
 * differ between the ABI's.  protolib cache would then naturally be
 * stored in the ABI object, when this is introduced.  */
struct protolib_cache {
	/* Dictionary of filename->protolib.  */
	struct dict *protolibs;
};


/* Single global prototype library.
 * XXX Eventually each struct library should have its own prototype
 * library, so that there is one prototype library per DSO.  */
extern struct protolib g_prototypes;

#endif /* _PROTOTYPE_H_ */
