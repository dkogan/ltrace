#ifndef DWARF_PROTOTYPES_H
#define DWARF_PROTOTYPES_H

#include <stdbool.h>
#include <elfutils/libdwfl.h>

#include "prototype.h"
#include "library.h"

bool import_DWARF_prototypes(struct library *lib);

#endif /* DWARF_PROTOTYPES_H */
