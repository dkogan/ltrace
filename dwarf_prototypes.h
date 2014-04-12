#pragma once

#include <stdbool.h>
#include <elfutils/libdwfl.h>

#include "prototype.h"
#include "library.h"

bool import_DWARF_prototypes( struct protolib* plib, struct library* lib, Dwfl *dwfl );
