#ifndef LTRACE_SYSDEP_H
#define LTRACE_SYSDEP_H

#include <arch.h>

#ifndef ARCH_HAVE_LTELF_DATA
struct arch_ltelf_data {
};
#endif

#ifndef ARCH_HAVE_BREAKPOINT_DATA
struct arch_breakpoint_data {
};
#endif

#endif /* LTRACE_SYSDEP_H */
