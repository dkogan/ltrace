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

#ifndef ARCH_HAVE_LIBRARY_SYMBOL_DATA
struct arch_library_symbol_data {
};
#endif

#ifndef ARCH_HAVE_LIBRARY_DATA
struct arch_library_data {
};
#endif

#ifndef ARCH_HAVE_PROCESS_DATA
struct arch_process_data {
};
#endif

#endif /* LTRACE_SYSDEP_H */
