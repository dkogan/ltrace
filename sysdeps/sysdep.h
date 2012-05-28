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

#ifndef ARCH_HAVE_ADDRESS_TYPES
/* We should in general be able to trace 64-bit processes with 32-bit
 * ltrace.  (At least PPC has several PTRACE requests related to
 * tracing 64-on-32, so presumably it should be possible.)  But ltrace
 * is currently hopelessly infested with using void* for host address.
 * So keep with it, for now.  */
typedef void *arch_addr_t;
#endif

#endif /* LTRACE_SYSDEP_H */
