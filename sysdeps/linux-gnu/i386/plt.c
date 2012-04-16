#include <gelf.h>
#include "proc.h"
#include "library.h"
#include "ltrace-elf.h"

GElf_Addr
arch_plt_sym_val(struct ltelf *lte, size_t ndx, GElf_Rela *rela)
{
	return lte->plt_addr + (ndx + 1) * 16;
}

void *
sym2addr(struct Process *proc, struct library_symbol *sym)
{
	return sym->enter_addr;
}
