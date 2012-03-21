#include "config.h"

#include <endian.h>
#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <gelf.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

#include "common.h"
#include "proc.h"
#include "library.h"

#ifdef PLT_REINITALISATION_BP
extern char *PLTs_initialized_by_here;
#endif

#ifndef DT_PPC_GOT
# define DT_PPC_GOT		(DT_LOPROC + 0)
#endif


#ifndef ARCH_HAVE_LTELF_DATA
int
arch_elf_dynamic_tag(struct ltelf *lte, GElf_Dyn dyn)
{
	return 0;
}

int
arch_elf_init(struct ltelf *lte)
{
	return 0;
}
#endif

Elf_Data *
elf_loaddata(Elf_Scn *scn, GElf_Shdr *shdr)
{
	Elf_Data *data = elf_getdata(scn, NULL);
	if (data == NULL || elf_getdata(scn, data) != NULL
	    || data->d_off || data->d_size != shdr->sh_size)
		return NULL;
	return data;
}

static int
inside(GElf_Addr addr, GElf_Shdr *shdr)
{
	return addr >= shdr->sh_addr
		&& addr < shdr->sh_addr + shdr->sh_size;
}

static int
section_covers(GElf_Addr addr,
	       Elf_Scn *in_sec, GElf_Shdr *in_shdr,
	       Elf_Scn **tgt_sec, GElf_Shdr *tgt_shdr)
{
	if (inside(addr, in_shdr)) {
		*tgt_sec = in_sec;
		*tgt_shdr = *in_shdr;
		return 1;
	}
	return 0;
}

int
elf_get_section_covering(struct ltelf *lte, GElf_Addr addr,
			 Elf_Scn **tgt_sec, GElf_Shdr *tgt_shdr)
{
	int i;
	for (i = 1; i < lte->ehdr.e_shnum; ++i) {
		Elf_Scn *scn;
		GElf_Shdr shdr;

		scn = elf_getscn(lte->elf, i);
		if (scn == NULL || gelf_getshdr(scn, &shdr) == NULL) {
			debug(1, "Couldn't read section or header.");
			return -1;
		}

		if (section_covers(addr, scn, &shdr, tgt_sec, tgt_shdr))
			return 0;
	}

	return -1;
}

static int
need_data(Elf_Data *data, size_t offset, size_t size)
{
	assert(data != NULL);
	if (data->d_size < size || offset > data->d_size - size) {
		debug(1, "Not enough data to read %zd-byte value"
		      " at offset %zd.", size, offset);
		return -1;
	}
	return 0;
}

#define DEF_READER(NAME, SIZE)						\
	int								\
	NAME(Elf_Data *data, size_t offset, uint##SIZE##_t *retp)	\
	{								\
		if (!need_data(data, offset, SIZE / 8) < 0)		\
			return -1;					\
									\
		union {							\
			uint##SIZE##_t dst;				\
			char buf[0];					\
		} u;							\
		memcpy(u.buf, data->d_buf + offset, sizeof(u.dst));	\
		*retp = u.dst;						\
		return 0;						\
	}

DEF_READER(elf_read_u16, 16)
DEF_READER(elf_read_u32, 32)
DEF_READER(elf_read_u64, 64)

#undef DEF_READER

int
open_elf(struct ltelf *lte, const char *filename)
{
	lte->fd = open(filename, O_RDONLY);
	if (lte->fd == -1)
		return 1;

	elf_version(EV_CURRENT);

#ifdef HAVE_ELF_C_READ_MMAP
	lte->elf = elf_begin(lte->fd, ELF_C_READ_MMAP, NULL);
#else
	lte->elf = elf_begin(lte->fd, ELF_C_READ, NULL);
#endif

	if (lte->elf == NULL || elf_kind(lte->elf) != ELF_K_ELF)
		error(EXIT_FAILURE, 0, "Can't open ELF file \"%s\"", filename);

	if (gelf_getehdr(lte->elf, &lte->ehdr) == NULL)
		error(EXIT_FAILURE, 0, "Can't read ELF header of \"%s\"",
		      filename);

	if (lte->ehdr.e_type != ET_EXEC && lte->ehdr.e_type != ET_DYN)
		error(EXIT_FAILURE, 0,
		      "\"%s\" is not an ELF executable nor shared library",
		      filename);

	if ((lte->ehdr.e_ident[EI_CLASS] != LT_ELFCLASS
	     || lte->ehdr.e_machine != LT_ELF_MACHINE)
#ifdef LT_ELF_MACHINE2
	    && (lte->ehdr.e_ident[EI_CLASS] != LT_ELFCLASS2
		|| lte->ehdr.e_machine != LT_ELF_MACHINE2)
#endif
#ifdef LT_ELF_MACHINE3
	    && (lte->ehdr.e_ident[EI_CLASS] != LT_ELFCLASS3
		|| lte->ehdr.e_machine != LT_ELF_MACHINE3)
#endif
	    )
		error(EXIT_FAILURE, 0,
		      "\"%s\" is ELF from incompatible architecture", filename);

	return 0;
}

static int
do_init_elf(struct ltelf *lte, const char *filename, GElf_Addr bias)
{
	int i;
	GElf_Addr relplt_addr = 0;
	GElf_Addr soname_offset = 0;

	debug(DEBUG_FUNCTION, "do_init_elf(filename=%s)", filename);
	debug(1, "Reading ELF from %s...", filename);

	if (open_elf(lte, filename) < 0)
		return -1;

	Elf_Data *plt_data = NULL;
	GElf_Addr ppcgot = 0;

	/* Find out the bias.  For DSOs, this will be just BASE,
	 * unless the DSO is pre-linked.  For ET_EXEC files, this will
	 * turn out to be 0.  */
	{
		GElf_Phdr phdr;
		for (i = 0; gelf_getphdr (lte->elf, i, &phdr) != NULL; ++i) {
			if (phdr.p_type == PT_LOAD) {
				if (base == 0)
					base = phdr.p_vaddr;
				lte->base_addr = base;
				lte->bias = lte->base_addr - phdr.p_vaddr;
				fprintf(stderr,
					" + vaddr=%#lx, base=%#lx, bias=%#lx\n",
					lte->base_addr, base, lte->bias);
				break;
			}
		}
	}

	lte->entry_addr = lte->ehdr.e_entry + lte->bias;

	for (i = 1; i < lte->ehdr.e_shnum; ++i) {
		Elf_Scn *scn;
		GElf_Shdr shdr;
		const char *name;

		scn = elf_getscn(lte->elf, i);
		if (scn == NULL || gelf_getshdr(scn, &shdr) == NULL)
			error(EXIT_FAILURE, 0,
			      "Couldn't get section header from \"%s\"",
			      filename);

		name = elf_strptr(lte->elf, lte->ehdr.e_shstrndx, shdr.sh_name);
		if (name == NULL)
			error(EXIT_FAILURE, 0,
			      "Couldn't get section header from \"%s\"",
			      filename);

		if (shdr.sh_type == SHT_SYMTAB) {
			Elf_Data *data;

			lte->symtab = elf_getdata(scn, NULL);
			lte->symtab_count = shdr.sh_size / shdr.sh_entsize;
			if ((lte->symtab == NULL
			     || elf_getdata(scn, lte->symtab) != NULL)
			    && opt_x != NULL)
				error(EXIT_FAILURE, 0,
				      "Couldn't get .symtab data from \"%s\"",
				      filename);

			scn = elf_getscn(lte->elf, shdr.sh_link);
			if (scn == NULL || gelf_getshdr(scn, &shdr) == NULL)
				error(EXIT_FAILURE, 0,
				      "Couldn't get section header from \"%s\"",
				      filename);

			data = elf_getdata(scn, NULL);
			if (data == NULL || elf_getdata(scn, data) != NULL
			    || shdr.sh_size != data->d_size || data->d_off)
				error(EXIT_FAILURE, 0,
				      "Couldn't get .strtab data from \"%s\"",
				      filename);

			lte->strtab = data->d_buf;
		} else if (shdr.sh_type == SHT_DYNSYM) {
			Elf_Data *data;

			lte->dynsym = elf_getdata(scn, NULL);
			lte->dynsym_count = shdr.sh_size / shdr.sh_entsize;
			if (lte->dynsym == NULL
			    || elf_getdata(scn, lte->dynsym) != NULL)
				error(EXIT_FAILURE, 0,
				      "Couldn't get .dynsym data from \"%s\"",
				      filename);

			scn = elf_getscn(lte->elf, shdr.sh_link);
			if (scn == NULL || gelf_getshdr(scn, &shdr) == NULL)
				error(EXIT_FAILURE, 0,
				      "Couldn't get section header from \"%s\"",
				      filename);

			data = elf_getdata(scn, NULL);
			if (data == NULL || elf_getdata(scn, data) != NULL
			    || shdr.sh_size != data->d_size || data->d_off)
				error(EXIT_FAILURE, 0,
				      "Couldn't get .dynstr data from \"%s\"",
				      filename);

			lte->dynstr = data->d_buf;
		} else if (shdr.sh_type == SHT_DYNAMIC) {
			Elf_Data *data;
			size_t j;

			lte->dyn_addr = shdr.sh_addr;
			fprintf(stderr, "dyn_addr = %#lx\n", lte->dyn_addr);
			extern void *dyn_addr;
			dyn_addr = (void *)lte->dyn_addr;
			lte->dyn_sz = shdr.sh_size;

			data = elf_getdata(scn, NULL);
			if (data == NULL || elf_getdata(scn, data) != NULL)
				error(EXIT_FAILURE, 0,
				      "Couldn't get .dynamic data from \"%s\"",
				      filename);

			for (j = 0; j < shdr.sh_size / shdr.sh_entsize; ++j) {
				GElf_Dyn dyn;

				if (gelf_getdyn(data, j, &dyn) == NULL)
					error(EXIT_FAILURE, 0,
					      "Couldn't get .dynamic data from \"%s\"",
					      filename);
				if (dyn.d_tag == DT_JMPREL)
					relplt_addr = dyn.d_un.d_ptr;
				else if (dyn.d_tag == DT_PLTRELSZ)
					lte->relplt_size = dyn.d_un.d_val;
				else if (dyn.d_tag == DT_SONAME)
					soname_offset = dyn.d_un.d_val;
				else if (arch_elf_dynamic_tag(lte, dyn) < 0)
					goto backend_fail;
			}
		} else if (shdr.sh_type == SHT_PROGBITS
			   || shdr.sh_type == SHT_NOBITS) {
			if (strcmp(name, ".plt") == 0) {
				lte->plt_addr = shdr.sh_addr;
				lte->plt_size = shdr.sh_size;
				lte->plt_data = elf_loaddata(scn, &shdr);
				if (lte->plt_data == NULL)
					fprintf(stderr,
						"Can't load .plt data\n");
				if (shdr.sh_flags & SHF_EXECINSTR)
					lte->lte_flags |= LTE_PLT_EXECUTABLE;
			}
#ifdef ARCH_SUPPORTS_OPD
			else if (strcmp(name, ".opd") == 0) {
				lte->opd_addr = (GElf_Addr *) (long) shdr.sh_addr;
				lte->opd_size = shdr.sh_size;
				lte->opd = elf_rawdata(scn, NULL);
			}
#endif
		}
	}

	if (lte->dynsym == NULL || lte->dynstr == NULL)
		error(EXIT_FAILURE, 0,
		      "Couldn't find .dynsym or .dynstr in \"%s\"", filename);

	if (arch_elf_init(lte) < 0) {
	backend_fail:
		fprintf(stderr, "Backend initialization failed.\n");
		return -1;
	}

	if (!relplt_addr || !lte->plt_addr) {
		debug(1, "%s has no PLT relocations", filename);
		lte->relplt = NULL;
		lte->relplt_count = 0;
	} else if (lte->relplt_size == 0) {
		debug(1, "%s has unknown PLT size", filename);
		lte->relplt = NULL;
		lte->relplt_count = 0;
	} else {

		for (i = 1; i < lte->ehdr.e_shnum; ++i) {
			Elf_Scn *scn;
			GElf_Shdr shdr;

			scn = elf_getscn(lte->elf, i);
			if (scn == NULL || gelf_getshdr(scn, &shdr) == NULL)
				error(EXIT_FAILURE, 0,
				      "Couldn't get section header from \"%s\"",
				      filename);
			if (shdr.sh_addr == relplt_addr
			    && shdr.sh_size == lte->relplt_size) {
				lte->relplt = elf_getdata(scn, NULL);
				lte->relplt_count =
				    shdr.sh_size / shdr.sh_entsize;
				if (lte->relplt == NULL
				    || elf_getdata(scn, lte->relplt) != NULL)
					error(EXIT_FAILURE, 0,
					      "Couldn't get .rel*.plt data from \"%s\"",
					      filename);
				break;
			}
		}

		if (i == lte->ehdr.e_shnum)
			error(EXIT_FAILURE, 0,
			      "Couldn't find .rel*.plt section in \"%s\"",
			      filename);

		debug(1, "%s %zd PLT relocations", filename, lte->relplt_count);
	}

	if (soname_offset != 0)
		lte->soname = lte->dynstr + soname_offset;

	return 0;
}

/* XXX temporarily non-static */
void
do_close_elf(struct ltelf *lte) {
	debug(DEBUG_FUNCTION, "do_close_elf()");
	elf_end(lte->elf);
	close(lte->fd);
}

struct library *
ltelf_read_library(const char *filename, GElf_Addr base)
{
	 // XXX we leak LTE contents
	struct ltelf lte = {};
	if (do_init_elf(&lte, filename, base) < 0)
		return NULL;
	proc->e_machine = lte.ehdr.e_machine;

	struct library *lib = malloc(sizeof(*lib));
	char *soname = NULL;
	if (lib == NULL) {
	fail:
		free(soname);
		library_destroy(lib);
		free(lib);
		lib = NULL;
		goto done;
	}

	if (lte.soname != NULL) {
		soname = strdup(lte.soname);
		if (soname == NULL)
			goto fail;
	}

	library_init(lib, soname, soname != NULL);
	lib->entry = (target_address_t)lte.entry_addr;
	lib->base = (target_address_t)lte.base_addr;

	size_t i;
	for (i = 0; i < lte.relplt_count; ++i) {
		GElf_Rel rel;
		GElf_Rela rela;
		GElf_Sym sym;
		void *ret;

		if (lte.relplt->d_type == ELF_T_REL) {
			ret = gelf_getrel(lte.relplt, i, &rel);
			rela.r_offset = rel.r_offset;
			rela.r_info = rel.r_info;
			rela.r_addend = 0;
		} else {
			ret = gelf_getrela(lte.relplt, i, &rela);
		}

		if (ret == NULL
		    || ELF64_R_SYM(rela.r_info) >= lte.dynsym_count
		    || gelf_getsym(lte.dynsym, ELF64_R_SYM(rela.r_info),
				   &sym) == NULL)
			error(EXIT_FAILURE, 0,
			      "Couldn't get relocation from \"%s\"",
			      filename);

		/* We will destroy the ELF object at the end of the
		 * scope.  We need to copy the name for our purposes.
		 * XXX consider just keeping the ELF around.  */
		char *name = strdup(lte.dynstr + sym.st_name);
		if (name == NULL) {
		fail2:
			free(name);
			goto fail;
		}

		enum toplt pltt = PLTS_ARE_EXECUTABLE(&lte)
			?  LS_TOPLT_EXEC : LS_TOPLT_POINT;
		GElf_Addr addr = arch_plt_sym_val(&lte, i, &rela);

		struct library_symbol *libsym = malloc(sizeof(*libsym));
		if (libsym == NULL)
			goto fail2;
		library_symbol_init(libsym, lib, addr + lte.bias, name, 1, pltt,
				    ELF64_ST_BIND(sym.st_info) == STB_WEAK);
		library_add_symbol(lib, libsym);
	}

done:
	do_close_elf(&lte);
	return lib;
}

struct library *
ltelf_read_main_binary(struct Process *proc, const char *path)
{
	fprintf(stderr, "ltelf_read_main_binary %d %s\n", proc->pid, path);
	char *fname = pid2name(proc->pid);
	struct library *lib = ltelf_read_library(fname, 0);
	library_set_name(lib, path, 0);
	return lib;
}
