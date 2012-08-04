#include "config.h"

#include <assert.h>
#ifdef	__linux__
#include <endian.h>
#endif
#include <errno.h>
#include <fcntl.h>
#include <gelf.h>
#include <inttypes.h>
#include <search.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "common.h"
#include "proc.h"
#include "library.h"
#include "filter.h"

#ifdef PLT_REINITALISATION_BP
extern char *PLTs_initialized_by_here;
#endif

#ifndef ARCH_HAVE_LTELF_DATA
int
arch_elf_init(struct ltelf *lte, struct library *lib)
{
	return 0;
}

void
arch_elf_destroy(struct ltelf *lte)
{
}
#endif

int
default_elf_add_plt_entry(struct Process *proc, struct ltelf *lte,
			  const char *a_name, GElf_Rela *rela, size_t ndx,
			  struct library_symbol **ret)
{
	char *name = strdup(a_name);
	if (name == NULL) {
	fail:
		free(name);
		return -1;
	}

	GElf_Addr addr = arch_plt_sym_val(lte, ndx, rela);

	struct library_symbol *libsym = malloc(sizeof(*libsym));
	if (libsym == NULL)
		goto fail;

	/* XXX The double cast should be removed when
	 * target_address_t becomes integral type.  */
	target_address_t taddr = (target_address_t)
		(uintptr_t)(addr + lte->bias);

	if (library_symbol_init(libsym, taddr, name, 1, LS_TOPLT_EXEC) < 0) {
		free(libsym);
		goto fail;
	}

	*ret = libsym;
	return 0;
}

#ifndef ARCH_HAVE_ADD_PLT_ENTRY
enum plt_status
arch_elf_add_plt_entry(struct Process *proc, struct ltelf *lte,
		       const char *a_name, GElf_Rela *rela, size_t ndx,
		       struct library_symbol **ret)
{
	return plt_default;
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
elf_get_section_if(struct ltelf *lte, Elf_Scn **tgt_sec, GElf_Shdr *tgt_shdr,
		   int (*predicate)(Elf_Scn *, GElf_Shdr *, void *data),
		   void *data)
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
		if (predicate(scn, &shdr, data)) {
			*tgt_sec = scn;
			*tgt_shdr = shdr;
			return 0;
		}
	}
	return -1;

}

static int
inside_p(Elf_Scn *scn, GElf_Shdr *shdr, void *data)
{
	GElf_Addr addr = *(GElf_Addr *)data;
	return addr >= shdr->sh_addr
		&& addr < shdr->sh_addr + shdr->sh_size;
}

int
elf_get_section_covering(struct ltelf *lte, GElf_Addr addr,
			 Elf_Scn **tgt_sec, GElf_Shdr *tgt_shdr)
{
	return elf_get_section_if(lte, tgt_sec, tgt_shdr,
				  &inside_p, &addr);
}

static int
type_p(Elf_Scn *scn, GElf_Shdr *shdr, void *data)
{
	GElf_Word type = *(GElf_Word *)data;
	return shdr->sh_type == type;
}

int
elf_get_section_type(struct ltelf *lte, GElf_Word type,
		     Elf_Scn **tgt_sec, GElf_Shdr *tgt_shdr)
{
	return elf_get_section_if(lte, tgt_sec, tgt_shdr,
				  &type_p, &type);
}

struct section_named_data {
	struct ltelf *lte;
	const char *name;
};

static int
name_p(Elf_Scn *scn, GElf_Shdr *shdr, void *d)
{
	struct section_named_data *data = d;
	const char *name = elf_strptr(data->lte->elf,
				      data->lte->ehdr.e_shstrndx,
				      shdr->sh_name);
	return strcmp(name, data->name) == 0;
}

int
elf_get_section_named(struct ltelf *lte, const char *name,
		     Elf_Scn **tgt_sec, GElf_Shdr *tgt_shdr)
{
	struct section_named_data data = {
		.lte = lte,
		.name = name,
	};
	return elf_get_section_if(lte, tgt_sec, tgt_shdr,
				  &name_p, &data);
}

static int
need_data(Elf_Data *data, GElf_Xword offset, GElf_Xword size)
{
	assert(data != NULL);
	if (data->d_size < size || offset > data->d_size - size) {
		debug(1, "Not enough data to read %"PRId64"-byte value"
		      " at offset %"PRId64".", size, offset);
		return -1;
	}
	return 0;
}

#define DEF_READER(NAME, SIZE)						\
	int								\
	NAME(Elf_Data *data, GElf_Xword offset, uint##SIZE##_t *retp)	\
	{								\
		if (!need_data(data, offset, SIZE / 8) < 0)		\
			return -1;					\
									\
		if (data->d_buf == NULL) /* NODATA section */ {		\
			*retp = 0;					\
			return 0;					\
		}							\
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

	if (lte->elf == NULL || elf_kind(lte->elf) != ELF_K_ELF) {
		fprintf(stderr, "\"%s\" is not an ELF file\n", filename);
		exit(EXIT_FAILURE);
	}

	if (gelf_getehdr(lte->elf, &lte->ehdr) == NULL) {
		fprintf(stderr, "can't read ELF header of \"%s\": %s\n",
			filename, elf_errmsg(-1));
		exit(EXIT_FAILURE);
	}

	if (lte->ehdr.e_type != ET_EXEC && lte->ehdr.e_type != ET_DYN) {
		fprintf(stderr, "\"%s\" is neither an ELF executable"
			" nor a shared library\n", filename);
		exit(EXIT_FAILURE);
	}

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
		) {
		fprintf(stderr,
			"\"%s\" is ELF from incompatible architecture\n",
			filename);
		exit(EXIT_FAILURE);
	}

	return 0;
}

static void
read_symbol_table(struct ltelf *lte, const char *filename,
		  Elf_Scn *scn, GElf_Shdr *shdr, const char *name,
		  Elf_Data **datap, size_t *countp, const char **strsp)
{
	*datap = elf_getdata(scn, NULL);
	*countp = shdr->sh_size / shdr->sh_entsize;
	if ((*datap == NULL || elf_getdata(scn, *datap) != NULL)
	    && options.static_filter != NULL) {
		fprintf(stderr, "Couldn't get data of section"
			" %s from \"%s\": %s\n",
			name, filename, elf_errmsg(-1));
		exit(EXIT_FAILURE);
	}

	scn = elf_getscn(lte->elf, shdr->sh_link);
	GElf_Shdr shdr2;
	if (scn == NULL || gelf_getshdr(scn, &shdr2) == NULL) {
		fprintf(stderr, "Couldn't get header of section"
			" #%d from \"%s\": %s\n",
			shdr2.sh_link, filename, elf_errmsg(-1));
		exit(EXIT_FAILURE);
	}

	Elf_Data *data = elf_getdata(scn, NULL);
	if (data == NULL || elf_getdata(scn, data) != NULL
	    || shdr2.sh_size != data->d_size || data->d_off) {
		fprintf(stderr, "Couldn't get data of section"
			" #%d from \"%s\": %s\n",
			shdr2.sh_link, filename, elf_errmsg(-1));
		exit(EXIT_FAILURE);
	}

	*strsp = data->d_buf;
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

	/* Find out the base address.  */
	{
		GElf_Phdr phdr;
		for (i = 0; gelf_getphdr (lte->elf, i, &phdr) != NULL; ++i) {
			if (phdr.p_type == PT_LOAD) {
				lte->base_addr = phdr.p_vaddr + bias;
				break;
			}
		}
	}

	if (lte->base_addr == 0) {
		fprintf(stderr, "Couldn't determine base address of %s\n",
			filename);
		return -1;
	}

	lte->bias = bias;
	lte->entry_addr = lte->ehdr.e_entry + lte->bias;

	for (i = 1; i < lte->ehdr.e_shnum; ++i) {
		Elf_Scn *scn;
		GElf_Shdr shdr;
		const char *name;

		scn = elf_getscn(lte->elf, i);
		if (scn == NULL || gelf_getshdr(scn, &shdr) == NULL) {
			fprintf(stderr,	"Couldn't get section #%d from"
				" \"%s\": %s\n", i, filename, elf_errmsg(-1));
			exit(EXIT_FAILURE);
		}

		name = elf_strptr(lte->elf, lte->ehdr.e_shstrndx, shdr.sh_name);
		if (name == NULL) {
			fprintf(stderr,	"Couldn't get name of section #%d from"
				" \"%s\": %s\n", i, filename, elf_errmsg(-1));
			exit(EXIT_FAILURE);
		}

		if (shdr.sh_type == SHT_SYMTAB) {
			read_symbol_table(lte, filename,
					  scn, &shdr, name, &lte->symtab,
					  &lte->symtab_count, &lte->strtab);

		} else if (shdr.sh_type == SHT_DYNSYM) {
			read_symbol_table(lte, filename,
					  scn, &shdr, name, &lte->dynsym,
					  &lte->dynsym_count, &lte->dynstr);

		} else if (shdr.sh_type == SHT_DYNAMIC) {
			Elf_Data *data;
			size_t j;

			lte->dyn_addr = shdr.sh_addr;
			lte->dyn_sz = shdr.sh_size;

			data = elf_getdata(scn, NULL);
			if (data == NULL || elf_getdata(scn, data) != NULL) {
				fprintf(stderr, "Couldn't get .dynamic data"
					" from \"%s\": %s\n",
					filename, strerror(errno));
				exit(EXIT_FAILURE);
			}

			for (j = 0; j < shdr.sh_size / shdr.sh_entsize; ++j) {
				GElf_Dyn dyn;

				if (gelf_getdyn(data, j, &dyn) == NULL) {
					fprintf(stderr, "Couldn't get .dynamic"
						" data from \"%s\": %s\n",
						filename, strerror(errno));
					exit(EXIT_FAILURE);
				}
				if (dyn.d_tag == DT_JMPREL)
					relplt_addr = dyn.d_un.d_ptr;
				else if (dyn.d_tag == DT_PLTRELSZ)
					lte->relplt_size = dyn.d_un.d_val;
				else if (dyn.d_tag == DT_SONAME)
					soname_offset = dyn.d_un.d_val;
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
				lte->plt_flags = shdr.sh_flags;
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

	if (lte->dynsym == NULL || lte->dynstr == NULL) {
		fprintf(stderr, "Couldn't find .dynsym or .dynstr in \"%s\"\n",
			filename);
		exit(EXIT_FAILURE);
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
			if (scn == NULL || gelf_getshdr(scn, &shdr) == NULL) {
				fprintf(stderr, "Couldn't get section header"
					" from \"%s\": %s\n",
					filename, elf_errmsg(-1));
				exit(EXIT_FAILURE);
			}
			if (shdr.sh_addr == relplt_addr
			    && shdr.sh_size == lte->relplt_size) {
				lte->relplt = elf_getdata(scn, NULL);
				lte->relplt_count =
				    shdr.sh_size / shdr.sh_entsize;
				if (lte->relplt == NULL
				    || elf_getdata(scn, lte->relplt) != NULL) {
					fprintf(stderr, "Couldn't get .rel*.plt"
						" data from \"%s\": %s\n",
						filename, elf_errmsg(-1));
					exit(EXIT_FAILURE);
				}
				break;
			}
		}

		if (i == lte->ehdr.e_shnum) {
			fprintf(stderr,
				"Couldn't find .rel*.plt section in \"%s\"\n",
				filename);
			exit(EXIT_FAILURE);
		}

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
	arch_elf_destroy(lte);
	elf_end(lte->elf);
	close(lte->fd);
}

static int
populate_plt(struct Process *proc, const char *filename,
	     struct ltelf *lte, struct library *lib)
{
	size_t i;
	for (i = 0; i < lte->relplt_count; ++i) {
		GElf_Rel rel;
		GElf_Rela rela;
		GElf_Sym sym;
		void *ret;

		if (lte->relplt->d_type == ELF_T_REL) {
			ret = gelf_getrel(lte->relplt, i, &rel);
			rela.r_offset = rel.r_offset;
			rela.r_info = rel.r_info;
			rela.r_addend = 0;
		} else {
			ret = gelf_getrela(lte->relplt, i, &rela);
		}

		if (ret == NULL
		    || ELF64_R_SYM(rela.r_info) >= lte->dynsym_count
		    || gelf_getsym(lte->dynsym, ELF64_R_SYM(rela.r_info),
				   &sym) == NULL) {
			fprintf(stderr,
				"Couldn't get relocation from \"%s\": %s\n",
				filename, elf_errmsg(-1));
			exit(EXIT_FAILURE);
		}

		char const *name = lte->dynstr + sym.st_name;

		if (!filter_matches_symbol(options.plt_filter, name, lib))
			continue;

		struct library_symbol *libsym = NULL;
		switch (arch_elf_add_plt_entry(proc, lte, name,
					       &rela, i, &libsym)) {
		case plt_default:
			if (default_elf_add_plt_entry(proc, lte, name,
						      &rela, i, &libsym) < 0)
			/* fall-through */
		case plt_fail:
				return -1;
			/* fall-through */
		case plt_ok:
			if (libsym != NULL)
				library_add_symbol(lib, libsym);
		}
	}
	return 0;
}

/* When -x rules result in request to trace several aliases, we only
 * want to add such symbol once.  The only way that those symbols
 * differ in is their name, e.g. in glibc you have __GI___libc_free,
 * __cfree, __free, __libc_free, cfree and free all defined on the
 * same address.  So instead we keep this unique symbol struct for
 * each address, and replace name in libsym with a shorter variant if
 * we find it.  */
struct unique_symbol {
	target_address_t addr;
	struct library_symbol *libsym;
};

static int
unique_symbol_cmp(const void *key, const void *val)
{
	const struct unique_symbol *sym_key = key;
	const struct unique_symbol *sym_val = val;
	return sym_key->addr != sym_val->addr;
}

static int
populate_this_symtab(struct Process *proc, const char *filename,
		     struct ltelf *lte, struct library *lib,
		     Elf_Data *symtab, const char *strtab, size_t size)
{
	/* Using sorted array would be arguably better, but this
	 * should be well enough for the number of symbols that we
	 * typically deal with.  */
	size_t num_symbols = 0;
	struct unique_symbol *symbols = malloc(sizeof(*symbols) * size);
	if (symbols == NULL) {
		fprintf(stderr, "couldn't insert symbols for -x: %s\n",
			strerror(errno));
		return -1;
	}

	GElf_Word secflags[lte->ehdr.e_shnum];
	size_t i;
	for (i = 1; i < lte->ehdr.e_shnum; ++i) {
		Elf_Scn *scn = elf_getscn(lte->elf, i);
		if (scn == NULL)
			continue;
		GElf_Shdr shdr;
		if (gelf_getshdr(scn, &shdr) == NULL)
			continue;
		secflags[i] = shdr.sh_flags;
	}

	size_t lib_len = strlen(lib->soname);
	for (i = 0; i < size; ++i) {
		GElf_Sym sym;
		if (gelf_getsym(symtab, i, &sym) == NULL) {
		fail:
			fprintf(stderr,
				"couldn't get symbol #%zd from %s: %s\n",
				i, filename, elf_errmsg(-1));
			continue;
		}

		/* XXX support IFUNC as well.  */
		if (GELF_ST_TYPE(sym.st_info) != STT_FUNC
		    || sym.st_value == 0
		    || sym.st_shndx == STN_UNDEF)
			continue;

		const char *orig_name = strtab + sym.st_name;
		const char *version = strchr(orig_name, '@');
		size_t len = version != NULL ? (assert(version > orig_name),
						(size_t)(version - orig_name))
			: strlen(orig_name);
		char name[len + 1];
		memcpy(name, orig_name, len);
		name[len] = 0;

		if (!filter_matches_symbol(options.static_filter, name, lib))
			continue;

		target_address_t addr = (target_address_t)
			(uintptr_t)(sym.st_value + lte->bias);
		target_address_t naddr;

		/* On arches that support OPD, the value of typical
		 * function symbol will be a pointer to .opd, but some
		 * will point directly to .text.  We don't want to
		 * translate those.  */
		if (secflags[sym.st_shndx] & SHF_EXECINSTR) {
			naddr = addr;
		} else if (arch_translate_address(lte, addr, &naddr) < 0) {
			fprintf(stderr,
				"couldn't translate address of %s@%s: %s\n",
				name, lib->soname, strerror(errno));
			continue;
		}

		char *full_name;
		if (lib->type != LT_LIBTYPE_MAIN) {
			full_name = malloc(strlen(name) + 1 + lib_len + 1);
			if (full_name == NULL)
				goto fail;
			sprintf(full_name, "%s@%s", name, lib->soname);
		} else {
			full_name = strdup(name);
			if (full_name == NULL)
				goto fail;
		}

		/* Look whether we already have a symbol for this
		 * address.  If not, add this one.  */
		struct unique_symbol key = { naddr, NULL };
		struct unique_symbol *unique
			= lsearch(&key, symbols, &num_symbols,
				  sizeof(*symbols), &unique_symbol_cmp);

		if (unique->libsym == NULL) {
			struct library_symbol *libsym = malloc(sizeof(*libsym));
			if (libsym == NULL
			    || library_symbol_init(libsym, naddr, full_name,
						   1, LS_TOPLT_NONE) < 0) {
				--num_symbols;
				goto fail;
			}
			unique->libsym = libsym;
			unique->addr = naddr;

		} else if (strlen(full_name) < strlen(unique->libsym->name)) {
			library_symbol_set_name(unique->libsym, full_name, 1);

		} else {
			free(full_name);
		}
	}

	for (i = 0; i < num_symbols; ++i) {
		assert(symbols[i].libsym != NULL);
		library_add_symbol(lib, symbols[i].libsym);
	}

	free(symbols);

	return 0;
}

static int
populate_symtab(struct Process *proc, const char *filename,
		struct ltelf *lte, struct library *lib)
{
	if (lte->symtab != NULL && lte->strtab != NULL)
		return populate_this_symtab(proc, filename, lte, lib,
					    lte->symtab, lte->strtab,
					    lte->symtab_count);
	else
		return populate_this_symtab(proc, filename, lte, lib,
					    lte->dynsym, lte->dynstr,
					    lte->dynsym_count);
}

int
ltelf_read_library(struct library *lib, struct Process *proc,
		   const char *filename, GElf_Addr bias)
{
	struct ltelf lte = {};
	if (do_init_elf(&lte, filename, bias) < 0)
		return -1;
	if (arch_elf_init(&lte, lib) < 0) {
		fprintf(stderr, "Backend initialization failed.\n");
		return -1;
	}

	proc->e_machine = lte.ehdr.e_machine;

	int status = 0;
	if (lib == NULL)
		goto fail;

	/* Note that we set soname and pathname as soon as they are
	 * allocated, so in case of further errors, this get released
	 * when LIB is release, which should happen in the caller when
	 * we return error.  */

	if (lib->pathname == NULL) {
		char *pathname = strdup(filename);
		if (pathname == NULL)
			goto fail;
		library_set_pathname(lib, pathname, 1);
	}

	if (lte.soname != NULL) {
		char *soname = strdup(lte.soname);
		if (soname == NULL)
			goto fail;
		library_set_soname(lib, soname, 1);
	} else {
		const char *soname = rindex(lib->pathname, '/') + 1;
		if (soname == NULL)
			soname = lib->pathname;
		library_set_soname(lib, soname, 0);
	}

	/* XXX The double cast should be removed when
	 * target_address_t becomes integral type.  */
	target_address_t entry = (target_address_t)(uintptr_t)lte.entry_addr;
	if (arch_translate_address(&lte, entry, &entry) < 0)
		goto fail;

	/* XXX The double cast should be removed when
	 * target_address_t becomes integral type.  */
	lib->base = (target_address_t)(uintptr_t)lte.base_addr;
	lib->entry = entry;
	/* XXX The double cast should be removed when
	 * target_address_t becomes integral type.  */
	lib->dyn_addr = (target_address_t)(uintptr_t)lte.dyn_addr;

	if (filter_matches_library(options.plt_filter, lib)
	    && populate_plt(proc, filename, &lte, lib) < 0)
		goto fail;

	if (filter_matches_library(options.static_filter, lib)
	    && populate_symtab(proc, filename, &lte, lib) < 0)
		goto fail;

done:
	do_close_elf(&lte);
	return status;

fail:
	status = -1;
	goto done;
}

struct library *
ltelf_read_main_binary(struct Process *proc, const char *path)
{
	struct library *lib = malloc(sizeof(*lib));
	if (lib == NULL)
		return NULL;
	library_init(lib, LT_LIBTYPE_MAIN);
	library_set_pathname(lib, path, 0);

	/* There is a race between running the process and reading its
	 * binary for internal consumption.  So open the binary from
	 * the /proc filesystem.  XXX Note that there is similar race
	 * for libraries, but there we don't have a nice answer like
	 * that.  Presumably we could read the DSOs from the process
	 * memory image, but that's not currently done.  */
	char *fname = pid2name(proc->pid);
	if (ltelf_read_library(lib, proc, fname, 0) < 0) {
		library_destroy(lib);
		free(lib);
		return NULL;
	}

	return lib;
}
