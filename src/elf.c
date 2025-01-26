// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifdef HAVE_LIBELF
#include <libelf.h>
#include <gelf.h>
#endif

#include <fcntl.h>
#include <linux/kernel.h>

#include "libbpf_internal.h"
#include "str_error.h"



#define STRERR_BUFSIZE  128

/* A SHT_GNU_versym section holds 16-bit words. This bit is set if
 * the symbol is hidden and can only be seen when referenced using an
 * explicit version number. This is a GNU extension.
 */
#define VERSYM_HIDDEN	0x8000

/* This is the mask for the rest of the data in a word read from a
 * SHT_GNU_versym section.
 */
#define VERSYM_VERSION	0x7fff


#ifdef  HAVE_LIBELF
int elf_open(const char *binary_path, struct elf_fd *elf_fd)
{
	char errmsg[STRERR_BUFSIZE];
	int fd, ret;
	Elf *elf;

	if (elf_version(EV_CURRENT) == EV_NONE) {
		pr_warn("elf: failed to init libelf for %s\n", binary_path);
		return -LIBBPF_ERRNO__LIBELF;
	}
	fd = open(binary_path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		ret = -errno;
		pr_warn("elf: failed to open %s: %s\n", binary_path,
			libbpf_strerror_r(ret, errmsg, sizeof(errmsg)));
		return ret;
	}
	elf = elf_begin(fd, ELF_C_READ_MMAP, NULL);
	if (!elf) {
		pr_warn("elf: could not read elf from %s: %s\n", binary_path, elf_errmsg(-1));
		close(fd);
		return -LIBBPF_ERRNO__FORMAT;
	}
	elf_fd->fd = fd;
	elf_fd->elf = elf;
	return 0;
}
#elif HAVE_ELFIO
int elf_open(const char *binary_path, struct elf_fd *elf_fd)
{
	pelfio_t pelfio = elfio_new();
	bool ret = false;
	ret = elfio_load(pelfio, binary_path);
	if (!ret) {
		pr_warn("elf: could not read elf from %s: %s\n", binary_path, elf_errmsg(-1));
		return -LIBBPF_ERRNO__FORMAT;
	}
	elf_fd->elf = pelfio;
	elf_fd->fd = -1;
	return 0;
}
#endif


void elf_close(struct elf_fd *elf_fd)
{
	if (!elf_fd)
		return;
#ifdef HAVE_LIBELF
	elf_end(elf_fd->elf);
	close(elf_fd->fd);
#elif HAVE_ELFIO
	elfio_delete(elf_fd->elf);
#endif
}

/* Return next ELF section of sh_type after scn, or first of that type if scn is NULL. */
#ifdef  HAVE_LIBELF
static Elf_Scn *elf_find_next_scn_by_type(Elf *elf, int sh_type, Elf_Scn *scn)
{
	while ((scn = elf_nextscn(elf, scn)) != NULL) {
		GElf_Shdr sh;

		if (!gelf_getshdr(scn, &sh))
			continue;
		if (sh.sh_type == sh_type)
			return scn;
	}
	return NULL;
}
#elif HAVE_ELFIO
static psection_t elf_find_next_scn_by_type(pelfio_t pelfio, int sh_type, psection_t pscn)
{
    int secno = elfio_get_sections_num(pelfio);
    int j = 0;
    if (pscn != NULL) {
        for (int i = 0; i < secno; i++) {
            psection_t psection = elfio_get_section_by_index(pelfio, i);
            if (psection == pscn) {
                j = i;
            }
        }
    }
    for (; j < secno; j++) {
        psection_t psection = elfio_get_section_by_index(pelfio, j);
        Elf_Word sec_type = elfio_section_get_type(psection);
        if (sec_type == sh_type) {
            return psection;
        }
    }
    return NULL;
}
#endif 

struct elf_sym {
	const char *name;
	GElf_Sym sym;
	GElf_Shdr sh;
	int ver;
	bool hidden;
};

struct elf_sym_iter {
#ifdef  HAVE_LIBELF
	Elf *elf;
#elif HAVE_ELFIO
	pelfio_t elf;
	psection_t symsSec;
#endif
	Elf_Data *syms;
	Elf_Data *versyms;
	Elf_Data *verdefs;
	size_t nr_syms;
	size_t strtabidx;
	size_t verdef_strtabidx;
	size_t next_sym_idx;
	struct elf_sym sym;
	int st_type;
};

#ifdef  HAVE_LIBELF
static int elf_sym_iter_new(struct elf_sym_iter *iter,
			    Elf *elf, const char *binary_path,
			    int sh_type, int st_type)
{
	Elf_Scn *scn = NULL;
	GElf_Ehdr ehdr;
	GElf_Shdr sh;

	memset(iter, 0, sizeof(*iter));

	if (!gelf_getehdr(elf, &ehdr)) {
		pr_warn("elf: failed to get ehdr from %s: %s\n", binary_path, elf_errmsg(-1));
		return -EINVAL;
	}

	scn = elf_find_next_scn_by_type(elf, sh_type, NULL);
	if (!scn) {
		pr_debug("elf: failed to find symbol table ELF sections in '%s'\n",
			 binary_path);
		return -ENOENT;
	}

	if (!gelf_getshdr(scn, &sh))
		return -EINVAL;

	iter->strtabidx = sh.sh_link;
	iter->syms = elf_getdata(scn, 0);
	if (!iter->syms) {
		pr_warn("elf: failed to get symbols for symtab section in '%s': %s\n",
			binary_path, elf_errmsg(-1));
		return -EINVAL;
	}
	iter->nr_syms = iter->syms->d_size / sh.sh_entsize;
	iter->elf = elf;
	iter->st_type = st_type;

	/* Version symbol table is meaningful to dynsym only */
	if (sh_type != SHT_DYNSYM)
		return 0;

	scn = elf_find_next_scn_by_type(elf, SHT_GNU_versym, NULL);
	if (!scn)
		return 0;
	iter->versyms = elf_getdata(scn, 0);

	scn = elf_find_next_scn_by_type(elf, SHT_GNU_verdef, NULL);
	if (!scn)
		return 0;

	iter->verdefs = elf_getdata(scn, 0);
	if (!iter->verdefs || !gelf_getshdr(scn, &sh)) {
		pr_warn("elf: failed to get verdef ELF section in '%s'\n", binary_path);
		return -EINVAL;
	}
	iter->verdef_strtabidx = sh.sh_link;

	return 0;
}
#elif HAVE_ELFIO
static int elf_sym_iter_new(struct elf_sym_iter *iter,pelfio_t elf, const char *binary_path, int sh_type, int st_type)
{
	psection_t pSec = NULL;
	memset(iter, 0, sizeof(*iter));
	pSec = elf_find_next_scn_by_type(elf, sh_type, NULL);
	iter->strtabidx = elfio_section_get_link(pSec);
	iter->syms->d_buf = (void*)elfio_section_get_data(pSec);
	iter->syms->d_size = elfio_section_get_size(pSec);
	if (!iter->syms->d_buf) {
		pr_warn("elf: failed to get symbols for symtab section in '%s': %s\n",
			binary_path, elf_errmsg(-1));
		return -EINVAL;
	}
	iter->nr_syms = iter->syms->d_size / elfio_section_get_entry_size(pSec);
	iter->symsSec = pSec;
	iter->elf = elf;
	iter->st_type = st_type;
	/* Version symbol table is meaningful to dynsym only */
	if (sh_type != SHT_DYNSYM)
		return 0;
	pSec = elf_find_next_scn_by_type(elf, SHT_GNU_versym, NULL);
	if (!pSec) {
		return 0;
	}
	iter->versyms->d_buf = (void*)elfio_section_get_data(pSec);
	iter->versyms->d_size = elfio_section_get_size(pSec);
	pSec = elf_find_next_scn_by_type(elf, SHT_GNU_verdef, NULL);
	if (!pSec) {
		return 0;
	}
	iter->verdefs->d_buf = (void*)elfio_section_get_data(pSec);
	iter->verdefs->d_size = elfio_section_get_size(pSec);
	if (!iter->verdefs->d_buf) {
		pr_warn("elf: failed to get verdef ELF section in '%s'\n", binary_path);
		return -EINVAL;
	}
	iter->verdef_strtabidx = elfio_section_get_link(pSec);
	return 0;
}
#endif

#ifdef  HAVA_ELFIO
static GElf_Shdr *elf_sec_hdr_by_idx(const pelfio_t elf, size_t idx, GElf_Shdr *sheader)
{
	psection_t psection = elfio_get_section_by_index(elf, idx);
	sheader->sh_name = elfio_section_get_name_string_offset(psection);
	sheader->sh_type = elfio_section_get_type(psection);
	sheader->sh_flags = elfio_section_get_flags(psection);
	sheader->sh_addr = elfio_section_get_address(psection);
	sheader->sh_offset = elfio_section_get_offset(psection);
	sheader->sh_size = elfio_section_get_size(psection);
	sheader->sh_link = elfio_section_get_link(psection);
	sheader->sh_info = elfio_section_get_info(psection);
	sheader->sh_addralign = elfio_section_get_addr_align(psection);
	sheader->sh_entsize = elfio_section_get_entry_size(psection);
	return sheader;
}
#endif  //HAVA_ELFIO


static struct elf_sym *elf_sym_iter_next(struct elf_sym_iter *iter)
{
	struct elf_sym *ret = &iter->sym;
	GElf_Sym *sym = &ret->sym;
	GElf_Versym versym;
#ifdef  HAVA_LIBELF
	Elf_Scn *sym_scn;
#elif HAVE_ELFIO
	psection_t sym_scn;
#endif
	const char *name = NULL;
	size_t idx;
	for (idx = iter->next_sym_idx; idx < iter->nr_syms; idx++) {
#ifdef  HAVA_LIBELF
		if (!gelf_getsym(iter->syms, idx, sym))
			continue;
		if (GELF_ST_TYPE(sym->st_info) != iter->st_type)
			continue;
		name = elf_strptr(iter->elf, iter->strtabidx, sym->st_name);
		if (!name)
			continue;
		sym_scn = elf_getscn(iter->elf, sym->st_shndx);
		if (!sym_scn)
			continue;
		if (!gelf_getshdr(sym_scn, &ret->sh))
			continue;
#elif HAVA_ELFIO
		if(memcpy(sym,iter->sysms->d_buf + idx,sizeof(GElf_Sym) == NULL) {
			continue;
		}
		if(((sym->st_info) & 0xf) != iter->st_type) {
			continue;
		}
		psection_t psection = elfio_get_section_by_index(iter->elf, iter->strtabidx);
		if (!psection)
			return -LIBBPF_ERRNO__FORMAT;
		pstring_t strstring = elfio_string_section_accessor_new(psection);
		name = elfio_string_get_string(strstring, sym->st_name);
		if(!name) {
			continue;
		}
		if(!elf_sec_hdr_by_idx(iter->elf, sym->st_shndx, &ret->sh)) {
			continue;
		}
#endif
		iter->next_sym_idx = idx + 1;
		ret->name = name;
		ret->ver = 0;
		ret->hidden = false;
		if (iter->versyms) {
#ifdef  HAVA_LIBELF
	if (!gelf_getversym(iter->versyms, idx, &versym))
				continue;
#elif HAVA_ELFIO
		versym = (GElf_Versym)iter->versysm->d_buf[idx];
#endif
		ret->ver = versym & VERSYM_VERSION;
		ret->hidden = versym & VERSYM_HIDDEN;
		}
		return ret;
	}
	return NULL;
}

static const char *elf_get_vername(struct elf_sym_iter *iter, int ver)
{
	GElf_Verdaux verdaux;
	GElf_Verdef verdef;
	int offset;
	if (!iter->verdefs)
		return NULL;
	offset = 0;
#ifdef  HAVE_LIBELF
	while (gelf_getverdef(iter->verdefs, offset, &verdef)) {
		if (verdef.vd_ndx != ver) {
			if (!verdef.vd_next)
				break;
			offset += verdef.vd_next;
			continue;
		}
	 if (!gelf_getverdaux(iter->verdefs, offset + verdef.vd_aux, &verdaux))
			break;
		return elf_strptr(iter->elf, iter->verdef_strtabidx, verdaux.vda_name);
	}
#elif HAVE_ELFIO
	while (memcpy(&verdef, (void *)iter->verdefs->d_buf + offset, sizeof(GElf_Verdef)) != NULL) {
		if (verdef.vd_ndx != ver) {
			if (!verdef.vd_next)
				break;
			offset += verdef.vd_next;
			continue;
		}
		if(memcpy(&verdaux, (void *)iter->verdefs->d_buf + offset + verdef.vd_aux, sizeof(GElf_Verdaux)) == NULL) {
			break;
		}
		psection_t psection = elfio_get_section_by_index(iter->elf, iter->verdef_strtabidx);
		if (!psection)
			return NULL;
		pstring_t strstring = elfio_string_section_accessor_new(psection);
		return elfio_string_get_string(strstring, verdaux.vda_name);
	}
#endif
return NULL;
}

static bool symbol_match(struct elf_sym_iter *iter, int sh_type, struct elf_sym *sym,
			 const char *name, size_t name_len, const char *lib_ver)
{
	const char *ver_name;

	/* Symbols are in forms of func, func@LIB_VER or func@@LIB_VER
	 * make sure the func part matches the user specified name
	 */
	if (strncmp(sym->name, name, name_len) != 0)
		return false;

	/* ...but we don't want a search for "foo" to match 'foo2" also, so any
	 * additional characters in sname should be of the form "@@LIB".
	 */
	if (sym->name[name_len] != '\0' && sym->name[name_len] != '@')
		return false;

	/* If user does not specify symbol version, then we got a match */
	if (!lib_ver)
		return true;

	/* If user specifies symbol version, for dynamic symbols,
	 * get version name from ELF verdef section for comparison.
	 */
	if (sh_type == SHT_DYNSYM) {
		ver_name = elf_get_vername(iter, sym->ver);
		if (!ver_name)
			return false;
		return strcmp(ver_name, lib_ver) == 0;
	}

	/* For normal symbols, it is already in form of func@LIB_VER */
	return strcmp(sym->name, name) == 0;
}

/* Transform symbol's virtual address (absolute for binaries and relative
 * for shared libs) into file offset, which is what kernel is expecting
 * for uprobe/uretprobe attachment.
 * See Documentation/trace/uprobetracer.rst for more details. This is done
 * by looking up symbol's containing section's header and using iter's virtual
 * address (sh_addr) and corresponding file offset (sh_offset) to transform
 * sym.st_value (virtual address) into desired final file offset.
 */
static unsigned long elf_sym_offset(struct elf_sym *sym)
{
	return sym->sym.st_value - sym->sh.sh_addr + sym->sh.sh_offset;
}

/* Find offset of function name in the provided ELF object. "binary_path" is
 * the path to the ELF binary represented by "elf", and only used for error
 * reporting matters. "name" matches symbol name or name@@LIB for library
 * functions.
 */
#ifdef HAVE_LIBELF  
long elf_find_func_offset(Elf *elf, const char *binary_path, const char *name)
#elif HAVE_ELFIO
long elf_find_func_offset(pelfio_t elf, const char *binary_path, const char *name)
#endif
{
	int i, sh_types[2] = { SHT_DYNSYM, SHT_SYMTAB };
	const char *at_symbol, *lib_ver;
	bool is_shared_lib;
	long ret = -ENOENT;
	size_t name_len;
#ifdef  HAVE_LIBELF
	GElf_Ehdr ehdr;

	if (!gelf_getehdr(elf, &ehdr)) {
		pr_warn("elf: failed to get ehdr from %s: %s\n", binary_path, elf_errmsg(-1));
		ret = -LIBBPF_ERRNO__FORMAT;
		goto out;
	}

	/* for shared lib case, we do not need to calculate relative offset */
	is_shared_lib = ehdr.e_type == ET_DYN;
#elif HAVA_ELFIO
	is_shared_lib = (ET_DYN == elfio_get_type(pelfio));
#endif
	/* Does name specify "@@LIB_VER" or "@LIB_VER" ? */
	at_symbol = strchr(name, '@');
	if (at_symbol) {
		name_len = at_symbol - name;
		/* skip second @ if it's @@LIB_VER case */
		if (at_symbol[1] == '@')
			at_symbol++;
		lib_ver = at_symbol + 1;
	} else {
		name_len = strlen(name);
		lib_ver = NULL;
	}

	/* Search SHT_DYNSYM, SHT_SYMTAB for symbol. This search order is used because if
	 * a binary is stripped, it may only have SHT_DYNSYM, and a fully-statically
	 * linked binary may not have SHT_DYMSYM, so absence of a section should not be
	 * reported as a warning/error.
	 */
	for (i = 0; i < ARRAY_SIZE(sh_types); i++) {
		struct elf_sym_iter iter;
		struct elf_sym *sym;
		int last_bind = -1;
		int cur_bind;

		ret = elf_sym_iter_new(&iter, elf, binary_path, sh_types[i], STT_FUNC);
		if (ret == -ENOENT)
			continue;
		if (ret)
			goto out;

		while ((sym = elf_sym_iter_next(&iter))) {
			if (!symbol_match(&iter, sh_types[i], sym, name, name_len, lib_ver))
				continue;

			cur_bind = GELF_ST_BIND(sym->sym.st_info);

			if (ret > 0) {
				/* handle multiple matches */
				if (elf_sym_offset(sym) == ret) {
					/* same offset, no problem */
					continue;
				} else if (last_bind != STB_WEAK && cur_bind != STB_WEAK) {
					/* Only accept one non-weak bind. */
					pr_warn("elf: ambiguous match for '%s', '%s' in '%s'\n",
						sym->name, name, binary_path);
					ret = -LIBBPF_ERRNO__FORMAT;
					goto out;
				} else if (cur_bind == STB_WEAK) {
					/* already have a non-weak bind, and
					 * this is a weak bind, so ignore.
					 */
					continue;
				}
			}

			ret = elf_sym_offset(sym);
			last_bind = cur_bind;
		}
		if (ret > 0)
			break;
	}

	if (ret > 0) {
		pr_debug("elf: symbol address match for '%s' in '%s': 0x%lx\n", name, binary_path,
			 ret);
	} else {
		if (ret == 0) {
			pr_warn("elf: '%s' is 0 in symtab for '%s': %s\n", name, binary_path,
				is_shared_lib ? "should not be 0 in a shared library" :
						"try using shared library path instead");
			ret = -ENOENT;
		} else {
			pr_warn("elf: failed to find symbol '%s' in '%s'\n", name, binary_path);
		}
	}
out:
	return ret;
}

/* Find offset of function name in ELF object specified by path. "name" matches
 * symbol name or name@@LIB for library functions.
 */
long elf_find_func_offset_from_file(const char *binary_path, const char *name)
{
	struct elf_fd elf_fd;
	long ret = -ENOENT;

	ret = elf_open(binary_path, &elf_fd);
	if (ret)
		return ret;
	ret = elf_find_func_offset(elf_fd.elf, binary_path, name);
	elf_close(&elf_fd);
	return ret;
}

struct symbol {
	const char *name;
	int bind;
	int idx;
};

static int symbol_cmp(const void *a, const void *b)
{
	const struct symbol *sym_a = a;
	const struct symbol *sym_b = b;

	return strcmp(sym_a->name, sym_b->name);
}

/*
 * Return offsets in @poffsets for symbols specified in @syms array argument.
 * On success returns 0 and offsets are returned in allocated array with @cnt
 * size, that needs to be released by the caller.
 */
int elf_resolve_syms_offsets(const char *binary_path, int cnt,
			     const char **syms, unsigned long **poffsets)
{
	int sh_types[2] = { SHT_DYNSYM, SHT_SYMTAB };
	int err = 0, i, cnt_done = 0;
	unsigned long *offsets;
	struct symbol *symbols;
	struct elf_fd elf_fd;

	err = elf_open(binary_path, &elf_fd);
	if (err)
		return err;

	offsets = calloc(cnt, sizeof(*offsets));
	symbols = calloc(cnt, sizeof(*symbols));

	if (!offsets || !symbols) {
		err = -ENOMEM;
		goto out;
	}

	for (i = 0; i < cnt; i++) {
		symbols[i].name = syms[i];
		symbols[i].idx = i;
	}

	qsort(symbols, cnt, sizeof(*symbols), symbol_cmp);

	for (i = 0; i < ARRAY_SIZE(sh_types); i++) {
		struct elf_sym_iter iter;
		struct elf_sym *sym;

		err = elf_sym_iter_new(&iter, elf_fd.elf, binary_path, sh_types[i], STT_FUNC);
		if (err == -ENOENT)
			continue;
		if (err)
			goto out;

		while ((sym = elf_sym_iter_next(&iter))) {
			unsigned long sym_offset = elf_sym_offset(sym);
			int bind = GELF_ST_BIND(sym->sym.st_info);
			struct symbol *found, tmp = {
				.name = sym->name,
			};
			unsigned long *offset;

			found = bsearch(&tmp, symbols, cnt, sizeof(*symbols), symbol_cmp);
			if (!found)
				continue;

			offset = &offsets[found->idx];
			if (*offset > 0) {
				/* same offset, no problem */
				if (*offset == sym_offset)
					continue;
				/* handle multiple matches */
				if (found->bind != STB_WEAK && bind != STB_WEAK) {
					/* Only accept one non-weak bind. */
					pr_warn("elf: ambiguous match found '%s@%lu' in '%s' previous offset %lu\n",
						sym->name, sym_offset, binary_path, *offset);
					err = -ESRCH;
					goto out;
				} else if (bind == STB_WEAK) {
					/* already have a non-weak bind, and
					 * this is a weak bind, so ignore.
					 */
					continue;
				}
			} else {
				cnt_done++;
			}
			*offset = sym_offset;
			found->bind = bind;
		}
	}

	if (cnt != cnt_done) {
		err = -ENOENT;
		goto out;
	}

	*poffsets = offsets;

out:
	free(symbols);
	if (err)
		free(offsets);
	elf_close(&elf_fd);
	return err;
}

/*
 * Return offsets in @poffsets for symbols specified by @pattern argument.
 * On success returns 0 and offsets are returned in allocated @poffsets
 * array with the @pctn size, that needs to be released by the caller.
 */
int elf_resolve_pattern_offsets(const char *binary_path, const char *pattern,
				unsigned long **poffsets, size_t *pcnt)
{
	int sh_types[2] = { SHT_SYMTAB, SHT_DYNSYM };
	unsigned long *offsets = NULL;
	size_t cap = 0, cnt = 0;
	struct elf_fd elf_fd;
	int err = 0, i;

	err = elf_open(binary_path, &elf_fd);
	if (err)
		return err;

	for (i = 0; i < ARRAY_SIZE(sh_types); i++) {
		struct elf_sym_iter iter;
		struct elf_sym *sym;

		err = elf_sym_iter_new(&iter, elf_fd.elf, binary_path, sh_types[i], STT_FUNC);
		if (err == -ENOENT)
			continue;
		if (err)
			goto out;

		while ((sym = elf_sym_iter_next(&iter))) {
			if (!glob_match(sym->name, pattern))
				continue;

			err = libbpf_ensure_mem((void **) &offsets, &cap, sizeof(*offsets),
						cnt + 1);
			if (err)
				goto out;

			offsets[cnt++] = elf_sym_offset(sym);
		}

		/* If we found anything in the first symbol section,
		 * do not search others to avoid duplicates.
		 */
		if (cnt)
			break;
	}

	if (cnt) {
		*poffsets = offsets;
		*pcnt = cnt;
	} else {
		err = -ENOENT;
	}

out:
	if (err)
		free(offsets);
	elf_close(&elf_fd);
	return err;
}
