#define _GNU_SOURCE /* For getline.  */
#include "config.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <inttypes.h>
#include <link.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <dirent.h>
#include <ctype.h>
#include <errno.h>
#include <sys/syscall.h>
#include <error.h>

#include "common.h"
#include "breakpoint.h"
#include "proc.h"
#include "library.h"

/* /proc/pid doesn't exist just after the fork, and sometimes `ltrace'
 * couldn't open it to find the executable.  So it may be necessary to
 * have a bit delay
 */

#define	MAX_DELAY	100000	/* 100000 microseconds = 0.1 seconds */

#define PROC_PID_FILE(VAR, FORMAT, PID)		\
	char VAR[strlen(FORMAT) + 6];		\
	sprintf(VAR, FORMAT, PID)

/*
 * Returns a (malloc'd) file name corresponding to a running pid
 */
char *
pid2name(pid_t pid) {
	if (!kill(pid, 0)) {
		int delay = 0;

		PROC_PID_FILE(proc_exe, "/proc/%d/exe", pid);

		while (delay < MAX_DELAY) {
			if (!access(proc_exe, F_OK)) {
				return strdup(proc_exe);
			}
			delay += 1000;	/* 1 milisecond */
		}
	}
	return NULL;
}

static FILE *
open_status_file(pid_t pid)
{
	PROC_PID_FILE(fn, "/proc/%d/status", pid);
	/* Don't complain if we fail.  This would typically happen
	   when the process is about to terminate, and these files are
	   not available anymore.  This function is called from the
	   event loop, and we don't want to clutter the output just
	   because the process terminates.  */
	return fopen(fn, "r");
}

static char *
find_line_starting(FILE * file, const char * prefix, size_t len)
{
	char * line = NULL;
	size_t line_len = 0;
	while (!feof(file)) {
		if (getline(&line, &line_len, file) < 0)
			return NULL;
		if (strncmp(line, prefix, len) == 0)
			return line;
	}
	return NULL;
}

static void
each_line_starting(FILE *file, const char *prefix,
		   enum callback_status (*cb)(const char *line,
					      const char *prefix,
					      void *data),
		   void *data)
{
	size_t len = strlen(prefix);
	char * line;
	while ((line = find_line_starting(file, prefix, len)) != NULL) {
		enum callback_status st = (*cb)(line, prefix, data);
		free (line);
		if (st == CBS_STOP)
			return;
	}
}

static enum callback_status
process_leader_cb(const char *line, const char *prefix, void *data)
{
	pid_t * pidp = data;
	*pidp = atoi(line + strlen(prefix));
	return CBS_STOP;
}

pid_t
process_leader(pid_t pid)
{
	pid_t tgid = 0;
	FILE * file = open_status_file(pid);
	if (file != NULL) {
		each_line_starting(file, "Tgid:\t", &process_leader_cb, &tgid);
		fclose(file);
	}

	return tgid;
}

static enum callback_status
process_stopped_cb(const char *line, const char *prefix, void *data)
{
	char c = line[strlen(prefix)];
	// t:tracing stop, T:job control stop
	*(int *)data = (c == 't' || c == 'T');
	return CBS_STOP;
}

int
process_stopped(pid_t pid)
{
	int is_stopped = -1;
	FILE * file = open_status_file(pid);
	if (file != NULL) {
		each_line_starting(file, "State:\t", &process_stopped_cb,
				   &is_stopped);
		fclose(file);
	}
	return is_stopped;
}

static enum callback_status
process_status_cb(const char *line, const char *prefix, void *data)
{
	const char * status = line + strlen(prefix);
	const char c = *status;

#define RETURN(C) do {					\
		*(enum process_status *)data = C;	\
		return CBS_STOP;			\
	} while (0)

	switch (c) {
	case 'Z': RETURN(ps_zombie);
	case 't': RETURN(ps_tracing_stop);
	case 'T':
		/* This can be either "T (stopped)" or, for older
		 * kernels, "T (tracing stop)".  */
		if (!strcmp(status, "T (stopped)\n"))
			RETURN(ps_stop);
		else if (!strcmp(status, "T (tracing stop)\n"))
			RETURN(ps_tracing_stop);
		else {
			fprintf(stderr, "Unknown process status: %s",
				status);
			RETURN(ps_stop); /* Some sort of stop
					  * anyway.  */
		}
	case 'D':
	case 'S': RETURN(ps_sleeping);
	}

	RETURN(ps_other);
#undef RETURN
}

enum process_status
process_status(pid_t pid)
{
	enum process_status ret = ps_invalid;
	FILE * file = open_status_file(pid);
	if (file != NULL) {
		each_line_starting(file, "State:\t", &process_status_cb, &ret);
		fclose(file);
		if (ret == ps_invalid)
			error(0, errno, "process_status %d", pid);
	} else
		/* If the file is not present, the process presumably
		 * exited already.  */
		ret = ps_zombie;

	return ret;
}

static int
all_digits(const char *str)
{
	while (isdigit(*str))
		str++;
	return !*str;
}

int
process_tasks(pid_t pid, pid_t **ret_tasks, size_t *ret_n)
{
	PROC_PID_FILE(fn, "/proc/%d/task", pid);
	DIR * d = opendir(fn);
	if (d == NULL)
		return -1;

	pid_t *tasks = NULL;
	size_t n = 0;
	size_t alloc = 0;

	while (1) {
		struct dirent entry;
		struct dirent *result;
		if (readdir_r(d, &entry, &result) != 0) {
			free(tasks);
			return -1;
		}
		if (result == NULL)
			break;
		if (result->d_type == DT_DIR && all_digits(result->d_name)) {
			pid_t npid = atoi(result->d_name);
			if (n >= alloc) {
				alloc = alloc > 0 ? (2 * alloc) : 8;
				pid_t *ntasks = realloc(tasks,
							sizeof(*tasks) * alloc);
				if (ntasks == NULL) {
					free(tasks);
					return -1;
				}
				tasks = ntasks;
			}
			if (n >= alloc)
				abort();
			tasks[n++] = npid;
		}
	}

	closedir(d);

	*ret_tasks = tasks;
	*ret_n = n;
	return 0;
}

/* On native 64-bit system, we need to be careful when handling cross
 * tracing.  This select appropriate pointer depending on host and
 * target architectures.  XXX Really we should abstract this into the
 * ABI object, as theorized about somewhere on pmachata/revamp
 * branch.  */
static void *
select_32_64(struct Process *proc, void *p32, void *p64)
{
	if (sizeof(long) == 4 || proc->mask_32bit)
		return p32;
	else
		return p64;
}

static int
fetch_dyn64(struct Process *proc, target_address_t *addr, Elf64_Dyn *ret)
{
	if (umovebytes(proc, *addr, ret, sizeof(*ret)) != sizeof(*ret))
		return -1;
	*addr += sizeof(*ret);
	return 0;
}

static int
fetch_dyn32(struct Process *proc, target_address_t *addr, Elf64_Dyn *ret)
{
	Elf32_Dyn dyn;
	if (umovebytes(proc, *addr, &dyn, sizeof(dyn)) != sizeof(dyn))
		return -1;

	*addr += sizeof(dyn);
	ret->d_tag = dyn.d_tag;
	ret->d_un.d_val = dyn.d_un.d_val;

	return 0;
}

static int (*
dyn_fetcher(struct Process *proc))(struct Process *,
				   target_address_t *, Elf64_Dyn *)
{
	return select_32_64(proc, fetch_dyn32, fetch_dyn64);
}

static int
find_dynamic_entry_addr(struct Process *proc, target_address_t src_addr,
			int d_tag, target_address_t *ret)
{
	debug(DEBUG_FUNCTION, "find_dynamic_entry()");

	if (ret == NULL || src_addr == 0 || d_tag < 0 || d_tag > DT_NUM)
		return -1;

	int i = 0;
	while (1) {
		Elf64_Dyn entry;
		if (dyn_fetcher(proc)(proc, &src_addr, &entry) < 0
		    || entry.d_tag == DT_NULL
		    || i++ > 100) { /* Arbitrary cut-off so that we
				     * don't loop forever if the
				     * binary is corrupted.  */
			debug(2, "Couldn't find address for dtag!");
			return -1;
		}

		if (entry.d_tag == d_tag) {
			*ret = (target_address_t)entry.d_un.d_val;
			debug(2, "found address: %p in dtag %d\n", *ret, d_tag);
			return 0;
		}
	}
}

/* Our own type for representing 32-bit linkmap.  We can't rely on the
 * definition in link.h, because that's only accurate for our host
 * architecture, not for target architecture (where the traced process
 * runs). */
#define LT_LINK_MAP(BITS)			\
	{					\
		Elf##BITS##_Addr l_addr;	\
		Elf##BITS##_Addr l_name;	\
		Elf##BITS##_Addr l_ld;		\
		Elf##BITS##_Addr l_next;	\
		Elf##BITS##_Addr l_prev;	\
	}
struct lt_link_map_32 LT_LINK_MAP(32);
struct lt_link_map_64 LT_LINK_MAP(64);

static int
fetch_lm64(struct Process *proc, target_address_t addr,
	   struct lt_link_map_64 *ret)
{
	if (umovebytes(proc, addr, ret, sizeof(*ret)) != sizeof(*ret))
		return -1;
	return 0;
}

static int
fetch_lm32(struct Process *proc, target_address_t addr,
	   struct lt_link_map_64 *ret)
{
	struct lt_link_map_32 lm;
	if (umovebytes(proc, addr, &lm, sizeof(lm)) != sizeof(lm))
		return -1;

	ret->l_addr = lm.l_addr;
	ret->l_name = lm.l_name;
	ret->l_ld = lm.l_ld;
	ret->l_next = lm.l_next;
	ret->l_prev = lm.l_prev;

	return 0;
}

static int (*
lm_fetcher(struct Process *proc))(struct Process *,
				  target_address_t, struct lt_link_map_64 *)
{
	return select_32_64(proc, fetch_lm32, fetch_lm64);
}

/* The same as above holds for struct r_debug.  */
#define LT_R_DEBUG(BITS)			\
	{					\
		int r_version;			\
		Elf##BITS##_Addr r_map;		\
		Elf##BITS##_Addr r_brk;		\
		int r_state;			\
		Elf##BITS##_Addr r_ldbase;	\
	}

struct lt_r_debug_32 LT_R_DEBUG(32);
struct lt_r_debug_64 LT_R_DEBUG(64);

static int
fetch_rd64(struct Process *proc, target_address_t addr,
	   struct lt_r_debug_64 *ret)
{
	if (umovebytes(proc, addr, ret, sizeof(*ret)) != sizeof(*ret))
		return -1;
	return 0;
}

static int
fetch_rd32(struct Process *proc, target_address_t addr,
	   struct lt_r_debug_64 *ret)
{
	struct lt_r_debug_32 rd;
	if (umovebytes(proc, addr, &rd, sizeof(rd)) != sizeof(rd))
		return -1;

	ret->r_version = rd.r_version;
	ret->r_map = rd.r_map;
	ret->r_brk = rd.r_brk;
	ret->r_state = rd.r_state;
	ret->r_ldbase = rd.r_ldbase;

	return 0;
}

static int (*
rdebug_fetcher(struct Process *proc))(struct Process *,
				      target_address_t, struct lt_r_debug_64 *)
{
	return select_32_64(proc, fetch_rd32, fetch_rd64);
}

static void
crawl_linkmap(struct Process *proc, struct lt_r_debug_64 *dbg)
{
	debug (DEBUG_FUNCTION, "crawl_linkmap()");

	if (!dbg || !dbg->r_map) {
		debug(2, "Debug structure or it's linkmap are NULL!");
		return;
	}

	target_address_t addr = (target_address_t)dbg->r_map;

	while (addr != 0) {
		struct lt_link_map_64 rlm;
		if (lm_fetcher(proc)(proc, addr, &rlm) < 0) {
			debug(2, "Unable to read link map");
			return;
		}

		target_address_t key = addr;
		addr = (target_address_t)rlm.l_next;
		if (rlm.l_name == 0) {
			debug(2, "Name of mapped library is NULL");
			return;
		}

		char lib_name[BUFSIZ];
		umovebytes(proc, (target_address_t)rlm.l_name,
			   lib_name, sizeof(lib_name));

		if (*lib_name == '\0') {
			/* VDSO.  No associated file, XXX but we might
			 * load it from the address space of the
			 * process.  */
			continue;
		}

		/* Do we have that library already?  */
		if (proc_each_library(proc, NULL, library_with_key_cb, &key))
			continue;

		struct library *lib = malloc(sizeof(*lib));
		if (lib == NULL) {
		fail:
			if (lib != NULL)
				library_destroy(lib);
			error(0, errno, "Couldn't load ELF object %s\n",
			      lib_name);
			continue;
		}
		library_init(lib, LT_LIBTYPE_DSO);

		if (ltelf_read_library(lib, proc, lib_name, rlm.l_addr) < 0)
			goto fail;

		lib->key = key;
		proc_add_library(proc, lib);
	}
	return;
}

/* A struct stored at proc->debug.  */
struct debug_struct
{
	target_address_t debug_addr;
	int state;
};

static int
load_debug_struct(struct Process *proc, struct lt_r_debug_64 *ret)
{
	debug(DEBUG_FUNCTION, "load_debug_struct");

	struct debug_struct *debug = proc->debug;

	if (rdebug_fetcher(proc)(proc, debug->debug_addr, ret) < 0) {
		debug(2, "This process does not have a debug structure!\n");
		return -1;
	}

	return 0;
}

static void
rdebug_bp_on_hit(struct breakpoint *bp, struct Process *proc)
{
	debug(DEBUG_FUNCTION, "arch_check_dbg");

	struct lt_r_debug_64 rdbg;
	if (load_debug_struct(proc, &rdbg) < 0) {
		debug(2, "Unable to load debug structure!");
		return;
	}

	struct debug_struct *debug = proc->debug;
	if (rdbg.r_state == RT_CONSISTENT) {
		debug(2, "Linkmap is now consistent");
		if (debug->state == RT_ADD) {
			debug(2, "Adding DSO to linkmap");
			//data.proc = proc;
			crawl_linkmap(proc, &rdbg);
			//&data);
		} else if (debug->state == RT_DELETE) {
			debug(2, "Removing DSO from linkmap");
		} else {
			debug(2, "Unexpected debug state!");
		}
	}

	debug->state = rdbg.r_state;
}

int
linkmap_init(struct Process *proc, target_address_t dyn_addr)
{
	debug(DEBUG_FUNCTION, "linkmap_init()");

	struct debug_struct *debug = malloc(sizeof(*debug));
	if (debug == NULL) {
		error(0, errno, "couldn't allocate debug struct");
	fail:
		proc->debug = NULL;
		free(debug);
		return -1;
	}
	proc->debug = debug;

	if (find_dynamic_entry_addr(proc, dyn_addr, DT_DEBUG,
				    &debug->debug_addr) == -1) {
		debug(2, "Couldn't find debug structure!");
		goto fail;
	}

	int status;
	struct lt_r_debug_64 rdbg;
	if ((status = load_debug_struct(proc, &rdbg)) < 0) {
		debug(2, "No debug structure or no memory to allocate one!");
		return status;
	}

	target_address_t addr = (target_address_t)rdbg.r_brk;
	if (arch_translate_address(proc, addr, &addr) < 0)
		goto fail;

	struct breakpoint *rdebug_bp = insert_breakpoint(proc, addr, NULL);
	static struct bp_callbacks rdebug_callbacks = {
		.on_hit = rdebug_bp_on_hit,
	};
	rdebug_bp->cbs = &rdebug_callbacks;

	crawl_linkmap(proc, &rdbg);

	return 0;
}

static int
fetch_auxv64_entry(int fd, Elf64_auxv_t *ret)
{
	/* Reaching EOF is as much problem as not reading whole
	 * entry.  */
	return read(fd, ret, sizeof(*ret)) == sizeof(*ret) ? 0 : -1;
}

static int
fetch_auxv32_entry(int fd, Elf64_auxv_t *ret)
{
	Elf32_auxv_t auxv;
	if (read(fd, &auxv, sizeof(auxv)) != sizeof(auxv))
		return -1;

	ret->a_type = auxv.a_type;
	ret->a_un.a_val = auxv.a_un.a_val;
	return 0;
}

static int (*
auxv_fetcher(struct Process *proc))(int, Elf64_auxv_t *)
{
	return select_32_64(proc, fetch_auxv32_entry, fetch_auxv64_entry);
}

int
process_get_entry(struct Process *proc,
		  target_address_t *entryp,
		  target_address_t *interp_biasp)
{
	PROC_PID_FILE(fn, "/proc/%d/auxv", proc->pid);
	int fd = open(fn, O_RDONLY);
	if (fd == -1) {
	fail:
		error(0, errno, "couldn't read %s", fn);
	done:
		if (fd != -1)
			close(fd);
		return fd == -1 ? -1 : 0;
	}

	target_address_t at_entry = 0;
	target_address_t at_bias = 0;
	while (1) {
		Elf64_auxv_t entry;
		if (auxv_fetcher(proc)(fd, &entry) < 0)
			goto fail;

		switch (entry.a_type) {
		case AT_BASE:
			at_bias = (target_address_t)entry.a_un.a_val;
			continue;

		case AT_ENTRY:
			at_entry = (target_address_t)entry.a_un.a_val;
		default:
			continue;

		case AT_NULL:
			break;
		}
		break;
	}

	*entryp = at_entry;
	*interp_biasp = at_bias;
	goto done;
}

int
task_kill (pid_t pid, int sig)
{
	// Taken from GDB
        int ret;

        errno = 0;
        ret = syscall (__NR_tkill, pid, sig);
	return ret;
}
