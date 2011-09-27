#define _GNU_SOURCE /* For getline.  */
#include "config.h"
#include "common.h"

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
each_line_starting(FILE * file, const char *prefix,
		   enum pcb_status (*cb)(const char * line, const char * prefix,
					 void * data),
		   void * data)
{
	size_t len = strlen(prefix);
	char * line;
	while ((line = find_line_starting(file, prefix, len)) != NULL) {
		enum pcb_status st = (*cb)(line, prefix, data);
		free (line);
		if (st == pcb_stop)
			return;
	}
}

static enum pcb_status
process_leader_cb(const char * line, const char * prefix, void * data)
{
	pid_t * pidp = data;
	*pidp = atoi(line + strlen(prefix));
	return pcb_stop;
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

static enum pcb_status
process_stopped_cb(const char * line, const char * prefix, void * data)
{
	char c = line[strlen(prefix)];
	// t:tracing stop, T:job control stop
	*(int *)data = (c == 't' || c == 'T');
	return pcb_stop;
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

static enum pcb_status
process_status_cb(const char * line, const char * prefix, void * data)
{
	const char * status = line + strlen(prefix);
	const char c = *status;

#define RETURN(C) do {					\
		*(enum process_status *)data = C;	\
		return pcb_stop;			\
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

static int
find_dynamic_entry_addr(Process *proc, void *pvAddr, int d_tag, void **addr) {
	int i = 0, done = 0;
	ElfW(Dyn) entry;

	debug(DEBUG_FUNCTION, "find_dynamic_entry()");

	if (addr ==	NULL || pvAddr == NULL || d_tag < 0 || d_tag > DT_NUM) {
		return -1;
	}

	while ((!done) && (i < ELF_MAX_SEGMENTS) &&
		(sizeof(entry) == umovebytes(proc, pvAddr, &entry, sizeof(entry))) &&
		(entry.d_tag != DT_NULL)) {
		if (entry.d_tag == d_tag) {
			done = 1;
			*addr = (void *)entry.d_un.d_val;
		}
		pvAddr += sizeof(entry);
		i++;
	}

	if (done) {
		debug(2, "found address: 0x%p in dtag %d\n", *addr, d_tag);
		return 0;
	}
	else {
		debug(2, "Couldn't address for dtag!\n");
		return -1;
	}
}

struct cb_data {
	const char *lib_name;
	struct ltelf *lte;
	ElfW(Addr) addr;
	Process *proc;
};

static void
crawl_linkmap(Process *proc, struct r_debug *dbg, void (*callback)(void *), struct cb_data *data) {
	struct link_map rlm;
	char lib_name[BUFSIZ];
	struct link_map *lm = NULL;

	debug (DEBUG_FUNCTION, "crawl_linkmap()");

	if (!dbg || !dbg->r_map) {
		debug(2, "Debug structure or it's linkmap are NULL!");
		return;
	}

	lm = dbg->r_map;

	while (lm) {
		if (umovebytes(proc, lm, &rlm, sizeof(rlm)) != sizeof(rlm)) {
			debug(2, "Unable to read link map\n");
			return;
		}

		lm = rlm.l_next;
		if (rlm.l_name == NULL) {
			debug(2, "Invalid library name referenced in dynamic linker map\n");
			return;
		}

		umovebytes(proc, rlm.l_name, lib_name, sizeof(lib_name));

		if (lib_name[0] == '\0') {
			debug(2, "Library name is an empty string");
			continue;
		}

		if (callback) {
			debug(2, "Dispatching callback for: %s, "
					"Loaded at 0x%" PRI_ELF_ADDR "\n",
					lib_name, rlm.l_addr);
			data->addr = rlm.l_addr;
			data->lib_name = lib_name;
			callback(data);
		}
	}
	return;
}

static struct r_debug *
load_debug_struct(Process *proc) {
	struct r_debug *rdbg = NULL;

	debug(DEBUG_FUNCTION, "load_debug_struct");

	rdbg = malloc(sizeof(*rdbg));
	if (!rdbg) {
		return NULL;
	}

	if (umovebytes(proc, proc->debug, rdbg, sizeof(*rdbg)) != sizeof(*rdbg)) {
		debug(2, "This process does not have a debug structure!\n");
		free(rdbg);
		return NULL;
	}

	return rdbg;
}

static void
linkmap_add_cb(void *data) { //const char *lib_name, ElfW(Addr) addr) {
	size_t i = 0;
	struct cb_data *lm_add = data;
	struct ltelf lte;
	struct opt_x_t *xptr;

	debug(DEBUG_FUNCTION, "linkmap_add_cb");

	/*
		XXX
		iterate through library[i]'s to see if this lib is in the list.
		if not, add it
	 */
	for(;i < library_num;i++) {
		if (strcmp(library[i], lm_add->lib_name) == 0) {
			/* found it, so its not new */
			return;
		}
	}

	/* new library linked! */
	debug(2, "New libdl loaded library found: %s\n", lm_add->lib_name);

	if (library_num < MAX_LIBRARIES) {
		library[library_num++] = strdup(lm_add->lib_name);
		memset(&lte, 0, sizeof(struct ltelf));
		lte.base_addr = lm_add->addr;
		do_init_elf(&lte, library[library_num-1]);
		/* add bps */
		for (xptr = opt_x; xptr; xptr = xptr->next) {
			if (xptr->found)
				continue;

			GElf_Sym sym;
			GElf_Addr addr;

			if (in_load_libraries(xptr->name, &lte, 1, &sym)) {
				debug(2, "found symbol %s @ %#" PRIx64
						", adding it.",
						xptr->name, sym.st_value);
				addr = sym.st_value;
				add_library_symbol(addr, xptr->name, &library_symbols, LS_TOPLT_NONE, 0);
				xptr->found = 1;
				insert_breakpoint(lm_add->proc,
						  sym2addr(lm_add->proc,
							   library_symbols),
						  library_symbols, 1);
			}
		}
		do_close_elf(&lte);
	}
}

void
arch_check_dbg(Process *proc) {
	struct r_debug *dbg = NULL;
	struct cb_data data;

	debug(DEBUG_FUNCTION, "arch_check_dbg");

	if (!(dbg = load_debug_struct(proc))) {
		debug(2, "Unable to load debug structure!");
		return;
	}

	if (dbg->r_state == RT_CONSISTENT) {
		debug(2, "Linkmap is now consistent");
		if (proc->debug_state == RT_ADD) {
			debug(2, "Adding DSO to linkmap");
			data.proc = proc;
			crawl_linkmap(proc, dbg, linkmap_add_cb, &data);
		} else if (proc->debug_state == RT_DELETE) {
			debug(2, "Removing DSO from linkmap");
		} else {
			debug(2, "Unexpected debug state!");
		}
	}

	proc->debug_state = dbg->r_state;

	return;
}

static void
hook_libdl_cb(void *data) {
	struct cb_data *hook_data = data;
	const char *lib_name = NULL;
	ElfW(Addr) addr;
	struct ltelf *lte = NULL;

	debug(DEBUG_FUNCTION, "add_library_cb");

	if (!data) {
		debug(2, "No callback data");
		return;
	}

	lib_name = hook_data->lib_name;
	addr = hook_data->addr;
	lte = hook_data->lte;

	if (library_num < MAX_LIBRARIES) {
		lte[library_num].base_addr = addr;
		library[library_num++] = strdup(lib_name);
	}
	else {
		fprintf (stderr, "MAX LIBS REACHED\n");
		exit(EXIT_FAILURE);
	}
}

int
linkmap_init(Process *proc, struct ltelf *lte) {
	void *dbg_addr = NULL, *dyn_addr = GELF_ADDR_CAST(lte->dyn_addr);
	struct r_debug *rdbg = NULL;
	struct cb_data data;

	debug(DEBUG_FUNCTION, "linkmap_init()");

	if (find_dynamic_entry_addr(proc, dyn_addr, DT_DEBUG, &dbg_addr) == -1) {
		debug(2, "Couldn't find debug structure!");
		return -1;
	}

	proc->debug = dbg_addr;

	if (!(rdbg = load_debug_struct(proc))) {
		debug(2, "No debug structure or no memory to allocate one!");
		return -1;
	}

	data.lte = lte;

	add_library_symbol(rdbg->r_brk, "", &library_symbols, LS_TOPLT_NONE, 0);
	insert_breakpoint(proc, sym2addr(proc, library_symbols),
			  library_symbols, 1);

	crawl_linkmap(proc, rdbg, hook_libdl_cb, &data);

	free(rdbg);
	return 0;
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
