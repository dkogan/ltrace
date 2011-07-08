#include "config.h"

#if defined(HAVE_LIBUNWIND)
#include <libunwind-ptrace.h>
#endif /* defined(HAVE_LIBUNWIND) */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <pwd.h>
#include <grp.h>

#include "common.h"

static void
change_uid(const char * command)
{
	uid_t run_uid, run_euid;
	gid_t run_gid, run_egid;

	if (options.user) {
		struct passwd *pent;

		if (getuid() != 0 || geteuid() != 0) {
			fprintf(stderr,
				"you must be root to use the -u option\n");
			exit(1);
		}
		if ((pent = getpwnam(options.user)) == NULL) {
			fprintf(stderr, "cannot find user `%s'\n", options.user);
			exit(1);
		}
		run_uid = pent->pw_uid;
		run_gid = pent->pw_gid;

		if (initgroups(options.user, run_gid) < 0) {
			perror("ltrace: initgroups");
			exit(1);
		}
	} else {
		run_uid = getuid();
		run_gid = getgid();
	}
	if (options.user || !geteuid()) {
		struct stat statbuf;
		run_euid = run_uid;
		run_egid = run_gid;

		if (!stat(command, &statbuf)) {
			if (statbuf.st_mode & S_ISUID) {
				run_euid = statbuf.st_uid;
			}
			if (statbuf.st_mode & S_ISGID) {
				run_egid = statbuf.st_gid;
			}
		}
		if (setregid(run_gid, run_egid) < 0) {
			perror("ltrace: setregid");
			exit(1);
		}
		if (setreuid(run_uid, run_euid) < 0) {
			perror("ltrace: setreuid");
			exit(1);
		}
	}
}

pid_t
execute_program(const char * command, char **argv)
{
	pid_t pid;

	debug(1, "Executing `%s'...", command);

	pid = fork();
	if (pid < 0) {
		perror("ltrace: fork");
		exit(1);
	} else if (!pid) {	/* child */
		change_uid(command);
		trace_me();
		execvp(command, argv);
		fprintf(stderr, "Can't execute `%s': %s\n", command,
			strerror(errno));
		_exit(1);
	}

	debug(1, "PID=%d", pid);

	return pid;
}
