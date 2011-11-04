/*
 * posix_spawn : starts a command without ASLR and halted so that one can attach a debugger to it
 *
 * (c) pod2g 11/2011
 */
#include <stdio.h>
#include <stdlib.h>
#include <spawn.h>
#define _POSIX_SPAWN_DISABLE_ASLR 0x0100

void usage(char* name) {
	printf("Usage: %s <command> [command args...]\n", name);
}

int main(int argc, char* argv[]) {
	int i;
	int pid = -1;
	int retval;
	posix_spawnattr_t spattr;
	short spflags = POSIX_SPAWN_SETEXEC;

	if (argc <= 1) {
		fprintf(stderr, "ERROR: not enough arguments.\n");
		usage(argv[0]);
		exit(1);
	}

	retval = posix_spawnattr_init(&spattr);
	if (retval != 0) {
		fprintf(stderr, "FAIL: posix_spawnattr_init returned %d\n", retval);
		exit(1);
	}
	char** spargv = malloc(sizeof(char*) * (argc + 1));
	if (spargv == NULL) {
		fprintf(stderr, "FAIL: can't allocate memory for args\n");
		exit(1);
	}
	for (i = 1; i < argc; i++) {
		spargv[i - 1] = argv[i];
	}
	spargv[argc - 1] = NULL;

	//spflags |= POSIX_SPAWN_START_SUSPENDED;
	spflags |= _POSIX_SPAWN_DISABLE_ASLR;
	retval = posix_spawnattr_setflags(&spattr, spflags);
	if (retval != 0) {
		fprintf(stderr, "FAIL: posix_spawnattr_setflags returned %d\n", retval);
		exit(1);
	}
	retval = posix_spawn(&pid, argv[1], NULL, &spattr, spargv, NULL);
	
	// not reached if posix_spawn worked
	if (retval != 0) {
		fprintf(stderr, "FAIL: posix_spawn returned %d\n", retval);
		exit(1);
	}

	// never reached
	return 0;
}
