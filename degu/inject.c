#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <elf.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <stddef.h>
#include <assert.h>
#include <sys/ptrace.h>
#include <asm/ptrace.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <signal.h>
#include <limits.h>
#include <dlfcn.h>
#include "degu.h"
#include "injector.h"

#define INVALID_PID -1

int inject(int pid,char *dso) {
	injector_t *injector;
    
    if (injector_attach(&injector, pid) != 0) {
        fprintf(stderr, "%i 3<\n",pid);
        return -101;
    }
	if (!injector_inject(injector, dso, NULL) == 0) {
		fprintf(stderr, "%s :(\n",dso);
		return -102;
	}
	return 0;
}

