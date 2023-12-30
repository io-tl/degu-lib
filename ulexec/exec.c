#include <fcntl.h>
#include <stddef.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <reflect.h>

#include "reflect_common.h"

extern char **environ;

#define JUMP_WITH_STACK(jump_addr, jump_stack) \
	__asm__ volatile ( \
			"movq %[stack], %%rsp\n" /* reset the stack to our pivot */ \
			"xor %%rdx, %%rdx\n" /* zero rdx so no one thinks it's a function pointer for cleanup */ \
			"jmp *%[entry]" /* Up, up, and away! */ \
			: /* None  */ \
			: [stack] "r" (jump_stack), [entry] "r" (jump_addr) \
			: "rdx", "memory" \
			)

int reflect_execv(const unsigned char *elf, char **argv,size_t binsize) {
	dprint("Using default environment %p\n", (void *)environ);
	return reflect_execve(elf, argv, NULL,binsize);
}

int reflect_execve(const unsigned char *elf, char **argv, char **env,size_t binsize) {
	// When allocating a new stack, be sure to give it lots of space since the OS
	// won't always honor MAP_GROWSDOWN
	size_t *new_stack = (void *) (2047 * PAGE_SIZE +  (char *) mmap(0, 2048 * PAGE_SIZE,
		PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE|MAP_GROWSDOWN, -1, 0));

	return reflect_execves(elf, argv, env, new_stack, binsize);
}

int reflect_execves(const unsigned char *elf, char **argv, char **env, size_t *stack,size_t binsize) {
	int fd;
	unsigned char *data = NULL;
	size_t argc;

	struct mapped_elf exe = {0}, interp = {0};

	if (!is_compatible_elf((ElfW(Ehdr) *)elf)) {
		return 1;
	}


	if (env == NULL) {
		env = environ;
	}

	map_elf(elf, &exe);
	if (exe.ehdr == MAP_FAILED) {
		dprint("Unable to map ELF file: %s\n", strerror(errno));
		return 1;
	}

	if (exe.interp) {
		// Load input ELF executable into memory
		fd = open(exe.interp, O_RDONLY);
		if(fd == -1) {
			dprint("Failed to open %p: %s\n", exe.interp, strerror(errno));
			return 1;
		}

		data = mmap(NULL, binsize, PROT_READ, MAP_PRIVATE, fd, 0);
		if(data == MAP_FAILED) {
			dprint("Unable to read ELF file in: %s\n", strerror(errno));
			return 1;
		}
		close(fd);

		map_elf(data, &interp);
		munmap(data, binsize);
		if (interp.ehdr == MAP_FAILED) {
			dprint("Unable to map interpreter for ELF file: %s\n", strerror(errno));
			return 1;
		}
		dprint("Mapped ELF interp file in: %s\n", exe.interp);
	} else {
		interp = exe;
	}

	for (argc = 0; argv[argc]; argc++);

	stack_setup(stack, argc, argv, env, NULL,
			exe.ehdr, interp.ehdr);

	JUMP_WITH_STACK(interp.entry_point, stack);
	return 0;
}
