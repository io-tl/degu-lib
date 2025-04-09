#CC = clang
CC = gcc
CLFAGS =
LDFLAGS = -Wl,--wrap=memcpy -Wl,--wrap=realpath -Wl,--wrap=__isoc99_sscanf -Wl,--wrap=vsscanf \
	  -Wl,--wrap=__isoc99_vsscanf -Wl,--wrap=stat -Wl,--wrap=__libc_start_main -Wl,--wrap=regexec \
	  -Wl,--wrap=getauxval -Wl,--wrap=fstat -Wl,--wrap=gnu_dev_makedev -Wl,--wrap=glob \
	  -Wl,--wrap=__isoc99_fscanf -Wl,--wrap=vfscanf

export CFLAGS
export LDFLAGS
ifeq ($(DEBUG),yes)
    CFLAGS +=  -Wall -fPIC -fno-stack-protector  -ggdb -g -DDEBUG 
    LDFLAGS +=  -Wl,-E  -pie  
else ifeq ($(ANALYZER),yes)
    CFLAGS +=  -Wall -fPIC -fno-stack-protector  -ggdb -g -DDEBUG -fanalyzer -fsanitize=address
    LDFLAGS +=  -Wl,-E  -pie -lasan 
else
    CFLAGS +=  -Wall -fPIC -fno-stack-protector -fvisibility=hidden -Wno-unused-value -Os -DPROD=1
    LDFLAGS +=  -g -Wl,-E -s -pie  
endif

.PHONY: degu
VERSION=0.0.3

export CFLAGS
export LDFLAGS

all:logo crypto/degucrypto.a injector/src/linux/libinjector.a ulexec/ulexe.a degu link

logo:
	@cat degu/degu.txt
	@echo DEGU ${VERSION}

crypto/degucrypto.a:
	@$(MAKE) -C crypto

injector/src/linux/libinjector.a:
	@echo Building injector
	@$(CC)           -c injector/src/linux/shellcode.S -o injector/src/linux/shellcode.o
	@$(CC) $(CFLAGS) -c injector/src/linux/elf.c -I injector/include -o injector/src/linux/elf.o -Wno-maybe-uninitialized
	@$(CC) $(CFLAGS) -c injector/src/linux/injector.c -I injector/include -o injector/src/linux/injector.o
	@$(CC) $(CFLAGS) -c injector/src/linux/ptrace.c -I injector/include -o injector/src/linux/ptrace.o
	@$(CC) $(CFLAGS) -c injector/src/linux/remote_call.c -I injector/include -o injector/src/linux/remote_call.o
	@$(CC) $(CFLAGS) -c injector/src/linux/util.c -I injector/include -o injector/src/linux/util.o
	@ar rcs injector/src/linux/libinjector.a injector/src/linux/elf.o injector/src/linux/injector.o \
        injector/src/linux/ptrace.o injector/src/linux/remote_call.o injector/src/linux/util.o injector/src/linux/shellcode.o


ulexec/ulexe.a:
	@$(MAKE) -C ulexec

degu:
	@$(MAKE) -C degu

link:
	@$(CC) p2s/pie2so.c -o pie2so
	@./pie2so degu.pie && mv degu.pie.so degu.so
	@rm -f pie2so degu.pie
	@strip degu.so
	@ls -al degu.so

clean:
	@$(RM) -f injector/src/linux/libinjector.a injector/src/linux/elf.o injector/src/linux/injector.o \
        injector/src/linux/ptrace.o injector/src/linux/remote_call.o injector/src/linux/util.o \
        injector/src/linux/shellcode.o
	@make -C crypto clean
	@make -C ulexec clean
	@make -C degu clean
	@$(RM) -f degu.so
