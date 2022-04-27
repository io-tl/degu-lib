#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <stdarg.h>
#include <fcntl.h>
#include <regex.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/stat.h>

asm (".symver memcpy, memcpy@GLIBC_2.2.5");
asm (".symver realpath, realpath@GLIBC_2.2.5");
asm (".symver __isoc99_sscanf, __isoc99_sscanf@GLIBC_2.2.5");
asm (".symver vsscanf, vsscanf@GLIBC_2.2.5");
asm (".symver __isoc99_vsscanf, vsscanf@GLIBC_2.2.5");
asm (".symver __libc_start_main, __libc_start_main@GLIBC_2.2.5");
asm (".symver regexec, regexec@GLIBC_2.2.5");

int __libc_start_main(int *main, int argc, char ** ubp_av, void *init, void *fini , void *rtld_fini, void *stack_end);

int __wrap___libc_start_main(int *main, int argc, char ** ubp_av, void *init, void *fini , void *rtld_fini, void *stack_end){
    return __libc_start_main(main,argc,ubp_av,init,fini,rtld_fini,stack_end);
}

void *__wrap_memcpy(void *dest, const void *src, size_t n)
{
    return memcpy(dest, src, n);
}
char *__wrap_realpath(const char *restrict path,char *restrict resolved_path)
{
    return realpath(path, resolved_path);
}

int __wrap___isoc99_sscanf(const char *restrict str,const char *restrict format, ...){
    va_list vargs = {0};
    va_start(vargs, format);
    int ret = vsscanf(str,format,vargs);
    va_end (vargs);
    return ret;
}

int __wrap___isoc99_vsscanf(const char *restrict str,const char *restrict format, va_list vargs){
    return vsscanf(str,format,vargs);
}

int __wrap_stat(const char *restrict path,struct stat *restrict buf) {
    return syscall( 4, path, buf );
}


int __wrap_regexec(void * preg, const char *restrict string, size_t nmatch, void *p , int eflags){
    return regexec(preg,string,nmatch,p,eflags);
}

