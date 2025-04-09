#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <stdarg.h>
#include <fcntl.h>
#include <regex.h>
#include <glob.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/auxv.h>

asm (".symver memcpy, memcpy@GLIBC_2.2.5");
asm (".symver realpath, realpath@GLIBC_2.2.5");
asm (".symver __isoc99_sscanf, __isoc99_sscanf@GLIBC_2.2.5");
asm (".symver __isoc99_vsscanf, vsscanf@GLIBC_2.2.5");
asm (".symver __isoc99_vfscanf, vfscanf@GLIBC_2.2.5");
asm (".symver __isoc99_fscanf, __isoc99_fscanf@GLIBC_2.2.5");
asm (".symver __libc_start_main, __libc_start_main@GLIBC_2.2.5");
asm (".symver regexec, regexec@GLIBC_2.2.5");
asm (".symver glob, glob@GLIBC_2.2.5");
//asm (".symver fstat, fstat@GLIBC_2.2");
//asm (".symver getauxval, getauxval@GLIBC_2.16");

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

int __wrap___isoc99_fscanf(FILE *restrict stream,const char *restrict format, ...){
    va_list vargs = {0};
    va_start(vargs, format);
    int ret = vfscanf(stream,format,vargs);
    va_end (vargs);
    return ret;
}


int __wrap___isoc99_vsscanf(const char *restrict str,const char *restrict format, va_list vargs){
    return vsscanf(str,format,vargs);
}

int __wrap_stat(const char *restrict path,struct stat *restrict buf) {
    return syscall( SYS_stat, path, buf );
}


int __wrap_regexec(void * preg, const char *restrict string, size_t nmatch, void *p , int eflags){
    return regexec(preg,string,nmatch,p,eflags);
}

int __wrap_gnu_dev_makedev(int x,int y){
    return  (((x)&0xfffff000ULL) << 32) | \
	        (((x)&0x00000fffULL) << 8) | \
            (((y)&0xffffff00ULL) << 12) | \
	        (((y)&0x000000ffULL));
}

int __wrap_glob(const char *restrict pat, int flags, int (*errfunc)(const char *path, int err), void *restrict g){
    return glob(pat,flags,errfunc,g);
}

void __procfdname(char *buf, unsigned fd) {
	unsigned i, j;
	for (i=0; (buf[i] = "/proc/self/fd/"[i]); i++);
	if (!fd) {
		buf[i] = '0';
		buf[i+1] = 0;
		return;
	}
	for (j=fd; j; j/=10, i++);
	buf[i] = 0;
	for (; fd; fd/=10) buf[--i] = '0' + fd%10;
}

long __syscall_ret(unsigned long r) {
	if (r > -4096UL) {
		return -1;
	}
	return r;
}

int __wrap_fstat(int fd, void *st){
	int ret = syscall(SYS_fstat, fd, st);
	if (ret != -9 || syscall(SYS_fcntl, fd, F_GETFD) < 0)
		return __syscall_ret(ret);

	char buf[15+3*sizeof(int)];
	__procfdname(buf, fd);

	return stat( buf, st);
}
