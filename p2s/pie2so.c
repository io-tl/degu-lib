#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/mman.h>
#include <elf.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <limits.h>

#if defined(__x86_64__)

#define Elf_Ehdr    Elf64_Ehdr
#define Elf_Phdr    Elf64_Phdr
#define Elf_Shdr    Elf64_Shdr
#define Elf_Dyn     Elf64_Dyn

#else

#define Elf_Ehdr    Elf32_Ehdr
#define Elf_Phdr    Elf32_Phdr
#define Elf_Shdr    Elf32_Shdr
#define Elf_Dyn     Elf32_Dyn

#endif

int patch_dtflags(void *map ){

    int i,idx, off, ret=1;

    Elf_Ehdr *hdr;
    Elf_Phdr *phdr = NULL, *phdyn= NULL;
    Elf_Shdr *shdr= NULL, *strtab= NULL;
    Elf_Dyn *dyn=NULL;

    hdr = (Elf_Ehdr*) map;

    for (i = 0; i <  hdr->e_phnum; i++){
        phdr = ( Elf_Phdr *) (map + hdr->e_phoff + (hdr->e_phentsize * i));
        if (phdr->p_type == PT_DYNAMIC)
            phdyn = phdr;

    }
    i = 0, idx = 0;
    do {
        dyn = (Elf_Dyn * ) (map + phdyn->p_offset + ( sizeof(Elf_Dyn) * i));
        if  (dyn->d_tag == DT_FLAGS_1) {
             dyn->d_tag = DT_DEBUG;
             dyn->d_un.d_val = 0;
             return 0;
        }
        i++;
    }while(dyn->d_tag != DT_NULL);
    return -1;
}

void gtfo(char *msg){
    perror("unable to open bin");
    _exit(0);
}

void usage(){
	fprintf(stderr,"pie2so ./path/to/bin");
	_exit(0);
}

int main (int argc,char **argv){


    if (argc != 2) usage();
    char *bin = argv[1];

    int fd,res;
    void *maped;
    struct stat fd_info;

    res = stat(bin, &fd_info);
    if (res < 0 ) gtfo("nofile");

    fd = open(bin, O_RDONLY );
    if (fd < 0) gtfo("unable to open bin");

    maped = mmap(NULL,fd_info.st_size, PROT_READ|PROT_WRITE,MAP_PRIVATE, fd, 0);
    if (maped == MAP_FAILED) gtfo("unable to mmap");

    patch_dtflags(maped);

    char outfile[4096] = {0};
    sprintf(outfile,"%s.so",bin);

    int fdout = open(outfile, O_CREAT|O_RDWR|O_APPEND,S_IRUSR|S_IWUSR);
    unsigned int size = fd_info.st_size;
    res = write(fdout, maped, size);
    if (res != size) gtfo("write error");
    close(fdout);

    munmap(maped, fd_info.st_size);
    close(fd);
    chmod(outfile,0755);
    //printf("%s converted to dso %s\n",bin,outfile);
    return 0;
}

