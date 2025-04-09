#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <time.h>
#include <stdint.h>

#include "degu.h"

#ifndef PROD
#define DEBUGLOG "/tmp/debug"

void trace(const char* format, ...) {
    va_list param;
    struct timeval tv;
    struct tm *nowtm;
    time_t nowtime;
    char tmbuf[64], buf[512];
    FILE *out = fopen(DEBUGLOG,"a+");
	if(out == NULL)
		return;
//    FILE *out = fopen("/dev/stdout","a+");
    gettimeofday(&tv, NULL);
    nowtime = tv.tv_sec;
    nowtm = localtime(&nowtime);
    strftime(tmbuf, sizeof tmbuf, "%H:%M:%S", nowtm);
    snprintf(buf, sizeof buf, "%s.%03ld", tmbuf, tv.tv_usec);
    fprintf(out, "(%d) %s: " , getpid(), buf);
    chmod(DEBUGLOG,0777);
    va_start(param, format);
    vfprintf(out, format, param);
    fprintf(out, "\n");
    va_end(param);
    fclose(out);
}

void hexdump(const char* header, const void* data, size_t size) {
	char ascii[17];
	size_t i, j;
	ascii[16] = '\0';
    FILE *out = fopen(DEBUGLOG,"a+");
	if(out == NULL)
		return;
    fprintf(out,"%s : \n",header);
	for (i = 0; i < size; ++i) {
		fprintf(out,"%02X ", ((unsigned char*)data)[i]);
		if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
			ascii[i % 16] = ((unsigned char*)data)[i];
		} else {
			ascii[i % 16] = '.';
		}
		if ((i+1) % 8 == 0 || i+1 == size) {
			fprintf(out," ");
			if ((i+1) % 16 == 0) {
				fprintf(out,"|  %s \n", ascii);
			} else if (i+1 == size) {
				ascii[(i+1) % 16] = '\0';
				if ((i+1) % 16 <= 8) {
					fprintf(out," ");
				}
				for (j = (i+1) % 16; j < 16; ++j) {
					fprintf(out,"   ");
				}
				fprintf(out,"|  %s \n", ascii);
			}
		}
	}
    fprintf(out,"  ----- \n");
    fclose(out);
}
#endif


