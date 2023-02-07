#include <stdio.h>
#include <stdlib.h>
#include "ed25519.h"
#include "ge.h"




void ed25519_getpub(unsigned char *public_key, unsigned char *private_key) {
    ge_p3 A;
    ge_scalarmult_base(&A, private_key);
    ge_p3_tobytes(public_key, &A);
}

