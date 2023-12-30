# degu-lib
**THIS IS JUST FOR EDUCATIONAL PURPOSE, USE IT ONLY ON YOUR OWN COMPUTER.**

**DEGU** is a stealth userland kit that doesn't use sys_clone/sys_execve call to run.

This software can't be easily spotted by volatility and conventionnal anti rootkit tools.

Actually it works on 3.17+ linux kernel to keep real in-memory execution using userland execve and memfd as fallback for lower kernels it also uses shm/fexecve execution.

It's an "autorelocatable" executable library (see p2s/pie2so.c for magical trick), and use signal to get execution inside parasited process without a fork, a thread or function hooking.

It can bypass netfilter settings for unidirectionnal command using raw ethernet ebpf rules, and use ed25519 library to sign messages from client and exchange keys for AES session.

See documentation for build instruction.
It works with a client part in python :

[degu-client](https://github.com/io-tl/degu-client)

### BUILD :
```
git submodule update --init
make clean && make
```

don't forget to replace keys :
```
$ cd degu-client && ./dgu keygen > ../keys.h && make clean && make
```


