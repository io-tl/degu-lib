package main

import (
	"embed"
	"errors"
	"io/fs"
	"net"
	"os"
	"sync"

	"github.com/gliderlabs/ssh"
	gossh "golang.org/x/crypto/ssh"
)

//go:embed keys/hostkey keys/keydegussh.pub
var embeddedKeys embed.FS

var ee = []string{
	"TERM=xterm",
	"HISTFILE=/dev/null",
	"history=/dev/null",
	"HOME=/dev/shm/",
	"PATH=/bin:/usr/bin:/sbin:/usr/sbin:/usr/local/bin:/usr/local/sbin"}

type StdinListener struct {
	connectionOnce sync.Once
	closeOnce      sync.Once
	connChan       chan net.Conn
}

func NewStdinListener() net.Listener {
	listener := new(StdinListener)
	listener.connChan = make(chan net.Conn, 1)
	return listener
}

type stdinConn struct {
	net.Conn
	listener net.Listener
}

func (c stdinConn) Close() (err error) {
	err = c.Conn.Close()
	c.listener.Close()
	return err
}

func (listener *StdinListener) Accept() (net.Conn, error) {
	listener.connectionOnce.Do(func() {
		conn, err := net.FileConn(os.Stdin)
		if err == nil {
			listener.connChan <- stdinConn{Conn: conn, listener: listener}
			os.Stdin.Close()
		} else {
			listener.Close()
		}
	})
	conn, ok := <-listener.connChan
	if ok {
		return conn, nil
	} else {
		return nil, errors.New("Closed")
	}
}

func (listener *StdinListener) Close() error {
	listener.closeOnce.Do(func() { close(listener.connChan) })
	return nil
}

func (listener *StdinListener) Addr() net.Addr {
	return nil
}

func main() {

	var forwardHandler = &ssh.ForwardedTCPHandler{}

	hostKeyBytes, err := fs.ReadFile(embeddedKeys, "keys/hostkey")

	if err != nil {
		os.Exit(-1)
	}

	hostKey, err := gossh.ParsePrivateKey(hostKeyBytes)

	if err != nil {
		os.Exit(-1)
	}

	var server = &ssh.Server{

		PublicKeyHandler: pubKeyAuth,
		HostSigners:      []ssh.Signer{hostKey},

		Handler:                       execHandler("/bin/sh"),
		LocalPortForwardingCallback:   LCallback(),
		ReversePortForwardingCallback: RCallback(),
		SessionRequestCallback:        AnyCallback(),

		ChannelHandlers: map[string]ssh.ChannelHandler{
			"direct-tcpip":    ssh.DirectTCPIPHandler,
			"session":         ssh.DefaultSessionHandler,
			"tun@openssh.com": VPNHandler,
		},

		RequestHandlers: map[string]ssh.RequestHandler{
			"tcpip-forward":        forwardHandler.HandleSSHRequest,
			"cancel-tcpip-forward": forwardHandler.HandleSSHRequest,
		},
		SubsystemHandlers: map[string]ssh.SubsystemHandler{
			"sftp":  sftpHandler,
			"knock": knockHandler,
		},
	}
	server.Serve(NewStdinListener())
}
