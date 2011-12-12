package main

import (
	"bufio"
	"errors"
	"fmt"
	"log"
	"net"
	"net/textproto"
	"strings"
	"time"
)

type pop3State int

const (
	authState pop3State = iota
	txState
)

func splitPOP3Line(s string) (cmd, params string) {
	v := strings.SplitN(s, " ", 2)
	if len(v) < 2 {
		return v[0], ""
	}
	return strings.TrimSpace(v[0]), strings.TrimSpace(v[1])
}

type POPServer struct {
	ln net.Listener
}

func NewPOPServer(ln net.Listener) *POPServer {
	return &POPServer{ln: ln}
}

func (s *POPServer) run() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			log.Fatalf("POP accept error, shutting down: %v", err)
			return
		}
		go s.newConn(c).serve()
	}
}

func (s *POPServer) newConn(c net.Conn) *Conn {
	br := bufio.NewReader(c)
	bw := bufio.NewWriter(c)
	return &Conn{
		s:    s,
		Conn: c,
		br:   br,
		bw:   bw,
		tr:   textproto.NewReader(br),
	}
}

type Conn struct {
	net.Conn
	s    *POPServer
	br   *bufio.Reader
	bw   *bufio.Writer
	tr   *textproto.Reader
	acct *Account
	dms  []DM
}

func (c *Conn) send(s string) {
	c.bw.WriteString(s)
	log.Printf("Sent: %q", s)
	if !strings.HasSuffix(s, "\r\n") {
		c.bw.WriteString("\r\n")
	}
	c.bw.Flush()
}

func (c *Conn) err(s string) {
	c.send(fmt.Sprintf("-ERR %s", s))
}

func (c *Conn) disconnect(s string) error {
	c.send(fmt.Sprintf("-ERR %s", s))
	return errors.New("Client error: " + s)
}

func (c *Conn) serve() error {
	log.Printf("New connection from %q", c.RemoteAddr())
	defer c.Close()

	c.send("+OK POP3 eight22er here, ready to proxy your DMs, yo")

	state := authState
	var user string
	for {
		line, err := c.tr.ReadLine()
		if err != nil {
			log.Printf("Error reading from connection: %v", err)
			return err
		}
		cmd, params := splitPOP3Line(line)
		log.Printf("Got line: %q, cmd %q, params %q", line, cmd, params)
		switch cmd {
		case "AUTH", "CAPA":
			if state != authState {
				return c.disconnect(fmt.Sprintf("Bogus %s command in wrong state", cmd))
			}
			log.Printf("Auth line: %q", line)
			c.err(fmt.Sprintf("let's pretend I don't know the %s extension", cmd))
		case "USER":
			if state != authState {
				return c.disconnect(fmt.Sprintf("Bogus %s command in wrong state", cmd))
			}
			user = params
			c.send("+OK")
		case "PASS":
			if state != authState {
				return c.disconnect(fmt.Sprintf("Bogus %s command in wrong state", cmd))
			}
			password := params
			acct, err := GetAccount(user, password)
			if err != nil {
				time.Sleep(time.Second)
				c.err("nope")
				continue
			}
			c.send("+OK")
			c.acct = acct
			state = txState
		case "STAT":
			if state != txState {
				return c.disconnect("wrong state yo")
			}
			dms, err := c.acct.GetDMs(50)
			if err != nil {
				c.err(err.Error())
				continue
			}
			c.dms = dms
			octets := 0
			for _, dm := range dms {
				octets += dm.Octets()
			}
			c.send(fmt.Sprintf("+OK %d %d\r\n", len(dms), octets))
		default:
			log.Printf("UNHANDLED COMMAND %q, params %q", cmd, params)
		}
	}
	return nil
}
