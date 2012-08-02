package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/textproto"
	"strconv"
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
	s         *POPServer
	br        *bufio.Reader
	bw        *bufio.Writer
	tr        *textproto.Reader
	acct      *Account
	dmsCached []DM
}

func (c *Conn) dms() ([]DM, error) {
	if c.dmsCached != nil {
		return c.dmsCached, nil
	}
	var err error
	c.dmsCached, err = c.acct.GetDMs(50)
	return c.dmsCached, err
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
	defer c.Close()

	if tlsConn, ok := c.Conn.(*tls.Conn); ok {
		log.Printf("New TLS connnection from %q", c.RemoteAddr())
		if err := tlsConn.Handshake(); err != nil {
			log.Printf("TLS handshake error from %q: %v", c.RemoteAddr(), err)
			return err
		}
	} else {
		log.Printf("New raw connnection from %q", c.RemoteAddr())
	}

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
			if err != nil || acct.Password == "" {
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
			dms, err := c.dms()
			if err != nil {
				c.err(err.Error())
				continue
			}
			octets := 0
			for _, dm := range dms {
				octets += dm.Octets()
			}
			c.send(fmt.Sprintf("+OK %d %d\r\n", len(dms), octets))
		case "LIST":
			if state != txState {
				return c.disconnect("wrong state yo")
			}
			if params != "" {
				c.err("TODO: support LIST with an argument")
				continue
			}
			dms, err := c.dms()
			if err != nil {
				c.err(err.Error())
				continue
			}
			var buf bytes.Buffer
			fmt.Fprintf(&buf, "+OK %d messages\r\n", len(dms))
			for n, dm := range dms {
				fmt.Fprintf(&buf, "%d %d\r\n", n+1, dm.Octets())
			}
			fmt.Fprintf(&buf, ".\r\n")
			c.send(buf.String())
		case "UIDL":
			if state != txState {
				return c.disconnect("wrong state yo")
			}
			if params != "" {
				c.err("TODO: support UIDL with an argument")
				continue
			}
			dms, err := c.dms()
			if err != nil {
				c.err(err.Error())
				continue
			}
			var buf bytes.Buffer
			fmt.Fprintf(&buf, "+OK %d messages\r\n", len(dms))
			for n, dm := range dms {
				fmt.Fprintf(&buf, "%d twdmid%d\r\n", n+1, dm.ID())
			}
			fmt.Fprintf(&buf, ".\r\n")
			c.send(buf.String())
		case "RETR", "TOP":
			if state != txState {
				return c.disconnect("wrong state yo")
			}
			// We're lazy and treat TOP like RETR, since
			// there's always like 1 line anyway.  So
			// ignore TOP's n value.
			ps := strings.Split(params, " ")
			if len(ps) < 1 {
				c.err("bad params")
				continue
			}
			n, err := strconv.Atoi(ps[0])
			if err != nil {
				c.err("bad number")
				continue
			}
			dms, _ := c.dms()
			if n > len(dms) {
				c.err("bad index")
				continue
			}
			dm := dms[n-1]
			msg := dm.RFC822()
			c.send(fmt.Sprintf("+OK %d octets\r\n%s\r\n.\r\n", len(msg), msg))
		case "DELE":
			if state != txState {
				return c.disconnect("wrong state yo")
			}
			n, err := strconv.Atoi(params)
			if err != nil {
				c.err("bad number")
				continue
			}
			log.Printf("client wants to delete message %d", n)
			c.send("+OK")
		case "QUIT":
			c.send("+OK")
			break
		default:
			log.Printf("UNHANDLED COMMAND %q, params %q", cmd, params)
		}
	}
	return nil
}
