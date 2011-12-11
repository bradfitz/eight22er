package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/textproto"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"

	"eight22er/oauth"
)

var (
	popPort  = flag.Int("pop_port", 1100, "POP3 plaintext port")
	smtpPort = flag.Int("smtp_port", 2500, "SMTP plaintext port")
)

func main() {
	log.Printf("server.")
	ln, err := net.Listen("tcp", ":"+strconv.Itoa(*popPort))
	check(err)
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Printf("Accept error, shutting down: %v", err)
			return
		}
		go NewConn(c).serve()
	}
}

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

func NewConn(c net.Conn) *Conn {
	br := bufio.NewReader(c)
	bw := bufio.NewWriter(c)
	return &Conn{
		Conn:  c,
		br: br,
		bw: bw,
		tr: textproto.NewReader(br),
	}
}

type Conn struct {
	net.Conn
	br *bufio.Reader
	bw *bufio.Writer
	tr *textproto.Reader
}

func (c *Conn) send(s string) {
	c.bw.WriteString(s)
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
	var user, password string
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
			password = params
			c.send("+OK")
		default:
			log.Printf("UNHANDLED COMMAND %q, params %q", cmd, params)
		}
	}
	log.Printf("user = %q, password = %q", user, password)

	oc := &oauth.Client{
		Credentials: oauth.Credentials{
			Token:  slurpFile("config-consumerkey"),
			Secret: slurpFile("config-consumersecret"),
		},
	}
	cred := &oauth.Credentials{
		Token:  slurpFile("config-token"),
		Secret: slurpFile("config-tokensecret"),
	}

	urlBase := "https://api.twitter.com/1/direct_messages.json"
	params := make(url.Values)
	params.Set("count", "50")
	oc.SignParam(cred, "GET", urlBase, map[string][]string(params))

	authHeader := buildAuthHeader(params)
	reqURL := fmt.Sprintf("%s?%s", urlBase, params.Encode())

	log.Printf("Req URL: %s", reqURL)
	log.Printf("Authorization: %s", authHeader)

	req, _ := http.NewRequest("GET", reqURL, nil)
	req.Header.Add("Authorization", authHeader)

	res, err := http.DefaultClient.Do(req)
	check(err)
	dms, err := parseDMs(res.Body)
	check(err)
	for _, dm := range dms {
		fmt.Printf("From: %s (%s)\t%q\n", dm.Sender().ScreenName(), dm.Sender().Name(), dm.Text())
	}

	return nil
}

type DM map[string]interface{}
type User map[string]interface{}

func (d DM) Sender() User {
	if m, ok := d["sender"].(map[string]interface{}); ok {
		return User(m)
	}
	return User(nil)
}

func (d DM) Text() string {
	if s, ok := d["text"].(string); ok {
		return s
	}
	return ""
}

func (u User) ScreenName() string {
	if s, ok := u["screen_name"].(string); ok {
		return s
	}
	return ""
}

func (u User) Name() string {
	if s, ok := u["name"].(string); ok {
		return s
	}
	return ""
}

func check(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func parseDMs(r io.Reader) ([]DM, error) {
	var dms interface{}
	err := json.NewDecoder(r).Decode(&dms)
	if err != nil {
		return nil, err
	}
	dmList, ok := dms.([]interface{})
	if !ok {
		return nil, fmt.Errorf("DM response not a list, got a %T", dms)
	}
	ret := []DM{}
	for _, v := range dmList {
		dmj, ok := v.(map[string]interface{})
		if ok {
			ret = append(ret, DM(dmj))
		}
	}
	return ret, nil
}

func buildAuthHeader(vals url.Values) string {
	var buf bytes.Buffer
	if _, ok := vals["oauth_version"]; !ok {
		vals.Set("oauth_version", "1.0")
	}
	fmt.Fprintf(&buf, "OAuth")
	remove := []string{}
	for k := range vals {
		if !strings.HasPrefix(k, "oauth_") {
			continue
		}
		remove = append(remove, k)
	}
	sort.Strings(remove)
	for n, k := range remove {
		if n > 0 {
			buf.WriteByte(',')
		}
		v := vals.Get(k)
		if k == "oauth_signature" {
			v = url.QueryEscape(v)
		}
		fmt.Fprintf(&buf, " %s=%q", k, v)
		delete(vals, k)
	}
	return buf.String()
}

func slurpFile(file string) string {
	f, err := os.Open(file)
	if err != nil {
		log.Fatalf("Error opening %q: %v", file, err)
	}
	defer f.Close()
	bs, err := ioutil.ReadAll(f)
	if err != nil {
		log.Fatal(err)
	}
	return strings.TrimSpace(string(bs))
}
