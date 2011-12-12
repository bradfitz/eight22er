package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"eight22er/oauth"
	"eight22er/smtp"
)

var (
	dev        = flag.Bool("dev", false, "Development mode; use localhost and stuff")
	popPort    = flag.Int("pop_port", 1100, "POP3 port")
	smtpPort   = flag.Int("smtp_port", 5870, "SMTP port")
	webPort    = flag.Int("web_port", 8000, "Web awesomeness port")
	doSSL      = flag.Bool("ssl", false, "Do SSL")
	webSSLPort = flag.Int("web_ssl_port", 8001, "Web awesomeness port")
)

func main() {
	flag.Parse()
	var (
		cert   tls.Certificate
		err    error
		config *tls.Config
	)
	if *doSSL {
		cert, err = tls.LoadX509KeyPair("ssl.crt", "ssl.key")
		check(err)
		config = &tls.Config{
			Certificates: []tls.Certificate{cert},
			ServerName:   "eight22er.danga.com",
		}
		ln, err := net.Listen("tcp", ":"+strconv.Itoa(*webSSLPort))
		check(err)
		tln := tls.NewListener(ln, config)
		go runWebServer(tln)
	}

	log.Printf("server.")
	wln, err := net.Listen("tcp", ":"+strconv.Itoa(*webPort))
	check(err)
	if *dev {
		go runWebServer(wln)
	} else {
		go runSSLRedirector(wln)
	}

	// POP Listener
	pln, err := net.Listen("tcp", ":"+strconv.Itoa(*popPort))
	check(err)
	if *doSSL {
		pln = tls.NewListener(pln, config)
	}
	pop := NewPOPServer(pln)
	go pop.run()

	// SMTP Listener
	sln, err := net.Listen("tcp", ":"+strconv.Itoa(*smtpPort))
	check(err)
	if *doSSL {
		sln = tls.NewListener(sln, config)
	}
	ss := &smtp.Server{
		Hostname:  "eight22er.danga.com",
		PlainAuth: true,
		OnNewMail: func(c smtp.Connection, from smtp.MailAddress) (smtp.Envelope, error) {
			return nil, errors.New("TODO: we haven't finished sending direct messasges via SMTP yet")
		},
	}
	go ss.Serve(sln)

	select {}
}

func oauthClient() *oauth.Client {
	return &oauth.Client{
		Credentials: oauth.Credentials{
			Token:  slurpFile("config-consumerkey"),
			Secret: slurpFile("config-consumersecret"),
		},
		TemporaryCredentialRequestURI: "https://api.twitter.com/oauth/request_token",
		ResourceOwnerAuthorizationURI: "https://api.twitter.com/oauth/authorize",
		TokenRequestURI:               "https://api.twitter.com/oauth/access_token",
	}
}

type Account struct {
	Username           string // on twitter
	Password           string // for local service
	Token, TokenSecret string
}

var errAuthFailure = errors.New("Auth failure")

// GetAccountNoAuth always returns an Account object, even if it
// doesn't exist on disk.  This is for the sign-up flow, assuming the
// web code will immediately call Save on this after tweaking some
// fields
func GetAccountNoAuth(user string) *Account {
	f, err := os.Open(fmt.Sprintf("db/%s.cred", user))
	if err != nil {
		return &Account{Username: user}
	}
	defer f.Close()
	bs, err := ioutil.ReadAll(f)
	if err != nil {
		return &Account{Username: user}
	}
	v := strings.Split(string(bs), "\n")
	if len(v) < 3 {
		return &Account{Username: user}
	}
	return &Account{
		Username:    user,
		Password:    v[0],
		Token:       strings.TrimSpace(v[1]),
		TokenSecret: strings.TrimSpace(v[2]),
	}
}

func GetAccount(user, pass string) (*Account, error) {
	f, err := os.Open(fmt.Sprintf("db/%s.cred", user))
	if err != nil {
		return nil, errAuthFailure
	}
	defer f.Close()
	bs, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, errAuthFailure
	}
	v := strings.Split(string(bs), "\n")
	if len(v) < 3 || v[0] != pass {
		return nil, errAuthFailure
	}
	a := &Account{
		Username:    user,
		Password:    pass,
		Token:       strings.TrimSpace(v[1]),
		TokenSecret: strings.TrimSpace(v[2]),
	}
	return a, nil
}

var userRx = regexp.MustCompile(`^[a-zA-Z0-9\.\-]+$`)

func (a *Account) Save() error {
	if !userRx.MatchString(a.Username) {
		return errors.New("bogus username")
	}
	pw := strings.Replace(a.Password, "\n", "", -1)
	content := fmt.Sprintf("%s\n%s\n%s\n", pw, a.Token, a.TokenSecret)
	return ioutil.WriteFile(fmt.Sprintf("db/%s.cred", a.Username), []byte(content), 0700)
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

func (d DM) CreatedAt() string {
	if s, ok := d["created_at"].(string); ok {
		return s
	}
	return ""
}

func (d DM) ID() int64 {
	if id, ok := d["id"].(float64); ok {
		return int64(id)
	}
	return 0
}

func (d DM) Subject() string {
	t := d.Text()
	t = strings.Replace(t, "\n", " / ", -1)
	t = strings.Replace(t, "\r", "", -1)
	return t
}

func (d DM) Octets() int {
	return len(d.RFC822())
}

func (d DM) RFC822() string {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "From: %s@eight22er.danga.com (%s)\r\n", d.Sender().ScreenName(), d.Sender().Name())
	fmt.Fprintf(&buf, "Subject: %s\r\n", d.Subject())
	fmt.Fprintf(&buf, "Date: %s\r\n", d.CreatedAt())
	fmt.Fprintf(&buf, "Message-Id: <%d@eight22er.danga.com>\r\n", d.ID())
	fmt.Fprintf(&buf, "\r\n%s", d.Text())
	return buf.String()
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

func (a *Account) GetDMs(n int) ([]DM, error) {
	oc := oauthClient()
	cred := &oauth.Credentials{
		Token:  a.Token,
		Secret: a.TokenSecret,
	}

	urlBase := "https://api.twitter.com/1/direct_messages.json"
	params := make(url.Values)
	params.Set("count", strconv.Itoa(n))
	oc.SignParam(cred, "GET", urlBase, map[string][]string(params))

	authHeader := buildAuthHeader(params)
	reqURL := fmt.Sprintf("%s?%s", urlBase, params.Encode())

	log.Printf("Req URL: %s", reqURL)
	log.Printf("Authorization: %s", authHeader)

	req, _ := http.NewRequest("GET", reqURL, nil)
	req.Header.Add("Authorization", authHeader)

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	dms, err := parseDMs(res.Body)
	if err != nil {
		return nil, err
	}
	return dms, nil
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
