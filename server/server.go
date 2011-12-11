package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"

	"eight22er/oauth"
)

func main() {
	log.Printf("server.")

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
