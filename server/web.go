package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"

	"github.com/bradfitz/eight22er/oauth"
)

func runWebServer(ln net.Listener) {
	mux := http.NewServeMux()
	mux.Handle("/submit", http.HandlerFunc(nil))
	mux.HandleFunc("/login", loginFunc)
	mux.HandleFunc("/setconfig", configFunc)
	mux.HandleFunc("/cb", cbFunc)
	mux.Handle("/", http.FileServer(http.Dir("static")))
	s := &http.Server{Handler: mux}
	s.Serve(ln)
}

func runSSLRedirector(ln net.Listener) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://eight22er.danga.com/", http.StatusFound)
	})
	s := &http.Server{Handler: h}
	s.Serve(ln)
}

func loginFunc(w http.ResponseWriter, r *http.Request) {
	oc := oauthClient()
	callback := "https://eight22er.danga.com/cb"
	if *dev {
		callback = fmt.Sprintf("http://localhost:%d/cb", *webPort)
	}
	cred, err := oc.RequestTemporaryCredentials(http.DefaultClient, callback)
	check(err)
	authURL := oc.AuthorizationURL(cred)
	println("AUTH URL: " + authURL)
	http.Redirect(w, r, authURL, http.StatusFound)
}

func cbFunc(w http.ResponseWriter, r *http.Request) {
	oauthToken := r.FormValue("oauth_token")
	verifier := r.FormValue("oauth_verifier")
	log.Printf("Got callback token=%q, verifier=%q", oauthToken, verifier)
	oc := oauthClient()

	tcred := &oauth.Credentials{
		Token:  oauthToken,
		Secret: oc.Credentials.Secret, // consumer secret
	}

	cred, m, err := oc.RequestToken(http.DefaultClient, tcred, verifier)
	if err != nil {
		fmt.Fprintf(w, "RequestToken failed: %q", err)
		return
	}

	acct := GetAccountNoAuth(m["screen_name"])
	acct.Token = cred.Token
	acct.TokenSecret = cred.Secret
	if acct.Password == "" {
		acct.Password = cred.Token
	}
	acct.Save()

	configURL := fmt.Sprintf("/config.html?user=%v&password=%v", m["screen_name"], url.QueryEscape(acct.Password))
	http.Redirect(w, r, configURL, http.StatusFound)
}

func configFunc(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")
	newPassword := r.FormValue("newPassword")

	acct, err := GetAccount(username, password)
	if err != nil {
		log.Printf("Getting account %q failed: %v", username, err)
		configURL := fmt.Sprintf("/config.html?user=%v&password=%v&wrongpw=1", username, password)
		http.Redirect(w, r, configURL, http.StatusFound)
		return
	}

	acct.Password = newPassword
	acct.Save()

	configURL := fmt.Sprintf("/config.html?user=%v&password=%v&setpw=1", username, newPassword)
	http.Redirect(w, r, configURL, http.StatusFound)
}
