package main

import (
	"fmt"
	"log"
	"net"
	"net/http"

	"eight22er/oauth"
)

func runWebServer(ln net.Listener) {
	mux := http.NewServeMux()
	mux.Handle("/submit", http.HandlerFunc(nil))
	mux.HandleFunc("/login", loginFunc)
	mux.HandleFunc("/cb", cbFunc)
	mux.Handle("/", http.FileServer(http.Dir("static")))
	s := &http.Server{Handler: mux}
	s.Serve(ln)
}

func loginFunc(w http.ResponseWriter, r *http.Request) {
	oc := oauthClient()
	cred, err := oc.RequestTemporaryCredentials(http.DefaultClient, "http://localhost:8000/cb")
	check(err)
	authURL := oc.AuthorizationURL(cred)
	println("AUTH URL: " + authURL)
	fmt.Fprintf(w, "<html><body>Got auth URL: <a href='%s'>%s</a></body></html>", authURL, authURL)
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
	fmt.Fprintf(w, "Got creds: %#v, map: %#v", cred, m)
}
