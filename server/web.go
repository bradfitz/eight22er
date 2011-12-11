package main

import (
	"net"
	"net/http"
)

func runWebServer(ln net.Listener) {
	mux := http.NewServeMux()
	mux.Handle("/submit", http.HandlerFunc(nil))
	mux.Handle("/", http.FileServer(http.Dir("static")))
	s := &http.Server{Handler: mux}
	s.Serve(ln)
}
