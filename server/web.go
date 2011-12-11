package main

import (
	"net"
	"net/http"
)

func runWebServer(ln net.Listener) {
	s := &http.Server{Handler:nil}
	s.Serve(ln)
}

