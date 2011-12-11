package main

import (
	"io/ioutil"
	"log"
	"os"
	"strings"

	"eight22er/oauth"
)

func main() {
	log.Printf("server.")

	oc := &oauth.Client{
		Credentials: oauth.Credentials{
			Token:  slurpFile("config-token"),
			Secret: slurpFile("config-tokensecret"),
		},
	}

	log.Printf("config: %#v", oc)
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
