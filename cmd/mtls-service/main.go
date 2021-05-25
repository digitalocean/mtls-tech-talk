package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
)

var (
	rootFile = flag.String("root", "target/root.crt", "Root CA certificate file")
	certFile = flag.String("cert", "target/server.crt", "Server TLS certificate file")
	keyFile  = flag.String("key", "target/server.pem", "Server TLS private key file")
)

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if name == "" {
		name = "World"
	}
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintln(w, "Hello", name)
}

func main() {
	flag.Parse()

	rootCaPool := x509.NewCertPool()
	rootPEM, err := ioutil.ReadFile(*rootFile)
	if err != nil {
		log.Fatalln(err)
	}
	if ok := rootCaPool.AppendCertsFromPEM(rootPEM); !ok {
		log.Fatalln("failed to parse Root CA file")
	}

	serverCert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		log.Fatalln(err)
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    rootCaPool,
	}
	server := &http.Server{
		Addr:      ":3000",
		Handler:   http.HandlerFunc(handler),
		TLSConfig: tlsCfg,
	}
	log.Println("starting server")
	if err := server.ListenAndServeTLS("", ""); err != nil {
		log.Fatalln(err)
	}
}
