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

func middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientCert := r.TLS.PeerCertificates[0]
		cn := clientCert.Subject.CommonName
		if cn != "alice.example.com" {
			log.Printf("%s is not allowed\n", cn)
			msg := fmt.Sprintf("you cannot be here %s", cn)
			http.Error(w, msg, http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
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
		Handler:   middleware(http.HandlerFunc(handler)),
		TLSConfig: tlsCfg,
	}
	log.Println("starting server")
	if err := server.ListenAndServeTLS("", ""); err != nil {
		log.Fatalln(err)
	}
}
