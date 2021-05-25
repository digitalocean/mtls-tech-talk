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
	certFile = flag.String("cert", "", "Client TLS certificate file")
	keyFile  = flag.String("key", "", "Client TLS private key file")
	sendName = flag.String("name", "", "Name to send to the server")
)

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

	clientCert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		log.Fatalln(err)
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:      rootCaPool,
				Certificates: []tls.Certificate{clientCert},
			},
		},
	}

	req, err := http.NewRequest("GET", "https://localhost:3000/", nil)
	if err != nil {
		log.Fatalln(err)
	}
	if *sendName != "" {
		q := req.URL.Query()
		q.Add("name", *sendName)
		req.URL.RawQuery = q.Encode()
	}
	res, err := client.Do(req)
	if err != nil {
		log.Fatalln(err)
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Println(string(body))
}
