# mtls-tech-talk

[From Wikipedia](https://en.wikipedia.org/wiki/Mutual_authentication)
> Mutual authentication or two-way authentication refers to two parties authenticating each other at the same time, being a default mode of authentication in some protocols (IKE, SSH) and optional in others (TLS). By default the TLS protocol only proves the identity of the server to the client using X.509 certificate and the authentication of the client to the server is left to the application layer. TLS also offers client-to-server authentication using client-side X.509 authentication. As it requires provisioning of the certificates to the clients and involves less user-friendly experience, it's rarely used in end-user applications.

Managing a PKI (public key infrastructure) and provisioning of client and server certificates is frequently seen as tedious and painful. The same can be said for configuring clients and servers, with the added annoyance of native key & certificate store formats.

In the last few years products like HashiCorp's [Vault](https://www.vaultproject.io/) have make managing a PKI easier, and have provided reasonable APIs to make issuing certificates a straight-forward process. Language libraries have evolved to allow developers to easily configure TLS for clients and servers. Tools have also evolved to make the conversion between certificate formats easier (for example [pemToJks](https://github.com/tomcz/pemToJks)).

I'd like to show you how to use Vault to manage a PKI infrastructure that allows for mTLS between golang-based clients and servers. All the following code is also available for you to explore in this repository.

## Requirements

1. Three open terminals (#1, #2, and #3)
2. [go v1.16](https://golang.org/dl/)
3. [curl](https://curl.haxx.se/)
4. [jq](https://stedolan.github.io/jq/)
5. [openssl](https://www.openssl.org/)

## Set up Vault

Download [Vault](https://www.vaultproject.io/downloads):

### On Linux

```
$> mkdir target
$> curl -SsfL -o target/vault.zip https://releases.hashicorp.com/vault/1.5.4/vault_1.5.4_linux_amd64.zip
$> unzip target/vault.zip -d target
$> rm target/vault.zip
$> chmod +x target/vault
```

### On OSX

```
$> mkdir target
$> curl -SsfL -o target/vault.zip https://releases.hashicorp.com/vault/1.5.4/vault_1.5.4_darwin_amd64.zip
$> unzip target/vault.zip -d target
$> rm target/vault.zip
$> chmod +x target/vault
```

### Start the Vault server in dev mode

This is great for experimentation as it does not require any backing data stores (like [Consul](https://learn.hashicorp.com/collections/vault/day-one-consul)), but it should not be how you run Vault in production.

In terminal #1:
```
$> ./target/vault server -dev -dev-root-token-id="root"
```

This will create a `.vault-token` file at the root of your home directory that will contain the `root` Vault token. We are going to skip a lot of Vault configuration that you'd need to make for a serious production setup because this is not an article about configuring Vault, but please note that using root tokens in production is a terrible idea.

If we want Vault to create TLS certificates for us it needs to be set up to act as a certifying authority (CA).

### Create a root certifying authority in vault

With Vault running in terminal #1, run the following in terminal #2:
```
$> export VAULT_ADDR='http://127.0.0.1:8200'
$> ./target/vault secrets enable \
        -path pki_local \
        -max-lease-ttl=87600h \
        pki
$> ./target/vault write pki_local/config/urls \
        issuing_certificates="http://127.0.0.1:8200/v1/pki_local/ca" \
        crl_distribution_points="http://127.0.0.1:8200/v1/pki_local/crl"
$> ./target/vault write -format=json \
        pki_local/root/generate/internal \
        common_name="Local Root CA" \
        ttl=87600h \
        key_type=rsa \
        key_bits=2048 \
        > target/root.json
$> ./target/vault write pki_local/roles/service \
        allowed_domains="example.com" \
        allow_bare_domains="true" \
        allow_subdomains="true" \
        allow_localhost="true" \
        enforce_hostnames="true" \
        allow_ip_sans="true" \
        max_ttl="720h" \
        key_type=rsa \
        key_bits=2048
$> jq -r '.data.certificate' target/root.json > target/root.crt
```

We now have a running Vault instance, set up to generate TLS certificates, and `target/root.crt` contains the public certificate of our new root CA.

## Server and client-side TLS (mTLS)

### Issue a server certificate using our new root CA

With Vault running in terminal #1, run the following in terminal #2:
```
$> export VAULT_ADDR='http://127.0.0.1:8200'
$> ./target/vault write -format=json \
        pki_local/issue/service \
        common_name=www.example.com \
        alt_names=localhost \
        ip_sans=127.0.0.1 \
        > target/server.json
$> jq -r '.data.certificate' target/server.json > target/server.crt
$> jq -r '.data.private_key' target/server.json > target/server.pem
```

This creates two files: `target/server.crt` which contains the server's public certificate, and `target/server.pem` which contains the server's private key.

### Issue a client certificate for Alice using our new root CA

With Vault running in terminal #1, run the following in terminal #2:
```
$> export VAULT_ADDR='http://127.0.0.1:8200'
$> ./target/vault write -format=json \
        pki_local/issue/service \
        common_name=alice.example.com \
        > target/alice.json
$> jq -r '.data.certificate' target/alice.json > target/alice.crt
$> jq -r '.data.private_key' target/alice.json > target/alice.pem
```

This creates two files: `target/alice.crt` which contains Alice's public certificate, and `target/alice.pem` which contains Alice's private key.

### Create a golang HTTPS service that requires client TLS certificates

The server presents its own TLS certificate to clients during the HTTPS handshake, and requires that a client must present its own certificate during the handshake. It validates a client's certificate to ensure that it has been signed by our root CA.

[cmd/mtls-service/main.go](https://github.com/digitalocean/mtls-tech-talk/blob/main/cmd/mtls-service/main.go)

```go
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
```

### Create a golang HTTPS client that presents its own TLS certificate

The client presents its own TLS certificate to a server during the HTTPS handshake, and validates the server's certificate to ensure that it has been signed by our root CA.

[cmd/mtls-client/main.go](https://github.com/digitalocean/mtls-tech-talk/blob/main/cmd/mtls-client/main.go)

```go
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
```

### Test it out

Run the server using in terminal #2:

```
$> go run ./cmd/mtls-service/main.go
```

Run the client as Alice in terminal #3:

```
$> go run ./cmd/mtls-client/main.go -name Alice -cert target/alice.crt -key target/alice.pem
Hello Alice
```

## What about Bob?

We can generate a certificate for Bob using Vault in terminal #3:

```
$> export VAULT_ADDR='http://127.0.0.1:8200'
$> ./target/vault write -format=json \
        pki_local/issue/service \
        common_name=bob.example.com \
        > target/bob.json
$> jq -r '.data.certificate' target/bob.json > target/bob.crt
$> jq -r '.data.private_key' target/bob.json > target/bob.pem
```

We can call the service as Bob in terminal #3:

```
go run ./cmd/mtls-client/main.go -name Bob -cert target/bob.crt -key target/bob.pem
Hello Bob
```

### What if we don't want to allow Bob to access the service?

The standard answer in some places is multiple CAs, and this is a valid option if you cannot configure your services in more complex ways.

1. We could create a two different CAs. One that generates certificates for Bobs, and another that generates certificates for Alices. That way a server that only trusts an Alice will never trust a Bob.
2. We could keep our root CA, and have it sign two intermediate CA certificates, one for an Alice CA and another for a Bob CA. This is an extension to option 1 that allows some services to trust the root CA and therefore allow any Alice or Bob to access them, but still have services that only trust the intermediate CAs and therefore only allow Alice to access Alices' services, and Bob to access Bobs' services.

#### Multiple intermediate CAs with vault

Set up an Alice-only CA in terminal #2:

```
$> export VAULT_ADDR='http://127.0.0.1:8200'
$> ./target/vault secrets enable -path=pki_alice pki
$> ./target/vault secrets tune -max-lease-ttl=43800h pki_alice
$> ./target/vault write -format=json \
        pki_alice/intermediate/generate/internal \
        common_name="Alice Intermediate Authority" \
        ttl=43800h \
        > target/alice-ca-csr.json
$> jq -r '.data.csr' target/alice-ca-csr.json > target/alice-ca.csr
$> ./target/vault write -format=json \
        pki_local/root/sign-intermediate \
        csr=@target/alice-ca.csr \
        format=pem_bundle \
        ttl=43800h \
        > target/alice-ca.json
$> jq -r '.data.certificate' target/alice-ca.json > target/alice-ca.crt
$> ./target/vault write \
        pki_alice/intermediate/set-signed \
        certificate=@target/alice-ca.crt
$> ./target/vault write pki_alice/config/urls \
        issuing_certificates="http://127.0.0.1:8200/v1/pki_alice/ca" \
        crl_distribution_points="http://127.0.0.1:8200/v1/pki_alice/crl"
$> ./target/vault write pki_alice/roles/service \
        allowed_domains="example.com" \
        allow_bare_domains="true" \
        allow_subdomains="true" \
        allow_localhost="true" \
        enforce_hostnames="true" \
        allow_ip_sans="true" \
        max_ttl="720h" \
        key_type=rsa \
        key_bits=2048
```

Set up a Bob-only CA in terminal #2:

```
$> export VAULT_ADDR='http://127.0.0.1:8200'
$> ./target/vault secrets enable -path=pki_bob pki
$> ./target/vault secrets tune -max-lease-ttl=43800h pki_bob
$> ./target/vault write -format=json \
        pki_bob/intermediate/generate/internal \
        common_name="Bob Intermediate Authority" \
        ttl=43800h \
        > target/bob-ca-csr.json
$> jq -r '.data.csr' target/bob-ca-csr.json > target/bob-ca.csr
$> ./target/vault write -format=json \
        pki_local/root/sign-intermediate \
        csr=@target/bob-ca.csr \
        format=pem_bundle \
        ttl=43800h \
        > target/bob-ca.json
$> jq -r '.data.certificate' target/bob-ca.json > target/bob-ca.crt
./target/vault write \
        pki_bob/intermediate/set-signed \
        certificate=@target/bob-ca.crt
$> ./target/vault write pki_bob/config/urls \
        issuing_certificates="http://127.0.0.1:8200/v1/pki_bob/ca" \
        crl_distribution_points="http://127.0.0.1:8200/v1/pki_bob/crl"
$> ./target/vault write pki_bob/roles/service \
        allowed_domains="example.com" \
        allow_bare_domains="true" \
        allow_subdomains="true" \
        allow_localhost="true" \
        enforce_hostnames="true" \
        allow_ip_sans="true" \
        max_ttl="720h" \
        key_type=rsa \
        key_bits=2048
```

Issue an Alice TLS certificate using the Alice-only CA in terminal #2:

```
$> export VAULT_ADDR='http://127.0.0.1:8200'
$> ./target/vault write -format=json \
        pki_alice/issue/service \
        common_name=alice.example.com \
        > target/alice-pki.json
$> jq -r '.data.certificate' target/alice-pki.json > target/alice-pki.crt
$> jq -r '.data.issuing_ca' target/alice-pki.json >> target/alice-pki.crt
$> jq -r '.data.private_key' target/alice-pki.json > target/alice-pki.pem
```

Please note that we are also appending the certificate of the issuing CA (ie. Alice Intermediate Authority) to `target/alice-pki.crt` so that services that only trust the root CA can verify that Alice's certificate was ultimately issued by a CA that they trust.

Issue a Bob TLS certificate using the Bob-only CA in terminal #2:

```
$> export VAULT_ADDR='http://127.0.0.1:8200'
$> ./target/vault write -format=json \
        pki_bob/issue/service \
        common_name=bob.example.com \
        > target/bob-pki.json
$> jq -r '.data.certificate' target/bob-pki.json > target/bob-pki.crt
$> jq -r '.data.issuing_ca' target/bob-pki.json >> target/bob-pki.crt
$> jq -r '.data.private_key' target/bob-pki.json > target/bob-pki.pem
```

Please note that we are also appending the certificate of the issuing CA (ie. Bob Intermediate Authority) to `target/bob-pki.crt` so that services that only trust the root CA can verify that Bob's certificate was ultimately issued by a CA that they trust.

In terminal #2, start the service using the root CA:

```
$> go run ./cmd/mtls-service/main.go -root target/root.crt
```

In terminal #3, both Alice and Bob should still have access using their new intermediate CA generated client certificates:

```
$> go run ./cmd/mtls-client/main.go -name Alice -cert target/alice-pki.crt -key target/alice-pki.pem
Hello Alice

$> go run ./cmd/mtls-client/main.go -name Bob -cert target/bob-pki.crt -key target/bob-pki.pem
Hello Bob
```

In terminal #2, if we change the service to use the Alice-only CA:

```
$> go run ./cmd/mtls-service/main.go -root target/alice-ca.crt
```

In terminal #3, Alice should be able to connect, and Bob fails for a mysterious certificate error:

```
$> go run ./cmd/mtls-client/main.go -cert target/alice-pki.crt -key target/alice-pki.pem
Hello World

$> go run ./cmd/mtls-client/main.go -cert target/bob-pki.crt -key target/bob-pki.pem
2020/09/22 10:14:07 Get "https://localhost:3000/?name=Bob": remote error: tls: bad certificate
```

Even the server logs in terminal #2 are not helpful:

```
2020/09/22 10:14:07 http: TLS handshake error from [::1]:61014: tls: client didn't provide a certificate
```

This is good enough, but we can do better.

### What if we want to only have the one CA?

But we still do not want to allow Bob to access services that only Alice should have access to.

There are three common options:

1. Generic: Use a proxy (like HAProxy or Nginx) to terminate TLS and validate the client certificate.
2. Go-specific: Fail certificate verification if the certificate does not belong to an Alice.
3. Go-specific: Use middleware to verify the certificate so that we can capture more information.

#### Option 1a - Nginx:

Create a Nginx configuration file to only permit Alice's Common Name:

[nginx.conf](https://github.com/digitalocean/mtls-tech-talk/blob/main/nginx.conf)

```
worker_processes  1;
error_log  stderr;

events {
    worker_connections  1024;
}

http {
    default_type  application/octet-stream;
    access_log  /dev/stdout;
    keepalive_timeout  60;
    gzip  on;

    map $ssl_client_s_dn $ssl_client_s_dn_cn {
        default "";
        ~CN=(?<CN>[^,]+) $CN;
    }

    map $ssl_client_s_dn_cn $ssl_client_s_dn_cn_allowed {
        default "no";
        ~^alice\.example\.com$ "yes";
    }

    server {
        listen                 3000 ssl;
        ssl_certificate        target/server.crt;
        ssl_certificate_key    target/server.pem;
        ssl_client_certificate target/root.crt;
        ssl_verify_client      on;
        ssl_verify_depth       3;

        if ($ssl_client_s_dn_cn_allowed = "no") {
            return 403;
        }

        location / {
            proxy_pass        http://127.0.0.1:3001;
            proxy_redirect    off;
            proxy_set_header  Host              $http_host;
            proxy_set_header  X-Forwarded-For   $proxy_add_x_forwarded_for;
            proxy_set_header  X-Forwarded-Proto https;
        }
    }
}
```

In terminal #1, start a basic http service:

```
go run ./cmd/http-service/main.go
```

In terminal #2, start Nginx:

```
$> export BASE_DIR=$(git rev-parse --show-toplevel 2>/dev/null)
$> nginx -g 'daemon off;' -p ${BASE_DIR} -c ${BASE_DIR}/nginx.conf
```

Connect as Alice and Bob in terminal #3:

```
$> go run ./cmd/mtls-client/main.go -name Alice -cert target/alice.crt -key target/alice.pem
Hello Alice

$> go run ./cmd/mtls-client/main.go -name Bob -cert target/bob.crt -key target/bob.pem
<html>
<head><title>403 Forbidden</title></head>
<body>
<center><h1>403 Forbidden</h1></center>
<hr><center>nginx/1.19.2</center>
</body>
</html>
```

Better than failing the TLS handshake.

#### Option 1b - HAProxy:

Create a HAProxy configuration file to only permit Alice's Common Name:

[haproxy.conf](https://github.com/digitalocean/mtls-tech-talk/blob/main/haproxy.conf)

```
global
    maxconn 256
    log stdout local0

defaults
    mode http
    timeout connect 5000ms
    timeout client 50000ms
    timeout server 50000ms
    log global

frontend http-in
    bind *:3000 ssl crt target/server-all.crt ca-file target/root.crt verify required
    default_backend servers

    acl tls_client_cn_allowed ssl_c_s_dn(cn) -m reg ^alice\.example\.com$
    http-request deny unless tls_client_cn_allowed

    http-request add-header X-Forwarded-Proto https

backend servers
    server server1 127.0.0.1:3001 maxconn 32
```

In terminal #1, start a basic http service:

```
go run ./cmd/http-service/main.go
```

In terminal #2, start HAProxy. Please note that HAProxy requires that the certificate and private key are in a single file:

```
$> export BASE_DIR=$(git rev-parse --show-toplevel 2>/dev/null)
$> cat target/server.crt > target/server-all.crt
$> cat target/server.pem >> target/server-all.crt
$> haproxy -C ${BASE_DIR} -f haproxy.conf
```

Connect as Alice and Bob in terminal #3:

```
$> go run ./cmd/mtls-client/main.go -name Alice -cert target/alice.crt -key target/alice.pem
Hello Alice

$> go run ./cmd/mtls-client/main.go -name Bob -cert target/bob.crt -key target/bob.pem
<html><body><h1>403 Forbidden</h1>
Request forbidden by administrative rules.
</body></html>
```

Better than failing the TLS handshake, less config than Nginx, but not really all that great.

#### Option 2:

Go's `net/http` TLS configuration allows us to abort the TLS handshake after its standard verification steps have completed. We can use that to reject non-Alice certificates.

[cmd/verify-connection/main.go](https://github.com/digitalocean/mtls-tech-talk/blob/main/cmd/verify-connection/main.go)

```go
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

func verifyConnection(state tls.ConnectionState) error {
	clientCert := state.PeerCertificates[0]
	cn := clientCert.Subject.CommonName
	if cn != "alice.example.com" {
		return fmt.Errorf("%s is not allowed", cn)
	}
	return nil
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
		Certificates:     []tls.Certificate{serverCert},
		ClientAuth:       tls.RequireAndVerifyClientCert,
		ClientCAs:        rootCaPool,
		VerifyConnection: verifyConnection,
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
```

Run the service in terminal #2:

```
$> go run ./cmd/verify-connection/main.go
```

Connect as Alice and Bob in terminal #3:

```
$> go run ./cmd/mtls-client/main.go -name Alice -cert target/alice.crt -key target/alice.pem
Hello Alice

$> go run ./cmd/mtls-client/main.go -name Bob -cert target/bob.crt -key target/bob.pem
2020/09/22 10:15:36 Get "https://localhost:3000/?name=Bob": remote error: tls: bad certificate
```

Alice can connect, Bob fails with a bad certificate error and attempts to tear their hair out figuring why they have a bad certificate. Meanwhile, the server terminal #2 shows a suspicious TLS error:

```
2020/09/22 10:15:36 http: TLS handshake error from [::1]:61025: bob.example.com not allowed
```

Oops, this is a bit worse than a proxy. We must be able to do better.

#### Option 3:

We can let the TLS connection get established, then use middleware to inspect the request and see who has connected to us. This allows us to return more informative errors to clients rather than just killing the HTTPS handshake.

[cmd/verify-middleware/main.go](https://github.com/digitalocean/mtls-tech-talk/tree/main/cmd/verify-middleware/main.go)

```go
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
```

Run the service in terminal #1:

```
$> go run ./cmd/verify-middleware/main.go
```

Connect as Alice and Bob in terminal #2:

```
$> go run ./cmd/mtls-client/main.go -name Alice -cert target/alice.crt -key target/alice.pem
Hello Alice

$> go run ./cmd/mtls-client/main.go -name Bob -cert target/bob.crt -key target/bob.pem
you cannot be here bob.example.com
```

Alice can connect, Bob fails with a much nicer error and far less hair pulling.

## gRPC and mTLS

The examples provided here have focused on HTTPS so that we could create relatively simple and self-contained services and clients. If you are looking to enable mTLS in a gRPC ecosystem then you may want to look at the various options for mTLS authentication and authorization provided by this author's [example-grpc](https://github.com/tomcz/example-grpc) project on GitHub.

## Summary

Allowing an organization to benefit from mTLS has required in the past significant operational and engineering effort, thus restricting it to companies with fairly large engineering and operations teams. This is no longer the case with products like Vault, and languages like Go, that make it easier to set up a custom PKI infrastructure and create services that have appropriate levels of authentication and authorization between them.
