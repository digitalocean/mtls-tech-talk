BASE_DIR := $(shell git rev-parse --show-toplevel 2>/dev/null)
export VAULT_ADDR=http://127.0.0.1:8200

# =====================================================================
# Services
# =====================================================================

.PHONY: run-mtls-service
run-mtls-service:
	go run ./cmd/mtls-service/main.go \
		-cert target/server.crt \
		-key target/server.pem

.PHONY: run-verify-connection
run-verify-connection:
	go run ./cmd/verify-connection/main.go

.PHONY: run-verify-middleware
run-verify-middleware:
	go run ./cmd/verify-middleware/main.go

.PHONY: run-alice-pki-service
run-alice-pki-service:
	go run ./cmd/mtls-service/main.go -root target/alice-ca.crt

.PHONY: run-http-service
run-http-service:
	go run ./cmd/http-service/main.go

.PHONY: run-nginx
run-nginx:
	nginx -g 'daemon off;' -p ${BASE_DIR} -c ${BASE_DIR}/nginx.conf

.PHONY: run-haproxy
run-haproxy:
	cat target/server.crt > target/server-all.crt
	cat target/server.pem >> target/server-all.crt
	haproxy -C ${BASE_DIR} -f haproxy.conf

# =====================================================================
# Clients
# =====================================================================

.PHONY: run-alice-client
run-alice-client:
	go run ./cmd/mtls-client/main.go \
		-cert target/alice.crt \
		-key target/alice.pem \
		-name Alice

.PHONY: run-bob-client
run-bob-client:
	go run ./cmd/mtls-client/main.go \
		-cert target/bob.crt \
		-key target/bob.pem \
		-name Bob

.PHONY: run-alice-pki-client
run-alice-pki-client:
	go run ./cmd/mtls-client/main.go \
		-cert target/alice-pki.crt \
		-key target/alice-pki.pem \
		-name Alice

.PHONY: run-bob-pki-client
run-bob-pki-client:
	go run ./cmd/mtls-client/main.go \
		-cert target/bob-pki.crt \
		-key target/bob-pki.pem \
		-name Bob

# =====================================================================
# Vault PKI
# =====================================================================

.PHONY: clean
clean:
	rm -rf target

target:
	mkdir target

target/vault: | target
ifeq ($(shell uname -s),Darwin)
	curl -SsfL -o target/vault.zip https://releases.hashicorp.com/vault/1.5.4/vault_1.5.4_darwin_amd64.zip
else
	curl -SsfL -o target/vault.zip https://releases.hashicorp.com/vault/1.5.4/vault_1.5.4_linux_amd64.zip
endif
	unzip target/vault.zip -d target
	rm target/vault.zip
	chmod +x target/vault

.PHONY: run-vault
run-vault: | target/vault
	bash -c 'trap "rm -f ~/.vault-token" EXIT; ./target/vault server -dev -dev-root-token-id="root"'

.PHONY: setup-pki
setup-pki: setup-root-pki setup-alice-pki setup-bob-pki

.PHONY: setup-root-pki
setup-root-pki: setup-root-ca issue-server-cert issue-alice-cert issue-bob-cert

.PHONY: setup-alice-pki
setup-alice-pki: setup-alice-ca issue-alice-pki-cert

.PHONY: setup-bob-pki
setup-bob-pki: setup-bob-ca issue-bob-pki-cert

.PHONY: setup-root-ca
setup-root-ca: | target/vault
	./target/vault secrets enable \
		-path pki_local \
		-max-lease-ttl=87600h \
		pki
	./target/vault write pki_local/config/urls \
		issuing_certificates="http://127.0.0.1:8200/v1/pki_local/ca" \
		crl_distribution_points="http://127.0.0.1:8200/v1/pki_local/crl"
	./target/vault write -format=json \
		pki_local/root/generate/internal \
		common_name="Local Root CA" \
		ttl=87600h \
		key_type=rsa \
		key_bits=2048 \
		> target/root.json
	./target/vault write pki_local/roles/service \
		allowed_domains="example.com" \
		allow_bare_domains="true" \
		allow_subdomains="true" \
		allow_localhost="true" \
		enforce_hostnames="true" \
		allow_ip_sans="true" \
		max_ttl="720h" \
		key_type=rsa \
		key_bits=2048
	jq -r '.data.certificate' target/root.json > target/root.crt
	openssl x509 -text -noout -in target/root.crt

.PHONY: issue-server-cert
issue-server-cert: | target/vault
	./target/vault write -format=json \
		pki_local/issue/service \
		common_name=www.example.com \
		alt_names=localhost \
		ip_sans=127.0.0.1 \
		> target/server.json
	jq -r '.data.certificate' target/server.json > target/server.crt
	jq -r '.data.private_key' target/server.json > target/server.pem
	openssl x509 -text -noout -in target/server.crt

.PHONY: issue-alice-cert
issue-alice-cert: | target/vault
	./target/vault write -format=json \
		pki_local/issue/service \
		common_name=alice.example.com \
		> target/alice.json
	jq -r '.data.certificate' target/alice.json > target/alice.crt
	jq -r '.data.private_key' target/alice.json > target/alice.pem
	openssl x509 -text -noout -in target/alice.crt

.PHONY: issue-bob-cert
issue-bob-cert: | target/vault
	./target/vault write -format=json \
		pki_local/issue/service \
		common_name=bob.example.com \
		> target/bob.json
	jq -r '.data.certificate' target/bob.json > target/bob.crt
	jq -r '.data.private_key' target/bob.json > target/bob.pem
	openssl x509 -text -noout -in target/bob.crt

.PHONY: setup-alice-ca
setup-alice-ca: | target/vault
	./target/vault secrets enable -path=pki_alice pki
	./target/vault secrets tune -max-lease-ttl=43800h pki_alice
	./target/vault write -format=json \
		pki_alice/intermediate/generate/internal \
		common_name="Alice Intermediate Authority" \
		ttl=43800h \
		> target/alice-ca-csr.json
	jq -r '.data.csr' target/alice-ca-csr.json > target/alice-ca.csr
	./target/vault write -format=json \
		pki_local/root/sign-intermediate \
		csr=@target/alice-ca.csr \
		format=pem_bundle \
		ttl=43800h \
		> target/alice-ca.json
	jq -r '.data.certificate' target/alice-ca.json > target/alice-ca.crt
	./target/vault write \
		pki_alice/intermediate/set-signed \
		certificate=@target/alice-ca.crt
	./target/vault write pki_alice/config/urls \
		issuing_certificates="http://127.0.0.1:8200/v1/pki_alice/ca" \
		crl_distribution_points="http://127.0.0.1:8200/v1/pki_alice/crl"
	./target/vault write pki_alice/roles/service \
		allowed_domains="example.com" \
		allow_bare_domains="true" \
		allow_subdomains="true" \
		allow_localhost="true" \
		enforce_hostnames="true" \
		allow_ip_sans="true" \
		max_ttl="720h" \
		key_type=rsa \
		key_bits=2048
	openssl x509 -text -noout -in target/alice-ca.crt

.PHONY: setup-bob-ca
setup-bob-ca: | target/vault
	./target/vault secrets enable -path=pki_bob pki
	./target/vault secrets tune -max-lease-ttl=43800h pki_bob
	./target/vault write -format=json \
		pki_bob/intermediate/generate/internal \
		common_name="Bob Intermediate Authority" \
		ttl=43800h \
		> target/bob-ca-csr.json
	jq -r '.data.csr' target/bob-ca-csr.json > target/bob-ca.csr
	./target/vault write -format=json \
		pki_local/root/sign-intermediate \
		csr=@target/bob-ca.csr \
		format=pem_bundle \
		ttl=43800h \
		> target/bob-ca.json
	jq -r '.data.certificate' target/bob-ca.json > target/bob-ca.crt
	./target/vault write \
		pki_bob/intermediate/set-signed \
		certificate=@target/bob-ca.crt
	./target/vault write pki_bob/config/urls \
		issuing_certificates="http://127.0.0.1:8200/v1/pki_bob/ca" \
		crl_distribution_points="http://127.0.0.1:8200/v1/pki_bob/crl"
	./target/vault write pki_bob/roles/service \
		allowed_domains="example.com" \
		allow_bare_domains="true" \
		allow_subdomains="true" \
		allow_localhost="true" \
		enforce_hostnames="true" \
		allow_ip_sans="true" \
		max_ttl="720h" \
		key_type=rsa \
		key_bits=2048
	openssl x509 -text -noout -in target/bob-ca.crt

.PHONY: issue-alice-pki-cert
issue-alice-pki-cert: | target/vault
	./target/vault write -format=json \
		pki_alice/issue/service \
		common_name=alice.example.com \
		> target/alice-pki.json
	jq -r '.data.certificate' target/alice-pki.json > target/alice-pki.crt
	jq -r '.data.issuing_ca' target/alice-pki.json >> target/alice-pki.crt
	jq -r '.data.private_key' target/alice-pki.json > target/alice-pki.pem
	openssl x509 -text -noout -in target/alice-pki.crt

.PHONY: issue-bob-pki-cert
issue-bob-pki-cert: | target/vault
	./target/vault write -format=json \
		pki_bob/issue/service \
		common_name=bob.example.com \
		> target/bob-pki.json
	jq -r '.data.certificate' target/bob-pki.json > target/bob-pki.crt
	jq -r '.data.issuing_ca' target/bob-pki.json >> target/bob-pki.crt
	jq -r '.data.private_key' target/bob-pki.json > target/bob-pki.pem
	openssl x509 -text -noout -in target/bob-pki.crt
