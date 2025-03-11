#!/bin/sh
set -e

[ -z "$SIGNATURE_ALGO" ] && { echo "Errore: SIGNATURE_ALGO non definita. Controlla .env."; exit 1; }

CA_KEY="/certs/CA.key"; CA_CERT="/certs/CA.crt"; SERVER_KEY="/certs/server.key"
SERVER_CERT="/certs/server.crt"; SERVER_CHAIN="/certs/qsc-ca-chain.crt"; SERVER_CSR="/certs/server.csr"
SERVER_IP="192.168.1.3"

openssl_pkey() {
  case "$1" in
    rsa-pss-sha256|rsa-pss-sha384|rsa-pss-sha512|rsa-pkcs1-sha256|rsa-pkcs1-sha512)
      openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out "$2";;
    ecdsa_p256) openssl ecparam -genkey -name prime256v1 -out "$2";;
    ecdsa_p384) openssl ecparam -genkey -name secp384r1 -out "$2";;
    ecdsa_p521) openssl ecparam -genkey -name secp521r1 -out "$2";;
    ed25519|ed448) openssl genpkey -algorithm $(echo "$1" | tr a-z A-Z) -out "$2";;
    *) openssl genpkey -algorithm "$1" -out "$2";;
  esac
}

sigopts() {
  case "$1" in
    ecdsa_p256) echo "-sha256";;
    ecdsa_p384) echo "-sha384";;
    ecdsa_p521) echo "-sha512";;
    rsa-pss-sha256) echo "-sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:-1 -sha256";;
    rsa-pss-sha384) echo "-sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:-1 -sha384";;
    rsa-pss-sha512) echo "-sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:-1 -sha512";;
    rsa-pkcs1-sha256) echo "-sha256";;
    rsa-pkcs1-sha512) echo "-sha512";;
    *) echo "";;
  esac
}

echo "Generazione certificati..."

openssl_pkey "$SIGNATURE_ALGO" "$CA_KEY"

SIGOPT_CA=$(sigopts "$SIGNATURE_ALGO")
openssl req -x509 -new -key "$CA_KEY" -out "$CA_CERT" -nodes -days 365 -config /cert-generator/openssl.cnf -subj "/CN=oqstest CA" -extensions v3_ca $SIGOPT_CA

openssl_pkey "$SIGNATURE_ALGO" "$SERVER_KEY"
openssl req -new -key "$SERVER_KEY" -out "$SERVER_CSR" -config /cert-generator/openssl.cnf -subj "/CN=$SERVER_IP" -reqexts v3_req

SIGOPT=$(sigopts "$SIGNATURE_ALGO")
openssl x509 -req -in "$SERVER_CSR" -out "$SERVER_CERT" -CA "$CA_CERT" -CAkey "$CA_KEY" -CAcreateserial -days 365 \
  -extfile /cert-generator/openssl.cnf -extensions v3_req $SIGOPT

cat "$SERVER_CERT" "$CA_CERT" > "$SERVER_CHAIN"
chmod 644 "$SERVER_KEY" "$SERVER_CHAIN" "$CA_CERT" "$SERVER_CERT"

echo "Certificati generati con successo!"

[ "$VERIFY_CERTS" = "1" ] && {
  echo "Verifica certificati..."
  openssl verify -CAfile "$CA_CERT" "$SERVER_CERT"
  openssl x509 -in "$SERVER_CERT" -text -noout | grep -A1 "Signature Algorithm"
  echo "Verifica completata!"
}
