#!/bin/sh
set -e

[ -z "$SIGNATURE_ALGO" ] && { echo "Errore: SIGNATURE_ALGO non definita. Controlla .env."; exit 1; }

CA_KEY="/certs/CA.key"; CA_CERT="/certs/CA.crt"; SERVER_KEY="/certs/server.key"
SERVER_CERT="/certs/server.crt"; SERVER_CHAIN="/certs/qsc-ca-chain.crt"; SERVER_CSR="/certs/server.csr"
EXTFILE="/tmp/ext.cnf"

openssl_pkey() {
  case "$1" in
    rsa-pss-*) openssl genrsa -out "$2" 4096 ;;
    ecdsa_p256) openssl ecparam -genkey -name prime256v1 -out "$2" ;;
    ecdsa_p384) openssl ecparam -genkey -name secp384r1 -out "$2" ;;
    ecdsa_p521) openssl ecparam -genkey -name secp521r1 -out "$2" ;;
    ed25519|ed448) openssl genpkey -algorithm "$(echo "$1" | tr a-z A-Z)" -out "$2" ;;
    *) openssl genpkey -algorithm "$1" -out "$2" ;;
  esac
}

sigopts() {
  case "$1" in
    ecdsa_p256) echo "-sha256" ;;
    ecdsa_p384) echo "-sha384" ;;
    ecdsa_p521) echo "-sha512" ;;
    rsa-pss-sha256) echo "-sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:-1 -sha256" ;;
    rsa-pss-sha384) echo "-sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:-1 -sha384" ;;
    rsa-pss-sha512) echo "-sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:-1 -sha512" ;;
    rsa-pkcs1-sha256) echo "-sha256" ;;
    rsa-pkcs1-sha512) echo "-sha512" ;;
    *) echo "" ;;
  esac
}

echo "Generazione certificati..."
openssl_pkey "$SIGNATURE_ALGO" "$CA_KEY"
SIGOPT_CA=$(sigopts "$SIGNATURE_ALGO")
openssl req -x509 -new -key "$CA_KEY" -out "$CA_CERT" -nodes -days 365 \
  -subj "/CN=oqstest CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" $SIGOPT_CA

openssl_pkey "$SIGNATURE_ALGO" "$SERVER_KEY"
openssl req -new -key "$SERVER_KEY" -out "$SERVER_CSR" \
  -subj "/CN=nginx_pq" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
  -addext "extendedKeyUsage=serverAuth"

SIGOPT=$(sigopts "$SIGNATURE_ALGO")
cat <<EOF > "$EXTFILE"
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
EOF

openssl x509 -req -in "$SERVER_CSR" -out "$SERVER_CERT" -CA "$CA_CERT" -CAkey "$CA_KEY" \
  -CAcreateserial -days 365 -extfile "$EXTFILE" $SIGOPT

cat "$SERVER_CERT" "$CA_CERT" > "$SERVER_CHAIN"
chmod 644 "$SERVER_KEY" "$SERVER_CHAIN" "$CA_CERT" "$SERVER_CERT"

echo "Certificati generati con successo!"
echo "Verifica certificati..."
openssl verify -CAfile "$CA_CERT" "$SERVER_CERT"
openssl x509 -in "$SERVER_CERT" -text -noout | grep -A1 "Signature Algorithm"
echo "Verifica completata!"