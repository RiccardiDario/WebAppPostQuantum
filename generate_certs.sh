#!/bin/sh

# Interrompe immediatamente lo script se un comando fallisce
set -e

# Genera il certificato della CA
openssl req -x509 -new -newkey dilithium5 -keyout /certs/CA.key -out /certs/CA.crt -nodes -days 365 -config /openssl.cnf -subj "/CN=oqstest CA" -extensions v3_ca 

# Genera la richiesta di firma per il certificato del server
openssl req -new -newkey dilithium5 -keyout /certs/server.key -out /certs/server.csr -nodes -config /openssl.cnf -subj "/CN=nginx_pq" -extensions v3_req 

# Firma il certificato del server usando la CA
openssl x509 -req -in /certs/server.csr -out /certs/server.crt -CA /certs/CA.crt -CAkey /certs/CA.key -CAcreateserial -days 365

# Crea la catena di certificati
cat /certs/server.crt > /certs/qsc-ca-chain.crt
cat /certs/CA.crt >> /certs/qsc-ca-chain.crt

# Imposta i permessi sui certificati generati
chmod 644 /certs/server.key
chmod 644 /certs/qsc-ca-chain.crt
chmod 644 /certs/CA.crt
chmod 644 /certs/server.crt

echo "Certificati generati, catena creata e permessi impostati correttamente!"

# Esegui controlli opzionali se VERIFY_CERTS è impostato su 1
if [ "$VERIFY_CERTS" = "1" ]; then
  echo "Esecuzione dei controlli sui certificati..."

  # Verifica il certificato del server
  openssl verify -CAfile /certs/CA.crt /certs/server.crt

  # Visualizza informazioni sulla chiave
  openssl x509 -in /certs/server.crt -text -noout
  openssl x509 -in /certs/server.crt -noout -text | grep "Public Key Algorithm"

  echo "Controlli completati!"
fi