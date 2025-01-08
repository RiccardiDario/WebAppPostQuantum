#!/bin/sh

# Interrompe immediatamente lo script se un comando fallisce
set -e

# Genera il certificato della CA
openssl req -x509 -new -newkey dilithium5 -keyout /nginx/certs/CA.key -out /nginx/certs/CA.crt -nodes -days 365 -config /openssl.cnf -subj "/CN=oqstest CA" -extensions v3_ca 

# Genera la richiesta di firma per il certificato del server
openssl req -new -newkey dilithium5 -keyout /nginx/certs/server.key -out /nginx/certs/server.csr -nodes -config /openssl.cnf -subj "/CN=nginx_pq" -extensions v3_req 

# Firma il certificato del server usando la CA
openssl x509 -req -in /nginx/certs/server.csr -out /nginx/certs/server.crt -CA /nginx/certs/CA.crt -CAkey /nginx/certs/CA.key -CAcreateserial -days 365

# Crea la catena di certificati
cat /nginx/certs/server.crt > /nginx/certs/qsc-ca-chain.crt
cat /nginx/certs/CA.crt >> /nginx/certs/qsc-ca-chain.crt

# Imposta i permessi sui certificati generati
chmod 644 /nginx/certs/server.key
chmod 644 /nginx/certs/qsc-ca-chain.crt
chmod 644 /nginx/certs/CA.crt
chmod 644 /nginx/certs/server.crt

echo "Certificati generati, catena creata e permessi impostati correttamente!"

# Esegui controlli opzionali se VERIFY_CERTS è impostato su 1
if [ "$VERIFY_CERTS" = "1" ]; then
  echo "Esecuzione dei controlli sui certificati..."

  # Verifica il certificato del server
  openssl verify -CAfile /nginx/certs/CA.crt /nginx/certs/server.crt

  # Visualizza informazioni sulla chiave
  openssl x509 -in /nginx/certs/server.crt -text -noout
  openssl x509 -in /nginx/certs/server.crt -noout -text | grep "Public Key Algorithm"

  echo "Controlli completati!"
fi
