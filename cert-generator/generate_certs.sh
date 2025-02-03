#!/bin/sh

# Interrompe immediatamente lo script se un comando fallisce
set -e

# Controlla che la variabile d'ambiente SIGNATURE_ALGO sia definita
if [ -z "$SIGNATURE_ALGO" ]; then
  echo "Errore: la variabile SIGNATURE_ALGO non è definita. Verifica il file .env."
  exit 1
fi

# Percorso assoluto dei certificati
CA_KEY="/certs/CA.key"
CA_CERT="/certs/CA.crt"
SERVER_KEY="/certs/server.key"
SERVER_CERT="/certs/server.crt"
SERVER_CHAIN="/certs/qsc-ca-chain.crt"
SERVER_CSR="/certs/server.csr"

# Definisce l'IP del server per il certificato
SERVER_IP="192.168.1.3"

# Controlla se i certificati esistono già
if [ -f "$CA_KEY" ] && [ -f "$CA_CERT" ] && [ -f "$SERVER_KEY" ] && [ -f "$SERVER_CERT" ]; then
  echo "I certificati sono già presenti. Nessuna nuova generazione necessaria."
else
  echo "Generazione dei certificati..."
  
  # Genera il certificato della CA
  openssl req -x509 -new -newkey "$SIGNATURE_ALGO" -keyout "$CA_KEY" -out "$CA_CERT" -nodes -days 365 -config /cert-generator/openssl.cnf -subj "/CN=oqstest CA" -extensions v3_ca 

  # Genera la richiesta di firma per il certificato del server con il SAN
  openssl req -new -newkey "$SIGNATURE_ALGO" -keyout "$SERVER_KEY" -out "$SERVER_CSR" -nodes -config /cert-generator/openssl.cnf -subj "/CN=$SERVER_IP" -reqexts v3_req

  # Firma il certificato del server usando la CA
  openssl x509 -req -in "$SERVER_CSR" -out "$SERVER_CERT" -CA "$CA_CERT" -CAkey "$CA_KEY" -CAcreateserial -days 365 -extfile /cert-generator/openssl.cnf -extensions v3_req

  # Crea la catena di certificati
  cat "$SERVER_CERT" > "$SERVER_CHAIN"
  cat "$CA_CERT" >> "$SERVER_CHAIN"

  # Imposta i permessi sui certificati generati
  chmod 644 "$SERVER_KEY" "$SERVER_CHAIN" "$CA_CERT" "$SERVER_CERT"
  
  echo "Certificati generati, catena creata e permessi impostati correttamente!"
fi

# Esegui controlli opzionali se VERIFY_CERTS è impostato su 1
if [ "$VERIFY_CERTS" = "1" ]; then
  echo "Esecuzione dei controlli sui certificati..."
  openssl verify -CAfile "$CA_CERT" "$SERVER_CERT"
  openssl x509 -in "$SERVER_CERT" -text -noout
  openssl x509 -in "$SERVER_CERT" -noout -text | grep "Public Key Algorithm"
  echo "Controlli completati!"
fi
