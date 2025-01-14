#!/bin/sh

# Percorsi dei file di report
TLS_REPORT_FILE="/output/tls_handshake_report.md"
PERFORMANCE_REPORT_FILE="/output/performance_metrics_report.md"

# Inizializza i file di report
printf "### TLS Handshake Information\n\n" > $TLS_REPORT_FILE
printf "### Performance Metrics\n\n" > $PERFORMANCE_REPORT_FILE

# Aggiungi metriche di tempo al report delle prestazioni
printf "#### Time Metrics\n\n" >> $PERFORMANCE_REPORT_FILE
curl --tlsv1.3 --curves x25519_mlkem512 --cacert /opt/certs/CA.crt \
  -w "\nConnect Time: %{time_connect} seconds (Tempo per stabilire la connessione TCP, incluso il DNS lookup)\nTLS Handshake: %{time_appconnect} seconds (Tempo per completare l'handshake TLS)\nTotal Time: %{time_total} seconds (Tempo totale dall'inizio della connessione alla ricezione della risposta, include trasmissione e ricezione dei dati HTTP)\n" \
  -o /dev/null https://nginx_pq:4433 >> $PERFORMANCE_REPORT_FILE 2>/dev/null

# Aggiungi informazioni sulla cifratura e firma al report delle prestazioni
printf "\n#### Cryptographic Details\n\n" >> $PERFORMANCE_REPORT_FILE
curl --tlsv1.3 --curves x25519_mlkem512 --cacert /opt/certs/CA.crt -v https://nginx_pq:4433 2>&1 | \
awk '/^\* SSL connection using/ {print "- Cipher Suite: " substr($0, index($0,$5))}' >> $PERFORMANCE_REPORT_FILE

# Aggiungi metriche relative alle dimensioni dei dati
printf "\n#### Data Metrics\n\n" >> $PERFORMANCE_REPORT_FILE
CERT_INFO=$(openssl x509 -in /opt/certs/CA.crt -text -noout)
KEY_SIZE=$(echo "$CERT_INFO" | awk '/Public-Key:/ {print $2}')
SIGNATURE_ALGO=$(echo "$CERT_INFO" | awk '/Signature Algorithm:/ {getline; print $1}')
printf "- Public Key Size: %s bits\n" "$KEY_SIZE" >> $PERFORMANCE_REPORT_FILE
printf "- Signature Algorithm: %s\n" "$SIGNATURE_ALGO" >> $PERFORMANCE_REPORT_FILE

# Analizza i dati scambiati durante l'handshake
curl --tlsv1.3 --curves x25519_mlkem512 --cacert /opt/certs/CA.crt -v https://nginx_pq:4433 2>&1 | \
awk '/bytes data/ {split($0, arr, " "); sum += arr[1]} END {print "- Total Data Exchanged During Handshake: " sum " bytes"}' >> $PERFORMANCE_REPORT_FILE

# Aggiungi dettagli dell'output di curl al report TLS
printf "#### Detailed TLS Handshake Output\n\n" >> $TLS_REPORT_FILE
curl --tlsv1.3 --curves x25519_mlkem512 --cacert /opt/certs/CA.crt -v https://nginx_pq:4433 \
  > /output/curl_output.txt 2>&1

# Elaborazione dell'output di curl per il report TLS
if [ -s /output/curl_output.txt ]; then
  awk '/^\\*/ {print "- " substr($0, 3)}' /output/curl_output.txt >> $TLS_REPORT_FILE
  printf "\n## HTTP Response\n" >> $TLS_REPORT_FILE
  awk '/^< / {print "- " substr($0, 3)}' /output/curl_output.txt >> $TLS_REPORT_FILE
else
  printf "\nNo detailed curl output available\n" >> $TLS_REPORT_FILE
fi

# Aggiungi metriche sul traffico (se iftop è disponibile) al report delle prestazioni
if command -v iftop >/dev/null 2>&1; then
  printf "\n#### Traffic Metrics\n\n" >> $PERFORMANCE_REPORT_FILE
  printf "(Unità di misura: Bit per secondo - bps)\n\n" >> $PERFORMANCE_REPORT_FILE
  iftop -t -n -s 5 >> $PERFORMANCE_REPORT_FILE
else
  printf "\niftop not found: Traffic metrics skipped\n" >> $PERFORMANCE_REPORT_FILE
fi

# Mantiene il container attivo
tail -f /dev/null
