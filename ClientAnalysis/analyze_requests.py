import subprocess
import csv
import time

# Configura i parametri per le richieste
URL = "https://nginx_pq:4433"
CURL_COMMAND = [
    "curl",
    "--tlsv1.3",
    "--curves", "x25519_mlkem512",
    "--cacert", "/opt/certs/CA.crt",
    "-w", "Connect Time: %{time_connect}, TLS Handshake: %{time_appconnect}, Total Time: %{time_total}\n",
    "-o", "/dev/null",
    "-s",
    URL,
]

# Numero di richieste da eseguire
NUM_REQUESTS = 100
OUTPUT_FILE = "/app/output/performance_report.csv"

# Inizializza il file CSV
with open(OUTPUT_FILE, mode="w", newline="") as file:
    writer = csv.writer(file)
    # Intestazione del file
    writer.writerow(["Request_Number", "Connect_Time", "TLS_Handshake", "Total_Time"])
    
    for i in range(NUM_REQUESTS):
        # Esegui la richiesta usando subprocess
        try:
            result = subprocess.run(CURL_COMMAND, capture_output=True, text=True, check=True)
            output = result.stdout.strip()
            
            # Estrai i tempi dall'output di curl
            metrics = dict(item.split(": ") for item in output.split(", "))
            connect_time = float(metrics["Connect Time"].replace("s", ""))
            handshake_time = float(metrics["TLS Handshake"].replace("s", ""))
            total_time = float(metrics["Total Time"].replace("s", ""))
            
            # Scrivi i dati nel file CSV
            writer.writerow([i + 1, connect_time, handshake_time, total_time])
            print(f"Request {i + 1}: Connect={connect_time}s, Handshake={handshake_time}s, Total={total_time}s")
        
        except subprocess.CalledProcessError as e:
            print(f"Errore nella richiesta {i + 1}: {e}")
        
        # Opzionale: Pausa tra le richieste
        time.sleep(1)

print(f"Report generato in: {OUTPUT_FILE}")
