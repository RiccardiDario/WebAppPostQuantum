import subprocess
import csv
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

# Configura i parametri per le richieste
URL = "https://nginx_pq:4433"
CURL_COMMAND_TEMPLATE = ["curl","--tlsv1.3","--curves", "x25519_mlkem512","--cacert", "/opt/certs/CA.crt",
    "-w", "Connect Time: %{time_connect}, TLS Handshake: %{time_appconnect}, Total Time: %{time_total}\n",
    "-o", "/dev/null","-s",URL,]

# Numero di richieste da eseguire
NUM_REQUESTS = 1000
OUTPUT_FILE = "/app/output/performance_report.csv"

# Funzione per eseguire una richiesta
def execute_request(request_number):
    try:
        result = subprocess.run(CURL_COMMAND_TEMPLATE, capture_output=True, text=True, check=True)
        output = result.stdout.strip()
        # Estrai i tempi dall'output di curl
        metrics = dict(item.split(": ") for item in output.split(", "))
        connect_time = float(metrics["Connect Time"].replace("s", ""))
        handshake_time = float(metrics["TLS Handshake"].replace("s", ""))
        total_time = float(metrics["Total Time"].replace("s", ""))
        return [request_number, connect_time, handshake_time, total_time, "Success"]
    except subprocess.CalledProcessError as e:
        # Ritorna un fallimento in caso di errore
        print(f"Errore nella richiesta {request_number}: {e}")
        return [request_number, None, None, None, "Failure"]

# Inizializza il file CSV
os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
with open(OUTPUT_FILE, mode="w", newline="", encoding="utf-8") as file:
    writer = csv.writer(file, delimiter=",", quotechar='"', quoting=csv.QUOTE_MINIMAL)
    # Intestazione del file
    writer.writerow(["Request_Number", "Connect_Time", "TLS_Handshake", "Total_Time", "Status"])

    # Esegui tutte le richieste in parallelo
    start_time = time.time()
    with ThreadPoolExecutor(max_workers=NUM_REQUESTS) as executor:
        # Avvia tutte le richieste contemporaneamente
        futures = [executor.submit(execute_request, i + 1) for i in range(NUM_REQUESTS)]
        for future in as_completed(futures):
            result = future.result()
            writer.writerow(result)
            print(f"Request {result[0]}: Status={result[4]}")

    end_time = time.time()

print(f"Test completato in {end_time - start_time:.2f} secondi.")
print(f"Report generato in: {OUTPUT_FILE}")
