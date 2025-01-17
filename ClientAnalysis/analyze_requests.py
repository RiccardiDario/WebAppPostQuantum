import subprocess
import csv
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

# Configura i parametri per le richieste
URL = "https://nginx_pq:4433"  # URL di destinazione per le richieste HTTPS
CURL_COMMAND_TEMPLATE = ["curl", "--tlsv1.3", "--curves", "x25519_mlkem512", "--cacert", "/opt/certs/CA.crt",
                         "-w", "Connect Time: %{time_connect}, TLS Handshake: %{time_appconnect}, Total Time: %{time_total}\n",
                         "-o", "/dev/null", "-s", URL]  # Comando curl configurato per l'uso con TLS 1.3 e curve specifiche

# Numero di richieste da eseguire
NUM_REQUESTS = 100  # Numero totale di richieste da inviare
OUTPUT_FILE = "/app/output/performance_report.csv"  # Percorso del file CSV per salvare i risultati

# Contatore delle richieste andate a buon fine
success_count = 0  # Variabile globale per contare le richieste riuscite

def execute_request(request_number):
    """Esegue una singola richiesta e raccoglie i dati sulle prestazioni."""
    global success_count
    try:
        start_time = time.time()  # Tempo di inizio della richiesta
        result = subprocess.run(CURL_COMMAND_TEMPLATE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)  # Esegue il comando curl
        end_time = time.time()  # Tempo di fine della richiesta

        output = result.stdout.strip()  # Estrae l'output di curl
        # Estrai i tempi dall'output di curl
        metrics = dict(item.split(": ") for item in output.split(", "))
        connect_time = float(metrics["Connect Time"].replace("s", ""))  # Tempo di connessione
        handshake_time = float(metrics["TLS Handshake"].replace("s", ""))  # Tempo di handshake TLS
        total_time = float(metrics["Total Time"].replace("s", ""))  # Tempo totale della richiesta

        # Calcola la larghezza di banda utilizzata
        bytes_sent = len(result.stderr) + len(result.stdout)  # Calcola i byte totali trasferiti
        bandwidth = bytes_sent / (end_time - start_time) / (1024 ** 2)  # Calcola la larghezza di banda in MB/s

        # Esegui il monitoraggio delle risorse (usiamo 'time' come esempio)
        resource_usage = subprocess.run(
            ["/usr/bin/time", "-v"] + CURL_COMMAND_TEMPLATE,  # Usa il comando 'time' per raccogliere dati sulle risorse
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        memory_usage = extract_memory_usage(resource_usage.stderr)  # Estrae l'uso della memoria RAM
        cpu_usage = extract_cpu_usage(resource_usage.stderr)  # Estrae l'uso della CPU

        success_count += 1  # Incrementa il contatore delle richieste riuscite
        return [request_number, connect_time, handshake_time, total_time, "Success",
                f"{success_count}/{NUM_REQUESTS}", bandwidth, memory_usage, bytes_sent, cpu_usage]  # Ritorna i dati raccolti
    except subprocess.CalledProcessError as e:
        print(f"Errore nella richiesta {request_number}: {e}")  # Log dell'errore
        return [request_number, None, None, None, "Failure",
                f"{success_count}/{NUM_REQUESTS}", None, None, None, None]  # Ritorna valori nulli in caso di errore

def extract_memory_usage(output):
    """Estrai l'uso della RAM dall'output di 'time'."""
    for line in output.splitlines():
        if "Maximum resident set size" in line:
            return int(line.split(":")[1].strip()) / 1024  # Converte i KB in MB
    return None

def extract_cpu_usage(output):
    """Estrai l'uso della CPU dall'output di 'time'."""
    for line in output.splitlines():
        if "Percent of CPU this job got" in line:
            return float(line.split(":")[1].strip().replace("%", ""))  # Converte la percentuale in float
    return None

# Inizializza il file CSV
os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)  # Crea la directory per il file di output, se necessario
with open(OUTPUT_FILE, mode="w", newline="", encoding="utf-8") as file:
    writer = csv.writer(file, delimiter=",", quotechar='"', quoting=csv.QUOTE_MINIMAL)  # Configura il writer CSV
    # Intestazione del file
    writer.writerow(["Request_Number", "Connect_Time", "TLS_Handshake", "Total_Time", "Status",
                     "Success_Count/Total", "Bandwidth_MBps", "Memory_Usage_MB", "Bytes_Transferred", "CPU_Usage_Percent"])

    # Esegui tutte le richieste in parallelo
    start_time = time.time()  # Tempo di inizio per tutte le richieste
    with ThreadPoolExecutor(max_workers=NUM_REQUESTS) as executor:
        # Avvia tutte le richieste contemporaneamente
        futures = [executor.submit(execute_request, i + 1) for i in range(NUM_REQUESTS)]
        for future in as_completed(futures):
            result = future.result()  # Raccoglie il risultato della richiesta
            writer.writerow(result)  # Scrive i risultati nel file CSV
            print(f"Request {result[0]}: Status={result[4]} Success_Count/Total={result[5]} Bandwidth={result[6]}MBps Bytes_Transferred={result[8]} CPU_Usage={result[9]}%")  # Log dei risultati

    end_time = time.time()  # Tempo di fine per tutte le richieste

print(f"Test completato in {end_time - start_time:.2f} secondi.")  # Stampa il tempo totale impiegato
print(f"Report generato in: {OUTPUT_FILE}")  # Indica il percorso del report generato