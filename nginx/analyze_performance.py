import csv
from datetime import datetime
import time
import os

RESOURCE_LOG = "/opt/nginx/output/resource_monitor.csv"
ACCESS_LOG = "/opt/nginx/logs/access_custom.log"
OUTPUT_FILE = "/opt/nginx/output/sampled_performance.csv"
EXPECTED_REQUESTS = 500

def load_resource_data():
    print("Caricamento dati di monitoraggio dal file:", RESOURCE_LOG)
    resource_data = []
    if not os.path.exists(RESOURCE_LOG):
        print(f"ERRORE: Il file {RESOURCE_LOG} non esiste.")
        return resource_data

    try:
        with open(RESOURCE_LOG, mode="r", encoding="utf-8") as file:
            reader = csv.DictReader(file)
            for row in reader:
                timestamp = datetime.strptime(row["Timestamp"], "%d/%b/%Y:%H:%M:%S")
                resource_data.append({
                    "timestamp": timestamp,
                    "cpu": float(row["CPU_Usage (%)"]),
                    "memory": float(row["Memory_Usage (MB)"]),
                    "bytes_sent": int(row["Bytes_Sent"]),
                    "bytes_received": int(row["Bytes_Received"]),
                    "active_connections": int(row["Active_Connections"]),
                })
    except Exception as e:
        print(f"ERRORE: Impossibile caricare i dati di monitoraggio. Dettagli: {e}")
    print(f"Caricati {len(resource_data)} campionamenti dal file di monitoraggio.")
    return resource_data

def wait_for_requests():
    print("In attesa che almeno", EXPECTED_REQUESTS, "richieste siano completate...")
    while True:
        try:
            if not os.path.exists(ACCESS_LOG):
                print(f"ERRORE: Il file {ACCESS_LOG} non esiste.")
                time.sleep(1)
                continue

            with open(ACCESS_LOG, mode="r", encoding="utf-8") as file:
                requests_count = sum(1 for _ in file)
            print(f"Trovate {requests_count} richieste nel file di log.")

            if requests_count >= EXPECTED_REQUESTS:
                print(f"Completate {requests_count} richieste su {EXPECTED_REQUESTS}.")
                break
        except Exception as e:
            print(f"ERRORE: Problema nel leggere il file di log. Dettagli: {e}")

        time.sleep(1)

def analyze_logs():
    print("Analisi del file di log:", ACCESS_LOG)
    timestamps = []
    if not os.path.exists(ACCESS_LOG):
        print(f"ERRORE: Il file {ACCESS_LOG} non esiste.")
        return None, None

    try:
        with open(ACCESS_LOG, mode="r", encoding="utf-8") as file:
            for line in file:
                parts = line.split()
                if len(parts) < 10:
                    continue
                try:
                    timestamp = datetime.strptime(parts[3][1:], "%d/%b/%Y:%H:%M:%S")
                    timestamps.append(timestamp)
                except ValueError as ve:
                    print(f"ERRORE: Problema nel parsare la riga: {line}. Dettagli: {ve}")
    except Exception as e:
        print(f"ERRORE: Problema nel leggere il file di log. Dettagli: {e}")

    if not timestamps:
        print("ERRORE: Nessuna richiesta trovata nel file di log.")
        return None, None

    print(f"Primo timestamp trovato: {timestamps[0]}")
    print(f"Ultimo timestamp trovato: {timestamps[-1]}")
    return min(timestamps), max(timestamps)

def analyze_performance():
    print("Attesa completamento delle richieste...")
    wait_for_requests()

    print("Caricamento dati di monitoraggio...")
    resource_data = load_resource_data()

    print("Analisi dei log per determinare l'intervallo del test...")
    start_time, end_time = analyze_logs()

    if start_time is None or end_time is None:
        print("ERRORE: Impossibile determinare l'intervallo del test.")
        return

    print(f"Intervallo del test: {start_time} - {end_time}")

    filtered_data = [
        entry for entry in resource_data if start_time <= entry["timestamp"] <= end_time
    ]

    if not filtered_data:
        print("ERRORE: Nessun dato di monitoraggio trovato nell'intervallo del test.")
        return

    print(f"Trovati {len(filtered_data)} campionamenti nell'intervallo del test.")

    try:
        with open(OUTPUT_FILE, mode="w", newline="", encoding="utf-8") as file:
            writer = csv.writer(file)
            writer.writerow([
                "Timestamp",
                "CPU_Usage (%)",
                "Memory_Usage (MB)",
                "Bytes_Sent",
                "Bytes_Received",
                "Active_Connections"
            ])
            for entry in filtered_data:
                writer.writerow([
                    entry["timestamp"],
                    entry["cpu"],
                    entry["memory"],
                    entry["bytes_sent"],
                    entry["bytes_received"],
                    entry["active_connections"]
                ])
        print("Campionamenti salvati in:", OUTPUT_FILE)
    except Exception as e:
        print(f"ERRORE: Problema nel salvare i campionamenti. Dettagli: {e}")

if __name__ == "__main__":
    try:
        analyze_performance()
    except Exception as e:
        print(f"ERRORE GENERALE: {e}")
