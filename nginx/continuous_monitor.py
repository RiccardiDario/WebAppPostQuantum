import psutil
import csv
from datetime import datetime
import time
import os

OUTPUT_FILE = "/opt/nginx/output/resource_monitor.csv"
STOP_FILE = "/opt/nginx/output/sampled_performance.csv"  # Usa il file CSV generato come segnale
SAMPLING_INTERVAL = 0.1  # Intervallo di campionamento in secondi

def monitor_resources():
    """Monitora l'utilizzo delle risorse e scrive i dati in un file CSV."""
    print("Inizio monitoraggio delle risorse...")

    # Configura il file CSV
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

        # Inizializza il calcolo della CPU
        psutil.cpu_percent(interval=None)

        while True:
            try:
                # Controlla se il file di segnalazione esiste
                if os.path.exists(STOP_FILE):  # Verifica se il file sampled_performance.csv esiste
                    print(f"File di segnalazione trovato: {STOP_FILE}. Interrompendo il monitoraggio...")
                    break

                # Timestamp corrente nel formato coerente con Nginx
                timestamp = datetime.now().strftime("%d/%b/%Y:%H:%M:%S")

                # Utilizzo globale della CPU
                cpu_usage = psutil.cpu_percent(interval=None)

                # Memoria utilizzata in MB
                memory_usage = psutil.virtual_memory().used / (1024 ** 2)

                # Rete: byte inviati e ricevuti
                net_counters = psutil.net_io_counters()
                bytes_sent = net_counters.bytes_sent
                bytes_recv = net_counters.bytes_recv

                # Connessioni attive su IPv4/IPv6
                connections = psutil.net_connections(kind="inet")
                active_connections = len([conn for conn in connections if conn.status == "ESTABLISHED"])

                # Scrivi i dati nel file CSV
                writer.writerow([
                    timestamp,
                    cpu_usage,
                    memory_usage,
                    bytes_sent,
                    bytes_recv,
                    active_connections
                ])
                file.flush()  # Forza la scrittura sul disco

                # Stampa dati per il debug
                print(f"{timestamp} - CPU: {cpu_usage}%, Memoria: {memory_usage}MB, "
                      f"Bytes Inviati: {bytes_sent}, Bytes Ricevuti: {bytes_recv}, "
                      f"Connessioni Attive: {active_connections}")

                # Aspetta il prossimo campionamento
                time.sleep(SAMPLING_INTERVAL)

            except KeyboardInterrupt:
                print("Monitoraggio interrotto manualmente.")
                break
            except Exception as e:
                print(f"Errore durante il monitoraggio: {e}")

if __name__ == "__main__":
    monitor_resources()
