import psutil
import csv
from datetime import datetime
import time

OUTPUT_FILE = "/opt/nginx/output/resource_monitor.csv"
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
                # Timestamp corrente
                timestamp = datetime.now()

                # Utilizzo globale della CPU
                cpu_usage = psutil.cpu_percent(interval=SAMPLING_INTERVAL)

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

            except KeyboardInterrupt:
                print("Monitoraggio interrotto manualmente.")
                break
            except Exception as e:
                print(f"Errore durante il monitoraggio: {e}")

if __name__ == "__main__":
    monitor_resources()
