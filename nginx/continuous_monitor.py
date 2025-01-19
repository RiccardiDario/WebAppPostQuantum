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
        writer.writerow(["Timestamp", "CPU_Usage (%)", "Memory_Usage (MB)", "IO_Read_Bytes", "IO_Write_Bytes"])

        # Calcola l'utilizzo iniziale della CPU
        psutil.cpu_percent(interval=None)  # Inizializza il calcolo della CPU

        while True:
            try:
                timestamp = datetime.now()  # Timestamp corrente
                cpu_usage = psutil.cpu_percent(interval=SAMPLING_INTERVAL)  # Utilizzo della CPU
                memory_usage = psutil.virtual_memory().used / (1024 ** 2)  # RAM utilizzata in MB
                io_counters = psutil.disk_io_counters()  # Statistiche di I/O
                io_read = io_counters.read_bytes  # Byte letti
                io_write = io_counters.write_bytes  # Byte scritti

                # Scrivi i dati nel file CSV
                writer.writerow([timestamp, cpu_usage, memory_usage, io_read, io_write])
                file.flush()  # Forza la scrittura sul disco

                print(f"{timestamp} - CPU: {cpu_usage}%, Memoria: {memory_usage}MB, Lettura: {io_read}, Scrittura: {io_write}")
            except KeyboardInterrupt:
                print("Monitoraggio interrotto manualmente.")
                break
            except Exception as e:
                print(f"Errore durante il monitoraggio: {e}")

if __name__ == "__main__":
    monitor_resources()
