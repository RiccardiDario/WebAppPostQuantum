import subprocess
import csv
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import psutil
from threading import Event, Thread, Lock
from datetime import datetime

# Configura i parametri per le richieste
URL = "https://nginx_pq:4433"
CURL_COMMAND_TEMPLATE = ["curl", "--tlsv1.3", "--curves", "x25519_mlkem512", "--cacert", "/opt/certs/CA.crt",
                         "-w", "Connect Time: %{time_connect}, TLS Handshake: %{time_appconnect}, Total Time: %{time_total}\n",
                         "-o", "/dev/null", "-s", URL]

# Numero di richieste da eseguire
NUM_REQUESTS = 1000
OUTPUT_FILE = "/app/output/analysis_client.csv"
MONITOR_FILE = "/app/output/system_monitoring.csv"

# Variabili di monitoraggio
success_count = 0
active_requests = 0
active_requests_lock = Lock()
global_stats = {"cpu_usage": [], "memory_usage": []}


def monitor_system():
    """Monitora l'utilizzo globale del sistema mentre ci sono richieste attive."""
    with open(MONITOR_FILE, mode="w", newline="", encoding="utf-8") as monitor_file:
        monitor_writer = csv.writer(monitor_file, delimiter=",", quotechar='"', quoting=csv.QUOTE_MINIMAL)
        monitor_writer.writerow(["Timestamp", "CPU_Usage_Percent", "Memory_Usage_Percent", "Active_TLS_Connections"])

        while True:
            with active_requests_lock:
                if active_requests == 0:
                    break
                tls_connections = active_requests  # Numero di connessioni TLS attive

            # Raccogli le statistiche solo se ci sono richieste attive
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")  # Formatta il timestamp leggibile
            cpu_usage = psutil.cpu_percent(interval=None)
            memory_usage = psutil.virtual_memory().percent

            global_stats["cpu_usage"].append(cpu_usage)
            global_stats["memory_usage"].append(memory_usage)

            # Scrivi il campionamento nel file CSV
            monitor_writer.writerow([timestamp, cpu_usage, memory_usage, tls_connections])
            time.sleep(0.1)


def execute_request(request_number):
    """Esegue una singola richiesta e raccoglie i dati sulle prestazioni."""
    global success_count, active_requests
    with active_requests_lock:
        active_requests += 1

    try:
        start_time = time.time()
        result = subprocess.run(CURL_COMMAND_TEMPLATE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        end_time = time.time()

        output = result.stdout.strip()
        metrics = dict(item.split(": ") for item in output.split(", "))
        connect_time = float(metrics["Connect Time"].replace("s", ""))
        handshake_time = float(metrics["TLS Handshake"].replace("s", ""))
        total_time = float(metrics["Total Time"].replace("s", ""))

        bytes_sent = len(result.stderr) + len(result.stdout)
        bandwidth = bytes_sent / (end_time - start_time) / (1024 ** 2)

        resource_usage = subprocess.run(["/usr/bin/time", "-v"] + CURL_COMMAND_TEMPLATE,
                                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        memory_usage = extract_memory_usage(resource_usage.stderr)
        cpu_usage = extract_cpu_usage(resource_usage.stderr)

        with active_requests_lock:
            success_count += 1

        return [request_number, connect_time, handshake_time, total_time, "Success",
                f"{success_count}/{NUM_REQUESTS}", bandwidth, memory_usage, bytes_sent, cpu_usage]
    except subprocess.CalledProcessError as e:
        print(f"Errore nella richiesta {request_number}: {e}")
        return [request_number, None, None, None, "Failure",
                f"{success_count}/{NUM_REQUESTS}", None, None, None, None]
    finally:
        with active_requests_lock:
            active_requests -= 1


def extract_memory_usage(output):
    """Estrai l'uso della RAM dall'output di 'time'."""
    for line in output.splitlines():
        if "Maximum resident set size" in line:
            return int(line.split(":")[1].strip()) / 1024
    return None


def extract_cpu_usage(output):
    """Estrai l'uso della CPU dall'output di 'time'."""
    for line in output.splitlines():
        if "Percent of CPU this job got" in line:
            return float(line.split(":")[1].strip().replace("%", ""))
    return None


# Inizializza il file CSV principale
os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
with open(OUTPUT_FILE, mode="w", newline="", encoding="utf-8") as file:
    writer = csv.writer(file, delimiter=",", quotechar='"', quoting=csv.QUOTE_MINIMAL)
    writer.writerow(["Request_Number", "Connect_Time", "TLS_Handshake", "Total_Time", "Status",
                     "Success_Count/Total", "Bandwidth_MBps", "Memory_Usage_MB", "Bytes_Transferred",
                     "CPU_Usage_Percent"])

    start_time = time.time()

    # Avvia il monitoraggio globale in un thread separato
    monitor_thread = Thread(target=monitor_system)
    monitor_thread.start()

    try:
        with ThreadPoolExecutor(max_workers=NUM_REQUESTS) as executor:
            futures = [executor.submit(execute_request, i + 1) for i in range(NUM_REQUESTS)]
            for future in as_completed(futures):
                result = future.result()
                writer.writerow(result)
                print(f"Request {result[0]}: Status={result[4]} Success_Count/Total={result[5]} Bandwidth={result[6]}MBps Bytes_Transferred={result[8]} CPU_Usage={result[9]}%")
    finally:
        monitor_thread.join()
        end_time = time.time()

# Calcola le statistiche globali
average_cpu = sum(global_stats["cpu_usage"]) / len(global_stats["cpu_usage"]) if global_stats["cpu_usage"] else 0
average_memory = sum(global_stats["memory_usage"]) / len(global_stats["memory_usage"]) if global_stats["memory_usage"] else 0
peak_memory = max(global_stats["memory_usage"]) if global_stats["memory_usage"] else 0

# Aggiungi statistiche aggregate al file CSV principale
with open(OUTPUT_FILE, mode="a", newline="", encoding="utf-8") as file:
    writer = csv.writer(file)
    writer.writerow([])
    writer.writerow(["Average_CPU_Usage", "Average_Memory_Usage", "Peak_Memory_Usage"])
    writer.writerow([f"{average_cpu:.2f}%", f"{average_memory:.2f}%", f"{peak_memory:.2f}%"])

print(f"Test completato in {end_time - start_time:.2f} secondi.")
print(f"Report principale generato in: {OUTPUT_FILE}")
print(f"Monitoraggio dettagliato salvato in: {MONITOR_FILE}")