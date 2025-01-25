import subprocess
import csv
import os
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import psutil
from threading import Thread, Lock
from datetime import datetime
import tempfile

# Configurazione logging
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()]
)

# Configura i parametri per le richieste
CURL_COMMAND_TEMPLATE = [
    "curl",
    "--tlsv1.3",
    "--curves", "x25519_mlkem512",  # Specifica curve post-quantum.
    "--cacert", "/opt/certs/CA.crt",  # Certificato CA.
    "-w", "Connect Time: %{time_connect}, TLS Handshake: %{time_appconnect}, Total Time: %{time_total}\n",  # Metriche.
    "-s",  # Esegue la richiesta in modo silenzioso.
    "https://nginx_pq:4433"  # URL di destinazione.
]

# Numero di richieste da eseguire
NUM_REQUESTS = 1000
OUTPUT_FILE = "/app/output/analysis_client.csv"  # File CSV per i risultati delle richieste.
MONITOR_FILE = "/app/output/system_monitoring.csv"  # File CSV per il monitoraggio delle risorse.

# Variabili di monitoraggio
success_count = 0  # Contatore delle richieste completate con successo.
active_requests = 0  # Contatore delle richieste attive.
active_requests_lock = Lock()  # Lock per garantire accesso thread-safe.
global_stats = {"cpu_usage": [], "memory_usage": [], "bytes_sent": 0, "bytes_received": 0}  # Statistiche globali su CPU, memoria e dati scambiati.


def monitor_system():
    """Monitora l'utilizzo globale del sistema mentre ci sono richieste attive."""
    with open(MONITOR_FILE, mode="w", newline="", encoding="utf-8") as monitor_file:
        monitor_writer = csv.writer(monitor_file, delimiter=",", quotechar='"', quoting=csv.QUOTE_MINIMAL)
        monitor_writer.writerow(["Timestamp", "CPU_Usage_Percent", "Memory_Usage_Percent", "Active_TLS_Connections", "Bytes_Sent", "Bytes_Received"])

        initial_net_io = psutil.net_io_counters()

        while True:
            with active_requests_lock:
                if active_requests == 0:  # Se non ci sono richieste attive, interrompe il monitoraggio.
                    break
                tls_connections = active_requests  # Numero di connessioni TLS attive.

            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
            cpu_usage = psutil.cpu_percent(interval=None)
            memory_usage = psutil.virtual_memory().percent

            net_io = psutil.net_io_counters()
            bytes_sent = net_io.bytes_sent - initial_net_io.bytes_sent
            bytes_received = net_io.bytes_recv - initial_net_io.bytes_recv

            global_stats["cpu_usage"].append(cpu_usage)
            global_stats["memory_usage"].append(memory_usage)
            global_stats["bytes_sent"] = bytes_sent
            global_stats["bytes_received"] = bytes_received

            monitor_writer.writerow([timestamp, cpu_usage, memory_usage, tls_connections, bytes_sent, bytes_received])
            time.sleep(0.1)


def execute_request(request_number):
    """Esegue una singola richiesta e raccoglie i dati sulle prestazioni."""
    global success_count, active_requests
    with active_requests_lock:
        active_requests += 1

    try:
        with tempfile.NamedTemporaryFile(delete=True) as temp_file, tempfile.NamedTemporaryFile(delete=True) as trace_file:
            curl_command = CURL_COMMAND_TEMPLATE + ["--trace", trace_file.name, "-o", temp_file.name]
            start_time = time.time()
            process = subprocess.Popen(curl_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = process.communicate()
            end_time = time.time()

            elapsed_time = end_time - start_time

            # Estrai le metriche dalla risposta curl
            metrics = stdout.strip()
            try:
                metrics_dict = dict(item.split(": ") for item in metrics.split(", "))
                connect_time = float(metrics_dict["Connect Time"].replace("s", ""))
                handshake_time = float(metrics_dict["TLS Handshake"].replace("s", ""))
                total_time = float(metrics_dict["Total Time"].replace("s", ""))
            except Exception as e:
                logging.error(f"Errore nel parsing delle metriche per la richiesta {request_number}: {e}")
                connect_time = handshake_time = total_time = None

            with active_requests_lock:
                success_count += 1

            logging.info(
                f"Richiesta {request_number}: Stato=Success, "
                f"Connect_Time={connect_time}, TLS_Handshake={handshake_time}, "
                f"Total_Time={total_time}, Elapsed_Time={elapsed_time}"
            )

            return [request_number, connect_time, handshake_time, total_time, elapsed_time, "Success",
                    f"{success_count}/{NUM_REQUESTS}"]
    except Exception as e:
        logging.error(f"Richiesta {request_number}: Stato=Failure, Errore={e}")
        return [request_number, None, None, None, None, "Failure",
                f"{success_count}/{NUM_REQUESTS}"]
    finally:
        with active_requests_lock:
            active_requests -= 1


os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
with open(OUTPUT_FILE, mode="w", newline="", encoding="utf-8") as file:
    writer = csv.writer(file, delimiter=",", quotechar='"', quoting=csv.QUOTE_MINIMAL)
    writer.writerow(["Request_Number", "Connect_Time", "TLS_Handshake", "Total_Time", "Elapsed_Time", "Status",
                     "Success_Count/Total"])

    start_time = time.time()
    monitor_thread = Thread(target=monitor_system)
    monitor_thread.start()

    try:
        with ThreadPoolExecutor(max_workers=NUM_REQUESTS) as executor:
            futures = [executor.submit(execute_request, i + 1) for i in range(NUM_REQUESTS)]
            for future in as_completed(futures):
                result = future.result()
                writer.writerow(result)
    finally:
        monitor_thread.join()
        end_time = time.time()

average_cpu = sum(global_stats["cpu_usage"]) / len(global_stats["cpu_usage"]) if global_stats["cpu_usage"] else 0
average_memory = sum(global_stats["memory_usage"]) / len(global_stats["memory_usage"]) if global_stats["memory_usage"] else 0
peak_memory = max(global_stats["memory_usage"]) if global_stats["memory_usage"] else 0
total_bytes_sent = global_stats["bytes_sent"]
total_bytes_received = global_stats["bytes_received"]

with open(OUTPUT_FILE, mode="a", newline="", encoding="utf-8") as file:
    writer = csv.writer(file)
    writer.writerow([])
    writer.writerow(["Average_CPU_Usage", "Average_Memory_Usage", "Peak_Memory_Usage", "Total_Bytes_Sent", "Total_Bytes_Received"])
    writer.writerow([f"{average_cpu:.2f}%", f"{average_memory:.2f}%", f"{peak_memory:.2f}%", total_bytes_sent, total_bytes_received])

logging.info(f"Test completato in {end_time - start_time:.2f} secondi.")
logging.info(f"Report principale generato in: {OUTPUT_FILE}")
