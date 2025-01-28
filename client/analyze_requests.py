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
import re  # Per analizzare i file di trace

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
NUM_REQUESTS = 500
OUTPUT_FILE = "/app/output/analysis_client.csv"  # File CSV per i risultati delle richieste.
MONITOR_FILE = "/app/output/system_monitoring.csv"  # File CSV per il monitoraggio delle risorse.

# Variabili di monitoraggio
active_requests = 0  # Contatore delle richieste attive.
active_requests_lock = Lock()  # Lock per garantire accesso thread-safe.
global_stats = {"cpu_usage": [], "memory_usage": []}  # Statistiche globali su CPU e memoria.


def monitor_system():
    """Monitora l'utilizzo globale del sistema mentre ci sono richieste attive."""
    with open(MONITOR_FILE, mode="w", newline="", encoding="utf-8") as monitor_file:
        monitor_writer = csv.writer(monitor_file, delimiter=",", quotechar='"', quoting=csv.QUOTE_MINIMAL)
        monitor_writer.writerow(["Timestamp", "CPU_Usage_Percent", "Memory_Usage_MB", "Active_TLS_Connections"])

        stable_counter = 0  # Contatore per verificare stabilità

        while True:
            with active_requests_lock:
                tls_connections = active_requests

            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
            cpu_usage = psutil.cpu_percent(interval=None)
            memory_usage = psutil.virtual_memory().used / (1024 ** 2)

            monitor_writer.writerow([timestamp, cpu_usage, memory_usage, tls_connections])

            if tls_connections == 0:
                stable_counter += 1
                if stable_counter >= 5:
                    break

            time.sleep(0.1)


def execute_request(request_number):
    global active_requests
    with active_requests_lock:
        active_requests += 1

    try:
        trace_file_name = f"/app/output/trace_request_{request_number}.log"
        with tempfile.NamedTemporaryFile(delete=True) as temp_file:
            curl_command = CURL_COMMAND_TEMPLATE + ["--trace", trace_file_name, "-o", temp_file.name]

            start_time = time.time()
            process = subprocess.Popen(curl_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = process.communicate()
            end_time = time.time()
            elapsed_time = end_time - start_time

            metrics = stdout.strip()
            try:
                metrics_dict = dict(item.split(": ") for item in metrics.split(", "))
                connect_time = float(metrics_dict["Connect Time"].replace("s", ""))
                handshake_time = float(metrics_dict["TLS Handshake"].replace("s", ""))
                total_time = float(metrics_dict["Total Time"].replace("s", ""))
            except Exception as e:
                logging.error(f"Errore nel parsing delle metriche per la richiesta {request_number}: {e}")
                connect_time = handshake_time = total_time = None

            logging.info(
                f"Richiesta {request_number}: Stato=Success, "
                f"Connect_Time={connect_time}, TLS_Handshake={handshake_time}, "
                f"Total_Time={total_time}, Elapsed_Time={elapsed_time}"
            )

            return [request_number, connect_time, handshake_time, total_time, elapsed_time, "Success"]

    except Exception as e:
        logging.error(f"Richiesta {request_number}: Stato=Failure, Errore={e}")
        return [request_number, None, None, None, None, "Failure"]
    finally:
        with active_requests_lock:
            active_requests -= 1


def analyze_traces():
    """Analizza i file di trace per calcolare i byte inviati e ricevuti per ogni richiesta."""
    trace_results = {}

    logging.info("Inizio dell'analisi dei file di trace...")
    for i in range(1, NUM_REQUESTS + 1):
        trace_file_name = f"/app/output/trace_request_{i}.log"
        try:
            with open(trace_file_name, "r", encoding="utf-8") as trace_file:
                bytes_sent = 0
                bytes_received = 0

                logging.debug(f"Analizzando il file di trace: {trace_file_name}")

                for line in trace_file:
                    match_sent = re.search(r"=> Send SSL data, (\d+) bytes", line)
                    if match_sent:
                        bytes_sent += int(match_sent.group(1))

                    match_received = re.search(r"<= Recv SSL data, (\d+) bytes", line)
                    if match_received:
                        bytes_received += int(match_received.group(1))

                trace_results[i] = (bytes_sent, bytes_received)
                logging.debug(f"File {trace_file_name}: Bytes Sent = {bytes_sent}, Bytes Received = {bytes_received}")

        except FileNotFoundError:
            logging.warning(f"File di trace non trovato: {trace_file_name}")
            trace_results[i] = (0, 0)
        except Exception as e:
            logging.error(f"Errore durante l'analisi del file {trace_file_name}: {e}")
            trace_results[i] = (0, 0)

    logging.info("Analisi completata.")
    return trace_results


os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
with open(OUTPUT_FILE, mode="w", newline="", encoding="utf-8") as file:
    writer = csv.writer(file, delimiter=",", quotechar='"', quoting=csv.QUOTE_MINIMAL)
    writer.writerow(["Request_Number", "Connect_Time", "TLS_Handshake", "Total_Time", "Elapsed_Time", "Status", "Success_Count", "Bytes_Sent", "Bytes_Received"])

    start_time = time.time()
    monitor_thread = Thread(target=monitor_system)
    monitor_thread.start()

    try:
        request_results = []
        with ThreadPoolExecutor(max_workers=NUM_REQUESTS) as executor:
            futures = [executor.submit(execute_request, i + 1) for i in range(NUM_REQUESTS)]
            for future in as_completed(futures):
                request_results.append(future.result())
    finally:
        monitor_thread.join()
        end_time = time.time()

    # Analisi dei file di trace
    trace_data = analyze_traces()

    success_count = 0
    for result in request_results:
        request_number = result[0]
        bytes_sent, bytes_received = trace_data.get(request_number, (0, 0))
        if result[5] == "Success":
            success_count += 1
            success_count_str = f"{success_count}/{NUM_REQUESTS}"  # Formato "500/500"
        else:
            success_count_str = f"/{NUM_REQUESTS}"  # Per richieste fallite, solo il totale

        writer.writerow(result + [success_count_str, bytes_sent, bytes_received])

average_cpu = sum(global_stats["cpu_usage"]) / len(global_stats["cpu_usage"]) if global_stats["cpu_usage"] else 0
average_memory = sum(global_stats["memory_usage"]) / len(global_stats["memory_usage"]) if global_stats["memory_usage"] else 0
peak_memory = max(global_stats["memory_usage"]) if global_stats["memory_usage"] else 0

logging.info(f"Test completato in {end_time - start_time:.2f} secondi.")
logging.info(f"Report principale generato in: {OUTPUT_FILE}")
