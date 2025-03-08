import os, re, math, time, logging, subprocess, csv, psutil, pandas as pd, matplotlib.pyplot as plt
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Thread, Lock
from datetime import datetime

CURL_COMMAND_TEMPLATE = ["curl", "--tlsv1.3", "--curves", "mlkem1024", "--cacert", "/opt/certs/CA.crt", "-w",
"Connect Time: %{time_connect}, TLS Handshake: %{time_appconnect}, Total Time: %{time_total}, %{http_code}\n","-s", "https://nginx_pq:4433"]
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s", handlers=[logging.StreamHandler()])

OUTPUT_DIR, MONITOR_DIR, TRACE_LOG_DIR = "/app/output/request_logs", "/app/output/system_logs", "/app/logs/"
for directory in (TRACE_LOG_DIR, OUTPUT_DIR, MONITOR_DIR): os.makedirs(directory, exist_ok=True)
GRAPH_DIR, SYSTEM_GRAPH_DIR = f"{OUTPUT_DIR}/graphs/", f"{MONITOR_DIR}/graphs/"
for d in [GRAPH_DIR, SYSTEM_GRAPH_DIR]: os.makedirs(d, exist_ok=True)

active_requests, active_requests_lock, global_stats = 0, Lock(), {"cpu_usage": [], "memory_usage": []}
NUM_REQUESTS, kem, sig_alg = 400, "Unknown", "Unknown"

def get_next_filename(base_path, base_name, extension):
    """Genera il nome del file con numerazione incrementale."""
    counter = 1
    while os.path.exists(filename := f"{base_path}/{base_name}{counter}.{extension}"): counter += 1
    return filename, counter
    
def monitor_system():
    """Monitora CPU, memoria e connessioni attive."""
    with open(MONITOR_FILE, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f); writer.writerow(["Timestamp", "CPU_Usage(%)", "Memory_Usage(%)", "Active_TLS"])
        stable_counter = 0
        while True:
            with active_requests_lock: tls = active_requests
            writer.writerow([datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f"), psutil.cpu_percent(), psutil.virtual_memory().percent, tls])
            if tls == 0: stable_counter += 1
            if stable_counter >= 5: break
            time.sleep(0.1)

def execute_request(req_num):
    """Esegue una richiesta HTTPS con curl, verifica HTTP 200 e analizza il file di trace generato."""
    global active_requests, kem, sig_alg
    trace_file, cert_size = f"{TRACE_LOG_DIR}trace_{req_num}.log", 0
    with active_requests_lock: active_requests += 1  
    try:
        start = time.time()
        process = subprocess.Popen(CURL_COMMAND_TEMPLATE + ["--trace", trace_file, "-o", "/dev/null"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, _ = process.communicate()
        elapsed_time = round((time.time() - start) * 1000, 3)
        bytes_sent = bytes_received = 0
        previous_line = ""
        if os.path.exists(trace_file):
            with open(trace_file, encoding="utf-8") as f:
                for line in f:
                    m_sent, m_recv = re.search(r"(=> Send SSL data, (\d+)|Send header, (\d+))", line), re.search(r"(<= Recv SSL data, (\d+)|Recv header, (\d+)|Recv data, (\d+))", line)
                    bytes_sent += int(m_sent.group(2) or m_sent.group(3)) if m_sent else 0
                    bytes_received += int(m_recv.group(2) or m_recv.group(3) or m_recv.group(4)) if m_recv else 0
                    if match_tls := re.search(r"SSL connection using TLSv1.3 / .* / (\S+) / (\S+)", line): kem = match_tls.group(1)
                    if match_sig := re.search(r"Certificate level 1: .* signed using ([^,]+)", line): sig_alg = match_sig.group(1)
                    if "TLS handshake, Certificate (11):" in previous_line and (match_cert_size := re.search(r"<= Recv SSL data, (\d+)", line)): cert_size = int(match_cert_size.group(1))
                    previous_line = line
        try:
            metrics = stdout.strip().rsplit(", ", 1)
            http_status = metrics[-1].strip()
            metrics_dict = {k + " (ms)": round(float(v[:-1]) * 1000, 3) for k, v in (item.split(": ") for item in metrics[0].split(", "))}
            connect_time, handshake_time, total_time = metrics_dict.get("Connect Time (ms)"), metrics_dict.get("TLS Handshake (ms)"), metrics_dict.get("Total Time (ms)")
            success_status = "Success" if http_status == "200" else "Failure"
        except Exception:
            logging.error(f"Errore parsing metriche richiesta {req_num}")
            connect_time = handshake_time = total_time = None
            success_status = "Failure"
        logging.info(f"Richiesta {req_num}: {success_status} | Connessione={connect_time} ms, Handshake={handshake_time} ms, Total_Time={total_time} ms, ElaspsedTime={elapsed_time} ms, Inviati={bytes_sent}, Ricevuti={bytes_received}, HTTP={http_status}, KEM={kem}, Firma={sig_alg}, Cert_Size={cert_size} B")
        return [req_num, connect_time, handshake_time, total_time, elapsed_time, success_status, bytes_sent, bytes_received, kem, sig_alg, cert_size]
    except Exception as e:
        logging.error(f"Errore richiesta {req_num}: {e}")
        return [req_num, None, None, None, None, "Failure", 0, 0, kem, sig_alg, cert_size]
    finally:
        with active_requests_lock: active_requests -= 1

def generate_performance_graphs():
    """Genera i grafici relativi alle metriche di prestazione raccolte."""
    logging.info("Generazione dei grafici mediati...")
    
    files = sorted([f for f in os.listdir(OUTPUT_DIR) if f.startswith("request_client") and f.endswith(".csv")])
    monitor_files = sorted([f for f in os.listdir(MONITOR_DIR) if f.startswith("system_client") and f.endswith(".csv")])
    
    if len(files) >= 3:
        dataframes = [pd.read_csv(os.path.join(OUTPUT_DIR, f)) for f in files]
        df_avg = pd.concat(dataframes)[["Connect_Time(s)", "TLS_Handshake(s)", "Total_Time(s)", "Elapsed_Time(s)", "Cert_Size(B)"]].groupby(level=0).mean()
        cert_size_mean = df_avg["Cert_Size(B)"].mean()
        num_plots = math.ceil(len(df_avg) / 100)
        
        for i in range(num_plots):
            start_idx, end_idx = i * 100, min((i + 1) * 100, len(df_avg))
            df_subset = df_avg.iloc[start_idx:end_idx]
            x_positions = (df_avg.index[start_idx:end_idx] + 1)

            plt.figure(figsize=(14, 7))
            plt.plot(x_positions, df_subset["Elapsed_Time(s)"], label="Elapsed Time (s)", color="blue", marker="o", linestyle="-")
            plt.xlabel("Entry Number in CSV")
            plt.ylabel("Elapsed Time (s)")
            plt.title(f"Elapsed Time per Request (Entries {start_idx+1} to {end_idx})")
            plt.legend(title=f"Certificate Size: {cert_size_mean:.2f} B")
            plt.grid(True, linestyle="--", alpha=0.7)
            plt.savefig(os.path.join(GRAPH_DIR, f"elapsed_time_graph_{start_idx+1}_{end_idx}.png"), dpi=300)
            plt.close()

            plt.figure(figsize=(14, 7))
            plt.bar(x_positions, df_subset["Connect_Time(s)"], label="Connect Time", color="red", alpha=0.7)
            plt.bar(x_positions, df_subset["TLS_Handshake(s)"], bottom=df_subset["Connect_Time(s)"], label="TLS Handshake Time", color="orange", alpha=0.7)
            plt.bar(x_positions, df_subset["Total_Time(s)"], bottom=df_subset["TLS_Handshake(s)"], label="Total Time", color="gray", alpha=0.7)
            plt.xlabel("Entry Number in CSV")
            plt.ylabel("Time (s)")
            plt.title(f"Timing Breakdown for TLS Connections (Entries {start_idx+1} to {end_idx})")
            plt.legend(title=f"Certificate Size: {cert_size_mean:.2f} B")
            plt.grid(axis="y", linestyle="--", alpha=0.7)
            plt.savefig(os.path.join(GRAPH_DIR, f"tls_avg_graph_{start_idx+1}_{end_idx}.png"), dpi=300)
            plt.close()

        monitor_dataframes = [pd.read_csv(os.path.join(MONITOR_DIR, f)) for f in monitor_files]
        for df in monitor_dataframes:
            df["Timestamp"] = pd.to_datetime(df["Timestamp"])
        
        min_range = min((df["Timestamp"].max() - df["Timestamp"].min()).total_seconds() for df in monitor_dataframes)
        num_samples = int(min_range / 0.1)
        
        df_monitor_avg = pd.concat([
            df[df["Timestamp"] <= (df["Timestamp"].min() + pd.Timedelta(seconds=min_range))]
            .assign(Index=lambda df: (df["Timestamp"] - df["Timestamp"].min()).dt.total_seconds() // 0.1)
            .groupby("Index").mean().reset_index()
            for df in monitor_dataframes
        ]).groupby("Index").mean().reset_index()
        
        sample_indices = (df_monitor_avg["Index"] * 0.1 * 1000).tolist()
        total_memory = psutil.virtual_memory().total / (1024 ** 2)
        total_cores = psutil.cpu_count(logical=True)
        num_graphs = math.ceil(num_samples / 100)

        for i in range(num_graphs):
            start_idx, end_idx = i * 100, min((i + 1) * 100, num_samples)
            df_subset = df_monitor_avg.iloc[start_idx:end_idx]
            x_positions = sample_indices[start_idx:end_idx]

            plt.figure(figsize=(14, 7))
            plt.plot(x_positions, df_subset["CPU_Usage(%)"], label="CPU Usage (%)", color="green", marker="o", linestyle="-")
            plt.plot(x_positions, df_subset["Memory_Usage(%)"], label="Memory Usage (%)", color="purple", marker="o", linestyle="-")
            plt.xlabel("Time (ms)")
            plt.ylabel("Usage (%)")
            plt.title(f"CPU & Memory Usage Over Time (Samples {start_idx+1} to {end_idx})")
            plt.legend(title=f"CPU Total Cores: {total_cores} | Total RAM: {total_memory:.2f} MB", loc="upper right")
            plt.grid(True, linestyle="--", alpha=0.7)
            plt.savefig(os.path.join(SYSTEM_GRAPH_DIR, f"cpu_memory_usage_{start_idx+1}_{end_idx}.png"), dpi=300)
            plt.close()

def update_average_report(request_results):
    """Genera o aggiorna il report delle medie delle metriche con CPU e RAM."""
    avg_file = os.path.join(OUTPUT_DIR, "average_metrics.csv")

    # Filtra solo le richieste di successo
    success_results = [r for r in request_results if r[1] is not None]

    if not success_results:
        logging.warning("Nessuna richiesta di successo, il report delle medie non verrà aggiornato.")
        return

    # Calcola le medie per i tempi di connessione
    avg_connect_time = sum(r[1] for r in success_results) / len(success_results)
    avg_handshake_time = sum(r[2] for r in success_results) / len(success_results)
    avg_total_time = sum(r[3] for r in success_results) / len(success_results)
    avg_elapsed_time = sum(r[4] for r in success_results) / len(success_results)

    # Leggi i dati di monitoraggio (CPU, RAM)
    if os.path.exists(MONITOR_FILE):
        df_monitor = pd.read_csv(MONITOR_FILE)

        # Filtro: consideriamo solo i valori con CPU ≠ 0
        valid_cpu = df_monitor[df_monitor["CPU_Usage(%)"] > 0]["CPU_Usage(%)"]
        valid_ram = df_monitor[df_monitor["CPU_Usage(%)"] > 0]["Memory_Usage(%)"]

        # Calcola la media SENZA usare round()
        avg_cpu = valid_cpu.mean() if not valid_cpu.empty else 0.0
        avg_ram = valid_ram.mean() if not valid_ram.empty else 0.0
    else:
        avg_cpu, avg_ram = 0.0, 0.0

    # Determina l'indice dell'esecuzione leggendo il numero di righe esistenti
    execution_index = 1  # Parte da 1 se il file non esiste
    if os.path.exists(avg_file):
        with open(avg_file, "r", encoding="utf-8") as f:
            execution_index = sum(1 for _ in f)  # Conta le righe esistenti per ottenere l'indice

    # Riga da scrivere nel file
    new_row = [execution_index, avg_connect_time, avg_handshake_time, avg_total_time, avg_elapsed_time, avg_cpu, avg_ram]

    # Controlla se il file esiste e scrive o appende
    file_exists = os.path.exists(avg_file)
    with open(avg_file, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(["Execution_Index", "Avg_Connect_Time(s)", "Avg_Handshake_Time(s)", "Avg_Total_Time(s)", "Avg_Elapsed_Time(s)", "Avg_CPU_Usage(%)", "Avg_RAM_Usage(%)"])
        writer.writerow(new_row)

    logging.info(f"Report delle medie aggiornato: {avg_file} con CPU={avg_cpu}% e RAM={avg_ram}%")


OUTPUT_FILE, file_index = get_next_filename(OUTPUT_DIR, "request_client", "csv")
MONITOR_FILE, _ = get_next_filename(MONITOR_DIR, "system_client", "csv")
with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerow(["Request_Number", "Connect_Time(ms)", "TLS_Handshake(ms)", "Total_Time(ms)", "Elapsed_Time(ms)", 
                     "Status", "Success_Count", "Bytes_Sent(B)", "Bytes_Received(B)", "KEM", "Signature", "Cert_Size(B)"])
    
    monitor_thread = Thread(target=monitor_system); monitor_thread.start()
    start_time = time.time()
    request_results = []  
    try:
        for i in range(NUM_REQUESTS):
            result = execute_request(i + 1)
            request_results.append(result)
    finally:
        monitor_thread.join()
        end_time = time.time()


    success_count = 0
    for result in request_results:
        request_number = result[0]
        if result[5] == "Success": success_count += 1
        writer.writerow(result[:6] + [f"{success_count}/{NUM_REQUESTS}"] + result[6:])

logging.info(f"Test completato in {end_time - start_time:.2f} secondi. Report: {OUTPUT_FILE}")
generate_performance_graphs()
update_average_report(request_results)
