import os, re, math, time, logging, subprocess, csv, psutil, pandas as pd, matplotlib.pyplot as plt
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Thread, Lock
from datetime import datetime

CURL_COMMAND_TEMPLATE = ["curl", "--tlsv1.3", "--curves", "p256_mlkem512", "--cacert", "/opt/certs/CA.crt", "-w",
"Connect Time: %{time_connect}, TLS Handshake: %{time_appconnect}, Total Time: %{time_total}, %{http_code}\n","-s", "https://nginx_pq:4433"]
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s", handlers=[logging.StreamHandler()])

OUTPUT_DIR, MONITOR_DIR, TRACE_LOG_DIR = "/app/output/request_logs", "/app/output/system_logs", "/app/logs/"
for directory in (TRACE_LOG_DIR, OUTPUT_DIR, MONITOR_DIR): os.makedirs(directory, exist_ok=True)
GRAPH_DIR, SYSTEM_GRAPH_DIR, AVG_DIR = f"{OUTPUT_DIR}/graphs/", f"{MONITOR_DIR}/graphs/", f"{OUTPUT_DIR}/avg/"
for d in [GRAPH_DIR, SYSTEM_GRAPH_DIR, AVG_DIR]: os.makedirs(d, exist_ok=True)

active_requests, active_requests_lock, global_stats = 0, Lock(), {"cpu_usage": [], "memory_usage": []}
NUM_REQUESTS, kem, sig_alg = 500, "Unknown", "Unknown"

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
    """Genera i grafici relativi alle metriche di prestazione per ogni batch di 3 esecuzioni."""
    logging.info("Generazione dei grafici mediati...")

    files = sorted([f for f in os.listdir(OUTPUT_DIR) if f.startswith("request_client") and f.endswith(".csv")])
    monitor_files = sorted([f for f in os.listdir(MONITOR_DIR) if f.startswith("system_client") and f.endswith(".csv")])

    for i in range(0, len(files), 3):
        batch_files = files[i:i+3]
        monitor_batch_files = monitor_files[i:i+3]

        if len(batch_files) < 3:
            logging.warning(f"Solo {len(batch_files)} file nel batch {i//3 + 1}, salto la generazione dei grafici.")
            continue

        dataframes = [pd.read_csv(os.path.join(OUTPUT_DIR, f)) for f in batch_files]
        df_avg = pd.concat(dataframes)[["Connect_Time(ms)", "TLS_Handshake(ms)", "Total_Time(ms)", "Elapsed_Time(ms)", "Cert_Size(B)"]].groupby(level=0).mean()
        cert_size_mean = df_avg["Cert_Size(B)"].mean()
        num_plots = math.ceil(len(df_avg) / 100)

        # **Recupero dinamico di KEM e firma**
        kem, sig_alg = get_kem_sig_from_csv(os.path.join(OUTPUT_DIR, batch_files[0]))

        for j in range(num_plots):
            start_idx, end_idx = j * 100, min((j + 1) * 100, len(df_avg))
            df_subset = df_avg.iloc[start_idx:end_idx]
            x_positions = (df_avg.index[start_idx:end_idx] + 1)

            plt.figure(figsize=(14, 7))
            plt.plot(x_positions, df_subset["Elapsed_Time(ms)"], label="Elapsed Time (ms)", color="blue", marker="o", linestyle="-")
            plt.xlabel("Request Completion Order")
            plt.ylabel("Elapsed Time (ms)")
            plt.title(f"Elapsed Time per Request\nKEM: {kem} | Signature: {sig_alg}")
            plt.legend(title=f"Certificate Size: {cert_size_mean:.2f} B")
            plt.grid(True, linestyle="--", alpha=0.7)
            plt.savefig(os.path.join(GRAPH_DIR, f"elapsed_time_graph_batch_{i//3 + 1}_{start_idx+1}_{end_idx}.png"), dpi=300)
            plt.close()

            plt.figure(figsize=(14, 7))
            plt.bar(x_positions, df_subset["Connect_Time(ms)"], label="Connect Time", color="red", alpha=0.7)
            plt.bar(x_positions, df_subset["TLS_Handshake(ms)"], bottom=df_subset["Connect_Time(ms)"], label="TLS Handshake Time", color="orange", alpha=0.7)
            plt.bar(x_positions, df_subset["Total_Time(ms)"], bottom=df_subset["TLS_Handshake(ms)"], label="Total Time", color="gray", alpha=0.7)
            plt.xlabel("Request Completion Order")
            plt.ylabel("Time (ms)")
            plt.title(f"Timing Breakdown for TLS Connections\nKEM: {kem} | Signature: {sig_alg}")
            plt.legend(title=f"Certificate Size: {cert_size_mean:.2f} B")
            plt.grid(axis="y", linestyle="--", alpha=0.7)
            plt.savefig(os.path.join(GRAPH_DIR, f"tls_avg_graph_batch_{i//3 + 1}_{start_idx+1}_{end_idx}.png"), dpi=300)
            plt.close()

        # **Gestione dei file di monitoraggio per il sistema**
        monitor_dataframes = [pd.read_csv(os.path.join(MONITOR_DIR, f)) for f in monitor_batch_files]
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

        plt.figure(figsize=(14, 7))
        plt.plot(sample_indices, df_monitor_avg["CPU_Usage(%)"], label="CPU Usage (%)", color="green", marker="o", linestyle="-")
        plt.plot(sample_indices, df_monitor_avg["Memory_Usage(%)"], label="Memory Usage (%)", color="purple", marker="o", linestyle="-")
        plt.xlabel("Time (ms)")
        plt.ylabel("Usage (%)")
        plt.title(f"Client Resource Usage (Avg. CPU & Memory) Over Time\nKEM: {kem} | Signature: {sig_alg}")

        # **Spostare la legenda fuori dal grafico**
        plt.legend(
            title=f"KEM: {kem} | Signature: {sig_alg}\nCPU Cores: {total_cores} | Total RAM: {total_memory:.2f} MB",
            loc="upper left",
            bbox_to_anchor=(1, 1)  # ← Posiziona la legenda fuori dal grafico
        )

        plt.grid(True, linestyle="--", alpha=0.7)
        graph_path = os.path.join(SYSTEM_GRAPH_DIR, f"cpu_memory_usage_batch_{i//3 + 1}.png")
        plt.savefig(graph_path, dpi=300, bbox_inches="tight")  # ← `bbox_inches="tight"` evita il taglio della legenda
        plt.close()

        logging.info(f"Grafici generati per il batch {i//3 + 1}")

def get_kem_sig_from_csv(csv_file):
    """Recupera KEM e firma direttamente dal CSV, scegliendo il primo valore univoco disponibile."""
    df = pd.read_csv(csv_file)

    if "KEM" in df.columns and "Signature" in df.columns:
        kem_value = df["KEM"].dropna().str.strip().unique()  # Rimuove spazi e caratteri speciali
        sig_value = df["Signature"].dropna().str.strip().unique()  # Rimuove `\n`

        kem_selected = kem_value[0] if len(kem_value) > 0 else "Unknown"
        sig_selected = sig_value[0] if len(sig_value) > 0 else "Unknown"

        return kem_selected, sig_selected

    return "Unknown", "Unknown"

def generate_cumulative_boxplots():
    """Genera boxplot per ogni metrica con più batch nello stesso grafico."""
    logging.info("Generazione dei boxplot cumulativi...")

    files = sorted([f for f in os.listdir(OUTPUT_DIR) if f.startswith("request_client") and f.endswith(".csv")])
    if len(files) < 3:
        logging.warning("Non ci sono almeno tre esecuzioni per generare i boxplot.")
        return

    metrics = {
        "Connect_Time(ms)": "Connect Time (ms)",
        "TLS_Handshake(ms)": "Handshake Time (ms)",
        "Total_Time(ms)": "Total Time (ms)",
        "Elapsed_Time(ms)": "Elapsed Time (ms)"
    }

    batch_data = {metric: [] for metric in metrics}
    batch_labels = []

    for i in range(0, len(files), 3):
        batch_files = files[i:i+3]
        if len(batch_files) < 3:
            logging.warning(f"Solo {len(batch_files)} file nel gruppo, salto il batch {i//3 + 1}.")
            continue

        df_list = [pd.read_csv(os.path.join(OUTPUT_DIR, f)) for f in batch_files]
        df = pd.concat(df_list, ignore_index=True)
        df = df[df["Status"] == "Success"]

        if df.empty:
            logging.warning(f"Nessuna richiesta di successo per il batch {i//3 + 1}, non verranno generati grafici.")
            continue

        # **Recupera KEM e firma direttamente dal CSV del primo file nel batch**
        algorithm_label = get_kem_sig_from_csv(os.path.join(OUTPUT_DIR, batch_files[0]))
        batch_labels.append(algorithm_label)

        for metric in metrics:
            batch_data[metric].append(df[metric].dropna().tolist())

    # **Generazione di un singolo grafico per ogni metrica con tutti i batch**
    for metric, ylabel in metrics.items():
        plt.figure(figsize=(12, 6))  # Maggiore spazio per evitare schiacciamenti
        plt.boxplot(batch_data[metric], patch_artist=True,
                    boxprops=dict(facecolor='lightblue', alpha=0.7, edgecolor='black', linewidth=1.5),
                    whiskerprops=dict(color='black', linewidth=2),
                    capprops=dict(color='black', linewidth=2),
                    medianprops=dict(color='red', linewidth=2),
                    flierprops=dict(marker='o', color='red', markersize=6)
        )

        # **Adattamento dinamico dell'asse Y migliorato**
        all_values = [val for sublist in batch_data[metric] for val in sublist]
        if all_values:
            min_val = min(all_values)
            max_val = max(all_values)
            Q1 = pd.Series(all_values).quantile(0.25)
            Q3 = pd.Series(all_values).quantile(0.75)
            IQR = Q3 - Q1

            lower_bound = max(min_val, Q1 - 1.5 * IQR)
            upper_bound = min(max_val, Q3 + 2.5 * IQR)

            # **Se il range è troppo piccolo, aggiungiamo un margine**
            if upper_bound - lower_bound < 0.1 * (max_val - min_val):
                lower_bound = min_val - 0.1 * (max_val - min_val)
                upper_bound = max_val + 0.1 * (max_val - min_val)

            plt.ylim([lower_bound, upper_bound])

        plt.title(ylabel)
        plt.ylabel(ylabel)
        plt.xticks(range(1, len(batch_labels) + 1), batch_labels, rotation=30, ha="right")
        plt.tight_layout()

        graph_path = os.path.join(GRAPH_DIR, f"{metric}_cumulative_boxplot.png")
        plt.savefig(graph_path, dpi=300)
        plt.close()

        logging.info(f"Boxplot cumulativo salvato: {graph_path}")

def convert_to_bytes(value, unit):
    """Converte i valori da diverse unità in bytes."""
    unit = unit.lower()
    value = float(value)
    if unit in ['byte', 'bytes', 'b']:
        return int(value)
    elif unit == 'kb':
        return int(value * 1024)
    elif unit == 'mb':
        return int(value * 1024**2)
    elif unit == 'gb':
        return int(value * 1024**3)
    else:
        raise ValueError(f"Unità non riconosciuta: {unit}")

def analyze_pcap():
    """Analizza il file pcap e calcola la media dei byte scambiati in upload e download."""
    pcap_file = "/app/pcap/capture.pcap"
    
    try:
        result = subprocess.run(
            ["tshark", "-r", pcap_file, "-q", "-z", "conv,tcp"],
            capture_output=True,
            text=True,
            timeout=60
        )

        if result.returncode != 0:
            logging.error("Errore nell'analisi del file pcap con tshark")
            return 0, 0

        upload_bytes, download_bytes, num_connessioni = 0, 0, 0

        pattern = re.compile(
            r"(\d+\.\d+\.\d+\.\d+:\d+)\s+<->\s+(\d+\.\d+\.\d+\.\d+:\d+)\s+\d+\s+(\d+)\s+(\w+)\s+\d+\s+(\d+)\s+(\w+)"
        )

        for line in result.stdout.split("\n"):
            match = pattern.search(line)
            if match:
                num_connessioni += 1
                upload_value = match.group(5)     
                upload_unit = match.group(6)      
                download_value = match.group(3)   
                download_unit = match.group(4) 

                upload = convert_to_bytes(upload_value, upload_unit)
                download = convert_to_bytes(download_value, download_unit)

                upload_bytes += upload
                download_bytes += download

        if num_connessioni == 0:
            logging.warning("Nessuna connessione TCP individuata nel file pcap.")
            return 0, 0

        media_upload = upload_bytes / num_connessioni
        media_download = download_bytes / num_connessioni

        logging.info(f"Numero connessioni individuate: {num_connessioni}")
        logging.info(f"Totale upload: {upload_bytes} bytes | Totale download: {download_bytes} bytes")
        logging.info(f"Media byte inviati: {media_upload:.2f} B | Media byte ricevuti: {media_download:.2f} B")

        return media_upload, media_download

    except subprocess.TimeoutExpired:
        logging.error("Timeout durante l'esecuzione di tshark.")
        return 0, 0
    except Exception as e:
        logging.error(f"Errore durante l'analisi: {e}")
        return 0, 0

def update_average_report(request_results):
    """Genera il report delle medie delle metriche, aggiungendo KEM, Signature e analizzando il pcap."""

    avg_file = os.path.join(AVG_DIR, "average_metrics.csv")
    per_request_avg_file = os.path.join(AVG_DIR, "average_metrics_per_request.csv")

    # Filtra solo le richieste di successo
    success_results = [r for r in request_results if r[1] is not None]

    if not success_results:
        logging.warning("Nessuna richiesta di successo, il report delle medie non verrà aggiornato.")
        return

    # Calcola le medie globali
    avg_connect_time = round(sum(r[1] for r in success_results) / len(success_results), 4)
    avg_handshake_time = round(sum(r[2] for r in success_results) / len(success_results), 4)
    avg_total_time = round(sum(r[3] for r in success_results) / len(success_results), 4)
    avg_elapsed_time = round(sum(r[4] for r in success_results) / len(success_results), 4)

    # Aggiunta medie logiche bytes da cURL
    avg_logical_bytes_sent = round(sum(r[6] for r in success_results) / len(success_results), 4)
    avg_logical_bytes_received = round(sum(r[7] for r in success_results) / len(success_results), 4)

    # Determina il KEM e la Signature usati
    kem_used = next((r[8] for r in success_results if r[8] and r[8] != "Unknown"), "Unknown")
    sig_used = next((r[9] for r in success_results if r[9] and r[9] != "Unknown"), "Unknown")

    # Lettura dati di monitoraggio (CPU, RAM)
    if os.path.exists(MONITOR_FILE):
        df_monitor = pd.read_csv(MONITOR_FILE)
        valid_cpu = df_monitor[df_monitor["CPU_Usage(%)"] > 0]["CPU_Usage(%)"]
        valid_ram = df_monitor[df_monitor["Memory_Usage(%)"] > 0]["Memory_Usage(%)"]
        avg_cpu = round(valid_cpu.mean(), 4) if not valid_cpu.empty else 0.0
        avg_ram = round(valid_ram.mean(), 4) if not valid_ram.empty else 0.0
    else:
        avg_cpu, avg_ram = 0.0, 0.0

    # **Analisi del pcap per ottenere il traffico effettivo**
    avg_upload, avg_download = analyze_pcap()

   # Aggiungi i campi al CSV
    file_exists = os.path.exists(avg_file)
    with open(avg_file, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow([
                "KEM", "Signature", "Avg_Connect_Time(ms)", "Avg_Handshake_Time(ms)", 
                "Avg_Total_Time(ms)", "Avg_Elapsed_Time(ms)", "Client_Avg_CPU_Usage(%)", 
                "Client_Avg_RAM_Usage(%)", "Avg_Upload_Bytes (Wireshark)", "Avg_Download_Bytes (Wireshark)",
                "Avg_Logical_Bytes_Sent (cURL)", "Avg_Logical_Bytes_Received (cURL)"])
        writer.writerow([
            kem_used, sig_used, avg_connect_time, avg_handshake_time, avg_total_time, 
            avg_elapsed_time, avg_cpu, avg_ram, avg_upload, avg_download,
            avg_logical_bytes_sent, avg_logical_bytes_received])

    logging.info(f"Report delle medie aggiornato: {avg_file}")

    # **Ora aggiorniamo il file per_request_avg_file con la media per richiesta (senza Execution_Index)**
    request_data = []
    files = sorted([f for f in os.listdir(OUTPUT_DIR) if f.startswith("request_client") and f.endswith(".csv")])

    for i in range(0, len(files), 3):  # Processiamo solo ogni terzo file, evitando duplicazioni
        if i + 3 <= len(files):  # Assicura che ci siano almeno 3 file per calcolare la media
            batch_files = files[i:i+3]
            dataframes = [pd.read_csv(os.path.join(OUTPUT_DIR, f)) for f in batch_files]
            df_avg = pd.concat(dataframes)[["Connect_Time(ms)", "TLS_Handshake(ms)", "Total_Time(ms)", "Elapsed_Time(ms)", "Cert_Size(B)"]].groupby(level=0).mean()

            for row in df_avg.itertuples():
                request_data.append([
                    kem_used, sig_used,  # KEM e Signature
                    row._1,  # Connect Time
                    row._2,  # Handshake Time
                    row._3,  # Total Time
                    row._4,  # Elapsed Time
                    row._5,  # Cert_Size
                ])

    per_request_file_exists = os.path.exists(per_request_avg_file)
    with open(per_request_avg_file, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        if not per_request_file_exists:
            writer.writerow(["KEM", "Signature", "Avg_Connect_Time(ms)", "Avg_Handshake_Time(ms)", 
                             "Avg_Total_Time(ms)", "Avg_Elapsed_Time(ms)", "Avg_Cert_Size(B)"])
        writer.writerows(request_data)

    logging.info(f"File delle medie per richiesta aggiornato: {per_request_avg_file}")

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
update_average_report(request_results)
#generate_performance_graphs()
#generate_cumulative_boxplots()