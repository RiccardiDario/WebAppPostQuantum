import os, re, math, time, logging, subprocess, csv, psutil, pandas as pd, matplotlib.pyplot as plt
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Thread, Lock
from datetime import datetime

CURL_COMMAND_TEMPLATE = ["curl", "--tlsv1.3", "--curves", "p521_mlkem1024", "--cacert", "/opt/certs/CA.crt", "-w",
"Connect Time: %{time_connect}, TLS Handshake: %{time_appconnect}, Total Time: %{time_total}, %{http_code}\n","-s", "https://nginx_pq:4433"]

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s", handlers=[logging.StreamHandler()])
OUTPUT_DIR, MONITOR_DIR, TRACE_LOG_DIR = "/app/output/request_logs", "/app/output/system_logs", "/app/logs/"
for directory in (TRACE_LOG_DIR, OUTPUT_DIR, MONITOR_DIR): os.makedirs(directory, exist_ok=True)
GRAPH_DIR, SYSTEM_GRAPH_DIR, AVG_DIR = f"{OUTPUT_DIR}/graphs/", f"{MONITOR_DIR}/graphs/", f"{OUTPUT_DIR}/avg/"
for d in [GRAPH_DIR, SYSTEM_GRAPH_DIR, AVG_DIR]: os.makedirs(d, exist_ok=True)
NUM_REQUESTS, active_requests, active_requests_lock, global_stats = 500, 0, Lock(), {"cpu_usage": [], "memory_usage": []}

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
    global active_requests
    trace_file, cert_size, kem, sig_alg  = f"{TRACE_LOG_DIR}trace_{req_num}.log", 0, "Unknown", "Unknown"
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

def generate_system_monitor_graph():
    """Genera il grafico dell'utilizzo di CPU e RAM per l'ultimo batch di monitoraggio (5 file)."""

    logging.info("Generazione grafico risorse sistema per l'ultimo batch...")

    monitor_files = sorted([f for f in os.listdir(MONITOR_DIR) if f.startswith("system_client") and f.endswith(".csv")], key=extract_monitor_number)
    request_files = sorted([f for f in os.listdir(OUTPUT_DIR) if f.startswith("request_client") and f.endswith(".csv")], key=extract_request_number)
    
    if len(monitor_files) < 5 or len(request_files) % 5 != 0:
        logging.info("Nessun batch completo di file di monitoraggio da processare.")
        return

    # Prendi gli ultimi 5 file di monitoraggio e batch corrispondente delle request
    monitor_batch_files = monitor_files[-5:]
    batch_request_files = request_files[-5:]
    batch_paths = [os.path.join(OUTPUT_DIR, f) for f in batch_request_files]
    kem, sig_alg, _ = get_kem_sig_from_csv(batch_paths)

    # Carica i dati di monitoraggio e converte Timestamp
    monitor_dataframes = [pd.read_csv(os.path.join(MONITOR_DIR, f)) for f in monitor_batch_files]
    for df in monitor_dataframes:
        df["Timestamp"] = pd.to_datetime(df["Timestamp"])

    # Calcola la finestra temporale comune e indice per media ogni 100ms
    min_range = min((df["Timestamp"].max() - df["Timestamp"].min()).total_seconds() for df in monitor_dataframes)
    num_samples = int(min_range / 0.1)

    df_monitor_avg = pd.concat([
        df[df["Timestamp"] <= (df["Timestamp"].min() + pd.Timedelta(seconds=min_range))]
        .assign(Index=lambda df: (df["Timestamp"] - df["Timestamp"].min()).dt.total_seconds() // 0.1)
        .groupby("Index").mean().reset_index()
        for df in monitor_dataframes
    ]).groupby("Index").mean().reset_index()

    sample_indices = (df_monitor_avg["Index"] * 0.1 * 1000).tolist()  # in ms
    total_memory = psutil.virtual_memory().total / (1024 ** 2)
    total_cores = psutil.cpu_count(logical=True)
    batch_num = len(monitor_files) // 5

    # Grafico
    plt.figure(figsize=(14, 7))
    plt.plot(sample_indices, df_monitor_avg["CPU_Usage(%)"], label="CPU Usage (%)", color="green", marker="o", linestyle="-")
    plt.plot(sample_indices, df_monitor_avg["Memory_Usage(%)"], label="Memory Usage (%)", color="purple", marker="o", linestyle="-")
    plt.xlabel("Time (ms)")
    plt.ylabel("Usage (%)")
    plt.title(f"Client Resource Usage (Avg. CPU & Memory) Over Time\nKEM: {kem} | Signature: {sig_alg}")

    plt.legend(
        title=f"KEM: {kem} | Signature: {sig_alg}\nCPU Cores: {total_cores} | Total RAM: {total_memory:.2f} MB",
        loc="upper left",
        bbox_to_anchor=(1, 1)
    )

    plt.grid(True, linestyle="--", alpha=0.7)
    graph_path = os.path.join(SYSTEM_GRAPH_DIR, f"cpu_memory_usage_batch_{batch_num}.png")
    plt.savefig(graph_path, dpi=300, bbox_inches="tight")
    plt.close()

    logging.info(f"Grafico CPU/Memoria salvato: {graph_path}")

def get_kem_sig_from_csv(file_list):
    """
    Recupera il KEM, la Signature e la dimensione del certificato da una lista di file CSV.
    Ritorna i valori più frequenti nel batch e la dimensione del certificato (assunta costante nel batch).
    """
    if not file_list:
        return "Unknown", "Unknown", -1

    if isinstance(file_list, str):
        file_list = [file_list]

    try:
        df_all = pd.concat([pd.read_csv(f) for f in file_list])
        df_success = df_all[df_all["Status"] == "Success"]

        kem_mode = df_success["KEM"].dropna().mode()
        sig_mode = df_success["Signature"].dropna().mode()
        cert_mode = df_success["Cert_Size(B)"].dropna().mode()

        kem = kem_mode[0] if not kem_mode.empty else "Unknown"
        sig = sig_mode[0] if not sig_mode.empty else "Unknown"
        cert_size = int(cert_mode[0]) if not cert_mode.empty else -1

        return kem, sig, cert_size
    except Exception as e:
        logging.warning(f"Errore durante analisi CSV: {e}")
        return "Unknown", "Unknown", -1

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
    """Analizza il file pcap e calcola la media dei byte scambiati in upload, download e traffico TLS."""
    pcap_file = "/app/pcap/capture.pcap"
    tls_keylog_file = "/tls_keys/tls-secrets.log"
    
    try:
        # Analizza la connessione TCP generale
        result = subprocess.run(
            ["tshark", "-r", pcap_file, "-q", "-z", "conv,tcp"],
            capture_output=True,
            text=True,
            timeout=60
        )

        if result.returncode != 0:
            logging.error("Errore nell'analisi del file pcap con tshark")
            return 0, 0, 0, 0

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

        # Analizza specificamente il traffico TLS con decrittazione
        tls_result = subprocess.run(
            ["tshark", "-r", pcap_file, "-Y", "tls.handshake", "-T", "fields", 
             "-e", "ip.src", "-e", "tcp.srcport", "-e", "ip.dst", "-e", "tcp.dstport", 
             "-e", "frame.len", "-e", "tls.handshake.type", "-o", f"tls.keylog_file:{tls_keylog_file}"],
            capture_output=True,
            text=True,
            timeout=60
        )

        tls_upload_bytes, tls_download_bytes = 0, 0
        server_ip = "192.168.1.100"  # IP statico del server
        
        if tls_result.returncode == 0:
            for line in tls_result.stdout.splitlines():
                try:
                    fields = line.split("\t")
                    if len(fields) >= 6:
                        src_ip, src_port, dst_ip, dst_port, frame_size, handshake_type = fields
                        frame_size = int(frame_size)
                        
                        if dst_ip == server_ip:
                            tls_upload_bytes += frame_size
                        else:
                            tls_download_bytes += frame_size
                except ValueError:
                    continue

        avg_upload = upload_bytes / num_connessioni if num_connessioni > 0 else 0
        avg_download = download_bytes / num_connessioni if num_connessioni > 0 else 0
        avg_tls_upload = tls_upload_bytes / num_connessioni if num_connessioni > 0 else 0
        avg_tls_download = tls_download_bytes / num_connessioni if num_connessioni > 0 else 0

        logging.info(f"Numero connessioni individuate: {num_connessioni}")
        logging.info(f"Totale upload: {upload_bytes} bytes | Totale download: {download_bytes} bytes")
        logging.info(f"Media byte inviati: {avg_upload:.2f} B | Media byte ricevuti: {avg_download:.2f} B")
        logging.info(f"Media traffico TLS inviato: {avg_tls_upload:.2f} B | Media traffico TLS ricevuto: {avg_tls_download:.2f} B")

        return avg_upload, avg_download, avg_tls_upload, avg_tls_download

    except subprocess.TimeoutExpired:
        logging.error("Timeout durante l'esecuzione di tshark.")
        return 0, 0, 0, 0
    except Exception as e:
        logging.error(f"Errore durante l'analisi: {e}")
        return 0, 0, 0, 0

def update_average_report(request_results):
    """Genera il report delle medie globali per il batch corrente e aggiorna average_metrics.csv."""

    avg_file = os.path.join(AVG_DIR, "average_metrics.csv")

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

    # Media dei byte logici da cURL
    avg_logical_bytes_sent = round(sum(r[6] for r in success_results) / len(success_results), 4)
    avg_logical_bytes_received = round(sum(r[7] for r in success_results) / len(success_results), 4)

    # Ricava KEM e Signature più usati
    kem_used = next((r[8] for r in success_results if r[8] and r[8] != "Unknown"), "Unknown")
    sig_used = next((r[9] for r in success_results if r[9] and r[9] != "Unknown"), "Unknown")

    # Lettura dati di monitoraggio (CPU e RAM)
    if os.path.exists(MONITOR_FILE):
        df_monitor = pd.read_csv(MONITOR_FILE)
        valid_cpu = df_monitor[df_monitor["CPU_Usage(%)"] > 0]["CPU_Usage(%)"]
        valid_ram = df_monitor[df_monitor["Memory_Usage(%)"] > 0]["Memory_Usage(%)"]
        avg_cpu = round(valid_cpu.mean(), 4) if not valid_cpu.empty else 0.0
        avg_ram = round(valid_ram.mean(), 4) if not valid_ram.empty else 0.0
    else:
        avg_cpu, avg_ram = 0.0, 0.0

    # Analisi del traffico (Wireshark)
    avg_upload, avg_download, avg_tls_upload, avg_tls_download = analyze_pcap()

    # Scrive (append) nel file average_metrics.csv
    file_exists = os.path.exists(avg_file)
    with open(avg_file, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow([
                "KEM", "Signature", "Avg_Connect_Time(ms)", "Avg_Handshake_Time(ms)", 
                "Avg_Total_Time(ms)", "Avg_Elapsed_Time(ms)", "Client_Avg_CPU_Usage(%)", 
                "Client_Avg_RAM_Usage(%)", "Avg_Upload_Bytes (Wireshark)", "Avg_Download_Bytes (Wireshark)",
                "Avg_TLS_Upload_Bytes (Wireshark)", "Avg_TLS_Download_Bytes (Wireshark)",
                "Avg_Logical_Bytes_Sent (cURL)", "Avg_Logical_Bytes_Received (cURL)"])
        writer.writerow([
            kem_used, sig_used, avg_connect_time, avg_handshake_time, avg_total_time, 
            avg_elapsed_time, avg_cpu, avg_ram, avg_upload, avg_download,
            avg_tls_upload, avg_tls_download, avg_logical_bytes_sent, avg_logical_bytes_received])

    logging.info(f"Report delle medie aggiornato: {avg_file}")

def extract_request_number(filename):
    match = re.search(r"request_client(\d+)", filename)
    return int(match.group(1)) if match else -1

def extract_monitor_number(filename):
    match = re.search(r"system_client(\d+)", filename)
    return int(match.group(1)) if match else -1

def append_last_batch_to_average_per_request():
    """Elabora solo l'ultimo batch di 5 file correttamente ordinati e li aggiunge al file average_metrics_per_request.csv."""
    per_request_avg_file = os.path.join(AVG_DIR, "average_metrics_per_request.csv")

    # Estrai i file ordinati per numero
    files = sorted([f for f in os.listdir(OUTPUT_DIR) if f.startswith("request_client") and f.endswith(".csv")],key=extract_request_number)

    if len(files) < 5 or len(files) % 5 != 0:
        logging.info("Il batch non è completo o non divisibile per 5.")
        return

    # Prendi gli ultimi 5 file
    batch_files = files[-5:]
    batch_paths = [os.path.join(OUTPUT_DIR, f) for f in batch_files]

    kem_used, sig_used, _ = get_kem_sig_from_csv(batch_paths)

    # Carica i file e ordina le righe per Request_Number
    dataframes = [pd.read_csv(p) for p in batch_paths]
    for df in dataframes:
        df.sort_values(by="Request_Number", inplace=True)
        df.reset_index(drop=True, inplace=True)

    metric_cols = ["Connect_Time(ms)", "TLS_Handshake(ms)", "Total_Time(ms)", "Elapsed_Time(ms)", "Cert_Size(B)"]
    request_data = []

    for i in range(len(dataframes[0])):
        values = [df.loc[i, metric_cols].values for df in dataframes]
        avg_values = sum(values) / len(values)
        request_data.append([kem_used.strip(), sig_used.strip()] + avg_values.tolist())

    # Scrittura nel CSV
    file_exists = os.path.exists(per_request_avg_file)
    with open(per_request_avg_file, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(["KEM", "Signature", "Avg_Connect_Time(ms)", "Avg_Handshake_Time(ms)",
                             "Avg_Total_Time(ms)", "Avg_Elapsed_Time(ms)", "Avg_Cert_Size(B)"])
        writer.writerows(request_data)

    logging.info(f"Aggiunti {len(request_data)} risultati al file: {per_request_avg_file}")

def generate_graphs_from_average_per_request():
    """Genera grafici Elapsed/Breakdown e boxplot da average_metrics_per_request.csv, un batch da 500 alla volta"""

    file_path = os.path.join(AVG_DIR, "average_metrics_per_request.csv")
    if not os.path.exists(file_path):
        logging.warning("File average_metrics_per_request.csv non trovato.")
        return

    df = pd.read_csv(file_path)
    if df.empty:
        logging.warning("Il file delle medie per richiesta è vuoto.")
        return

    requests_per_batch = 500
    requests_per_plot = 100
    total_requests = len(df)
    total_batches = total_requests // requests_per_batch

    # Per i boxplot
    batch_labels = []
    boxplot_data = {
        "Avg_Connect_Time(ms)": [],
        "Avg_Handshake_Time(ms)": [],
        "Avg_Total_Time(ms)": [],
        "Avg_Elapsed_Time(ms)": []
    }

    # Ciclo sui batch
    for b in range(total_batches):
        df_batch = df.iloc[b * requests_per_batch:(b + 1) * requests_per_batch]
        kem = df_batch["KEM"].iloc[0]
        sig = df_batch["Signature"].iloc[0]
        cert_size = df_batch["Avg_Cert_Size(B)"].iloc[0]
        cert_label = f"{kem}\n{sig}\n{int(cert_size)} B"

        # Salva dati per boxplot
        batch_labels.append(cert_label)
        for metric in boxplot_data:
            boxplot_data[metric].append(df_batch[metric].tolist())

        # Genera grafici a blocchi da 100 (x locale al batch)
        for i in range(0, requests_per_batch, requests_per_plot):
            start = i + 1
            end = min(i + requests_per_plot, requests_per_batch)
            df_subset = df_batch.iloc[i:i + requests_per_plot].reset_index(drop=True)
            x = list(range(start, end + 1))
            cert_str = f"{cert_size:.2f} B"

            # Elapsed Time Graph
            plt.figure(figsize=(10, 5))
            plt.plot(x, df_subset["Avg_Elapsed_Time(ms)"], marker='o', linestyle='-', color='blue', label="Elapsed Time (ms)")
            plt.xlabel("Request Completion Order")
            plt.ylabel("Elapsed Time (ms)")
            plt.title(f"Elapsed Time per Request\nKEM: {kem} | Signature: {sig}")
            plt.legend(title=f"Certificate Size: {cert_str}")
            plt.grid(True)
            fname = f"elapsed_time_graph_batch_{b+1}_{start}_{end}.png"
            plt.tight_layout()
            plt.savefig(os.path.join(GRAPH_DIR, fname))
            plt.close()

            # TLS Breakdown corretto (impilato ma realistico)
            connect = df_subset["Avg_Connect_Time(ms)"]
            handshake = df_subset["Avg_Handshake_Time(ms)"] - connect
            total = df_subset["Avg_Total_Time(ms)"] - df_subset["Avg_Handshake_Time(ms)"]

            plt.figure(figsize=(14, 7))
            plt.bar(x, connect, label="Connect Time", color="red", alpha=0.7)
            plt.bar(x, handshake, bottom=connect, label="TLS Handshake Time", color="orange", alpha=0.7)
            plt.bar(x, total, bottom=df_subset["Avg_Handshake_Time(ms)"], label="Total Time", color="gray", alpha=0.7)
            plt.xlabel("Request Completion Order")
            plt.ylabel("Time (ms)")
            plt.title(f"Timing Breakdown for TLS Connections\nKEM: {kem} | Signature: {sig}")
            plt.legend(title=f"Certificate Size: {cert_str}")
            plt.grid(axis="y", linestyle="--", alpha=0.7)
            fname_bar = f"tls_avg_graph_batch_{b+1}_{start}_{end}.png"
            plt.tight_layout()
            plt.savefig(os.path.join(GRAPH_DIR, fname_bar), dpi=300)
            plt.close()

    # ✅ Fuori dal ciclo: genera una sola volta i boxplot cumulativi
    for metric, ylabel in {
        "Avg_Connect_Time(ms)": "Connect Time (ms)",
        "Avg_Handshake_Time(ms)": "Handshake Time (ms)",
        "Avg_Total_Time(ms)": "Total Time (ms)",
        "Avg_Elapsed_Time(ms)": "Elapsed Time (ms)"
    }.items():
        num_boxes = len(batch_labels)
        fig = plt.figure(figsize=(max(6, num_boxes * 1.2), 6))
        ax = fig.add_axes([0.1, 0.15, 0.8, 0.75])  # [left, bottom, width, height]

        data = [item for sublist in boxplot_data[metric] for item in sublist]

        ax.boxplot(boxplot_data[metric], patch_artist=True,
                   boxprops=dict(facecolor='lightblue', alpha=0.7, edgecolor='black', linewidth=1.5),
                   whiskerprops=dict(color='black', linewidth=2),
                   capprops=dict(color='black', linewidth=2),
                   medianprops=dict(color='red', linewidth=2),
                   flierprops=dict(marker='o', color='black', markersize=6, alpha=0.6))  # ✅ outlier visibili

        ax.set_title(ylabel)
        ax.set_ylabel(ylabel)
        ax.set_xticks(range(1, num_boxes + 1))
        ax.set_xticklabels(batch_labels, rotation=30, ha="right")

        path = os.path.join(GRAPH_DIR, f"{ylabel.replace(' ', '_')}_cumulative_boxplot.png")
        fig.savefig(path, dpi=300)
        plt.close(fig)

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

update_average_report(request_results)
append_last_batch_to_average_per_request()
generate_system_monitor_graph()
generate_graphs_from_average_per_request()
logging.info(f"Test completato in {end_time - start_time:.2f} secondi. Report: {OUTPUT_FILE}")