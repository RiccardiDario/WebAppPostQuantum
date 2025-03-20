import subprocess, re, psutil, csv, time, os, pandas as pd, matplotlib.pyplot as plt
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend

def get_next_filename(path, name, ext, counter=1):
    while os.path.exists(f"{path}/{name}{counter}.{ext}"): counter += 1
    return f"{path}/{name}{counter}.{ext}"

def ensure_dirs(*dirs):
    for d in dirs: os.makedirs(d, exist_ok=True)

OUTPUT_DIR = "/opt/nginx/output"
RESOURCE_LOG_DIR, FILTERED_LOG_DIR, GRAPH_DIR = f"{OUTPUT_DIR}/resource_logs", f"{OUTPUT_DIR}/filtered_logs", f"{OUTPUT_DIR}/filtered_logs/graphs"
ensure_dirs(RESOURCE_LOG_DIR, FILTERED_LOG_DIR, GRAPH_DIR)

RESOURCE_LOG, OUTPUT_FILE = get_next_filename(RESOURCE_LOG_DIR, "monitor_nginx", "csv"), get_next_filename(FILTERED_LOG_DIR, "monitor_nginx_filtered", "csv")
ACCESS_LOG, EXPECTED_REQUESTS, SAMPLING_INTERVAL = "/opt/nginx/logs/access_custom.log", 500, 0.1
AVG_METRICS_FILE = f"{FILTERED_LOG_DIR}/avg_nginx_usage.csv"

def get_kem_sig_from_logs(log_path, cert_path):
    """Estrae il KEM dal log di accesso e la firma dal certificato del server Nginx."""
    kem, sig_alg = "Unknown", "Unknown"

    # 📌 **Estrazione del KEM dai log di accesso di Nginx**
    try:
        with open(log_path, "r") as f:
            for line in reversed(f.readlines()):  # Legge i log dall'ultima richiesta in poi
                kem_match = re.search(r'KEM=([\w\d_-]+)', line)
                if kem_match:
                    kem = kem_match.group(1)
                    break  # Prendi l'ultimo KEM usato nelle richieste
    except Exception as e:
        print(f"Errore nella lettura dei log di accesso di Nginx: {e}")

    # 📌 **Estrazione dell'algoritmo di firma dal certificato di Nginx**
    try:
        with open(cert_path, "rb") as cert_file:
            cert_data = cert_file.read()
        cert = x509.load_pem_x509_certificate(cert_data, default_backend())
        sig_alg = cert.signature_algorithm_oid._name  # Estrai l'algoritmo di firma
    except Exception as e:
        print(f"Errore nell'estrazione della firma dal certificato: {e}")
        sig_alg = "Unknown"

    return kem, sig_alg

def generate_server_performance_graphs():
    """Genera i grafici relativi alle risorse utilizzate da Nginx ogni cinque file rilevati."""
    print("Generazione dei grafici di performance del server...")

    FILTERED_LOG_DIR = "/opt/nginx/output/filtered_logs"
    monitor_files = sorted([f for f in os.listdir(FILTERED_LOG_DIR) if f.startswith("monitor_nginx_filtered") and f.endswith(".csv")])

    if len(monitor_files) < 5:
        print("Non ci sono abbastanza file per generare i grafici.")
        return

    log_path = "/opt/nginx/logs/access_custom.log"
    cert_path = "/etc/nginx/certs/qsc-ca-chain.crt"
    kem, sig_alg = get_kem_sig_from_logs(log_path, cert_path)

    for i in range(0, len(monitor_files), 5):
        batch_files = monitor_files[i:i+5]

        # Leggi i dati dei file batch
        dataframes = [pd.read_csv(os.path.join(FILTERED_LOG_DIR, f)) for f in batch_files]
        for df in dataframes:
            df["Timestamp"] = pd.to_datetime(df["Timestamp"], format="%d/%b/%Y:%H:%M:%S.%f")

        min_range = min((df["Timestamp"].max() - df["Timestamp"].min()).total_seconds() for df in dataframes)
        num_samples = int(min_range / 0.1)

        df_monitor_avg = pd.concat([
            df[df["Timestamp"] <= (df["Timestamp"].min() + pd.Timedelta(seconds=min_range))]
            .assign(Index=lambda df: (df["Timestamp"] - df["Timestamp"].min()).dt.total_seconds() // 0.1)
            .groupby("Index").mean().reset_index()
            for df in dataframes
        ]).groupby("Index").mean().reset_index()

        sample_indices = (df_monitor_avg["Index"] * 0.1 * 1000).tolist()

        plt.figure(figsize=(14, 7))
        plt.plot(sample_indices, df_monitor_avg["CPU (%)"], label="CPU Usage (%)", color="red", marker="o", linestyle="-")
        plt.plot(sample_indices, df_monitor_avg["Mem (%)"], label="Memory Usage (%)", color="blue", marker="o", linestyle="-")
        plt.xlabel("Time (ms)")
        plt.ylabel("Usage (%)")
        plt.title(f"Server Resource Usage (Avg. CPU & Memory) Over Time\nKEM: {kem} | Signature: {sig_alg}")

        plt.legend(
            title=f"KEM: {kem} | Signature: {sig_alg}",
            loc="upper left",
            bbox_to_anchor=(1, 1)
        )

        plt.grid(True, linestyle="--", alpha=0.7)
        graph_path = os.path.join(GRAPH_DIR, f"server_cpu_memory_usage_batch_{i//5 + 1}.png")
        plt.savefig(graph_path, dpi=300, bbox_inches="tight")
        plt.close()

        print(f"Grafico generato: {graph_path}")

def monitor_resources():
    print("Inizio monitoraggio delle risorse...")
    with open(RESOURCE_LOG, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        psutil.cpu_percent(None)
        w.writerow(["Timestamp", "CPU (%)", "Mem (%)", "Bytes Sent", "Bytes Recv", "Conn Attive"])
        while True:
            if os.path.exists(ACCESS_LOG) and sum(1 for _ in open(ACCESS_LOG, encoding="utf-8")) >= EXPECTED_REQUESTS:
                break
            w.writerow([datetime.now().strftime("%d/%b/%Y:%H:%M:%S.%f")[:-3], psutil.cpu_percent(), psutil.virtual_memory().percent,
                        *psutil.net_io_counters()[:2], sum(1 for c in psutil.net_connections("inet") if c.status == "ESTABLISHED")])
            f.flush()
            time.sleep(SAMPLING_INTERVAL)
    print("Monitoraggio terminato.")

def analyze_logs():
    if not os.path.exists(ACCESS_LOG): return None, None
    try:
        with open(ACCESS_LOG, encoding="utf-8") as f:
            timestamps = [datetime.fromtimestamp(float(l.split()[3][1:-1])) for l in f if len(l.split()) >= 4]
        return (min(timestamps), max(timestamps)) if timestamps else (None, None)
    except: return None, None

def analyze_performance():
    s, e = analyze_logs()
    if not s or not e: return print("ERRORE: Intervallo di test non disponibile.")
    try:
        with open(RESOURCE_LOG, encoding="utf-8") as f:
            data = [r for r in csv.DictReader(f) if s <= datetime.strptime(r["Timestamp"], "%d/%b/%Y:%H:%M:%S.%f") <= e]
        if not data: return print("ERRORE: Nessun dato nel periodo di test.")
        with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["Timestamp", "CPU (%)", "Mem (%)", "Bytes Sent", "Bytes Recv", "Conn Attive"])
            w.writerows([[r[c] for c in ["Timestamp", "CPU (%)", "Mem (%)", "Bytes Sent", "Bytes Recv", "Conn Attive"]] for r in data])
        print(f"Salvati {len(data)} campionamenti in {OUTPUT_FILE}.")
    except Exception as e:
        print(f"ERRORE nel salvataggio dati: {e}")

def generate_avg_resource_usage():
    try:
        with open(OUTPUT_FILE, encoding="utf-8") as f:
            data = list(csv.DictReader(f))
        if not data: return print("ERRORE: Nessun dato disponibile per calcolare la media.")
        avg_cpu = sum(float(r["CPU (%)"]) for r in data) / len(data)
        avg_ram = sum(float(r["Mem (%)"]) for r in data) / len(data)

        file_exists = os.path.isfile(AVG_METRICS_FILE)
        with open(AVG_METRICS_FILE, "a", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            if not file_exists:
                w.writerow(["Timestamp", "CPU Media (%)", "Mem Media (%)"])
            w.writerow([datetime.now().strftime("%d/%b/%Y:%H:%M:%S"), f"{avg_cpu:.2f}", f"{avg_ram:.2f}"])
        print(f"Medie CPU e RAM aggiornate in {AVG_METRICS_FILE}.")
    except Exception as e:
        print(f"ERRORE nel calcolo delle medie: {e}")
    
def log_system_info():
    cpu_info = psutil.cpu_freq()
    ram_info = psutil.virtual_memory()

    print(f"--- Informazioni CPU ---")
    print(f"Core logici disponibili: {psutil.cpu_count(logical=True)}")
    print(f"Core fisici disponibili: {psutil.cpu_count(logical=False)}")
    print(f"\n--- Informazioni RAM ---")
    print(f"RAM totale: {ram_info.total / (1024**3):.2f} GB")
    
if __name__ == "__main__":
    try:
        monitor_resources()
        analyze_performance()
        generate_avg_resource_usage()
        generate_server_performance_graphs()
        log_system_info()
    except Exception as e:
        print(f"ERRORE GENERALE: {e}")