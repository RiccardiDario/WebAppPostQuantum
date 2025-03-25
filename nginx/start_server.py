import subprocess, re, psutil, csv, time, os, pandas as pd, matplotlib.pyplot as plt
from datetime import datetime

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
    kem_map = { "0x0200": "mlkem512", "0x0201": "mlkem768", "0x0202": "mlkem1024", "0x2f4b": "p256_mlkem512", "0x2f4c": "p384_mlkem768", "0x2f4d": "p521_mlkem1024" }
    sig_oid_map = { "2.16.840.1.101.3.4.3.17": "mldsa44", "2.16.840.1.101.3.4.3.18": "mldsa65", "2.16.840.1.101.3.4.3.19": "mldsa87",
        "1.3.9999.7.5": "p256_mldsa44", "1.3.9999.7.7": "p384_mldsa65", "1.3.9999.7.8": "p521_mldsa87"}
    kem, sig_alg = "Unknown", "Unknown"
    try:
        with open(log_path, "r") as f:
            for line in reversed(f.readlines()):
                if m := re.search(r'KEM=([\w\d._:-]+)', line):
                    kem = kem_map.get(m.group(1), m.group(1)); break
    except Exception as e:
        print(f"Errore log Nginx: {e}")

    try:
        result = subprocess.run(["openssl", "x509", "-in", cert_path, "-noout", "-text"], capture_output=True, text=True, check=True)
        for line in result.stdout.splitlines():
            if "Signature Algorithm" in line:
                oid = line.strip().split()[-1]
                sig_alg = oid if oid.isalnum() else sig_oid_map.get(oid, oid)
                break
    except Exception as e:
        print(f"Errore firma certificato: {e}")
    return kem, sig_alg

def generate_server_performance_graphs():
    print("Generazione grafici performance server...")
    monitor_files = sorted([f for f in os.listdir(FILTERED_LOG_DIR) if f.startswith("monitor_nginx_filtered") and f.endswith(".csv")], key=extract_monitor_server_number)
    if len(monitor_files) < 5:
        print("Non ci sono abbastanza file per generare i grafici."); return

    for i in range(0, len(monitor_files), 5):
        batch_files = monitor_files[i:i+5]
        if len(batch_files) < 5: print(f"Batch incompleto ({len(batch_files)} file), salto."); continue

        batch_index = i // 5 + 1
        graph_path = os.path.join(GRAPH_DIR, f"server_cpu_memory_usage_batch_{batch_index}.png")
        if os.path.exists(graph_path): print(f"Grafico già esistente per batch {batch_index}, salto."); continue

        kem, sig = get_kem_sig_from_logs(ACCESS_LOG, "/etc/nginx/certs/qsc-ca-chain.crt")
        dfs = [pd.read_csv(os.path.join(FILTERED_LOG_DIR, f)) for f in batch_files]
        for df in dfs: df["Timestamp"] = pd.to_datetime(df["Timestamp"], format="%d/%b/%Y:%H:%M:%S.%f")

        min_range = min((df["Timestamp"].max() - df["Timestamp"].min()).total_seconds() for df in dfs)

        df_monitor_avg = pd.concat([
            df[df["Timestamp"] <= df["Timestamp"].min() + pd.Timedelta(seconds=min_range)]
            .assign(Index=(df["Timestamp"] - df["Timestamp"].min()).dt.total_seconds() // 0.1)
            .groupby("Index").mean(numeric_only=True).reset_index()
            for df in dfs
        ]).groupby("Index").mean(numeric_only=True).reset_index()

        time_ms = df_monitor_avg["Index"] * 100

        fig, ax = plt.subplots(figsize=(14, 7))
        ax.plot(time_ms, df_monitor_avg["CPU (%)"], label="CPU Usage (%)", color="red", marker="o")
        ax.plot(time_ms, df_monitor_avg["Mem (%)"], label="Memory Usage (%)", color="blue", marker="o")
        ax.set(xlabel="Time (ms)", ylabel="Usage (%)",
               title=f"Server Resource Usage (Avg. CPU & Memory) Over Time\nKEM: {kem} | Signature: {sig}")
        ax.legend(title=f"KEM: {kem} | Signature: {sig}", loc="upper left", bbox_to_anchor=(1, 1))
        ax.grid(True, linestyle="--", alpha=0.7)
        fig.savefig(graph_path, dpi=300, bbox_inches="tight"); plt.close(fig)
        print(f"✅ Grafico generato: {graph_path}")

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

def extract_monitor_server_number(filename): return int(m.group(1)) if (m := re.search(r"monitor_nginx_filtered(\d+)", filename)) else -1

if __name__ == "__main__":
    try:
        monitor_resources()
        analyze_performance()
        generate_avg_resource_usage()
        generate_server_performance_graphs()
        log_system_info()
    except Exception as e:
        print(f"ERRORE GENERALE: {e}")