import psutil, csv, time, os
from datetime import datetime

def get_next_filename(path, name, ext, counter=1):
    while os.path.exists(f"{path}/{name}{counter}.{ext}"): counter += 1
    return f"{path}/{name}{counter}.{ext}"

def ensure_dirs(*dirs):
    for d in dirs: os.makedirs(d, exist_ok=True)

OUTPUT_DIR = "/opt/nginx/output"
RESOURCE_LOG_DIR, FILTERED_LOG_DIR = f"{OUTPUT_DIR}/resource_logs", f"{OUTPUT_DIR}/filtered_logs"
ensure_dirs(RESOURCE_LOG_DIR, FILTERED_LOG_DIR)

RESOURCE_LOG, OUTPUT_FILE = get_next_filename(RESOURCE_LOG_DIR, "monitor_nginx", "csv"), get_next_filename(FILTERED_LOG_DIR, "monitor_nginx_filtered", "csv")
ACCESS_LOG, EXPECTED_REQUESTS, SAMPLING_INTERVAL = "/opt/nginx/logs/access_custom.log", 400, 0.1

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

if __name__ == "__main__":
    try:
        monitor_resources()
        analyze_performance()
    except Exception as e:
        print(f"ERRORE GENERALE: {e}")
