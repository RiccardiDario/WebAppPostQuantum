import psutil, csv, time, os  # Import librerie necessarie
from datetime import datetime  # Per gestione timestamp

# Definizione dei file
RESOURCE_LOG, ACCESS_LOG, OUTPUT_FILE = "/opt/nginx/output/monitor_nginx.csv", "/opt/nginx/logs/access_custom.log", "/opt/nginx/output/monitor_nginx_filtered.csv"
EXPECTED_REQUESTS, SAMPLING_INTERVAL = 500, 0.01  # Soglia richieste e intervallo di campionamento

def monitor_resources():
    """Monitora le risorse fino al raggiungimento delle richieste attese."""
    print("Inizio monitoraggio delle risorse...")
    with open(RESOURCE_LOG, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["Timestamp", "CPU (%)", "Mem (MB)", "Bytes Sent", "Bytes Recv", "Conn Attive"])
        psutil.cpu_percent(None)  # Inizializza la lettura CPU per valori realistici

        while True:
            if os.path.exists(ACCESS_LOG):
                with open(ACCESS_LOG, encoding="utf-8") as log_file:
                    requests_count = sum(1 for _ in log_file)
                print(f"Trovate {requests_count} richieste nel log.")
                if requests_count >= EXPECTED_REQUESTS: 
                    print(f"Raggiunte {requests_count} richieste, terminazione monitoraggio.")
                    break

            ts = datetime.now().strftime("%d/%b/%Y:%H:%M:%S")
            cpu, mem = psutil.cpu_percent(None), psutil.virtual_memory().used / (1024 ** 2)
            net, conns = psutil.net_io_counters(), len([c for c in psutil.net_connections("inet") if c.status == "ESTABLISHED"])
            w.writerow([ts, cpu, mem, net.bytes_sent, net.bytes_recv, conns]), f.flush()

            print(f"{ts} - CPU: {cpu}%, Mem: {mem}MB, Sent: {net.bytes_sent}, Recv: {net.bytes_recv}, Conn: {conns}")
            time.sleep(SAMPLING_INTERVAL)

def analyze_logs():
    """Analizza i log Nginx per determinare l'intervallo di test."""
    print(f"Analisi del log: {ACCESS_LOG}")
    if not os.path.exists(ACCESS_LOG): 
        print("ERRORE: File log non trovato.")
        return None, None
    try:
        with open(ACCESS_LOG, encoding="utf-8") as f:
            t = [datetime.strptime(l.split()[3][1:], "%d/%b/%Y:%H:%M:%S") for l in f if len(l.split()) >= 10]
        if not t:
            print("ERRORE: Nessun timestamp trovato nei log.")
            return None, None
        print(f"Intervallo richieste: {min(t)} - {max(t)}")
        return min(t), max(t)
    except Exception as e:
        print(f"ERRORE nella lettura log: {e}")
        return None, None

def load_resource_data():
    """Carica i dati di monitoraggio dal file CSV."""
    print(f"Caricamento dati da {RESOURCE_LOG}")
    if not os.path.exists(RESOURCE_LOG):
        print("ERRORE: File dati non trovato.")
        return []
    try:
        with open(RESOURCE_LOG, encoding="utf-8") as f:
            data = [{"timestamp": datetime.strptime(r["Timestamp"], "%d/%b/%Y:%H:%M:%S"), "cpu": float(r["CPU (%)"]),
                     "memory": float(r["Mem (MB)"]), "bytes_sent": int(r["Bytes Sent"]), "bytes_received": int(r["Bytes Recv"]),
                     "active_connections": int(r["Conn Attive"])} for r in csv.DictReader(f)]
        print(f"Caricati {len(data)} campionamenti.")
        return data
    except Exception as e:
        print(f"ERRORE nel caricamento dati: {e}")
        return []

def analyze_performance():
    """Filtra e salva i dati delle risorse relativi al periodo di test."""
    print("Analisi delle prestazioni...")
    s, e = analyze_logs()
    if not s or not e: 
        print("ERRORE: Intervallo di test non disponibile.")
        return

    data = [d for d in load_resource_data() if s <= d["timestamp"] <= e]
    if not data:
        print("ERRORE: Nessun dato di monitoraggio nel periodo di test.")
        return

    try:
        with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["Timestamp", "CPU (%)", "Mem (MB)", "Bytes Sent", "Bytes Recv", "Conn Attive"])
            w.writerows([[d["timestamp"], d["cpu"], d["memory"], d["bytes_sent"], d["bytes_received"], d["active_connections"]] for d in data])
        print(f"Salvati {len(data)} campionamenti in {OUTPUT_FILE}.")
    except Exception as e:
        print(f"ERRORE nel salvataggio dati: {e}")

if __name__ == "__main__":
    try: 
        monitor_resources()  # Avvia monitoraggio
        analyze_performance()  # Analizza prestazioni
    except Exception as e: 
        print(f"ERRORE GENERALE: {e}")  # Gestione errori
