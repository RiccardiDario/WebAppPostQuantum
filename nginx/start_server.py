import psutil, csv, time, os  # Import librerie necessarie
from datetime import datetime  # Rimosso UTC per evitare offset-aware datetimes

def get_next_filename(base_path, base_name, extension):
    """Genera il nome del file con numerazione incrementale."""
    counter = 1
    while os.path.exists(f"{base_path}/{base_name}{counter}.{extension}"):
        counter += 1
    return f"{base_path}/{base_name}{counter}.{extension}", counter

# Definizione delle cartelle di output
OUTPUT_DIR = "/opt/nginx/output"
RESOURCE_LOG_DIR = f"{OUTPUT_DIR}/resource_logs"
FILTERED_LOG_DIR = f"{OUTPUT_DIR}/filtered_logs"
os.makedirs(RESOURCE_LOG_DIR, exist_ok=True)
os.makedirs(FILTERED_LOG_DIR, exist_ok=True)

# Generazione nomi file con numerazione incrementale
RESOURCE_LOG, _ = get_next_filename(RESOURCE_LOG_DIR, "monitor_nginx", "csv")
OUTPUT_FILE, _ = get_next_filename(FILTERED_LOG_DIR, "monitor_nginx_filtered", "csv")

ACCESS_LOG = "/opt/nginx/logs/access_custom.log"
EXPECTED_REQUESTS, SAMPLING_INTERVAL = 400, 0.1  # Soglia richieste e intervallo di campionamento

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

            unix_time = time.time()  # Timestamp UNIX con precisione millisecondo
            readable_time = datetime.fromtimestamp(unix_time).strftime("%d/%b/%Y:%H:%M:%S.%f")[:-3]  # Formato leggibile senza fuso orario
            cpu, mem = psutil.cpu_percent(None), psutil.virtual_memory().used / (1024 ** 2)
            net, conns = psutil.net_io_counters(), len([c for c in psutil.net_connections("inet") if c.status == "ESTABLISHED"])
            w.writerow([readable_time, cpu, mem, net.bytes_sent, net.bytes_recv, conns]), f.flush()

            print(f"{readable_time} - CPU: {cpu}%, Mem: {mem}MB, Sent: {net.bytes_sent}, Recv: {net.bytes_recv}, Conn: {conns}")
            time.sleep(SAMPLING_INTERVAL)

def analyze_logs():
    """Analizza i log Nginx per determinare l'intervallo di test."""
    print(f"Analisi del log: {ACCESS_LOG}")
    
    if not os.path.exists(ACCESS_LOG): 
        print("ERRORE: File log non trovato.")
        return None, None

    try:
        timestamps = []
        
        with open(ACCESS_LOG, encoding="utf-8") as f:
            for line in f:
                parts = line.split()
                if len(parts) < 4:
                    continue  # Salta righe non valide
                
                try:
                    raw_timestamp = parts[3][1:-1]  # Rimuove le []
                    unix_time = float(raw_timestamp)  # Converte in float per mantenere i millisecondi
                    timestamps.append(datetime.fromtimestamp(unix_time))  # Ora senza fuso orario
                except ValueError:
                    print(f"Errore parsing timestamp: {parts[3]}")
                    continue

        if not timestamps:
            print("ERRORE: Nessun timestamp trovato nei log.")
            return None, None

        print(f"Intervallo richieste: {min(timestamps)} - {max(timestamps)}")
        return min(timestamps), max(timestamps)

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
            data = []
            reader = csv.DictReader(f)
            for row in reader:
                try:
                    readable_time = row["Timestamp"]  # Ora il CSV contiene solo timestamp leggibili
                    data.append({
                        "timestamp": datetime.strptime(readable_time, "%d/%b/%Y:%H:%M:%S.%f").replace(tzinfo=None),  # Rimuove fuso orario
                        "cpu": float(row["CPU (%)"]),
                        "memory": float(row["Mem (MB)"]),
                        "bytes_sent": int(row["Bytes Sent"]),
                        "bytes_received": int(row["Bytes Recv"]),
                        "active_connections": int(row["Conn Attive"]),
                    })
                except ValueError:
                    print(f"Errore parsing riga: {row}")
                    continue

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
            w.writerows([[d["timestamp"].strftime("%d/%b/%Y:%H:%M:%S.%f")[:-3], d["cpu"], d["memory"], d["bytes_sent"], d["bytes_received"], d["active_connections"]] for d in data])
        print(f"Salvati {len(data)} campionamenti in {OUTPUT_FILE}.")
    except Exception as e:
        print(f"ERRORE nel salvataggio dati: {e}")

if __name__ == "__main__":
    try: 
        monitor_resources()  # Avvia monitoraggio
        analyze_performance()  # Analizza prestazioni
    except Exception as e: 
        print(f"ERRORE GENERALE: {e}")  # Gestione errori
