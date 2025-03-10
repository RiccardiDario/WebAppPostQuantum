import subprocess
import time
import os
import re

# Numero di test da eseguire
NUM_RUNS = 3
TIMEOUT_SECONDS = 300  # Massimo tempo d'attesa per la generazione dei file

# Directory dei log e dei report
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(BASE_DIR, "report", "filtered_logs")
GRAPH_DIR = os.path.join(BASE_DIR, "report", "request_logs", "graphs")  # Cartella dei grafici

FILE_PREFIX = "monitor_nginx_filtered"
FILE_EXTENSION = ".csv"

def ensure_output_directory():
    """Crea la cartella di output se non esiste"""
    if not os.path.exists(OUTPUT_DIR):
        print(f"📂 Creazione cartella: {OUTPUT_DIR}")
        os.makedirs(OUTPUT_DIR)

def get_latest_file_index():
    """Trova l'ultimo file numerato di monitor_nginx_filtered.csv, se esiste"""
    if not os.path.exists(OUTPUT_DIR):
        return 0  # Nessun file trovato perché la cartella non esiste ancora

    existing_files = [f for f in os.listdir(OUTPUT_DIR) if f.startswith(FILE_PREFIX) and f.endswith(FILE_EXTENSION)]
    numbers = [int(re.search(r"(\d+)", f).group(1)) for f in existing_files if re.search(r"(\d+)", f)]
    
    return max(numbers) if numbers else 0  # Restituisce 0 se nessun file è presente

def check_last_graph_exists():
    """Verifica se l'ultimo boxplot generato esiste nella cartella dei grafici."""
    metrics = ["Connect_Time(ms)", "TLS_Handshake(ms)", "Total_Time(ms)", "Elapsed_Time(ms)"]
    last_graph_path = os.path.join(GRAPH_DIR, f"{metrics[-1]}_cumulative_boxplot.png")  # Ultimo grafico atteso

    return os.path.exists(last_graph_path)

# Assicuriamoci che le cartelle esistano prima di partire
ensure_output_directory()

for i in range(1, NUM_RUNS + 1):
    print(f"\n🚀 Avvio test numero {i}...")

    # Trova l'ultimo file numerato prima di avviare il test
    last_file_index = get_latest_file_index()
    print(f"🔍 Ultimo file di monitor rilevato: {FILE_PREFIX}{last_file_index}.csv (se esiste)")

    # Avvia i container con Docker Compose
    subprocess.run(["docker-compose", "up", "--build", "-d"], check=True)

    print(f"⌛ In attesa che il file {FILE_PREFIX}{last_file_index + 1}.csv venga generato...")

    start_time = time.time()

    while True:
        # Controlliamo se il file di monitor è stato aggiornato
        current_file_index = get_latest_file_index()

        # Se il file è stato aggiornato, possiamo procedere
        if current_file_index > last_file_index:
            print(f"✅ Il file {FILE_PREFIX}{current_file_index}.csv è stato generato.")
            break

        # Controllo timeout per evitare blocchi infiniti
        if time.time() - start_time > TIMEOUT_SECONDS:
            print(f"⚠️ Timeout raggiunto ({TIMEOUT_SECONDS} sec), fermo i container.")
            break

        time.sleep(2)  # Controllo ogni 2 secondi

    # **Solo alla terza iterazione, controlliamo se il grafico finale è stato generato**
    if i == 3:
        print("⌛ Controllo la generazione dell'ultimo boxplot prima di fermare i container...")

        start_time = time.time()
        while True:
            if check_last_graph_exists():
                print(f"✅ Ultimo grafico rilevato correttamente in {GRAPH_DIR}")
                break

            # Controllo timeout per evitare blocchi infiniti
            if time.time() - start_time > TIMEOUT_SECONDS:
                print(f"⚠️ Timeout raggiunto ({TIMEOUT_SECONDS} sec), il grafico non è stato trovato.")
                break

            time.sleep(2)  # Controllo ogni 2 secondi

    # Arresta i container dopo il test
    print(f"🛑 Fermando i container dopo il test numero {i}...")
    subprocess.run(["docker-compose", "down"], check=True)

    # Pausa tra un'esecuzione e l'altra per evitare errori di misurazione
    if i < NUM_RUNS:
        print("⏳ Attesa di 10 secondi prima del prossimo test...")
        time.sleep(2)

print("\n🎉 Tutti i test sono stati completati con successo!")
