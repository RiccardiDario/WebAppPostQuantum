import subprocess
import time
import os
import re

# Numero di test da eseguire
NUM_RUNS = 3

# Directory base relativa (assumendo che lo script sia in WebAppPostQuantum/)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(BASE_DIR, "report", "filtered_logs")

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

# Assicuriamoci che la cartella esista prima di partire
ensure_output_directory()

for i in range(1, NUM_RUNS + 1):
    print(f"\n🚀 Avvio test numero {i}...")

    # Trovare l'indice dell'ultimo file numerato prima di avviare il test
    last_file_index = get_latest_file_index()
    print(f"🔍 Ultimo file rilevato: {FILE_PREFIX}{last_file_index}.csv (se esiste)")

    # Avvia i container con Docker Compose
    subprocess.run(["docker-compose", "up", "--build", "-d"], check=True)

    # Attende che venga generato il nuovo file di monitoraggio
    print(f"⌛ In attesa della generazione del file {FILE_PREFIX}{last_file_index + 1}.csv...")
    while True:
        current_file_index = get_latest_file_index()
        if current_file_index > last_file_index:
            print(f"✅ File rilevato: {FILE_PREFIX}{current_file_index}.csv")
            break
        time.sleep(2)  # Controllo ogni 2 secondi

    # Arresta i container dopo il test
    print(f"🛑 Fermando i container dopo il test numero {i}...")
    subprocess.run(["docker-compose", "down"], check=True)

    # Pausa tra un'esecuzione e l'altra per evitare errori di misurazione
    if i < NUM_RUNS:
        print("⏳ Attesa di 10 secondi prima del prossimo test...")
        time.sleep(10)

print("\n🎉 Tutti i test sono stati completati con successo!")
