import subprocess
import time
import re
import os

# Configurazioni da testare
kem_list = ["mlkem512", "mlkem1024"]
sig_list = ["mldsa65", "mldsa87"]

# Parametri dei test
NUM_RUNS = 5
TIMEOUT_SECONDS = 300
SLEEP_INTERVAL = 2

# Container coinvolti
CONTAINER_CLIENT = "client_analysis"
CONTAINER_SERVER = "nginx_pq"

# Pattern per determinare la fine dell'esecuzione
CLIENT_DONE_PATTERN = r"\[INFO\] Test completato in .* Report: /app/output/request_logs/request_client\d+\.csv"
SERVER_DONE_PATTERN = r"--- Informazioni RAM ---"

# Percorsi assoluti dei file da modificare
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
START_CLIENT_PATH = os.path.join(BASE_DIR, "client", "start_client_serie.py")
ENV_PATH = os.path.join(BASE_DIR, "cert-generator", ".env")

def check_logs_for_completion(container_name, pattern):
    """Controlla i log recenti del container per la presenza del pattern specificato."""
    try:
        result = subprocess.run(["docker", "logs", "--tail", "100", container_name],
                                capture_output=True, text=True, timeout=5)
        return re.search(pattern, result.stdout) is not None
    except subprocess.TimeoutExpired:
        print(f"⚠️ Timeout nella lettura dei log di {container_name}.")
        return False

def update_start_client_kem(kem):
    """Aggiorna il parametro --curves nel file start_client_serie.py per modificare il KEM."""
    with open(START_CLIENT_PATH, "r", encoding="utf-8") as f:
        content = f.read()
    # Regex per sostituire il secondo argomento della coppia "--curves", "..."
    new_content = re.sub(r'("--curves",\s*")[^"]+(")', f'\\1{kem}\\2', content)
    with open(START_CLIENT_PATH, "w", encoding="utf-8") as f:
        f.write(new_content)
    print(f"✅ [DEBUG] start_client_serie.py aggiornato con KEM: {kem}")

def update_env_signature(sig):
    """Aggiorna il valore SIGNATURE_ALGO nel file .env."""
    with open(ENV_PATH, "r", encoding="utf-8") as f:
        lines = f.readlines()
    with open(ENV_PATH, "w", encoding="utf-8") as f:
        for line in lines:
            if line.startswith("SIGNATURE_ALGO="):
                f.write(f"SIGNATURE_ALGO={sig}\n")
            else:
                f.write(line)
    print(f"✅ [DEBUG] .env aggiornato con Signature:{sig}")

# Esecuzione batch per ogni coppia KEM/Signature
for kem, sig in zip(kem_list, sig_list):
    print(f"\n🔁 Inizio nuovo batch con KEM:{kem}, Signature:{sig}")
    update_start_client_kem(kem)
    update_env_signature(sig)

    for i in range(1, NUM_RUNS + 1):
        print(f"\n🚀 Avvio test numero {i}...")

        subprocess.run(["docker-compose", "up", "--force-recreate", "-d"], check=True)
        print("⌛ Attesa completamento log dei container...")

        start_time = time.time()
        client_done = server_done = False

        while time.time() - start_time < TIMEOUT_SECONDS:
            if not client_done:
                client_done = check_logs_for_completion(CONTAINER_CLIENT, CLIENT_DONE_PATTERN)
            if not server_done:
                server_done = check_logs_for_completion(CONTAINER_SERVER, SERVER_DONE_PATTERN)

            if client_done and server_done:
                print(f"✅ Test {i} completato da entrambi i container.")
                break

            time.sleep(SLEEP_INTERVAL)
        else:
            print(f"⚠️ Timeout raggiunto ({TIMEOUT_SECONDS} sec). Arresto forzato.")

        print(f"🛑 Arresto dei container (test {i})...")
        subprocess.run(["docker-compose", "down"], check=True)

        if i < NUM_RUNS:
            print("⏳ Pausa di 2 secondi prima del test successivo...")
            time.sleep(2)

print("\n🎉 Tutti i batch completati con successo!")
