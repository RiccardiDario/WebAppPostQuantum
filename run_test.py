import subprocess
import time
import re

# Numero di test da eseguire
NUM_RUNS = 5
TIMEOUT_SECONDS = 300
SLEEP_INTERVAL = 2

# Nomi reali dei container
CONTAINER_CLIENT = "client_analysis"
CONTAINER_SERVER = "nginx_pq"

# Pattern univoci che indicano la fine dell’esecuzione
CLIENT_DONE_PATTERN = r"\[INFO\] Test completato in .* Report: /app/output/request_logs/request_client\d+\.csv"
SERVER_DONE_PATTERN = r"--- Informazioni RAM ---"

def check_logs_for_completion(container_name, pattern):
    """Controlla i log recenti del container per la presenza del pattern specificato."""
    log_command = ["docker", "logs", "--tail", "100", container_name]
    
    try:
        result = subprocess.run(log_command, capture_output=True, text=True, timeout=5)
        logs = result.stdout
        return re.search(pattern, logs) is not None
    except subprocess.TimeoutExpired:
        print(f"⚠️ Timeout nella lettura dei log di {container_name}.")
        return False

for i in range(1, NUM_RUNS + 1):
    print(f"\n🚀 Avvio test numero {i}...")

    subprocess.run(["docker-compose", "up", "--build", "-d"], check=True)
    print(f"⌛ Attesa completamento log dei container...")

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

print("\n🎉 Tutti i test completati con successo!")
