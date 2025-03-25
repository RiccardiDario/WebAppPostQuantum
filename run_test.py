import subprocess, time, re, os
# Configurazioni da testare
#sig_list = [ "ecdsa_p256", "ecdsa_p384", "ecdsa_p521", "mldsa44", "mldsa65", "mldsa87", "p256_mldsa44", "p384_mldsa65", "p521_mldsa87"]
#kem_list = ["secp256r1", "secp384r1", "secp521r1", "mlkem512", "mlkem768", "mlkem1024","p256_mlkem512", "p384_mlkem768", "p521_mlkem1024"]

kem_list = ["mlkem512"]
sig_list = ["mldsa44"]
NUM_RUNS, TIMEOUT, SLEEP = 5, 300, 2
CLIENT, SERVER = "client_analysis", "nginx_pq"
CLIENT_DONE = r"\[INFO\] Test completato in .* Report: /app/output/request_logs/request_client\d+\.csv"
SERVER_DONE = r"--- Informazioni RAM ---"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
START_CLIENT_PATH = os.path.join(BASE_DIR, "client", "start_client_serie.py")
ENV_PATH = os.path.join(BASE_DIR, "cert-generator", ".env")

def check_logs(container, pattern):
    try:
        out = subprocess.run(["docker", "logs", "--tail", "100", container], capture_output=True, text=True, timeout=5)
        return re.search(pattern, out.stdout) is not None
    except subprocess.TimeoutExpired:
        print(f"⚠️ Timeout nella lettura dei log di {container}."); return False

def update_kem(kem):
    with open(START_CLIENT_PATH, "r", encoding="utf-8") as f:
        content = re.sub(r'("--curves",\s*")[^"]+(")', f'\\1{kem}\\2', f.read())
    with open(START_CLIENT_PATH, "w", encoding="utf-8") as f: f.write(content)
    print(f"✅ KEM aggiornato: {kem}")

def update_sig(sig):
    with open(ENV_PATH, "r", encoding="utf-8") as f:
        lines = [f"SIGNATURE_ALGO={sig}\n" if l.startswith("SIGNATURE_ALGO=") else l for l in f]
    with open(ENV_PATH, "w", encoding="utf-8") as f: f.writelines(lines)
    print(f"✅ Signature aggiornata: {sig}")

# Esecuzione batch
for kem, sig in zip(kem_list, sig_list):
    print(f"\n🔁 Batch con KEM: {kem}, Signature: {sig}")
    update_kem(kem); update_sig(sig)

    for i in range(1, NUM_RUNS + 1):
        print(f"\n🚀 Test {i} in corso...")
        subprocess.run(["docker-compose", "up", "--force-recreate", "-d"], check=True)
        print("⌛ Attesa log container...")

        start = time.time()
        while time.time() - start < TIMEOUT:
            if check_logs(CLIENT, CLIENT_DONE) and check_logs(SERVER, SERVER_DONE):
                print(f"✅ Test {i} completato."); break
            time.sleep(SLEEP)
        else:
            print(f"⚠️ Timeout ({TIMEOUT}s).")

        print("🛑 Arresto container...")
        subprocess.run(["docker-compose", "down"], check=True)
        if i < NUM_RUNS:
            print("⏳ Pausa..."); time.sleep(SLEEP)

print("\n🎉 Tutti i batch completati con successo!")
