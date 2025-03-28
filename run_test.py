# Configurazioni da testare
#sig_list = ["ecdsa_p256", "mldsa44", "p256_mldsa44", "ecdsa_p384", "mldsa65", "p384_mldsa65", "ecdsa_p521", "mldsa87", "p521_mldsa87"]
#kem_list = ["secp256r1", "mlkem512", "p256_mlkem512", "secp384r1", "mlkem768", "p384_mlkem768", "secp521r1", "mlkem1024","p521_mlkem1024"]

import subprocess, time, re, os

sig_list = ["ecdsa_p256", "mldsa44", "p256_mldsa44", "ecdsa_p384", "mldsa65", "p384_mldsa65", "ecdsa_p521", "mldsa87", "p521_mldsa87"]
kem_list = ["secp256r1", "mlkem512", "p256_mlkem512", "secp384r1", "mlkem768", "p384_mlkem768", "secp521r1", "mlkem1024","p521_mlkem1024"]
NUM_RUNS, TIMEOUT, SLEEP = 5, 300, 2
CLIENT, SERVER = "client_analysis", "nginx_pq"
CLIENT_DONE = r"\[INFO\] Test completato in .* Report: /app/output/request_logs/request_client\d+\.csv"
SERVER_DONE = r"--- Informazioni RAM ---"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
START_CLIENT_PATH = os.path.join(BASE_DIR, "client", "start_client.py")
ENV_PATH = os.path.join(BASE_DIR, "cert-generator", ".env")


def run_subprocess(command, timeout=None):
    """Esegue un comando e forza la chiusura del processo"""
    try:
        proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="replace")
        stdout, stderr = proc.communicate(timeout=timeout)
        return proc.returncode, stdout, stderr
    except subprocess.TimeoutExpired:
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()
        return -1, "", "⏱️ Timeout scaduto. Processo terminato forzatamente."

def check_logs(container, pattern):
    code, stdout, stderr = run_subprocess(["docker", "logs", "--tail", "100", container], timeout=5)
    if stdout:
        return re.search(pattern, stdout) is not None
    return False


def update_kem(kem):
    with open(START_CLIENT_PATH, "r", encoding="utf-8") as f:
        content = re.sub(r'("--curves",\s*")[^"]+(")', f'\\1{kem}\\2', f.read())
    with open(START_CLIENT_PATH, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"✅ KEM aggiornato: {kem}")


def update_sig(sig):
    with open(ENV_PATH, "r", encoding="utf-8") as f:
        lines = [f"SIGNATURE_ALGO={sig}\n" if l.startswith("SIGNATURE_ALGO=") else l for l in f]
    with open(ENV_PATH, "w", encoding="utf-8") as f:
        f.writelines(lines)
    print(f"✅ Signature aggiornata: {sig}")


def run_single_test(i):
    print(f"\n🚀 Test {i} in corso...")

    # Avvio container
    code, _, err = run_subprocess(["docker-compose", "up", "-d"], timeout=30)
    if code != 0:
        print(f"❌ Errore avvio container: {err}")
        return

    print("⌛ In attesa completamento log...")

    start = time.time()
    while time.time() - start < TIMEOUT:
        if check_logs(CLIENT, CLIENT_DONE) and check_logs(SERVER, SERVER_DONE):
            print(f"✅ Test {i} completato.")
            break
        time.sleep(SLEEP)
    else:
        print(f"⚠️ Timeout test {i} dopo {TIMEOUT} secondi.")

    print("🛑 Arresto container...")
    run_subprocess(["docker-compose", "down"], timeout=30)

    print("🧹 Rimozione volumi specifici...")
    for volume in ["webapppostquantum_certs", "webapppostquantum_pcap", "webapppostquantum_tls_keys"]:
        run_subprocess(["docker", "volume", "rm", "-f", volume])

    if i < NUM_RUNS:
        time.sleep(SLEEP)


# Esecuzione principale
for kem, sig in zip(kem_list, sig_list):
    print(f"\n🔁 Inizio test per KEM: {kem}, Signature: {sig}")
    update_kem(kem)
    update_sig(sig)

    for i in range(1, NUM_RUNS + 1):
        run_single_test(i)

print("\n🎉 Tutti i test completati con successo!")
