# Configurazioni da testare
#sig_list = ["ecdsa_p256", "mldsa44", "p256_mldsa44"]
#kem_list = ["secp256r1", "mlkem512", "p256_mlkem512"]

#sig_list = ["ecdsa_p384", "mldsa65", "p384_mldsa65"]
#kem_list = ["secp384r1", "mlkem768", "p384_mlkem768"]

#sig_list = ["ecdsa_p521", "mldsa87", "p521_mldsa87"]
#kem_list = ["secp521r1", "mlkem1024","p521_mlkem1024"]
import subprocess, time, re, os, random, csv, pandas as pd
from collections import defaultdict

sig_list = ["ecdsa_p521", "mldsa87", "p521_mldsa87"]
kem_list = ["secp521r1", "mlkem1024", "p521_mlkem1024"]
NUM_RUNS, TIMEOUT, SLEEP = 3, 300, 2
CLIENT, SERVER = "client_analysis", "nginx_pq"
CLIENT_DONE = r"\[INFO\] Test completato in .* Report: /app/output/request_logs/request_client\d+\.csv"
SERVER_DONE = r"--- Informazioni RAM ---"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
START_CLIENT_PATH = os.path.join(BASE_DIR, "client", "start_client.py")
ENV_PATH = os.path.join(BASE_DIR, "cert-generator", ".env")
input_folder = os.path.join(BASE_DIR, "report", "request_logs")
output_csv = os.path.join(input_folder, "avg", "average_metrics_per_request.csv")

def get_kem_sig_from_file(filepath):
    try:
        df = pd.read_csv(filepath)
        df = df[df["Status"] == "Success"]
        kem = df["KEM"].dropna().mode()[0]
        sig = df["Signature"].dropna().mode()[0]
        return kem.strip(), sig.strip()
    except Exception as e:
        print(f"Errore durante l'estrazione di KEM/SIG da {filepath}: {e}")
        return "Unknown", "Unknown"

def group_request_files_by_kem_sig(folder):
    grouped = defaultdict(list)
    for file in sorted(f for f in os.listdir(folder) if os.path.isfile(os.path.join(folder, f))):
        if file.startswith("request_client") and file.endswith(".csv"):
            path = os.path.join(folder, file)
            kem, sig = get_kem_sig_from_file(path)
            if kem != "Unknown" and sig != "Unknown":
                grouped[(kem, sig)].append(path)

    # Mantieni solo i gruppi con almeno 10 file
    return {k: v for k, v in grouped.items() if len(v) >= 3}

def generate_average_metrics_per_request(kem, sig, files, output_csv):
    dfs = [pd.read_csv(f).sort_values("Request_Number").reset_index(drop=True) for f in files[:3]]
    metric_cols = ["Connect_Time(ms)", "TLS_Handshake(ms)", "Total_Time(ms)", "Elapsed_Time(ms)", "Cert_Size(B)"]
    result_rows = []
    for i in range(len(dfs[0])):
        avg_row = sum(df.loc[i, metric_cols].values for df in dfs) / len(dfs)
        result_rows.append([kem, sig] + avg_row.tolist())

    file_exists = os.path.exists(output_csv)
    with open(output_csv, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(["KEM", "Signature", "Avg_Connect_Time(ms)", "Avg_Handshake_Time(ms)",
                             "Avg_Total_Time(ms)", "Avg_Elapsed_Time(ms)", "Avg_Cert_Size(B)"])
        writer.writerows(result_rows)

    print(f"✅ Aggiunte {len(result_rows)} righe ad average_metrics_per_request.csv per {kem} - {sig}")

def process_all_batches_for_avg_per_request(input_folder, output_csv):
    grouped_files = group_request_files_by_kem_sig(input_folder)
    for (kem, sig), file_list in grouped_files.items():
        generate_average_metrics_per_request(kem, sig, file_list, output_csv)

def run_subprocess(cmd, timeout=None):
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="replace")
        stdout, stderr = proc.communicate(timeout=timeout)
        return proc.returncode, stdout, stderr
    except subprocess.TimeoutExpired:
        proc.terminate()
        try: proc.wait(timeout=2)
        except subprocess.TimeoutExpired: proc.kill()
        return -1, "", "⏱️ Timeout"

def check_logs(container, pattern):
    code, out, err = run_subprocess(["docker", "logs", "--tail", "100", container], timeout=5)
    return re.search(pattern, out) is not None if out else False

def update_kem(kem):
    with open(START_CLIENT_PATH, "r", encoding="utf-8") as f:
        content = re.sub(r'("--curves",\s*")[^"]+(")', f'\\1{kem}\\2', f.read())
    with open(START_CLIENT_PATH, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"✅ KEM: {kem}")

def update_sig(sig):
    with open(ENV_PATH, "r", encoding="utf-8") as f:
        lines = [f"SIGNATURE_ALGO={sig}\n" if l.startswith("SIGNATURE_ALGO=") else l for l in f]
    with open(ENV_PATH, "w", encoding="utf-8") as f:
        f.writelines(lines)
    print(f"✅ Signature: {sig}")

def run_single_test(i):
    print(f"\n🚀 Test {i}")
    code, _, err = run_subprocess(["docker-compose", "up", "-d"], timeout=30)
    if code != 0:
        print(f"❌ Errore: {err}")
        return
    print("⌛ In attesa log...")
    start = time.time()
    while time.time() - start < TIMEOUT:
        if check_logs(CLIENT, CLIENT_DONE) and check_logs(SERVER, SERVER_DONE):
            print(f"✅ Completato.")
            break
        time.sleep(SLEEP)
    else:
        print(f"⚠️ Timeout dopo {TIMEOUT}s.")
    print("🛑 Arresto container...")
    run_subprocess(["docker-compose", "down"], timeout=30)
    print("🧹 Cleanup volumi...")
    for v in ["webapppostquantum_certs", "webapppostquantum_pcap", "webapppostquantum_tls_keys"]:
        run_subprocess(["docker", "volume", "rm", "-f", v])
    if i < NUM_RUNS:
        time.sleep(SLEEP)

def run_all_tests_randomized():
    plan = [(i, j) for i in range(len(kem_list)) for j in range(1, NUM_RUNS + 1)]
    random.shuffle(plan)
    last_kem, last_sig = None, None
    for scenario_idx, replica in plan:
        kem, sig = kem_list[scenario_idx], sig_list[scenario_idx]
        print(f"\n🔀 Scenario: {kem} + {sig} | Replica: {replica}")
        if kem != last_kem: update_kem(kem); last_kem = kem
        if sig != last_sig: update_sig(sig); last_sig = sig
        run_single_test(replica)
    print("\n🎉 Tutti i test completati!")

if __name__ == "__main__":
    #run_all_tests_randomized()
    print(f"\n📊 Generazione medie e grafici per tutti i batch completati...")
    process_all_batches_for_avg_per_request(input_folder, output_csv)

