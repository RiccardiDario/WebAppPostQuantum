# Configurazioni da testare
#sig_list = ["ecdsa_p256", "mldsa44", "p256_mldsa44"]
#kem_list = ["secp256r1", "mlkem512", "p256_mlkem512"]

#sig_list = ["ecdsa_p384", "mldsa65", "p384_mldsa65"]
#kem_list = ["secp384r1", "mlkem768", "p384_mlkem768"]

#sig_list = ["ecdsa_p521", "mldsa87", "p521_mldsa87"]
#kem_list = ["secp521r1", "mlkem1024","p521_mlkem1024"]
import subprocess, psutil, time, math, re, os, random, csv, pandas as pd, numpy as np, matplotlib.pyplot as plt
from collections import defaultdict

sig_list = ["ecdsa_p521", "mldsa87", "p521_mldsa87"]
kem_list = ["secp521r1", "mlkem1024", "p521_mlkem1024"]
NUM_RUNS, TIMEOUT, SLEEP = 3, 300, 2
CLIENT, SERVER = "client_analysis", "nginx_pq"
CLIENT_DONE = r"\[INFO\] Test completato in .* Report: /app/output/request_logs/request_client\d+\.csv"
SERVER_DONE = r"--- Informazioni RAM ---"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
START_CLIENT_PATH = os.path.join(BASE_DIR, "client/start_client.py")
ENV_PATH = os.path.join(BASE_DIR, "cert-generator/.env")
output_csv = os.path.join(BASE_DIR, "report/request_logs/avg/average_metrics_per_request.csv")
GRAPH_DIR = os.path.join(BASE_DIR, "report/graph")
FILTERED_LOG_DIR= os.path.join(BASE_DIR, "report/filtered_logs")
input_folder = os.path.join(BASE_DIR, "report", "request_logs")
os.makedirs(GRAPH_DIR, exist_ok=True)
os.makedirs(FILTERED_LOG_DIR, exist_ok=True)

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

def generate_graphs_from_average_per_request():
    file_path = output_csv
    if not os.path.exists(file_path):
        logging.warning("File average_metrics_per_request.csv non trovato.")
        return

    df = pd.read_csv(file_path)
    if df.empty:
        logging.warning("Il file delle medie per richiesta è vuoto.")
        return

    requests_per_batch, requests_per_plot = 500, 100
    total_batches = len(df) // requests_per_batch
    batch_labels, boxplot_data = [], {k: [] for k in [
        "Avg_Connect_Time(ms)",
        "Avg_Handshake_Time(ms)",
        "Avg_Total_Time(ms)",
        "Avg_Elapsed_Time(ms)"
    ]}

    for b in range(total_batches):
        df_batch = df.iloc[b * requests_per_batch:(b + 1) * requests_per_batch]
        kem, sig = df_batch["KEM"].iloc[0], df_batch["Signature"].iloc[0]
        cert_size = int(df_batch["Avg_Cert_Size(B)"].iloc[0])
        batch_labels.append(f"{kem}\n{sig}\n{cert_size} B")
        for m in boxplot_data:
            boxplot_data[m].append(df_batch[m].tolist())

        for i in range(0, requests_per_batch, requests_per_plot):
            df_subset = df_batch.iloc[i:i + requests_per_plot].reset_index(drop=True)
            x = list(range(i + 1, i + 1 + len(df_subset)))
            cert_str = f"{cert_size:.2f} B"

            # Elapsed Time
            plt.figure(figsize=(10, 5))
            plt.plot(x, df_subset["Avg_Elapsed_Time(ms)"], marker='o', linestyle='-', color='blue', label="Elapsed Time (ms)")
            plt.xlabel("Request Completion Order")
            plt.ylabel("Elapsed Time (ms)")
            plt.title(f"Elapsed Time per Request\nKEM: {kem} | Signature: {sig}")
            plt.legend(title=f"Certificate Size: {cert_str}")
            plt.grid(True)
            plt.tight_layout()
            plt.savefig(os.path.join(GRAPH_DIR, f"elapsed_time_graph_batch_{b+1}_{x[0]}_{x[-1]}.png"))
            plt.close()

            # TLS Breakdown
            connect = df_subset["Avg_Connect_Time(ms)"]
            handshake = df_subset["Avg_Handshake_Time(ms)"] - connect
            total = df_subset["Avg_Total_Time(ms)"] - df_subset["Avg_Handshake_Time(ms)"]
            plt.figure(figsize=(14, 7))
            plt.bar(x, connect, label="Connect Time", color="red", alpha=0.7)
            plt.bar(x, handshake, bottom=connect, label="TLS Handshake Time", color="orange", alpha=0.7)
            plt.bar(x, total, bottom=df_subset["Avg_Handshake_Time(ms)"], label="Total Time", color="gray", alpha=0.7)
            plt.xlabel("Request Completion Order")
            plt.ylabel("Time (ms)")
            plt.title(f"Timing Breakdown for TLS Connections\nKEM: {kem} | Signature: {sig}")
            plt.legend(title=f"Certificate Size: {cert_str}")
            plt.grid(axis="y", linestyle="--", alpha=0.7)
            plt.tight_layout()
            plt.savefig(os.path.join(GRAPH_DIR, f"tls_avg_graph_batch_{b+1}_{x[0]}_{x[-1]}.png"), dpi=300)
            plt.close()

        # Boxplot segmentati ogni 3 batch
    max_per_image = 3
    whis_val = 4.0
    perc_limit = 99

    for metric, ylabel in {
        "Avg_Connect_Time(ms)": "Connect Time (ms)",
        "Avg_Handshake_Time(ms)": "Handshake Time (ms)",
        "Avg_Total_Time(ms)": "Total Time (ms)",
        "Avg_Elapsed_Time(ms)": "Elapsed Time (ms)"
    }.items():
        num_images = math.ceil(len(batch_labels) / max_per_image)
        for img_index in range(num_images):
            start_idx = img_index * max_per_image
            end_idx = min((img_index + 1) * max_per_image, len(batch_labels))
            data_subset = boxplot_data[metric][start_idx:end_idx]
            labels_subset = batch_labels[start_idx:end_idx]

            fig = plt.figure(figsize=(max(6, len(labels_subset) * 1.8), 6))
            ax = fig.add_axes([0.1, 0.15, 0.8, 0.75])

            # widths non impostato: torna al default
            bp = ax.boxplot(data_subset, patch_artist=True, whis=whis_val,
                            boxprops=dict(facecolor='lightblue', alpha=0.7, edgecolor='black', linewidth=1.5),
                            whiskerprops=dict(color='black', linewidth=2),
                            capprops=dict(color='black', linewidth=2),
                            medianprops=dict(color='red', linewidth=2),
                            flierprops=dict(marker='o', color='black', markersize=6, alpha=0.6))

            # Espansione verticale intelligente
            flat_data = [item for sublist in data_subset for item in sublist]
            if flat_data:
                perc_y = np.percentile(flat_data, perc_limit)
                box_stats = [
                    np.percentile(b, 75) + whis_val * (np.percentile(b, 75) - np.percentile(b, 25))
                    for b in data_subset
                ]
                y_max = max(perc_y, max(box_stats))
                y_min = min(min(b) for b in data_subset)
                y_margin = (y_max - y_min) * 0.2  # espande sopra e sotto del 20%
                ax.set_ylim(max(0, y_min - y_margin), y_max + y_margin)

                # Annotazioni outlier
                for idx, single_box in enumerate(data_subset):
                    threshold = np.percentile(single_box, perc_limit)
                    num_outliers = sum(val > threshold for val in single_box)
                    if num_outliers > 0:
                        ax.annotate(f"+{num_outliers} outlier",
                                    xy=(idx + 1, y_max + y_margin * 0.1),
                                    ha='center', fontsize=8, color='gray')

            ax.set_title(ylabel)
            ax.set_ylabel(ylabel)
            ax.set_xticks(range(1, len(labels_subset) + 1))
            ax.set_xticklabels(labels_subset, rotation=30, ha="right")
            ax.set_xlim(0.5, len(labels_subset) + 0.5)

            plot_filename = f"{ylabel.replace(' ', '_')}_boxplot_part{img_index + 1}.png"
            plt.savefig(os.path.join(GRAPH_DIR, plot_filename), dpi=300)
            plt.close(fig)

def generate_server_performance_graphs():
    print("📈 Generazione grafici performance server per ogni coppia KEM/Signature...")
    
    # Raggruppamento per (KEM, Signature)
    grouped_files = defaultdict(list)
    for file in os.listdir(FILTERED_LOG_DIR):
        if file.startswith("monitor_nginx_filtered") and file.endswith(".csv"):
            full_path = os.path.join(FILTERED_LOG_DIR, file)
            kem, sig = get_kem_sig_from_monitor_file(full_path)
            if kem != "Unknown" and sig != "Unknown":
                grouped_files[(kem, sig)].append(full_path)

    for (kem, sig), file_list in grouped_files.items():
        if len(file_list) < 3:
            print(f"⏭️ Salto {kem} + {sig} (solo {len(file_list)} file)")
            continue

        output_path = os.path.join(GRAPH_DIR, f"server_cpu_memory_usage_{kem}_{sig}.png".replace("/", "_"))
        if os.path.exists(output_path):
            print(f"📁 Già esistente: {output_path}, salto.")
            continue

        dfs = []
        for f in file_list[:3]:
            try:
                df = pd.read_csv(f)
                df["Timestamp"] = pd.to_datetime(df["Timestamp"], format="%d/%b/%Y:%H:%M:%S.%f")
                dfs.append(df)
            except Exception as e:
                print(f"⚠️ Errore nel parsing di {f}: {e}")

        if len(dfs) < 3:
            print(f"⚠️ File validi insufficienti per {kem} + {sig}, salto.")
            continue

        # Trova intervallo minimo per allineare i dataframe
        min_range = min((df["Timestamp"].max() - df["Timestamp"].min()).total_seconds() for df in dfs)

        df_monitor_avg = pd.concat([
            df[df["Timestamp"] <= df["Timestamp"].min() + pd.Timedelta(seconds=min_range)]
            .assign(Index=(df["Timestamp"] - df["Timestamp"].min()).dt.total_seconds() // 0.1)
            .groupby("Index")[["CPU (%)", "Mem (%)"]].mean().reset_index()
            for df in dfs
        ]).groupby("Index")[["CPU (%)", "Mem (%)"]].mean().reset_index()

        time_ms = df_monitor_avg["Index"] * 100

        fig, ax = plt.subplots(figsize=(14, 7))
        ax.plot(time_ms, df_monitor_avg["CPU (%)"], label="CPU Usage (%)", color="red", marker="o")
        ax.plot(time_ms, df_monitor_avg["Mem (%)"], label="Memory Usage (%)", color="blue", marker="o")
        ax.set(xlabel="Time (ms)", ylabel="Usage (%)",
               title=f"Server Resource Usage Over Time\nKEM: {kem} | Signature: {sig}")
        ax.legend(title=f"KEM: {kem} | Signature: {sig}", loc="upper left", bbox_to_anchor=(1, 1))
        ax.grid(True, linestyle="--", alpha=0.7)
        fig.savefig(output_path, dpi=300, bbox_inches="tight")
        plt.close(fig)
        print(f"✅ Grafico generato: {output_path}")

def get_kem_sig_from_monitor_file(filepath):
    try:
        df = pd.read_csv(filepath)
        kem = df["KEM"].dropna().iloc[0]
        sig = df["Signature"].dropna().iloc[0]
        return kem.strip(), sig.strip()
    except Exception as e:
        print(f"Errore durante l'estrazione di KEM/SIG dal file di monitoraggio {filepath}: {e}")
        return "Unknown", "Unknown"

def generate_system_monitor_graph():
    monitor_folder = os.path.join(BASE_DIR, "report", "system_logs")
    output_folder = os.path.join(input_folder, "graphs")
    os.makedirs(output_folder, exist_ok=True)

    monitor_files = [
        os.path.join(monitor_folder, f) for f in os.listdir(monitor_folder)
        if f.startswith("system_client") and f.endswith(".csv")
    ]

    if not monitor_files:
        print("⚠️ Nessun file di monitoraggio trovato.")
        return

    # Raggruppa per (KEM, Signature)
    grouped_monitors = defaultdict(list)
    for path in monitor_files:
        try:
            df = pd.read_csv(path)
            kem = df["KEM"].dropna().iloc[0]
            sig = df["Signature"].dropna().iloc[0]
            grouped_monitors[(kem, sig)].append(df)
        except Exception as e:
            print(f"Errore durante la lettura di {path}: {e}")

    for (kem, sig), dfs in grouped_monitors.items():
        if len(dfs) < 3:
            print(f"⏭️ Non abbastanza file per {kem} + {sig} (trovati {len(dfs)})")
            continue

        # Troncamento minimo dei timestamp
        for df in dfs:
            df["Timestamp"] = pd.to_datetime(df["Timestamp"])
        min_range = min((df["Timestamp"].max() - df["Timestamp"].min()).total_seconds() for df in dfs)

        df_monitor_avg = pd.concat([df[df["Timestamp"] <= df["Timestamp"].min() + pd.Timedelta(seconds=min_range)]
            .assign(Index=lambda x: (x["Timestamp"] - x["Timestamp"].min()).dt.total_seconds() // 0.1)
            .groupby("Index")[["CPU_Usage(%)", "Memory_Usage(%)"]].mean().reset_index()
            for df in dfs ]).groupby("Index")[["CPU_Usage(%)", "Memory_Usage(%)"]].mean().reset_index()

        x = (df_monitor_avg["Index"] * 100).tolist()  # in ms
        total_memory = psutil.virtual_memory().total / (1024 ** 2)
        total_cores = psutil.cpu_count(logical=True)

        # Generazione grafico
        plt.figure(figsize=(14, 6))
        plt.plot(x, df_monitor_avg["CPU_Usage(%)"], label="CPU Usage (%)", color="green", marker="o")
        plt.plot(x, df_monitor_avg["Memory_Usage(%)"], label="Memory Usage (%)", color="purple", marker="x")
        plt.xlabel("Time (ms)")
        plt.ylabel("Usage (%)")
        plt.title(f"CPU & RAM Usage Over Time\nKEM: {kem} | Signature: {sig}")
        plt.legend(
            title=f"Cores: {total_cores} | RAM: {total_memory:.1f} MB",
            loc="upper right"
        )
        plt.grid(True, linestyle="--", alpha=0.6)
        plt.tight_layout()

        filename = f"resource_usage_{kem}_{sig}".replace("/", "_").replace("\n", "_").strip() + ".png"
        plt.savefig(os.path.join(output_folder, filename), dpi=300)
        plt.close()
        print(f"✅ Grafico salvato: {filename}")

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
    generate_graphs_from_average_per_request()
    generate_system_monitor_graph()
    generate_server_performance_graphs()