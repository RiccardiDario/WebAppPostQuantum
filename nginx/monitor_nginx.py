import psutil
import time
import subprocess
import csv
import os

def get_nginx_processes():
    """Ritorna una lista di oggetti Process relativi ai worker di Nginx."""
    nginx_processes = []
    for proc in psutil.process_iter(['name']):
        if proc.info['name'] == 'nginx':
            nginx_processes.append(proc)
    return nginx_processes

def get_network_bandwidth():
    """Ritorna l'uso di banda di rete (in byte/s)."""
    net_before = psutil.net_io_counters()
    time.sleep(1)
    net_after = psutil.net_io_counters()
    bandwidth_in = net_after.bytes_recv - net_before.bytes_recv
    bandwidth_out = net_after.bytes_sent - net_before.bytes_sent
    return bandwidth_in, bandwidth_out

def monitor_nginx(output_file="/opt/nginx/output/nginx_performance.csv", interval=5, duration=60):
    """Monitoraggio delle risorse di Nginx e salvataggio in un file CSV.

    Args:
        output_file (str): Nome del file CSV per salvare i risultati.
        interval (int): Intervallo tra una misurazione e l'altra (in secondi).
        duration (int): Durata del monitoraggio (in secondi).
    """
    os.makedirs(os.path.dirname(output_file), exist_ok=True)  # Crea la directory per il file di output, se necessario
    end_time = time.time() + duration

    with open(output_file, mode="w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(["Timestamp", "CPU_Usage", "Memory_Usage_MB", "Bandwidth_In_Bps", "Bandwidth_Out_Bps", "TLS_Handshakes", "Open_Connections"])

        while time.time() < end_time:
            nginx_processes = get_nginx_processes()

            # Calcola l'uso della CPU e della RAM
            total_cpu = sum(proc.cpu_percent(interval=0.1) for proc in nginx_processes)
            total_memory = sum(proc.memory_info().rss for proc in nginx_processes) / (1024 ** 2)  # Converti in MB

            # Calcola l'uso della banda di rete
            bandwidth_in, bandwidth_out = get_network_bandwidth()

            # Conteggia il numero di connessioni attive
            try:
                result = subprocess.run(["ss", "-s"], capture_output=True, text=True)
                open_connections = int([line for line in result.stdout.splitlines() if "estab" in line][0].split()[1])
            except Exception:
                open_connections = None

            # Conteggia i TLS handshakes dai log di Nginx
            tls_handshakes = None
            try:
                result = subprocess.run(["grep", "TLS handshake", "/opt/nginx/logs/access.log"], capture_output=True, text=True)
                tls_handshakes = len(result.stdout.splitlines())
            except Exception:
                tls_handshakes = None

            # Scrivi i dati nel file CSV
            writer.writerow([
                time.strftime("%Y-%m-%d %H:%M:%S"),
                total_cpu,
                total_memory,
                bandwidth_in,
                bandwidth_out,
                tls_handshakes,
                open_connections
            ])

            # Aspetta l'intervallo specificato prima della prossima misurazione
            time.sleep(interval)

if __name__ == "__main__":
    monitor_nginx(output_file="/opt/nginx/output/nginx_performance.csv", interval=5, duration=60)
