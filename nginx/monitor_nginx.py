import psutil
import time
import subprocess
import csv
import os
import logging

# Configura il logging per registrare informazioni utili durante l'esecuzione
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

def get_nginx_processes():
    """
    Ritorna una lista di oggetti `Process` relativi ai worker di Nginx.
    Utilizza `psutil` per iterare tra i processi attivi e seleziona quelli con nome 'nginx'.
    """
    nginx_processes = []
    for proc in psutil.process_iter(['name']):
        if proc.info['name'] == 'nginx':  # Verifica se il nome del processo è 'nginx'
            nginx_processes.append(proc)
    logging.debug(f"Processi Nginx trovati: {len(nginx_processes)}")  # Log del numero di processi trovati
    return nginx_processes

def get_network_bandwidth():
    """
    Ritorna l'uso della banda di rete in byte/s.
    Misura l'I/O di rete prima e dopo un intervallo di 1 secondo per calcolare il traffico in entrata e in uscita.
    """
    net_before = psutil.net_io_counters()  # Statistiche di rete iniziali
    time.sleep(1)  # Aspetta 1 secondo per calcolare la differenza
    net_after = psutil.net_io_counters()  # Statistiche di rete finali
    bandwidth_in = net_after.bytes_recv - net_before.bytes_recv  # Dati ricevuti
    bandwidth_out = net_after.bytes_sent - net_before.bytes_sent  # Dati inviati
    logging.debug(f"Banda rilevata: In={bandwidth_in}, Out={bandwidth_out}")  # Log della banda
    return bandwidth_in, bandwidth_out

def monitor_nginx(output_file="/opt/nginx/output/nginx_performance.csv", interval=5, duration=60):
    """
    Monitora l'utilizzo delle risorse di Nginx e salva i dati raccolti in un file CSV.

    Args:
        output_file (str): Percorso del file CSV per salvare i risultati.
        interval (int): Intervallo tra una misurazione e l'altra (in secondi).
        duration (int): Durata totale del monitoraggio (in secondi).
    """
    # Crea la directory per il file di output, se non esiste
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    end_time = time.time() + duration  # Calcola l'orario di fine del monitoraggio

    # Apre il file CSV per scrivere i risultati
    with open(output_file, mode="w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(["Timestamp", "CPU_Usage", "Memory_Usage_MB", "Bandwidth_In_Bps", "Bandwidth_Out_Bps", "TLS_Handshakes", "Open_Connections"])

        while time.time() < end_time:
            nginx_processes = get_nginx_processes()  # Ottieni i processi Nginx attivi

            # Calcola l'uso della CPU e della memoria
            total_cpu = sum(proc.cpu_percent(interval=0.1) for proc in nginx_processes)  # Uso CPU totale
            total_memory = sum(proc.memory_info().rss for proc in nginx_processes) / (1024 ** 2)  # Memoria totale in MB

            # Calcola la banda di rete
            bandwidth_in, bandwidth_out = get_network_bandwidth()

            # Conteggia il numero di connessioni attive
            try:
                result = subprocess.run(["ss", "-s"], capture_output=True, text=True)  # Esegue il comando `ss` per ottenere le connessioni
                open_connections = int([line for line in result.stdout.splitlines() if "estab" in line][0].split()[1])  # Connessioni stabilite
            except Exception as e:
                logging.error(f"Errore nel conteggio delle connessioni: {e}")
                open_connections = None

            # Conteggia il numero di handshake TLS dai log di accesso di Nginx
            tls_handshakes = None
            try:
                result = subprocess.run(["grep", "TLS handshake", "/opt/nginx/logs/access.log"], capture_output=True, text=True)  # Cerca le righe con "TLS handshake"
                tls_handshakes = len(result.stdout.splitlines())  # Conta il numero di handshake
            except Exception as e:
                logging.error(f"Errore nel conteggio degli handshake TLS: {e}")
                tls_handshakes = None

            # Scrive i dati raccolti nel file CSV
            writer.writerow([
                time.strftime("%Y-%m-%d %H:%M:%S"),
                total_cpu,
                total_memory,
                bandwidth_in,
                bandwidth_out,
                tls_handshakes,
                open_connections
            ])
            logging.info(f"Scritti dati: CPU={total_cpu}, Mem={total_memory}MB, In={bandwidth_in}, Out={bandwidth_out}, Handshakes={tls_handshakes}, Connessioni={open_connections}")

            # Aspetta l'intervallo specificato prima della prossima misurazione
            time.sleep(interval)

if __name__ == "__main__":
    monitor_nginx(output_file="/opt/nginx/output/nginx_performance.csv", interval=5, duration=60)