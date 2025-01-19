import psutil
import time
import csv
from datetime import datetime
import os

RESOURCE_LOG = "/opt/nginx/output/resource_monitor.csv"

def get_nginx_pids():
    """Trova i processi Nginx."""
    return [p.info["pid"] for p in psutil.process_iter(attrs=["pid", "name"]) if "nginx" in p.info["name"]]

def monitor_resources(interval=0.5):
    """Monitoraggio continuo delle risorse di Nginx."""
    os.makedirs(os.path.dirname(RESOURCE_LOG), exist_ok=True)

    with open(RESOURCE_LOG, mode="w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(["Timestamp", "CPU_Usage (%)", "Memory_Usage (MB)", "IO_Read_Bytes", "IO_Write_Bytes"])

        while True:
            nginx_pids = get_nginx_pids()
            if not nginx_pids:
                print("Nginx non in esecuzione.")
                time.sleep(interval)
                continue

            cpu_usage = 0
            memory_usage = 0
            io_read = 0
            io_write = 0

            for pid in nginx_pids:
                try:
                    process = psutil.Process(pid)
                    cpu_usage += process.cpu_percent(interval=0)
                    memory_usage += process.memory_info().rss / (1024 * 1024)
                    io_counters = process.io_counters()
                    io_read += io_counters.read_bytes
                    io_write += io_counters.write_bytes
                except psutil.NoSuchProcess:
                    continue

            writer.writerow([
                datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f"),
                cpu_usage,
                memory_usage,
                io_read,
                io_write
            ])
            file.flush()
            time.sleep(interval)

if __name__ == "__main__":
    monitor_resources()