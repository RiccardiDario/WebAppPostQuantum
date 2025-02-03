import psutil, csv, time, os
from datetime import datetime

RESOURCE_LOG, ACCESS_LOG, OUTPUT_FILE = "/opt/nginx/output/monitor_server.csv", "/opt/nginx/logs/access_custom.log", "/opt/nginx/output/performance_server.csv"
EXPECTED_REQUESTS, SAMPLING_INTERVAL = 500, 0.1

def monitor_resources():
    print("Inizio monitoraggio...")  
    with open(RESOURCE_LOG, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["Timestamp", "CPU (%)", "Mem (MB)", "Bytes Sent", "Bytes Recv", "Conn Attive"])
        psutil.cpu_percent(None)
        while True:
            if os.path.exists(ACCESS_LOG) and sum(1 for _ in open(ACCESS_LOG, encoding="utf-8")) >= EXPECTED_REQUESTS: break
            ts, cpu, mem = datetime.now().strftime("%d/%b/%Y:%H:%M:%S"), psutil.cpu_percent(None), psutil.virtual_memory().used / (1024 ** 2)
            net, conns = psutil.net_io_counters(), len([c for c in psutil.net_connections("inet") if c.status == "ESTABLISHED"])
            w.writerow([ts, cpu, mem, net.bytes_sent, net.bytes_recv, conns]), f.flush()
            print(f"{ts} - CPU: {cpu}%, Mem: {mem}MB, Sent: {net.bytes_sent}, Recv: {net.bytes_recv}, Conn: {conns}")
            time.sleep(SAMPLING_INTERVAL)

def analyze_logs():
    if not os.path.exists(ACCESS_LOG): return None, None
    with open(ACCESS_LOG, encoding="utf-8") as f:
        t = [datetime.strptime(l.split()[3][1:], "%d/%b/%Y:%H:%M:%S") for l in f if len(l.split()) >= 10]
    return (min(t), max(t)) if t else (None, None)

def load_resource_data():
    if not os.path.exists(RESOURCE_LOG): return []
    with open(RESOURCE_LOG, encoding="utf-8") as f:
        return [{"timestamp": datetime.strptime(r["Timestamp"], "%d/%b/%Y:%H:%M:%S"), "cpu": float(r["CPU (%)"]),
                 "memory": float(r["Mem (MB)"]), "bytes_sent": int(r["Bytes Sent"]), "bytes_received": int(r["Bytes Recv"]),
                 "active_connections": int(r["Conn Attive"])} for r in csv.DictReader(f)]

def analyze_performance():
    s, e = analyze_logs()
    if not s or not e: return
    data = [d for d in load_resource_data() if s <= d["timestamp"] <= e]
    if not data: return
    with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["Timestamp", "CPU (%)", "Mem (MB)", "Bytes Sent", "Bytes Recv", "Conn Attive"])
        w.writerows([[d["timestamp"], d["cpu"], d["memory"], d["bytes_sent"], d["bytes_received"], d["active_connections"]] for d in data])

if __name__ == "__main__":
    try: monitor_resources(), analyze_performance()
    except Exception as e: print(f"ERRORE: {e}")
