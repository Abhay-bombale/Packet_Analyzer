from scapy.all import sniff, IP, TCP
from collections import defaultdict
from rich.console import Console
from rich.table import Table
from rich.live import Live
import threading
import datetime
import time

# --- Configuration ---
THRESHOLD = 100
TIME_WINDOW = 10

# --- Storage ---
ip_tracker = defaultdict(list)
console = Console()

# --- Logging ---
def log_alert(src_ip, count):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    message = f"[{timestamp}] ALERT: Port scan from {src_ip} — {count} packets in {TIME_WINDOW}s\n"
    with open("alerts.log", "a") as f:
        f.write(message)

# --- Packet Processing ---
def process_packet(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        src_ip = packet[IP].src
        now = time.time()

        ip_tracker[src_ip].append(now)
        ip_tracker[src_ip] = [
            t for t in ip_tracker[src_ip]
            if now - t <= TIME_WINDOW
        ]

        if len(ip_tracker[src_ip]) > THRESHOLD:
            log_alert(src_ip, len(ip_tracker[src_ip]))

# --- Dashboard ---
def build_table():
    table = Table(title="🛡️  IDS Live Monitor")
    table.add_column("Source IP", style="cyan")
    table.add_column("Packets", style="magenta")
    table.add_column("Status", style="white")

    for ip, timestamps in list(ip_tracker.items()):
        count = len(timestamps)
        status = "⚠️  ALERT" if count > THRESHOLD else "✅ Normal"
        table.add_row(ip, str(count), status)

    return table

# --- Sniffer Thread ---
def start_sniffing():
    sniff(filter="tcp", prn=process_packet, store=False)

# --- Main ---
sniff_thread = threading.Thread(target=start_sniffing)
sniff_thread.daemon = True
sniff_thread.start()

with Live(console=console, refresh_per_second=0.5) as live:
    while True:
        live.update(build_table())
        time.sleep(2)