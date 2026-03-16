from scapy.all import sniff, IP, TCP
import time
from collections import defaultdict
import datetime

THRESHOLD = 50
TIME_WINDOW = 5

ip_tracker = defaultdict(list)

def log_alert(src_ip, count, time_window):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    message = f"[{timestamp}] ALERT: Port scan from {src_ip} — {count} packets in {time_window}s\n"
    
    with open("alerts.log", "a") as f:
        f.write(message)

def packet_process(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport
        # print(f"Packet from {src_ip} -> port {dst_port}")
        now = time.time()

        ip_tracker[src_ip].append(now)

        ip_tracker[src_ip] = [
            t for t in ip_tracker[src_ip]
            if now - t <= TIME_WINDOW
        ]
        
        if len(ip_tracker[src_ip]) >= THRESHOLD:
            print(f"[ALERT] Possible Port Scan For {src_ip} - {len(ip_tracker[src_ip])} in {TIME_WINDOW}s")
            log_alert(src_ip, len(ip_tracker[src_ip]), TIME_WINDOW)

sniff(filter="tcp", prn=packet_process, store=False,)