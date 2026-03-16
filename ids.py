from scapy.all import sniff, IP, TCP
import time
from collections import defaultdict

THRESHOLD = 300
TIME_WINDOW = 5

ip_tracker = defaultdict(list)

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

sniff(filter="tcp", prn=packet_process, store=False,)