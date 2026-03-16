import socket
import time

target = "10.12.9.167"
print(f"[*] Starting port scan on {target}")

for port in range(1, 1025):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.1)
        s.connect((target, port))
        print(f"[+] Port {port} is OPEN")
        s.close()
    except:
        pass

print("[*] Scan complete")