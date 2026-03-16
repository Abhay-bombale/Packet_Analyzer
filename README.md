# 🛡️ Network Intrusion Detection System (NIDS)

A lightweight, real-time **Network Intrusion Detection System** built in Python that monitors live TCP traffic, detects port scan attacks using a sliding time window algorithm, logs alerts to a file, and displays a live terminal dashboard.

---

## 📸 Preview

```
┌─────────────────────────────────────────────────────┐
│                 🛡️  IDS Live Monitor                │
├──────────────────┬──────────────────┬───────────────┤
│ Source IP        │ Peak Packets     │ Status        │
├──────────────────┼──────────────────┼───────────────┤
│ 10.12.9.167      │ 875              │ ⚠️  ALERT     │
└──────────────────┴──────────────────┴───────────────┘
```

---

## 🔍 How It Works

The IDS sniffs live TCP packets on the network interface using **Scapy**. For every packet captured, it:

1. Extracts the **source IP** (Layer 3) and **destination port** (Layer 4)
2. Tracks packet timestamps per IP using a **sliding time window**
3. If any IP exceeds the packet threshold within the time window → triggers an **alert**
4. Logs the alert to `alerts.log` with a timestamp
5. Displays live stats on a **Rich terminal dashboard**

A separate **attack simulator** (`attacker.py`) performs a TCP port scan against the local machine to test the IDS in action.

---

## 🧠 Key Concepts Demonstrated

| Concept | Implementation |
|---|---|
| Packet sniffing | Scapy `sniff()` with TCP filter |
| OSI Layer awareness | Reading IP (L3) and TCP (L4) headers |
| Sliding time window | Timestamp-based packet tracking |
| False positive/negative tradeoff | Tunable threshold and time window |
| Multithreading | Sniffer and dashboard on separate threads |
| Thread safety | `threading.Lock()` for shared state |
| Persistent logging | Append-mode file I/O with timestamps |
| Live terminal UI | Rich `Live` dashboard with tables |

---

## 📁 Project Structure

```
network-intrusion-detection-system/
│
├── ids.py          # Main IDS — sniffing, detection, dashboard, logging
├── attacker.py     # Port scan simulator for testing the IDS
├── alerts.log      # Auto-generated alert log file
└── README.md       # Project documentation
```

---

## ⚙️ Requirements

- Python 3.8+
- Scapy
- Rich

Install dependencies:

```bash
pip install scapy rich
```

> **Note:** Scapy requires **administrator/root privileges** to sniff raw packets.

---

## 🚀 Usage

### Step 1 — Run the IDS

**Windows (run as Administrator):**
```bash
python ids.py
```

**Linux / macOS:**
```bash
sudo python ids.py
```

### Step 2 — Simulate a Port Scan Attack

Open a second terminal and run:

```bash
python attacker.py
```

This scans ports 1–1024 on your local machine. Watch the IDS dashboard catch it in real time.

### Step 3 — Review Alerts

```bash
cat alerts.log
```

Sample output:
```
[2026-03-16 10:45:23] ALERT: Port scan from 10.12.9.167 — 875 packets in 10s
[2026-03-16 10:45:24] ALERT: Port scan from 10.12.9.167 — 912 packets in 10s
```

---

## 🔧 Configuration

Edit these values in `ids.py` to tune the IDS for your environment:

```python
THRESHOLD = 100    # Max packets allowed per IP within the time window
TIME_WINDOW = 10   # Time window in seconds
```

| Environment | Recommended Threshold | Recommended Window |
|---|---|---|
| Personal laptop | 100 | 10s |
| Small office network | 500 | 10s |
| College/enterprise network | 1000+ | 10s |

> **Why does it matter?** A threshold too low causes **false positives** (normal traffic flagged as attacks). Too high causes **false negatives** (real attacks missed). Tune based on your network's baseline traffic.

---

## ⚠️ Disclaimer

This tool is built for **educational purposes** and **authorized security testing only**. Only run `attacker.py` against systems you own or have explicit permission to test. Unauthorized port scanning is illegal in most jurisdictions.

---

## 🛠️ Built With

- [Python 3](https://www.python.org/)
- [Scapy](https://scapy.net/) — Packet sniffing and analysis
- [Rich](https://rich.readthedocs.io/) — Terminal dashboard UI

---

## 👤 Author

**Abhay**
B.Tech Computer Science Engineering | Cybersecurity Specialization

---

## 🙏 Credits

- Built with guidance from [Claude.ai] (Anthropic)