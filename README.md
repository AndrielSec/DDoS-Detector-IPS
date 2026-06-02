# 🛡️ Real-Time DDoS Detector & IPS (Intrusion Prevention System)

A lightweight, high-performance network security tool written in Python that monitors live network traffic (e.g., `wlan0`, `eth0`) and dynamically mitigates potential DDoS attacks by automatically injecting firewall rules into Linux `iptables` in real-time.

---

## ✨ Features
* **Live Traffic Analysis:** Utilizes the `scapy` engine to sniff and measure packet transmission rates per second.
* **Automated Active Mitigation (IPS):** Detects threshold breaches and dynamically drops malicious traffic at the kernel level using `iptables` (DROP rules).
* **Auto-Unban Mechanism:** Automatically lifts temporary blocks after a configurable duration (e.g., 30 seconds) to prevent permanent network lockout.
* **Persistent Analytics:** Continuously tracks persistent threats and maintains attack histories inside `banned_ips.json` and records raw event timelines in `ddos_detector.log`.
* **Safe Diagnostics (Dry-Run Mode):** Includes a `--dry-run` flag allowing network administrators to safely test thresholds and analyze traffic metrics without modifying firewall rule sets.
* **Graceful Exception Management:** Features safe interrupt handling (`Ctrl+C`) that automatically purges all active rules created during the runtime before terminating.

---

## 🚀 Installation & Requirements

### 1. Prerequisites
Ensure you have `iptables` installed and the necessary Python libraries configured on your Linux system (Kali Linux / Debian / Ubuntu):

```bash
sudo apt update
sudo apt install iptables python3-pip -y
pip3 install scapy colorama

2. Configuration & Deployment

Since the application interacts directly with raw network sockets and system firewall rules, it must be executed with root administrative privileges:
Bash

# Run on Wi-Fi interface, with a 15 pkt/s threshold and a 30-second ban duration:
sudo python3 ddos_detector.py --iface wlan0 --threshold 15 --ban-dur 30

Command Line Arguments:

    --iface      : The target network interface to monitor (e.g., wlan0, eth0). [Required]

    --threshold  : Maximum packet volume allowed per second from a single IP source. (Default: 15. Recommended for production environments: 80-100).

    --ban-dur    : The penalty period (in seconds) that an offending IP will remain blocked. (Default: 30.0).

    --dry-run    : Simulates threat detection and logs metrics without appending real firewall rules.

    --verbose    : Prints descriptive debugging and system state information to the console.

🧪 Testing (Attack Simulation)

You can benchmark and test the detection threshold using hping3 from a secondary terminal interface:
Bash

# Generate a burst of 50 rapid packets towards your interface IP
sudo hping3 --fast -c 50 <YOUR_INTERFACE_IP>

When the limit is breached, you can verify active blocking parameters by inspecting your system's raw input chain:
Bash

sudo iptables -L INPUT -v -n --line-numbers

📊 Sample Output (Console Alerts)

When a threshold violation occurs, the engine blocks the origin and throws a warning dashboard:
Plaintext

══════════════════════════════════════════════════════════════
  ⚠  [ALERT] DDoS Attack Detected!  [BLOCKED]
  IP         : 142.251.150.2
  Protocol   : TCP/0x18
  Rate       : 16 pkt/s  (limit: 15)
  iptables   : DROP rule added
  Ban Period : 30.0s  →  auto-unban
  JSON log   : banned_ips.json
══════════════════════════════════════════════════════════════

[2026-06-02 03:37:05] WARNING  ATTACK src=142.251.150.2 proto=TCP/0x18 rate=16pkt/s threshold=15 iptables=APPLIED
[STATS] Total: 144 pkt | Blocked: 36 pkt | Attacks: 1 | Active Bans: 1 IP | Historical Unique: 1 IP

⚠️ Important Note

To safely shut down the engine, issue a standard interrupt sign (Ctrl + C). The internal cleanup routine will automatically flush all temporary blockades from your iptables chain and restore your initial system state cleanly.
📝 License

This project is open-source and available under the MIT License.
