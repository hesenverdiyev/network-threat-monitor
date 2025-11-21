# Network Threat Monitor

A lightweight Python tool that monitors active network connections, detects external IPs accessed by local processes, and performs automated reputation scoring using **VirusTotal**, **AbuseIPDB**, and **IPInfo**. Results are exported to a color‑coded Excel report for quick threat analysis. (Insipired by "Process Monitor" of Sysinternals)

---

## 🚀 Features

* Monitors all established outbound network connections
* Identifies external (non‑private) IPs contacted by each process
* Performs reputation lookup via:

  * **VirusTotal** (malicious score)
  * **AbuseIPDB** (abuse confidence score)
  * **IPInfo** (country & ASN/organization)
  * Reverse DNS lookup
* Generates a structured Excel report (`network_results.xlsx`)
* Applies color‑coded threat indicators

  * 🟥 High risk
  * 🟨 Medium risk
  * 🟩 Low/No risk
* No admin privileges required on most systems

---

## 📦 Installation

### 1. Clone the repository

```bash
git clone https://github.com/hesenverdiyev/network-threat-monitor.git
cd network-threat-monitor
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

---

## 🔧 Configuration

The script requires API keys for **VirusTotal** and **AbuseIPDB**.

### Replace with your API's

```bash
VT_API_KEY="your_virustotal_api_key"
ABUSE_API_KEY="your_abuseipdb_api_key"
```

The script reads them automatically.

---

## ▶️ Usage

Run the script directly:

```bash
python network_scan.py
```

By default, the monitor runs for **100 seconds**, you can change this section:

```python
SCAN_DURATION = 100
```

Output file will be saved as:

```
network_results.xlsx
```

---

## ▶️ Advanced Usage

If you want to see "Ports" and "Services (HTTP, FTP, SSH, etc.)" in result table, then use Version 2 👇

```bash
python network_scan_v2.py
```

If you want to see "Ports" and "Services (HTTP, FTP, SSH, etc.)", "Wireshark Filter" and "Accessed Files" in result table, then use Version 3 👇

```bash
python network_scan_v3.py
```



---

## 📊 Excel Report Structure

The generated Excel file contains:

| Column      | Description                        |
| ----------- | ---------------------------------- |
| IP          | Remote external IP address         |
| Domain      | Reverse DNS hostname               |
| Process     | Process name making the connection |
| PID         | Process ID                         |
| Country     | IPInfo country code                |
| AS Name     | ISP / ASN / Organization           |
| VT Score    | Number of malicious detections     |
| AbuseIPDB Score | AbuseIPDB confidence score         |

Color coding is applied to the **VT Score** and **Abuse Score** fields.

Example screenshot :
![screenshot](https://github.com/user-attachments/assets/78452f49-d9a6-47ba-819e-268b1483113d)

---

## 🧠 How It Works

1. Continuously scans running processes via **psutil**.
2. Extracts remote endpoints from `ESTABLISHED` TCP connections.
3. Filters out private/local addresses.
4. Performs threat intelligence lookups.
5. Writes results to Excel with styling and risk colors.

---

## ⚠️ API Usage Notes

* VirusTotal free API is **rate-limited** (4 requests/min). Large volumes may take time.
* AbuseIPDB also throttles requests on free plans.
* You may need API keys with higher limits for intensive scanning.

---

## 📄 License

MIT License — free to use, modify, and distribute.

---

## 🤝 Contributions

Pull requests and feature suggestions are welcome!

---

## ⭐ Support

If you find this project helpful, please consider giving the repository a **star** on GitHub.
