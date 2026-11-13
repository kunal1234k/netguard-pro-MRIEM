# NetGuard Pro — Advanced Network Security System

**Project by:** Kunal Bhardwaj (BCA 1st Year)  
**Teacher:** Monika mam  
**Institution:** MATU RAM INSTITUTE OF ENGINEERING & MANAGEMENT, ROHTAK

NetGuard Pro is a Python-based educational network-security project for Windows. It combines TCP port checks, Windows Defender Firewall rule management, and live observation of established TCP connections in one terminal application.

> Use this project only on devices and networks you own or are explicitly authorized to test.

## Features

- **TCP Port Scanner:** Checks TCP ports 21, 22, 80, 443, and 8080 on a target IP/hostname using `socket.connect_ex()`.
- **Windows Firewall Manager:** Adds and removes inbound Windows Defender Firewall rules for individual IP addresses using the built-in `netsh` command.
- **Connection Burst Monitor:** Uses `psutil` to inspect established TCP connections and detect bursts of newly observed remote endpoints.
- **Security Logging:** Writes events to `logs/security.log`.
- **Single entry point:** Start the complete application with `python main.py`.

## Project structure

```text
NetGuard-Pro/
├── main.py
├── port_scanner.py
├── firewall.py
├── bot_detection.py
├── requirements.txt
├── README.md
├── LICENSE
└── logs/
    └── .gitkeep
```

## Requirements

- Windows 10 or Windows 11
- Python 3.9+
- Administrator privileges for adding/removing Windows Firewall rules
- `psutil` dependency for connection monitoring

## Installation

```powershell
git clone https://github.com/kunal1234k/netguard-pro-MRIEM.git
cd NetGuard-Pro
py -m venv .venv
.venv\Scripts\activate
py -m pip install -r requirements.txt
```

```kali

# 1. Home directory में जाओ
cd ~

# 2. Git install/check
sudo apt update
sudo apt install -y git python3 python3-pip python3-venv

# 3. GitHub से project clone करो
git clone https://github.com/kunal1234k/netguard-pro-MRIEM.git

# 4. Project directory में जाओ
cd netguard-pro-MRIEM

# 5. Files verify करो
ls -la

# 6. Virtual environment बनाओ
python3 -m venv .venv

# 7. Virtual environment activate करो
source .venv/bin/activate

# 8. Dependencies install करो
python -m pip install -r requirements.txt

# 9. NetGuard Pro start करो
python main.py
```

The startup banner displays the project author, teacher, and institution. The TCP connection monitor starts in the background. Port scanning is performed when selected from the menu; it is not repeatedly run without operator action.

## How the modules work

### 1. Port scanner
Makes real TCP connection attempts to the selected host and ports. A port reported as "closed or filtered" did not accept the TCP connection; the scanner cannot always distinguish a closed port from filtering or a network timeout.

### 2. Firewall manager
Creates inbound Windows Defender Firewall block rules named with the `NetGuardPro_Block_` prefix. The unblock option deletes the matching NetGuard Pro rule only. Administrator rights are normally required.

### 3. Connection burst monitor
Reads the local operating system's established TCP connection table through `psutil`. It counts newly observed connection endpoint tuples per remote IP over a rolling time window.

**Important limitation:** This is connection-level observation, not packet capture or HTTP request counting. It may miss short-lived connections between polling intervals, and it cannot independently prove that traffic is malicious or that a DDoS attack is occurring. The default threshold is conservative and is intended for demonstration and tuning.

Automatic firewall blocking is **OFF by default** to avoid blocking legitimate users due to false positives. If you deliberately enable `auto_block=True` in `main.py`, the monitor can ask the Windows Firewall module to block an IP after a threshold alert. Test this only in a controlled environment and maintain an allowlist/recovery plan.

## Troubleshooting

- **Firewall command fails:** Run the terminal as Administrator and verify Windows Defender Firewall is enabled.
- **Access denied while monitoring:** Run with appropriate permissions. Some Windows configurations restrict access to the complete connection table.
- **psutil missing:** Run `py -m pip install -r requirements.txt`.
- **No alerts:** The monitor only sees established TCP connections visible during its polling intervals. Lack of an alert does not mean a network is safe.

## Project scope and disclaimer

NetGuard Pro is an educational project, not a replacement for enterprise endpoint protection, an IDS/IPS, a packet analyzer, or a managed firewall. It does not inspect payload contents, count HTTP requests, mitigate volumetric DDoS attacks, or guarantee prevention of intrusion.

## License

See [LICENSE](LICENSE).
