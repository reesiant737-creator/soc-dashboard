# 🧪 VirtualBox Home Lab Setup Guide
## SOC Dashboard — Real Attack & Defense Environment

This guide walks you through building a complete home cybersecurity lab using VirtualBox.
You will have a Kali Linux attacker machine, a vulnerable target (Metasploitable 2),
and your SOC Dashboard running — all talking to each other on an isolated private network.

---

## 🖥️ What You're Building

```
┌─────────────────────────────────────────────────┐
│              YOUR WINDOWS PC (Host)             │
│                                                 │
│  ┌──────────────┐      ┌─────────────────────┐  │
│  │  Kali Linux  │◄────►│   Metasploitable 2  │  │
│  │  (Attacker)  │      │   (Vulnerable VM)   │  │
│  │ 192.168.56.x │      │   192.168.56.x      │  │
│  │              │      │                     │  │
│  │ • Nmap       │      │ • vsftpd backdoor   │  │
│  │ • Wireshark  │      │ • Telnet open       │  │
│  │ • SOC Dash   │      │ • MySQL exposed     │  │
│  └──────────────┘      │ • 20+ vulns         │  │
│                        └─────────────────────┘  │
│         HOST-ONLY NETWORK (192.168.56.0/24)     │
│         Isolated — no internet access from VMs  │
└─────────────────────────────────────────────────┘
```

---

## 📦 Step 1 — Download Everything

### VirtualBox
1. Go to **virtualbox.org** → Downloads
2. Download **VirtualBox for Windows**
3. Also download the **VirtualBox Extension Pack** (same page)
4. Install VirtualBox first, then double-click the Extension Pack to install it

### Kali Linux
1. Go to **kali.org/get-kali**
2. Click **Virtual Machines** → **VirtualBox** → Download the `.ova` file (~3GB)
3. This is a pre-built VM — no installation needed

### Metasploitable 2
1. Search **"Metasploitable 2 SourceForge"** → download the `.zip` file (~900MB)
2. Extract the zip — you'll get a folder with a `.vmdk` file inside

---

## 🔧 Step 2 — Set Up the Host-Only Network

This creates a private network that only your VMs can use — completely isolated from the internet.

1. Open VirtualBox
2. Go to **File → Tools → Network Manager** (or **File → Host Network Manager**)
3. Click **Create** — it makes `vboxnet0` (or `VirtualBox Host-Only Ethernet Adapter`)
4. Set these values:
   - **IPv4 Address:** `192.168.56.1`
   - **IPv4 Mask:** `255.255.255.0`
   - **DHCP Server:** ✅ Enable
   - **Server Address:** `192.168.56.100`
   - **Lower Bound:** `192.168.56.101`
   - **Upper Bound:** `192.168.56.254`
5. Click **Apply**

---

## 🐉 Step 3 — Import Kali Linux

1. Open VirtualBox → **File → Import Appliance**
2. Select the Kali `.ova` file you downloaded
3. Click **Next → Import** (takes a few minutes)
4. Once imported, right-click the Kali VM → **Settings**
5. Go to **Network**:
   - **Adapter 1:** NAT (keeps internet access for updates)
   - **Adapter 2:** Host-Only Adapter → select `vboxnet0`
6. Click **OK**
7. Start the Kali VM
8. Default login: **kali / kali**

### Find Kali's IP on the host-only network:
```bash
ip a
# Look for 192.168.56.x on eth1 or enp0s8
```

---

## 💀 Step 4 — Import Metasploitable 2

1. Open VirtualBox → **Machine → New**
2. Settings:
   - **Name:** Metasploitable2
   - **Type:** Linux
   - **Version:** Ubuntu (64-bit)
   - **Memory:** 512 MB is enough
3. On the **Hard Disk** screen → **Use an existing virtual hard disk file**
4. Click the folder icon → Add → browse to the `.vmdk` file you extracted
5. Click **Create**
6. Right-click Metasploitable2 → **Settings → Network**:
   - **Adapter 1:** Host-Only Adapter → `vboxnet0`
   - ⚠️ **Do NOT give Metasploitable NAT** — it is intentionally vulnerable and should never touch the internet
7. Click **OK**
8. Start Metasploitable2
9. Login: **msfadmin / msfadmin**

### Find Metasploitable's IP:
```bash
ifconfig
# Look for 192.168.56.x
```

---

## ✅ Step 5 — Verify the Network

From inside Kali, ping Metasploitable:
```bash
ping 192.168.56.101   # use Metasploitable's actual IP
```

You should get replies. If not, check both VMs are on the same host-only adapter name.

---

## 🔍 Step 6 — Run Your First Real Nmap Scan

Open a terminal in Kali and run:

```bash
# Quick scan — find the host
nmap 192.168.56.0/24

# Full scan with version detection, OS, scripts, and vuln detection
nmap -sV -sC -O --script vuln -oX /home/kali/metasploitable_scan.xml 192.168.56.101

# This takes 5-10 minutes — worth the wait
```

When it finishes you'll have a `metasploitable_scan.xml` file with real findings.

---

## 📊 Step 7 — Get the Scan into Your Dashboard

### Option A — Dashboard running on your Windows host
Copy the XML file from Kali to Windows:

**On Kali:**
```bash
# Install a simple HTTP server to serve the file
python3 -m http.server 8000 --directory /home/kali/
```

**On Windows (browser):**
Go to `http://192.168.56.x:8000` (Kali's IP) → download `metasploitable_scan.xml`

Then upload it to your dashboard at `http://localhost:5000`

### Option B — Run the dashboard on Kali itself
```bash
# On Kali
sudo apt update && sudo apt install python3-pip -y
git clone https://github.com/YOUR_USERNAME/soc-dashboard.git
cd soc-dashboard
pip3 install -r requirements.txt
cp .env.example .env
nano .env   # add your API key
python3 app.py
```

Open `http://localhost:5000` on Kali — upload the scan directly.

---

## 🦈 Step 8 — Capture Traffic with Wireshark

While Nmap is scanning, capture the traffic in Wireshark to get real PCAP data.

### On Kali:
```bash
# Find your interface name
ip a
# Usually eth1 or enp0s8 for the host-only network

# Capture while scanning (run this BEFORE the nmap scan)
sudo tshark -i eth1 -w /home/kali/capture.pcap

# In another terminal, run the nmap scan
nmap -sV 192.168.56.101

# Stop tshark with Ctrl+C when done
```

### Convert to JSON for the dashboard:
```bash
tshark -r /home/kali/capture.pcap -T json > /home/kali/capture.json
```

Upload `capture.json` to the Wireshark panel on the dashboard.

### Or use Wireshark GUI:
1. Open Wireshark on Kali
2. Select your host-only interface
3. Start capture → run your Nmap scan → stop capture
4. File → Export Packet Dissections → As JSON
5. Upload to dashboard

---

## 🎯 What You'll Find on Metasploitable 2

Metasploitable is intentionally loaded with vulnerabilities. Your dashboard will detect:

| Service | Port | Vulnerability | CVSS |
|---|---|---|---|
| vsftpd 2.3.4 | 21 | Backdoor command execution | **10.0** |
| OpenSSH 4.7p1 | 22 | Multiple CVEs | HIGH |
| Telnet | 23 | Cleartext credentials | CRITICAL |
| SMTP | 25 | Open relay | MEDIUM |
| Apache 2.2.8 | 80 | Multiple CVEs | HIGH |
| MySQL 5.0.51a | 3306 | Auth bypass, no root password | HIGH |
| PostgreSQL 8.3 | 5432 | Trust auth | HIGH |
| VNC | 5900 | Password "password" | CRITICAL |
| distccd | 3632 | Remote code execution | HIGH |
| Samba 3.0.20 | 445 | username map script RCE | **10.0** |
| IRC (UnrealIRCd) | 6667 | Backdoor | **10.0** |
| Tomcat 5.5 | 8180 | Default credentials | HIGH |

Your alert correlation engine will fire on nearly every rule.

---

## 🧪 Practice Attack Scenarios

### Scenario 1 — Port Scan + Report
```bash
nmap -sV -sC -O --script vuln -oX scan.xml 192.168.56.101
```
Upload to dashboard → Run AI Analysis → Export PDF report

### Scenario 2 — Traffic Analysis
```bash
# Terminal 1 — capture
sudo tshark -i eth1 -w capture.pcap

# Terminal 2 — aggressive scan
nmap -A -T4 192.168.56.101

# Stop capture, convert, upload
tshark -r capture.pcap -T json > capture.json
```

### Scenario 3 — Full Subnet Discovery
```bash
# Discover all live hosts
nmap -sn 192.168.56.0/24 -oX subnet.xml
# Then full scan
nmap -sV --script vuln -iL - -oX full.xml < <(grep 'addr' subnet.xml | grep -oP '(?<=addr=")[^"]+')
```

---

## 🛡️ Safety Rules

1. **Never give Metasploitable a NAT adapter** — it is full of backdoors and will be compromised if exposed to internet
2. **Host-only network only** for vulnerable VMs — they cannot reach the internet and nothing outside can reach them
3. **Only scan machines you own** — never point Nmap at real networks without authorization
4. **Snapshots** — take a VirtualBox snapshot of Metasploitable before any exploits so you can restore it

---

## 📚 What This Lab Teaches You

- **Network reconnaissance** — how attackers map a network with Nmap
- **Vulnerability assessment** — reading CVE/CVSS scores and understanding severity
- **Traffic analysis** — spotting port scans and C2 beacons in Wireshark
- **MITRE ATT&CK** — mapping real observed techniques to the framework
- **SOC workflows** — alert triage, incident documentation, remediation prioritization
- **Report writing** — generating professional incident reports from raw scan data

---

## 🆘 Common Issues

| Problem | Fix |
|---|---|
| VMs can't ping each other | Check both are on the same host-only adapter in Network settings |
| Metasploitable gets no IP | Enable DHCP in the host-only network settings |
| Nmap scan is very slow | Add `-T4` flag to speed it up |
| Wireshark shows no packets | Make sure you're capturing on the host-only interface, not NAT |
| Dashboard can't reach NVD API | Check internet connection on host — CVE lookup needs internet |
| Kali loses internet | Make sure Adapter 1 is NAT and Adapter 2 is Host-Only |

---

## 🔗 Useful Resources

- **Kali Linux docs:** kali.org/docs
- **Nmap reference:** nmap.org/book
- **MITRE ATT&CK:** attack.mitre.org
- **NVD CVE database:** nvd.nist.gov
- **Metasploitable walkthrough:** Search "Metasploitable 2 walkthrough" on YouTube
