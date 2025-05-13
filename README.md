# DomainMaps – Automated Network Mapping & Enumeration Tool 🌐

**DomainMaps.sh** is a powerful Bash script designed for semi-automated domain and network reconnaissance in internal lab networks. It chains together progressive levels of scanning, enumeration, and exploitation, each building on the results of the previous step.

---

## 📚 Table of Contents
1. [Overview](#overview)
2. [Features](#features)
3. [Requirements](#requirements)
4. [Tested On](#tested-on)
5. [Usage](#usage)
6. [Modes & Workflow](#modes--workflow)

---

## 🧭 Overview

**DomainMaps.sh** automates a multi-stage internal network reconnaissance process, ideal for SOC training labs and red-team simulations.

- 🧪 **Stage 1 – Basic**: Service/version detection and basic vulnerability scan
- 🛠 **Stage 2 – Intermediate**: Full port scan, service enumeration, credential spray
- 🚨 **Stage 3 – Advanced**: Masscan UDP scan, domain enumeration, Kerberos ticket discovery

Each stage logs outputs and stores results in a clean directory structure.

---

## ✨ Features

- 🔍 Network-wide scanning with live host discovery
- 📁 Organized directory output per phase
- 💡 NSE vulnerability scanning
- 🧠 Domain service enumeration (users, groups, shares)
- 🕵️ Credential spraying (optional with custom wordlists)
- 🔐 Kerberos ticket analysis if available

---

## 🔧 Requirements

Ensure the following tools are installed:
- `nmap`
- `masscan`
- `crackmapexec` or `impacket` tools (for Kerberos/domain enum)
- `rockyou.txt` or custom lists for password testing

> Root privileges required for full functionality

---

## 🖥️ Tested On

- ✅ Kali Linux (latest)
- ✅ Ubuntu with added tools
- ✅ Lab environments (e.g. Metasploitable, AD simulator VMs)

---

## 🚀 Usage

```bash
chmod +x DomainMaps.sh
sudo ./DomainMaps.sh
```

Follow the on-screen prompts:
- Provide the network range (e.g. `192.168.246.0/24`)
- Provide custom or default username/password lists
- Select scan mode: Basic / Intermediate / Advanced

---

## 🧱 Modes & Workflow

### 🔹 Basic Mode
- Nmap scan for open ports and services
- NSE vuln scan (`--script vuln`)
- Saves data to `/BASIC/` folder

### 🔸 Intermediate Mode
- Full TCP scan (1-65535) per host
- Greps for known services (FTP, SSH, LDAP, etc.)
- Runs 3 selected NSE scripts
- Optional credential spraying

### 🔻 Advanced Mode
- Runs all prior modes
- Adds Masscan UDP scan
- Enumerates domain users, groups, shares
- Dumps Kerberos tickets (if possible)

---

## ⚠️ Disclaimer

**DomainMaps.sh** is intended for use in controlled, educational, and authorized environments only. Do not use on networks without explicit permission.

---

**Author**: Hadroxx  
**Script**: `DomainMaps.sh`