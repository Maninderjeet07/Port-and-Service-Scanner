# Full Network, Nmap & API Scanner (Python GUI)

A complete cybersecurity scanning tool built using **Python**, **CustomTkinter GUI**, **Nmap**, and **Requests**.  
This project performs **Network Port Scanning**, **Service & Version Detection**, and **API Endpoint Testing** — all in one modern GUI.

---

## 🚀 Features

### 🔵 1. Network Port Scanner
- Scans **ports 1–1024 automatically**
- Detects **open/closed ports**
- Performs **banner grabbing**
- Identifies common services (HTTP, SSH, DNS, etc.)
- Multithreaded → GUI does not freeze

---

### 🔵 2. Nmap Integration (Advanced Mode)
If Nmap is installed, the tool switches to professional mode:
- Runs `nmap -sV` for service & version detection  
- Parses XML output  
- Shows service name, product, version  
- Much faster and more accurate than socket scanning

If Nmap is not installed → tool automatically falls back to socket scanning.

---

### 🔵 3. API Scanner Module
Test any API by entering a base URL (example: `https://api.github.com`).

Features:
- Tests multiple endpoints like `/api`, `/status`, `/login`, `/auth`, `/health`
- Shows:
  - Status code  
  - Response time  
  - Content-Type  
  - CORS header  
  - Authentication hints (401/403)  
  - Body preview  
- Great for API recon & security analysis

---

### 🔵 4. Modern GUI (CustomTkinter)
- Clean dark mode interface  
- Two tabs:
  - **Network Scan**
  - **API Scan**
- Buttons to:
  - Start Scan  
  - Clear Output  
  - Save Results  
- Auto port range (1–1024)

---

## 🛠️ Technologies Used
- **Python 3**
- **CustomTkinter**
- **socket**
- **subprocess**
- **Nmap 7.98**
- **Requests**
- **Threading**
- **XML Parser**

---

## 📥 Installation

### 1️⃣ Install Python  
Download Python from:  
https://www.python.org/downloads/  
> Make sure to tick **“Add Python to PATH”** during installation.

---

### 2️⃣ Install required Python libraries  
```bash
pip install customtkinter requests
