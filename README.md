
# 🛡️ Security Tools - Antonio Romero

My cybersecurity toolkit: **Port Scanner (Enterprise)** and **Web Security Auditor**.  
Both tools generate professional PDF reports with risk analysis.

🔗 **GitHub:** [github.com/antonio247365/security-tools](https://github.com/antonio247365/security-tools)

---

## 🚀 Enterprise Port Scanner

Multi-threaded TCP port scanner with banner grabbing and vulnerability assessment.

### ✨ Features
- Scan common ports (1-1024) or all 65,535 ports
- Multi-threaded (fast) using `ThreadPoolExecutor`
- Smart banner grabbing (listens first, then requests)
- Risk mapping for critical ports (SMB, RDP, Telnet, FTP, etc.)
- Generates **professional PDF report** with:
  - Table of open ports, banners, and risks
  - Executive summary (High/Medium/Low breakdown)
  - Security recommendations

### 📸 Example output
