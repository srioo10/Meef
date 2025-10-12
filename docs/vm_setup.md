# VM Setup & Isolation Guide

## Goal
Create a secure, offline analysis environment for MEeF (Malware Extraction & Evaluation Framework).

---

### 1. Virtual Machine Setup
- Use **VirtualBox** or **VMware Workstation**.
- Allocate at least **2 CPU cores, 4 GB RAM, 40 GB storage**.
- Use a **Windows 10** guest OS (recommended).

---

### 2. Isolation Settings
| Setting | Value |
|----------|--------|
| Shared Clipboard | Disabled |
| Drag & Drop | Disabled |
| Shared Folders | None |
| USB Controller | Disabled |
| Network Adapter | Host-Only Adapter (no internet) |

---
3. **Inside VM**
   - Install Python 3.10+, Notepad++, PEStudio, Detect It Easy, Strings.exe.
   - Create venv → install project deps:
     ```bash
     python -m venv venv
     venv\Scripts\activate
     pip install -r requirements.txt
     ```

4. **Snapshot**
   - After setup, take snapshot named `mclf_lab_base`.

5. **Safety**
   - Keep Windows Firewall & Defender **ON**.
   - Never copy `.exe` files outside VM.

