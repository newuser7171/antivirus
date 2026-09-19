# Jev-AV: AI-Powered File Antivirus & Threat Triage Scanner

A next-generation antivirus scanner, URL threat intelligence engine, and real-time **Endpoint Detection & Response (EDR)** sentinel powered by TypeSafe's **Jev** (`jev-latest`). Jev-AV inspects binary executables, running processes, scripts, documents, plain text, and web links—extracting structural features (Shannon entropy, hashes, strings, PE imports/sections, PDF triggers, macros, process lineage, LOLBIN arguments, network sockets) and applying System One decision intelligence to deliver calibrated threat verdicts, severity scores, and automated protection actions.

---

## Features

* 🖥️ **Modern Cyber Desktop GUI**: Built with CustomTkinter (Windows 11 dark mode theme) featuring live threat score meters, real-time activity logs, and responsive multi-threading.
* ⚡ **Live Process & Memory EDR**: Real-time Windows process triage, parent-child anomaly detection (e.g. Office/Browser spawning PowerShell/CMD), LOLBIN abuse recognition, active network socket monitoring, and one-click process termination.
* 🔗 **Universal Link & URL Scanner**: Inspects URLs for phishing portals, fake brand credential harvesting, direct malware droppers, and unmasks multi-hop redirect chains (e.g. `bit.ly`).
* 👁️ **Sentinel Real-Time Shield**: Background watchdog folder protection that instantly intercepts newly downloaded or modified files.
* 🗄️ **Quarantine Vault**: Isolates threats with cryptographic history logs, one-click file restoration, and permanent shredding.
* 🧠 **TypeSafe System One Engine**: Leverages `Choice`, `Score`, and `Noul` primitives for sub-second calibrated judgments without hallucination risk.
* 🌐 **Universal File Format Coverage**: Full structural inspection across PE, ELF, PDF, Office, LNK, Archives, Scripts, and Prompt Injections.

---

## Desktop GUI

Launch the graphical dashboard with any of the following:

```bash
# Via Python:
python gui.py

# Via CLI:
jev-av gui

# Or double-click:
jev-av-gui.bat
```

### GUI Highlights
1. **Dashboard**: System protection health overview, real-time threat counters, and one-click quick actions.
2. **File Scanner**: Single file analysis with animated progress bar, visual severity gauge (0–100%), classification badges, and granular feature breakdown.
3. **Link Scanner**: Dedicated URL threat analyzer with "Paste from Clipboard", safe redirect-chain unmasking, phishing probability rating, and browser launch protection.
4. **Live EDR**: Real-time Windows process monitor. Displays active processes, lineage anomalies, network connections, and Jev threat scores with one-click **Terminate** and **Suspend** controls.
5. **Folder Scanner**: Recursive directory scanning with file-by-file live status streaming.
6. **Sentinel Guard**: Toggle real-time background protection on your `Downloads` folder with an interactive alert feed.
7. **Quarantine Vault**: Review neutralized files, inspect threat origins, or restore files safely.
8. **Engine Settings**: Inspect API key status, select models, and adjust threat sensitivity thresholds (Strict, Balanced, Permissive).

---

## Supported File Formats, Links & Processes

Jev-AV supports deep static inspection and semantic evaluation across **all domains**:

* **Running Windows Processes (EDR)**: Process lineage (PPID), parentage anomalies (Office/Browser spawning command interpreters), Living-off-the-Land Binaries (LOLBINs), masquerading system binaries outside `System32`, command-line obfuscation, memory RSS, and active outbound TCP/UDP sockets.
* **Links & Web URLs** (`http://`, `https://`): Evaluates domain lexical features, IP-in-host, high-risk TLDs (`.xyz`, `.top`, `.click`), Shannon domain entropy (DGA), credential harvesting tokens, direct binary payload extensions, and follows redirect chains safely.
* **Windows PE Executables & DLLs** (`.exe`, `.dll`, `.sys`): Section entropy analysis (`.upx`, `.aspack`) and sensitive imported APIs (process injection, memory tampering, network C2, registry persistence).
* **Linux ELF Binaries** (`.elf`): Dynamic symbols, stripped status, and process control primitives (`ptrace`, `mprotect`, `execve`).
* **Office Documents** (`.docx`, `.xlsx`, `.pptx`, `.docm`, `.xlsm`): VBA macro detection (`vbaProject.bin`), external template injection, and embedded payloads.
* **PDF Documents** (`.pdf`): Scans for automated launch actions (`/Launch`, `/OpenAction`), embedded JavaScript (`/JS`), and hidden attachments.
* **Containers & Archives** (`.zip`, `.apk`, `.jar`, `.tar`): Scans contained files, detecting hidden executables and double-extension decoys (`.pdf.exe`).
* **Windows Shortcuts** (`.lnk`): Discovers command-line argument smuggling (`powershell -w hidden`, `mshta`, `cmd.exe`).
* **Scripts & Code** (`.ps1`, `.bat`, `.vbs`, `.js`, `.py`, `.sh`, `.cmd`): Detects base64 encoding, download strings, and evasion parameters.
* **Web & Markup** (`.html`, `.hta`, `.svg`, `.xml`): Script tag inspection, HTA applets, and redirect triggers.
* **Text & Data / LLM Prompts** (`.txt`, `.md`, `.json`): Evaluates for hidden Unicode exploits, bi-directional Trojan Source overrides, and adversarial prompt injections.

---

## CLI Usage

### 1. Launch Desktop GUI
```bash
python cli.py gui
# or: jev-av gui
```

### 2. Live Process EDR Triage
```bash
# Sweep running processes and display Jev threat triage:
python cli.py edr-ps

# Deep forensic inspection of a specific process by PID:
python cli.py edr-scan 1234

# Safely terminate a hostile or compromised process:
python cli.py edr-kill 1234
```

### 3. Scan a URL or Link
```bash
# Scan a suspicious website:
python cli.py scan-url https://suspicious-login-update.xyz/verify.php

# Scan a direct download link:
python cli.py scan-url http://example.com/payload.exe
```

### 4. Scan an Individual File
```bash
# Scan a script:
python cli.py scan ./samples/test_dropper.ps1

# Scan an executable:
python cli.py scan C:\Windows\System32\notepad.exe
```

### 5. Scan an Entire Directory
```bash
python cli.py scan-dir C:\Users\newuser\Downloads --limit 10
```

### 6. Run Real-Time Sentinel Guard
```bash
python cli.py watch C:\Users\newuser\Downloads
```

### 7. High-Speed Bulk Triage (Powered by classifier.dev / Jev System One)
```bash
# Bulk pre-filter thousands of folder files in 1 batch call:
python cli.py bulk-files C:\Users\newuser\Downloads --deep-scan

# Bulk triage hundreds of URLs or threat intel feeds:
python cli.py bulk-urls https://domain1.com https://domain2.com/payload.exe urls.txt

# Audit all running Windows system processes in 1 batch call (< 2 seconds):
python cli.py bulk-edr --tier fast
```
