# Jev-AV: AI-Powered File Antivirus & Threat Triage Scanner

A static analysis antivirus scanner powered by TypeSafe's **Jev** (`jev-latest`). Jev-AV inspects binary executables, scripts, and documents, extracting structural features (Shannon entropy, hashes, strings, PE imports/sections) and applying System One decision intelligence to deliver calibrated threat verdicts, severity scores, and MITRE-aligned behavioral indicators.

---

## Supported File Formats (Universal Scanning)

Jev-AV supports deep static inspection and semantic evaluation across **all file types**:

* **Windows PE Executables & DLLs** (`.exe`, `.dll`, `.sys`): Section entropy analysis (`.upx`, `.aspack`) and sensitive imported APIs (process injection, memory tampering, network C2, registry persistence).
* **Linux ELF Binaries** (`.elf`): Dynamic symbols, stripped status, and process control primitives (`ptrace`, `mprotect`, `execve`).
* **Office Documents** (`.docx`, `.xlsx`, `.pptx`, `.docm`, `.xlsm`): VBA macro detection (`vbaProject.bin`), external template injection, and embedded payloads.
* **PDF Documents** (`.pdf`): Scans for automated launch actions (`/Launch`, `/OpenAction`), embedded JavaScript (`/JS`), and hidden attachments.
* **Containers & Archives** (`.zip`, `.apk`, `.jar`, `.tar`): Scans contained files, detecting hidden executables and double-extension decoys (`.pdf.exe`).
* **Windows Shortcuts** (`.lnk`): Discovers command-line argument smuggling (`powershell -w hidden`, `mshta`, `cmd.exe`).
* **Scripts & Code** (`.ps1`, `.bat`, `.vbs`, `.js`, `.py`, `.sh`, `.cmd`): Detects base64 encoding, download strings, and evasion parameters.
* **Web & Markup** (`.html`, `.hta`, `.svg`, `.xml`): Script tag inspection, HTA applets, and redirect triggers.
* **Text & Data** (`.json`, `.yaml`, `.txt`, `.csv`, `.ini`, `.cfg`): Shannon entropy and string extraction.
* **Generic / Raw Binary**: Magic byte detection, high-entropy zone mapping, and URL/IP harvesting.

---

## Usage

### 1. Run the Demo Suite
```bash
python cli.py demo
```

### 2. Scan an Individual File
```bash
# Scan a script:
python cli.py scan ./samples/test_dropper.ps1

# Scan an executable:
python cli.py scan C:\Windows\System32\notepad.exe
```

### 3. Scan an Entire Directory
```bash
python cli.py scan-dir C:\Path\To\Inspect
```
