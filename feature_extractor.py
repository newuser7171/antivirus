import io
import math
import re
import struct
import hashlib
import zipfile
import tarfile
from pathlib import Path
from typing import Dict, Any, List

try:
    import pefile
except ImportError:
    pefile = None

SENSITIVE_APIS = {
    "process_injection": [
        "virtualalloc", "virtualallocex", "writeprocessmemory", "createremotethread",
        "queueuserapc", "ntqueueapcthread", "ntwritevirtualmemory", "setthreadcontext"
    ],
    "anti_analysis_evasion": [
        "isdebuggerpresent", "checkremotedebuggerpresent", "ntqueryinformationprocess",
        "outputdebugstringa", "sleep", "timegettime"
    ],
    "network_c2": [
        "internetopena", "internetopenw", "internetconnecta", "httpsendrequesta",
        "urldownloadtofilea", "urldownloadtofilew", "wsastartup", "socket", "connect"
    ],
    "persistence_registry": [
        "regsetvalueexa", "regsetvaluew", "createservicea", "createservicew",
        "startservicectrldispatchera"
    ],
    "crypto_ransom": [
        "cryptencrypt", "cryptdecrypt", "cryptacquirecontexta", "bcryptencrypt"
    ]
}

SUSPICIOUS_KEYWORDS = [
    "downloadstring", "invoke-expression", "iex", "frombase64string",
    "windowstyle hidden", "executionpolicy bypass", "bypass", "noprofile",
    "certutil", "bitsadmin", "vssadmin delete shadows", "wmic shadowcopy delete",
    "net user", "reg add", "schtasks /create", "curl", "wget", "mshta",
    "reverse_tcp", "payload", "mimikatz", "lsass", "rundll32", "regsvr32",
    "powershell -w hidden", "cscript", "wscript.shell"
]

def calculate_entropy(data: bytes) -> float:
    """Calculates the Shannon entropy of a byte array (0.0 to 8.0)."""
    if not data:
        return 0.0
    entropy = 0.0
    total_len = len(data)
    byte_counts = [0] * 256
    for b in data:
        byte_counts[b] += 1
    for count in byte_counts:
        if count > 0:
            prob = count / total_len
            entropy -= prob * math.log2(prob)
    return round(entropy, 3)

def extract_strings(data: bytes, min_len: int = 4) -> List[str]:
    """Extracts printable ASCII and UTF-16 strings."""
    ascii_strings = re.findall(rb"[\x20-\x7E]{" + str(min_len).encode() + rb",}", data)
    found = [s.decode("ascii", errors="ignore") for s in ascii_strings]
    
    utf16_strings = re.findall(rb"(?:[\x20-\x7E]\x00){" + str(min_len).encode() + rb",}", data)
    for s in utf16_strings:
        try:
            found.append(s.decode("utf-16le", errors="ignore"))
        except Exception:
            pass
    return found

def detect_file_format(raw_data: bytes, ext: str) -> str:
    """Identifies the true file type via magic bytes and extensions."""
    if raw_data.startswith(b"MZ"):
        return "pe_binary"
    elif raw_data.startswith(b"\x7fELF"):
        return "elf_binary"
    elif raw_data.startswith(b"PK\x03\x04") or raw_data.startswith(b"PK\x05\x06"):
        if ext in [".docx", ".docm", ".dotm"]:
            return "office_word"
        elif ext in [".xlsx", ".xlsm", ".xltm"]:
            return "office_excel"
        elif ext in [".pptx", ".pptm"]:
            return "office_powerpoint"
        elif ext in [".apk", ".jar"]:
            return "android_or_java_archive"
        return "zip_archive"
    elif raw_data.startswith(b"%PDF"):
        return "pdf_document"
    elif raw_data.startswith(b"{\\rtf"):
        return "rtf_document"
    elif raw_data.startswith(b"\xd0\xcf\x11\xe0"):
        return "ole_compound_doc"
    elif raw_data.startswith(b"\x4c\x00\x00\x00\x01\x14\x02\x00") or ext == ".lnk":
        return "windows_shortcut_lnk"
    elif ext in [".ps1", ".bat", ".cmd", ".vbs", ".js", ".py", ".sh", ".bash"]:
        return "script"
    elif ext in [".html", ".htm", ".hta", ".svg", ".xml"]:
        return "web_or_markup"
    elif ext in [".txt", ".json", ".yaml", ".yml", ".ini", ".cfg", ".log", ".csv", ".md"]:
        return "text_data"
    else:
        return "generic_binary"

def analyze_pe(raw_data: bytes) -> Dict[str, Any]:
    """Analyzes a Windows Portable Executable (EXE/DLL)."""
    pe_info = {
        "imphash": None,
        "sections": [],
        "suspicious_sections": [],
        "matched_apis": {},
        "all_imports_count": 0
    }
    if not pefile:
        return pe_info

    try:
        pe = pefile.PE(data=raw_data, fast_load=True)
        pe.parse_data_directories()
        pe_info["imphash"] = pe.get_imphash()

        for section in pe.sections:
            sec_name = section.Name.decode("latin-1", errors="ignore").strip("\x00")
            sec_entropy = calculate_entropy(section.get_data())
            pe_info["sections"].append({
                "name": sec_name,
                "entropy": sec_entropy
            })
            if sec_name.lower().startswith((".upx", "upx", ".aspack", ".themida")) or sec_entropy > 7.3:
                pe_info["suspicious_sections"].append(f"{sec_name} (entropy: {sec_entropy})")

        matched_apis = {cat: [] for cat in SENSITIVE_APIS}
        total_imports = 0

        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    total_imports += 1
                    if imp.name:
                        func_name = imp.name.decode("latin-1", errors="ignore").lower()
                        for cat, api_list in SENSITIVE_APIS.items():
                            if func_name in api_list:
                                matched_apis[cat].append(func_name)

        pe_info["all_imports_count"] = total_imports
        pe_info["matched_apis"] = {k: list(set(v)) for k, v in matched_apis.items() if v}
        pe.close()
    except Exception as e:
        pe_info["error"] = str(e)

    return pe_info

def analyze_archive(raw_data: bytes, fmt: str) -> Dict[str, Any]:
    """Inspects archives and Office OpenXML documents for macros, embedded executables, etc."""
    info = {
        "contained_files": [],
        "has_vba_macros": False,
        "has_embedded_executables": False,
        "suspicious_entries": []
    }
    try:
        with zipfile.ZipFile(io.BytesIO(raw_data)) as z:
            names = z.namelist()
            info["contained_files"] = names[:20]

            for name in names:
                name_lower = name.lower()
                # Check for VBA macros in Office docs
                if "vbaproject.bin" in name_lower or "vba/" in name_lower or name_lower.endswith(".vba"):
                    info["has_vba_macros"] = True
                    info["suspicious_entries"].append(f"VBA Macro: {name}")
                
                # Check for hidden executables or scripts inside archive
                if name_lower.endswith((".exe", ".scr", ".bat", ".vbs", ".ps1", ".hta", ".cmd", ".iso")):
                    info["has_embedded_executables"] = True
                    info["suspicious_entries"].append(f"Executable Payload: {name}")

                # Double extension check
                if re.search(r"\.[a-zA-Z0-9]{2,4}\.(exe|scr|bat|vbs|ps1)$", name_lower):
                    info["suspicious_entries"].append(f"Double-Extension Decoy: {name}")
    except Exception as e:
        info["archive_read_error"] = str(e)

    return info

def analyze_pdf(raw_data: bytes) -> Dict[str, Any]:
    """Inspects PDF files for exploit triggers, embedded scripts, and launch actions."""
    text = raw_data.decode("latin-1", errors="ignore")
    findings = []
    
    triggers = [
        ("/JavaScript", "Embedded JavaScript code"),
        ("/JS", "Direct JavaScript action"),
        ("/Launch", "Automated system command execution"),
        ("/OpenAction", "Auto-executes payload on document open"),
        ("/EmbeddedFiles", "Carries hidden attachments or binary droppers"),
        ("/RichMedia", "Embedded Flash/video asset"),
        ("/URI", "Outbound hyperlink")
    ]
    for tag, desc in triggers:
        count = len(re.findall(re.escape(tag), text, re.IGNORECASE))
        if count > 0:
            findings.append(f"{desc} ({tag} count: {count})")

    return {
        "pdf_triggers": findings,
        "is_active_pdf": len([f for f in findings if "/Launch" in f or "/JS" in f or "/OpenAction" in f]) > 0
    }

def analyze_lnk(raw_data: bytes) -> Dict[str, Any]:
    """Inspects Windows LNK shortcuts for disguised PowerShell/CMD arguments."""
    strings = extract_strings(raw_data)
    combined = " ".join(strings)
    suspicious_args = []

    for kw in SUSPICIOUS_KEYWORDS:
        if kw in combined.lower():
            suspicious_args.append(kw)

    return {
        "lnk_strings": strings[:10],
        "suspicious_command_indicators": suspicious_args,
        "is_smuggling_command": len(suspicious_args) > 0 or "powershell" in combined.lower() or "cmd.exe" in combined.lower()
    }

def analyze_elf(raw_data: bytes) -> Dict[str, Any]:
    """Inspects Linux ELF binaries for symbols and network/process primitives."""
    strings = extract_strings(raw_data)
    combined = " ".join(strings).lower()
    
    elf_indicators = []
    for term in ["ptrace", "mprotect", "fork", "execve", "socket", "connect", "dlopen", "gethostbyname", "system"]:
        if term in combined:
            elf_indicators.append(term)

    return {
        "elf_sensitive_calls": elf_indicators[:8],
        "is_stripped": ".symtab" not in combined
    }

def extract_features(file_path: str | Path) -> Dict[str, Any]:
    """Inspects ANY file type and produces a rich, structured security feature dictionary."""
    path = Path(file_path).resolve()
    if not path.exists() or not path.is_file():
        raise FileNotFoundError(f"Target file not found: {path}")

    raw_data = path.read_bytes()
    file_size = len(raw_data)
    entropy = calculate_entropy(raw_data)

    md5_hash = hashlib.md5(raw_data).hexdigest()
    sha256_hash = hashlib.sha256(raw_data).hexdigest()

    all_strings = extract_strings(raw_data)
    text_content = "\n".join(all_strings[:1000])

    urls = list(set(re.findall(r"https?://[^\s\"'<>]+", text_content, re.IGNORECASE)))
    ips = list(set(re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", text_content)))
    public_ips = [ip for ip in ips if not ip.startswith(("127.", "10.", "192.168.", "0."))]

    found_keywords = []
    text_lower = text_content.lower()
    for kw in SUSPICIOUS_KEYWORDS:
        if re.search(r"\b" + re.escape(kw) + r"\b", text_lower):
            found_keywords.append(kw)

    file_fmt = detect_file_format(raw_data, path.suffix.lower())

    features = {
        "file_name": path.name,
        "extension": path.suffix.lower(),
        "file_format": file_fmt,
        "file_size_bytes": file_size,
        "entropy": entropy,
        "is_high_entropy": entropy > 7.15,
        "md5": md5_hash,
        "sha256": sha256_hash,
        "urls_detected": urls[:8],
        "ips_detected": public_ips[:8],
        "suspicious_keywords_found": found_keywords,
        "format_analysis": {}
    }

    # Format-specific deep inspections
    if file_fmt == "pe_binary":
        features["format_analysis"] = {"pe": analyze_pe(raw_data)}
    elif file_fmt in ["office_word", "office_excel", "office_powerpoint", "zip_archive", "android_or_java_archive"]:
        features["format_analysis"] = {"archive_or_office": analyze_archive(raw_data, file_fmt)}
    elif file_fmt == "pdf_document":
        features["format_analysis"] = {"pdf": analyze_pdf(raw_data)}
    elif file_fmt == "windows_shortcut_lnk":
        features["format_analysis"] = {"lnk": analyze_lnk(raw_data)}
    elif file_fmt == "elf_binary":
        features["format_analysis"] = {"elf": analyze_elf(raw_data)}
    elif file_fmt in ["script", "web_or_markup", "text_data"]:
        # Safe text preview
        try:
            script_text = raw_data.decode("utf-8", errors="ignore")
        except Exception:
            script_text = raw_data.decode("latin-1", errors="ignore")
        lines = script_text.splitlines()[:60]
        features["format_analysis"] = {"text_preview": "\n".join(lines)[:3500]}
    else: # Generic binary fallback
        features["format_analysis"] = {
            "generic_info": f"Raw binary data ({file_size} bytes). Entropy: {entropy}. Extracted strings count: {len(all_strings)}"
        }

    return features
