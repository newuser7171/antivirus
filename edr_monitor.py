import os
import sys
import time
import re
from pathlib import Path
from typing import Dict, Any, List, Tuple, Optional

import psutil
from typesafe_sdk import TypeSafeClient, Choice, Score, Noul
from config import API_KEY, MODEL

# Living-off-the-Land Binaries commonly abused by attackers
LOLBINS = {
    "powershell.exe", "pwsh.exe", "cmd.exe", "certutil.exe", "mshta.exe",
    "cscript.exe", "wscript.exe", "rundll32.exe", "regsvr32.exe", "bitsadmin.exe",
    "wmic.exe", "vssadmin.exe", "schtasks.exe", "reg.exe", "net.exe", "nltest.exe"
}

# Suspicious parent processes that should not typically spawn command interpreters
SUSPICIOUS_PARENTS = {
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
    "acrord32.exe", "acrobat.exe", "chrome.exe", "msedge.exe", "firefox.exe",
    "sqlservr.exe", "w3wp.exe", "httpd.exe", "nginx.exe"
}

# Hostile or obfuscated command-line argument patterns
SUSPICIOUS_CMD_PATTERNS = [
    (r"-w\s+hidden|-windowstyle\s+hidden", "Hidden Window Style"),
    (r"-enc\s+|-encodedcommand\s+", "Base64 Encoded Command"),
    (r"bypass", "ExecutionPolicy Bypass"),
    (r"downloadstring|downloadfile", "Remote Web Download"),
    (r"iex\s+|invoke-expression", "Dynamic Code Execution (IEX)"),
    (r"frombase64string", "Base64 Decoding in Memory"),
    (r"vssadmin\s+delete\s+shadows", "Shadow Copy Deletion (Ransomware)"),
    (r"certutil.*-urlcache", "Certutil Remote Dropper"),
    (r"mimikatz|sekurlsa|lsass\.dmp", "Credential Dumping Signature")
]

# Standard Windows system binaries that should ONLY execute from C:\Windows\System32
CRITICAL_SYSTEM_BINARIES = {
    "svchost.exe", "lsass.exe", "services.exe", "csrss.exe",
    "smss.exe", "winlogon.exe", "wininit.exe", "explorer.exe"
}


def extract_process_features(proc: psutil.Process) -> Dict[str, Any]:
    """Safely inspects a running process, extracting behavioral, parentage, and network telemetry."""
    try:
        pid = proc.pid
        name = proc.name()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        raise

    exe_path = ""
    try:
        exe_path = proc.exe() or ""
    except Exception:
        pass

    cmdline_list = []
    try:
        cmdline_list = proc.cmdline() or []
    except Exception:
        pass
    cmdline_str = " ".join(cmdline_list)

    ppid = 0
    parent_name = "unknown"
    try:
        ppid = proc.ppid()
        parent = proc.parent()
        if parent:
            parent_name = parent.name()
    except Exception:
        pass

    # Memory & resource info
    mem_info = {"rss_mb": 0.0, "vms_mb": 0.0}
    try:
        m = proc.memory_info()
        mem_info = {
            "rss_mb": round(m.rss / (1024 * 1024), 2),
            "vms_mb": round(m.vms / (1024 * 1024), 2)
        }
    except Exception:
        pass

    # Active network connections
    net_conns = []
    try:
        for c in proc.connections(kind="inet"):
            if c.raddr:
                remote_ip = c.raddr.ip
                remote_port = c.raddr.port
                # Filter internal loopback
                if not remote_ip.startswith(("127.", "::1")):
                    net_conns.append({
                        "remote_ip": remote_ip,
                        "remote_port": remote_port,
                        "status": c.status,
                        "type": "TCP" if c.type == 1 else "UDP"
                    })
    except Exception:
        pass

    # Behavioral indicators
    name_lower = name.lower()
    exe_lower = exe_path.lower()
    parent_lower = parent_name.lower()
    cmd_lower = cmdline_str.lower()

    is_lolbin = name_lower in LOLBINS
    is_suspicious_parent = parent_lower in SUSPICIOUS_PARENTS and (name_lower in LOLBINS or "cmd" in name_lower or "powershell" in name_lower)

    # Masquerading check: binary named like system file but located in temp/appdata
    is_masquerading = False
    if name_lower in CRITICAL_SYSTEM_BINARIES:
        if exe_lower and not ("c:\\windows\\system32" in exe_lower or "c:\\windows" in exe_lower):
            is_masquerading = True

    is_temp_or_appdata = any(loc in exe_lower for loc in ["\\appdata\\", "\\temp\\", "\\downloads\\"])

    detected_cmd_anomalies = []
    for pattern, desc in SUSPICIOUS_CMD_PATTERNS:
        if re.search(pattern, cmd_lower):
            detected_cmd_anomalies.append(desc)

    return {
        "pid": pid,
        "name": name,
        "exe_path": exe_path,
        "ppid": ppid,
        "parent_name": parent_name,
        "cmdline": cmdline_str,
        "is_lolbin": is_lolbin,
        "is_suspicious_parent_spawn": is_suspicious_parent,
        "is_masquerading_system_binary": is_masquerading,
        "is_temp_or_appdata": is_temp_or_appdata,
        "cmdline_anomalies": detected_cmd_anomalies,
        "memory": mem_info,
        "network_connections": net_conns,
        "has_external_network": len(net_conns) > 0
    }


class JevEDRScanner:
    """Evaluates running process telemetry using TypeSafe Jev System One models."""

    def __init__(self, api_key: str = API_KEY, model: str = MODEL):
        self.api_key = api_key
        self.model = model
        if api_key:
            os.environ["TYPESAFE_API_KEY"] = api_key
        self.client = TypeSafeClient()

    def scan_process_by_pid(self, pid: int) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        try:
            proc = psutil.Process(pid)
            features = extract_process_features(proc)
            result = self._evaluate_process_features(features)
            return features, result
        except psutil.NoSuchProcess:
            raise ProcessLookupError(f"Process with PID {pid} is no longer running.")
        except psutil.AccessDenied:
            raise PermissionError(f"Access denied to process PID {pid}. Administrator rights required.")

    def _evaluate_process_features(self, features: Dict[str, Any]) -> Dict[str, Any]:
        if not self.api_key:
            return self._heuristic_fallback(features)

        state = {
            "pid": features["pid"],
            "process_name": features["name"],
            "executable_path": features["exe_path"],
            "parent_process": features["parent_name"],
            "command_line": features["cmdline"][:1000],
            "is_lolbin": features["is_lolbin"],
            "is_suspicious_parent_spawn": features["is_suspicious_parent_spawn"],
            "is_masquerading": features["is_masquerading_system_binary"],
            "is_running_from_temp_or_appdata": features["is_temp_or_appdata"],
            "command_line_anomalies": features["cmdline_anomalies"],
            "external_network_connections": features["network_connections"][:5]
        }

        try:
            response = self.client.system_one(
                state=state,
                model=self.model,
                questions={
                    "process_verdict": Choice(
                        instructions="Classify this running Windows process based on its execution context, parentage, arguments, and network state.",
                        criteria={
                            "clean_system": "Legitimate Windows OS background service or system component",
                            "clean_user_app": "Legitimate user desktop application, browser, or developer tooling",
                            "suspicious_anomaly": "Unusual execution path, unexpected parent, or ambiguous command-line arguments requiring review",
                            "active_malware_c2": "Process exhibiting active command-and-control communication, reverse shell, dropper, or credential access",
                            "defense_evasion_injection": "Process utilizing masquerading, process injection, defense tampering, or obfuscated Living-off-the-Land commands"
                        }
                    ),
                    "threat_severity": Score(
                        instructions="Rate the threat level of this running process on an ordered scale from 0.0 (benign) to 4.0 (critical hostile process).",
                        criteria=[
                            "0: Benign - Standard OS or user process with expected arguments",
                            "1: Low - Unsigned or dual-use tool without malicious intent",
                            "2: Suspicious - LOLBIN with network call, unexpected parent spawn, or temp execution",
                            "3: High - Obfuscated shell execution, unauthorized persistence, or masquerading system name",
                            "4: Critical - Active reverse shell, ransomware activity, or verified C2 communication"
                        ]
                    ),
                    "should_terminate": Noul(
                        instructions="Should this running process be terminated immediately to stop malicious activity and prevent system compromise?"
                    ),
                    "is_c2_beaconing": Noul(
                        instructions="Is this process communicating with an external Command & Control server or downloading remote payloads?"
                    ),
                    "is_living_off_the_land": Noul(
                        instructions="Is this a legitimate Windows administrative utility being abused to execute malicious commands or evade defenses?"
                    )
                }
            )

            answers = response.answers
            classification = getattr(answers["process_verdict"], "choice", "clean_user_app")
            class_conf = getattr(answers["process_verdict"], "confidence", 0.75)
            threat_sev = getattr(answers["threat_severity"], "score", 0.5)
            should_term_prob = getattr(answers["should_terminate"], "noul", 0.0)
            c2_prob = getattr(answers["is_c2_beaconing"], "noul", 0.0)
            lolbin_prob = getattr(answers["is_living_off_the_land"], "noul", 0.0)

            normalized_score = round(threat_sev / 4.0, 3)

            action = "ALLOW"
            if should_term_prob > 0.50 or normalized_score >= 0.60 or c2_prob > 0.65:
                action = "TERMINATE"
            elif normalized_score >= 0.35 or should_term_prob > 0.30:
                action = "SOC_REVIEW"

            return {
                "verdict": classification,
                "confidence": class_conf,
                "threat_score": normalized_score,
                "raw_severity": threat_sev,
                "action": action,
                "should_terminate_probability": should_term_prob,
                "is_c2_beaconing_probability": c2_prob,
                "is_living_off_the_land_probability": lolbin_prob,
                "probabilities": getattr(answers["process_verdict"], "probabilities", {}),
                "model": self.model
            }

        except Exception as e:
            fallback = self._heuristic_fallback(features)
            fallback["api_error"] = str(e)
            return fallback

    def _heuristic_fallback(self, features: Dict[str, Any]) -> Dict[str, Any]:
        risk_points = 0.0

        if features["is_masquerading_system_binary"]:
            risk_points += 2.5
        if features["is_suspicious_parent_spawn"]:
            risk_points += 2.0
        if len(features["cmdline_anomalies"]) > 0:
            risk_points += 1.5 * len(features["cmdline_anomalies"])
        if features["is_temp_or_appdata"] and features["is_lolbin"]:
            risk_points += 1.8
        elif features["is_temp_or_appdata"]:
            risk_points += 0.8
        if features["has_external_network"] and features["is_lolbin"]:
            risk_points += 1.2

        threat_score = min(1.0, round(risk_points / 4.0, 3))

        if features["is_masquerading_system_binary"] or (features["is_lolbin"] and "Base64" in str(features["cmdline_anomalies"])):
            classification = "defense_evasion_injection"
        elif features["has_external_network"] and features["is_lolbin"]:
            classification = "active_malware_c2"
        elif threat_score > 0.35:
            classification = "suspicious_anomaly"
        elif features["exe_path"].lower().startswith("c:\\windows"):
            classification = "clean_system"
        else:
            classification = "clean_user_app"

        action = "TERMINATE" if threat_score >= 0.6 else ("SOC_REVIEW" if threat_score >= 0.35 else "ALLOW")

        return {
            "verdict": classification,
            "confidence": 0.80,
            "threat_score": threat_score,
            "raw_severity": threat_score * 4.0,
            "action": action,
            "should_terminate_probability": threat_score,
            "is_c2_beaconing_probability": 0.75 if features["has_external_network"] and threat_score > 0.5 else 0.1,
            "is_living_off_the_land_probability": 0.9 if features["is_lolbin"] and threat_score > 0.4 else 0.1,
            "model": "heuristic_fallback"
        }


def get_all_active_processes(suspicious_only: bool = False) -> List[Dict[str, Any]]:
    """Gathers running process snapshots and filters prioritized items."""
    results = []
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            features = extract_process_features(proc)
            # If suspicious_only is true, filter out standard system services with no anomalies
            if suspicious_only:
                has_anomaly = (
                    features["is_lolbin"] or
                    features["is_suspicious_parent_spawn"] or
                    features["is_masquerading_system_binary"] or
                    features["is_temp_or_appdata"] or
                    len(features["cmdline_anomalies"]) > 0 or
                    features["has_external_network"]
                )
                if not has_anomaly:
                    continue
            results.append(features)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return results


def terminate_process_by_pid(pid: int) -> Tuple[bool, str]:
    """Safely attempts to kill a malicious process by PID."""
    try:
        proc = psutil.Process(pid)
        name = proc.name()
        proc.kill()
        proc.wait(timeout=2.0)
        return True, f"Process {name} (PID {pid}) was successfully terminated."
    except psutil.NoSuchProcess:
        return True, f"Process with PID {pid} is already terminated."
    except psutil.AccessDenied:
        return False, f"Access denied to terminate PID {pid}. Administrator rights required."
    except Exception as e:
        return False, f"Error terminating PID {pid}: {e}"


def suspend_process_by_pid(pid: int) -> Tuple[bool, str]:
    """Freezes process execution (useful for forensic memory preservation before triage)."""
    try:
        proc = psutil.Process(pid)
        name = proc.name()
        proc.suspend()
        return True, f"Process {name} (PID {pid}) execution suspended."
    except Exception as e:
        return False, f"Error suspending PID {pid}: {e}"


def resume_process_by_pid(pid: int) -> Tuple[bool, str]:
    """Resumes a suspended process."""
    try:
        proc = psutil.Process(pid)
        name = proc.name()
        proc.resume()
        return True, f"Process {name} (PID {pid}) execution resumed."
    except Exception as e:
        return False, f"Error resuming PID {pid}: {e}"
