"""
Bulk Triage Engine for Jev-AV powered by classifier.dev (TypeSafe Jev System One).
Enables high-throughput, keyless batch pre-filtering of files, URLs, and running processes.
Batches up to 1,000 items per HTTP call with calibrated confidence and multi-label tagging.
"""

import json
import urllib.request
import urllib.error
from pathlib import Path
from typing import List, Dict, Any, Optional

CLASSIFIER_ENDPOINT = "https://classifier.dev"
USER_AGENT = "jev-av-edr/2.0 (Windows NT; TypeSafe Jev System One)"

def classify_batch(
    inputs: List[str],
    labels: List[str],
    instructions: Optional[str] = None,
    tier: str = "fast",
    multi: bool = False,
    max_labels: Optional[int] = None
) -> List[Dict[str, Any]]:
    """
    Classifies a batch of text inputs using classifier.dev (Jev System One).
    Supports up to 1,000 items per call.
    """
    if not inputs or not labels:
        return []

    # Ensure batch doesn't exceed 1000 items per call
    chunk_size = 1000
    all_results = []

    for i in range(0, len(inputs), chunk_size):
        chunk = inputs[i:i + chunk_size]
        payload: Dict[str, Any] = {
            "inputs": chunk,
            "labels": labels,
            "tier": tier
        }
        if instructions:
            payload["instructions"] = instructions
        if multi:
            payload["multi"] = True
            if max_labels:
                payload["max_labels"] = max_labels

        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            CLASSIFIER_ENDPOINT,
            data=body,
            headers={
                "Content-Type": "application/json",
                "User-Agent": USER_AGENT
            }
        )

        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.load(resp)
                all_results.extend(data.get("results", []))
        except Exception as e:
            # Fallback error objects for this chunk
            for _ in chunk:
                all_results.append({
                    "label": "unknown",
                    "confidence": 0.0,
                    "error": str(e),
                    "model": "fallback"
                })

    return all_results


def triage_urls_bulk(urls: List[str], tier: str = "fast") -> List[Dict[str, Any]]:
    """
    Bulk pre-filters up to 1,000 URLs in a single round-trip.
    Labels: clean_benign, phishing_credential_theft, malware_dropper, scam_fraud, suspicious_redirector.
    """
    labels = [
        "clean_benign",
        "phishing_credential_theft",
        "malware_dropper",
        "scam_fraud",
        "suspicious_redirector"
    ]
    instructions = (
        "Classify the security disposition of each URL. Flag login mimicry as phishing, "
        "direct payloads as malware_dropper, and legitimate domains as clean_benign. "
        "When in doubt, preserve suspicious URLs for SOC review."
    )
    results = classify_batch(urls, labels, instructions=instructions, tier=tier)
    
    annotated = []
    for url, res in zip(urls, results):
        annotated.append({
            "url": url,
            "verdict": res.get("label", "unknown"),
            "confidence": res.get("confidence", 0.0),
            "scores": res.get("scores", {}),
            "model": res.get("model", "jev-fast"),
            "action": "BLOCK" if res.get("label") in ["phishing_credential_theft", "malware_dropper"] and res.get("confidence", 0) >= 0.75 else ("ALERT" if res.get("label") != "clean_benign" else "ALLOW")
        })
    return annotated


def triage_files_bulk(file_paths: List[Path], tier: str = "fast") -> List[Dict[str, Any]]:
    """
    Fast pre-filter for large folders before expensive deep decompression or static extraction.
    Generates semantic summary per file and classifies them concurrently.
    """
    summaries = []
    valid_paths = []
    
    for p in file_paths:
        try:
            if not p.exists() or not p.is_file():
                continue
            stat = p.stat()
            size_kb = round(stat.st_size / 1024, 1)
            ext = p.suffix.lower()
            name = p.name
            summary = f"File '{name}' (ext: {ext}, size: {size_kb} KB)"
            summaries.append(summary)
            valid_paths.append(p)
        except Exception:
            continue

    if not summaries:
        return []

    labels = ["clean", "suspicious_pua", "malicious", "none of these"]
    instructions = (
        "Identify potentially malicious executables, macro scripts, obfuscated installers, "
        "or weaponized shortcuts. Standard documents, images, and verified system files are clean."
    )
    results = classify_batch(summaries, labels, instructions=instructions, tier=tier)

    annotated = []
    for p, summary, res in zip(valid_paths, summaries, results):
        verdict = res.get("label", "clean")
        if verdict == "none of these":
            verdict = "clean"
        conf = res.get("confidence", 0.0)
        annotated.append({
            "path": p,
            "name": p.name,
            "summary": summary,
            "verdict": verdict,
            "confidence": conf,
            "scores": res.get("scores", {}),
            "model": res.get("model", "jev-fast"),
            "needs_deep_scan": (verdict != "clean" or conf < 0.80)
        })
    return annotated


def triage_processes_bulk(process_list: List[Dict[str, Any]], tier: str = "fast") -> List[Dict[str, Any]]:
    """
    Audits hundreds of live running processes simultaneously in a single HTTP call.
    Flags LOLBIN abuse, hidden execution, and reverse shells.
    """
    descriptions = []
    for proc in process_list:
        pid = proc.get("pid", 0)
        name = proc.get("name", "unknown")
        parent = proc.get("parent_name", "unknown")
        cmd = proc.get("cmdline", "")[:200]
        net_count = len(proc.get("network_connections", []))
        desc = f"PID {pid} [{name}] parent=[{parent}] cmd=[{cmd}] active_net_sockets={net_count}"
        descriptions.append(desc)

    if not descriptions:
        return []

    labels = [
        "benign_system_process",
        "benign_user_application",
        "lolbin_execution_anomaly",
        "hostile_command_or_dropper",
        "none of these"
    ]
    instructions = (
        "Audit process execution telemetry. Flag Office or browsers spawning cmd/powershell, "
        "encoded commands, certutil downloads, and hidden window styles as lolbin or hostile. "
        "Standard OS services (svchost, explorer) and standard software are benign."
    )
    results = classify_batch(descriptions, labels, instructions=instructions, tier=tier)

    annotated = []
    for proc, desc, res in zip(process_list, descriptions, results):
        verdict = res.get("label", "benign_system_process")
        if verdict == "none of these":
            verdict = "benign_user_application"
        conf = res.get("confidence", 0.0)
        is_threat = verdict in ["lolbin_execution_anomaly", "hostile_command_or_dropper"]
        annotated.append({
            "pid": proc.get("pid"),
            "name": proc.get("name"),
            "parent_name": proc.get("parent_name"),
            "cmdline": proc.get("cmdline"),
            "verdict": verdict,
            "confidence": conf,
            "model": res.get("model", "jev-fast"),
            "is_threat": is_threat,
            "action": "TERMINATE_RECOMMENDED" if is_threat and conf >= 0.85 else ("INVESTIGATE" if is_threat else "ALLOW")
        })
    return annotated


def tag_mitre_techniques_bulk(threat_descriptions: List[str]) -> List[Dict[str, Any]]:
    """
    Multi-label tagging of threat events into MITRE ATT&CK tactical techniques.
    """
    labels = [
        "initial_access",
        "execution",
        "persistence",
        "privilege_escalation",
        "defense_evasion",
        "credential_access",
        "discovery",
        "lateral_movement",
        "command_and_control",
        "exfiltration",
        "impact_ransomware"
    ]
    return classify_batch(threat_descriptions, labels, multi=True, max_labels=4)
