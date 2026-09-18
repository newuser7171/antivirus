import os
from typing import Dict, Any
from typesafe_sdk import TypeSafeClient, Choice, Score, Noul
from config import API_KEY, MODEL

class JevFileScanner:
    def __init__(self):
        if API_KEY:
            os.environ["TYPESAFE_API_KEY"] = API_KEY
        self.client = TypeSafeClient()

    def build_state(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """Constructs a rich, semantic state payload for Jev across any file type."""
        state = {
            "file_name": features["file_name"],
            "extension": features["extension"],
            "detected_format": features["file_format"],
            "size_kb": round(features["file_size_bytes"] / 1024, 2),
            "entropy": features["entropy"],
            "is_high_entropy": features["is_high_entropy"],
            "urls_detected": features["urls_detected"],
            "public_ips_detected": features["ips_detected"],
            "suspicious_keywords": features["suspicious_keywords_found"],
            "format_specific_evidence": features.get("format_analysis", {})
        }
        return state

    def scan_file_features(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """Queries Jev to evaluate threat verdict, severity, and MITRE indicators."""
        state = self.build_state(features)

        response = self.client.system_one(
            state=state,
            model=MODEL,
            questions={
                "verdict": Choice(
                    instructions="Determine the overall security disposition and verdict for this file",
                    criteria={
                        "clean": "Legitimate document, administrative tool, standard software binary, or benign script",
                        "suspicious_pua": "Potentially unwanted application, ambiguous dual-use utility, unverified macro/script, or anomaly",
                        "malicious": "Active threat: dropper, weaponized document, trojan, reverse shell, ransomware, or stealer"
                    }
                ),
                "threat_severity": Score(
                    instructions="Rate the threat severity level on an ordered 0 to 4 scale",
                    criteria=[
                        "0: Benign - Harmless user document or system utility",
                        "1: Low - Minor anomaly or dual-use administrative script",
                        "2: Moderate - Suspicious network calls, active macros, or unverified script behavior",
                        "3: High - Obfuscated dropper, weaponized PDF/LNK, unauthorized persistence, or credential access",
                        "4: Critical - Hostile payload, active ransomware, or reverse shell"
                    ]
                ),
                "is_packed_or_obfuscated": Noul(
                    instructions="Does this file employ high-entropy packing, code obfuscation, container smuggling, or evasion to conceal its logic?"
                ),
                "has_c2_download": Noul(
                    instructions="Does this file attempt to download remote binaries or communicate with an external command-and-control server?"
                ),
                "has_persistence": Noul(
                    instructions="Does this file attempt to install persistence mechanisms such as autorun keys, scheduled tasks, or services?"
                ),
                "has_injection_or_evasion": Noul(
                    instructions="Does this file attempt process injection, memory manipulation, exploit launching, debugger evasion, or defense tampering?"
                )
            }
        )

        verdict_ans = response.answers["verdict"]
        score_ans = response.answers["threat_severity"]
        obf_ans = response.answers["is_packed_or_obfuscated"]
        c2_ans = response.answers["has_c2_download"]
        persist_ans = response.answers["has_persistence"]
        inject_ans = response.answers["has_injection_or_evasion"]

        verdict_choice = getattr(verdict_ans, "choice", "suspicious_pua")
        verdict_conf = getattr(verdict_ans, "confidence", 0.5)
        severity_val = getattr(score_ans, "score", 2.0)
        c2_prob = getattr(c2_ans, "noul", 0.0)
        obf_prob = getattr(obf_ans, "noul", 0.0)
        inject_prob = getattr(inject_ans, "noul", 0.0)

        # Policy Triage Decision
        if verdict_choice == "malicious" and (verdict_conf > 0.55 or severity_val >= 2.5 or c2_prob > 0.6 or inject_prob > 0.6):
            action = "QUARANTINE"
        elif verdict_choice == "clean" and verdict_conf > 0.60 and severity_val < 1.3:
            action = "ALLOW"
        else:
            action = "SOC_REVIEW"

        return {
            "verdict": verdict_choice,
            "verdict_confidence": verdict_conf,
            "verdict_probabilities": getattr(verdict_ans, "probabilities", {}),
            "severity_score": severity_val,
            "severity_confidence": getattr(score_ans, "confidence", 0.5),
            "indicators": {
                "obfuscated_or_packed": obf_prob,
                "c2_dropper": c2_prob,
                "persistence": getattr(persist_ans, "noul", 0.0),
                "injection_or_evasion": inject_prob
            },
            "action": action
        }
