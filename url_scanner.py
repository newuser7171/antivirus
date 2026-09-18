import math
import re
import socket
from urllib.parse import urlparse, parse_qs
from typing import Dict, Any, List, Tuple, Optional

import httpx
from typesafe_sdk import TypeSafeClient, Choice, Score, Noul
from config import API_KEY, MODEL

# High-risk top-level domains commonly abused for short-lived phishing/scam campaigns
HIGH_RISK_TLDS = {
    ".xyz", ".top", ".click", ".buzz", ".club", ".work", ".loan",
    ".tk", ".ml", ".ga", ".cf", ".gq", ".country", ".stream", ".kim"
}

# Suspicious keywords in domain or path indicating credential harvesting or account takeover
PHISHING_KEYWORDS = [
    "login", "signin", "verify", "verification", "secure", "account",
    "update", "banking", "wallet", "paypal", "appleid", "microsoft",
    "netflix", "recovery", "password", "authenticate", "confirm", "billing"
]

# Direct executable / payload extensions
PAYLOAD_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".msi",
    ".apk", ".iso", ".img", ".jar", ".hta", ".docm", ".xlsm"
}


def calculate_entropy(text: str) -> float:
    """Calculates Shannon entropy of a string (identifies random DGA domains)."""
    if not text:
        return 0.0
    freq = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    entropy = 0.0
    total = len(text)
    for count in freq.values():
        p = count / total
        entropy -= p * math.log2(p)
    return round(entropy, 3)


def extract_url_features(raw_url: str, probe_network: bool = True) -> Dict[str, Any]:
    """Inspects lexical, structural, and network characteristics of any URL."""
    url = raw_url.strip().strip("'\"")
    if not url.startswith(("http://", "https://", "ftp://")):
        url = "http://" + url

    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""

    # Lexical checks
    is_ip_address = bool(re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", hostname))
    is_punycode = "xn--" in hostname.lower()
    subdomains = hostname.split(".")
    subdomain_count = max(0, len(subdomains) - 2)

    # TLD analysis
    tld = ""
    if "." in hostname and not is_ip_address:
        tld = "." + subdomains[-1].lower()
    is_high_risk_tld = tld in HIGH_RISK_TLDS

    # Keyword detection in hostname and path
    combined_path_host = f"{hostname}/{path}".lower()
    matched_phish_keywords = [kw for kw in PHISHING_KEYWORDS if kw in combined_path_host]

    # Payload extension in path
    has_payload_extension = any(path.lower().endswith(ext) for ext in PAYLOAD_EXTENSIONS)
    detected_payload_ext = next((ext for ext in PAYLOAD_EXTENSIONS if path.lower().endswith(ext)), None)

    # Open redirect parameter checking
    has_open_redirect = any(param in query.lower() for param in ["url=", "redirect=", "next=", "dest=", "target="])

    # Hostname Shannon entropy (DGA detection)
    domain_entropy = calculate_entropy(hostname.replace(".", ""))

    features: Dict[str, Any] = {
        "original_url": raw_url,
        "normalized_url": url,
        "scheme": parsed.scheme,
        "hostname": hostname,
        "port": parsed.port or (443 if parsed.scheme == "https" else 80),
        "path": path,
        "query": query,
        "is_ip_address": is_ip_address,
        "is_punycode": is_punycode,
        "tld": tld,
        "is_high_risk_tld": is_high_risk_tld,
        "subdomain_count": subdomain_count,
        "domain_entropy": domain_entropy,
        "is_high_entropy_domain": domain_entropy > 3.85,
        "url_length": len(url),
        "phishing_keywords": matched_phish_keywords,
        "has_payload_extension": has_payload_extension,
        "payload_extension": detected_payload_ext,
        "has_open_redirect": has_open_redirect,
        "network_probe": {}
    }

    # Safe network probing (following redirects without executing JS/downloading body)
    if probe_network and hostname and not hostname.startswith(("127.", "10.", "192.168.", "0.")):
        try:
            with httpx.Client(follow_redirects=True, timeout=3.5, verify=False) as client:
                resp = client.head(url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"})
                # If HEAD fails or method not allowed, try streaming GET reading only first 512 bytes
                if resp.status_code in [405, 501]:
                    with client.stream("GET", url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}) as stream_resp:
                        resp = stream_resp

                redirect_chain = [str(r.url) for r in resp.history] + [str(resp.url)]
                features["network_probe"] = {
                    "reachable": True,
                    "final_url": str(resp.url),
                    "status_code": resp.status_code,
                    "redirect_count": len(resp.history),
                    "redirect_chain": redirect_chain,
                    "content_type": resp.headers.get("content-type", "unknown"),
                    "content_length": resp.headers.get("content-length", "unknown"),
                    "server": resp.headers.get("server", "unknown")
                }
        except Exception as e:
            features["network_probe"] = {
                "reachable": False,
                "error": str(e)
            }

    return features


class JevURLScanner:
    """Evaluates URL features using TypeSafe Jev System One models."""

    def __init__(self, api_key: str = API_KEY, model: str = MODEL):
        self.api_key = api_key
        self.model = model
        if api_key:
            import os
            os.environ["TYPESAFE_API_KEY"] = api_key
        self.client = TypeSafeClient()

    def scan_url(self, raw_url: str, probe_network: bool = True) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        features = extract_url_features(raw_url, probe_network=probe_network)
        result = self._evaluate_features(features)
        return features, result

    def _evaluate_features(self, features: Dict[str, Any]) -> Dict[str, Any]:
        if not self.api_key:
            return self._heuristic_fallback(features)

        state = {
            "url": features["normalized_url"],
            "hostname": features["hostname"],
            "path": features["path"],
            "is_ip_as_host": features["is_ip_address"],
            "is_punycode_homograph": features["is_punycode"],
            "tld": features["tld"],
            "is_high_risk_tld": features["is_high_risk_tld"],
            "domain_entropy": features["domain_entropy"],
            "subdomain_count": features["subdomain_count"],
            "detected_phishing_keywords": features["phishing_keywords"],
            "direct_payload_download": features["payload_extension"],
            "has_open_redirect": features["has_open_redirect"],
            "network": features.get("network_probe", {})
        }

        try:
            response = self.client.system_one(
                state=state,
                model=self.model,
                questions={
                    "url_classification": Choice(
                        instructions="Classify this URL into its most accurate security category.",
                        criteria={
                            "clean_benign": "Legitimate, reputable domain or benign web link",
                            "phishing_credential_theft": "Phishing portal, fake brand mimicry, or login credential harvester",
                            "malware_dropper": "Link delivering executable malware, exploit kit, or malicious binary payload",
                            "scam_social_engineering": "Scam website, fake tech support, or fraudulent lure",
                            "suspicious_redirector": "Obfuscated redirector, link shortener hiding payload, or open-redirect anomaly"
                        }
                    ),
                    "threat_severity": Score(
                        instructions="Rate the threat level of this link on a continuous scale from safe (0.0) to active cyberattack (4.0).",
                        criteria=[
                            "0: Safe - Legitimate, reputable domain with standard parameters",
                            "1: Low Risk - Minor anomalies, marketing tracking, or unverified new domain",
                            "2: Suspicious - High-risk TLD, credential tokens, or unmasked redirector",
                            "3: High Danger - Probable phishing site, fake brand portal, or unverified binary link",
                            "4: Critical Threat - Verified credential harvester, exploit kit, or active malware dropper"
                        ]
                    ),
                    "should_block": Noul(
                        instructions="Should network traffic or browser navigation to this URL be blocked to prevent credential theft or malware download?"
                    ),
                    "is_phishing": Noul(
                        instructions="Is this URL attempting phishing, fake brand mimicry, or login credential harvesting?"
                    ),
                    "is_malware_dropper": Noul(
                        instructions="Does this URL point directly to an executable dropper or malicious binary payload?"
                    )
                }
            )

            answers = response.answers
            classification = getattr(answers["url_classification"], "choice", "clean_benign")
            class_conf = getattr(answers["url_classification"], "confidence", 0.75)
            threat_sev = getattr(answers["threat_severity"], "score", 0.5)
            should_block_prob = getattr(answers["should_block"], "noul", 0.0)
            is_phish_prob = getattr(answers["is_phishing"], "noul", 0.0)
            is_dropper_prob = getattr(answers["is_malware_dropper"], "noul", 0.0)

            # Normalized 0.0 - 1.0 threat score
            normalized_score = round(threat_sev / 4.0, 3)

            action = "ALLOW"
            if should_block_prob > 0.50 or normalized_score >= 0.60 or is_phish_prob > 0.65 or is_dropper_prob > 0.65:
                action = "BLOCK"
            elif normalized_score >= 0.35 or should_block_prob > 0.30:
                action = "WARNING"

            return {
                "verdict": classification,
                "confidence": class_conf,
                "threat_score": normalized_score,
                "raw_severity": threat_sev,
                "action": action,
                "should_block_probability": should_block_prob,
                "is_phishing_probability": is_phish_prob,
                "is_malware_dropper_probability": is_dropper_prob,
                "probabilities": getattr(answers["url_classification"], "probabilities", {}),
                "model": self.model
            }

        except Exception as e:
            fallback = self._heuristic_fallback(features)
            fallback["api_error"] = str(e)
            return fallback

    def _heuristic_fallback(self, features: Dict[str, Any]) -> Dict[str, Any]:
        risk_points = 0.0

        if features["is_ip_address"]:
            risk_points += 1.5
        if features["is_punycode"]:
            risk_points += 1.8
        if features["is_high_risk_tld"]:
            risk_points += 1.0
        if features["has_payload_extension"]:
            risk_points += 2.2
        if len(features["phishing_keywords"]) >= 2:
            risk_points += 1.6
        elif len(features["phishing_keywords"]) == 1:
            risk_points += 0.8
        if features["has_open_redirect"]:
            risk_points += 1.0
        if features["is_high_entropy_domain"]:
            risk_points += 1.0

        threat_score = min(1.0, round(risk_points / 4.0, 3))

        if features["has_payload_extension"]:
            classification = "malware_dropper"
        elif features["phishing_keywords"]:
            classification = "phishing_credential_theft"
        elif features["has_open_redirect"]:
            classification = "suspicious_redirector"
        elif threat_score > 0.4:
            classification = "scam_social_engineering"
        else:
            classification = "clean_benign"

        action = "BLOCK" if threat_score >= 0.6 else ("WARNING" if threat_score >= 0.35 else "ALLOW")

        return {
            "verdict": classification,
            "confidence": 0.85,
            "threat_score": threat_score,
            "raw_severity": threat_score * 4.0,
            "action": action,
            "should_block_probability": threat_score,
            "is_phishing_probability": 0.8 if "phishing" in classification else 0.1,
            "is_malware_dropper_probability": 0.9 if "malware" in classification else 0.05,
            "model": "heuristic_fallback"
        }
