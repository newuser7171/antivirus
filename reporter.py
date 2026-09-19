from typing import Dict, Any
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()

def render_scan_report(features: Dict[str, Any], result: Dict[str, Any]):
    """Renders a comprehensive Rich terminal report for any scanned file type."""
    
    file_name = features["file_name"]
    file_size_kb = round(features["file_size_bytes"] / 1024, 2)
    entropy = features["entropy"]
    sha256 = features["sha256"]
    file_fmt = features.get("file_format", "unknown").replace("_", " ").title()

    action = result["action"]
    verdict = result["verdict"]
    conf = result["verdict_confidence"] * 100
    sev_score = result["severity_score"]
    indicators = result["indicators"]

    # Action Styling
    if action == "QUARANTINE":
        banner_title = "🛑 THREAT DETECTED: QUARANTINE RECOMMENDED"
        banner_style = "bold white on red"
        verdict_color = "red"
    elif action == "SOC_REVIEW":
        banner_title = "⚠️ SUSPICIOUS ANOMALY: SOC REVIEW REQUIRED"
        banner_style = "bold black on yellow"
        verdict_color = "yellow"
    else:
        banner_title = "✅ VERIFIED CLEAN: ALLOWED"
        banner_style = "bold white on green"
        verdict_color = "green"

    console.print()
    console.print(Panel(
        f"[bold]{banner_title}[/bold]\n"
        f"File: [bold]{file_name}[/bold] ({file_size_kb} KB) | Format: [bold cyan]{file_fmt}[/bold cyan] | SHA-256: [dim]{sha256[:16]}...[/dim]",
        style=banner_style
    ))

    # File Details Table
    file_table = Table(title="📄 Static Analysis Attributes", box=None)
    file_table.add_column("Attribute", style="cyan", width=24)
    file_table.add_column("Value", style="white")

    file_table.add_row("File Name", file_name)
    file_table.add_row("Detected Format", f"{file_fmt} ({features['extension']})")
    file_table.add_row("Shannon Entropy", f"{entropy:.3f} / 8.00 {'[bold red](HIGH ENTROPY - PACKED/ENCRYPTED)[/bold red]' if features['is_high_entropy'] else '[green](Normal distribution)[/green]'}")
    file_table.add_row("SHA-256 Hash", sha256)
    
    if features.get("urls_detected"):
        file_table.add_row("Extracted URLs", ", ".join(features["urls_detected"][:3]))
    if features.get("ips_detected"):
        file_table.add_row("Extracted IPs", ", ".join(features["ips_detected"][:3]))
    if features.get("suspicious_keywords_found"):
        file_table.add_row("Keywords Found", ", ".join(features["suspicious_keywords_found"][:5]))

    # Deep format specific findings
    fmt_analysis = features.get("format_analysis", {})
    if "pdf" in fmt_analysis:
        pdf_info = fmt_analysis["pdf"]
        if pdf_info.get("pdf_triggers"):
            file_table.add_row("PDF Triggers", "; ".join(pdf_info["pdf_triggers"]))
    elif "archive_or_office" in fmt_analysis:
        arch_info = fmt_analysis["archive_or_office"]
        if arch_info.get("suspicious_entries"):
            file_table.add_row("Archive Findings", "; ".join(arch_info["suspicious_entries"][:4]))
        if arch_info.get("has_vba_macros"):
            file_table.add_row("Macro Status", "[bold red]VBA Macros Present[/bold red]")
    elif "lnk" in fmt_analysis:
        lnk_info = fmt_analysis["lnk"]
        if lnk_info.get("suspicious_command_indicators"):
            file_table.add_row("LNK Command Injection", ", ".join(lnk_info["suspicious_command_indicators"]))
    elif "pe" in fmt_analysis:
        pe_info = fmt_analysis["pe"]
        if pe_info.get("suspicious_sections"):
            file_table.add_row("Suspicious Sections", ", ".join(pe_info["suspicious_sections"]))
        if pe_info.get("matched_apis"):
            apis = [f"{cat}: {', '.join(funcs)}" for cat, funcs in pe_info["matched_apis"].items()]
            file_table.add_row("Sensitive APIs", " | ".join(apis[:3]))

    console.print(Panel(file_table, border_style="cyan"))

    # Jev System One Telemetry Panel
    jev_table = Table(title="🧠 Jev System One Threat Assessment", box=None)
    jev_table.add_column("Decision Dimension", style="cyan", width=25)
    jev_table.add_column("Verdict / Score", style="white", width=20)
    jev_table.add_column("Confidence / Probability", style="white")

    # Verdict
    jev_table.add_row(
        "Security Verdict (Choice)",
        f"[{verdict_color}][bold]{verdict.upper()}[/bold][/{verdict_color}]",
        f"{conf:.1f}% confidence"
    )

    # Severity Score
    score_bar = "█" * int(sev_score * 5)
    sev_color = "red" if sev_score > 2.5 else "yellow" if sev_score > 1.2 else "green"
    jev_table.add_row(
        "Threat Severity (Score 0-4)",
        f"[{sev_color}]{sev_score:.2f} / 4.0[/{sev_color}]",
        f"[{sev_color}]{score_bar:<20}[/{sev_color}]"
    )

    # MITRE Indicators (Noul)
    for ind_name, prob in indicators.items():
        clean_name = ind_name.replace("_", " ").title()
        prob_pct = prob * 100
        p_color = "red" if prob > 0.50 else "yellow" if prob > 0.20 else "green"
        bar = "█" * int(prob * 20)
        flag = "🚨 ACTIVE" if prob > 0.50 else "⚠️ SUSPICIOUS" if prob > 0.20 else "CLEAN"
        jev_table.add_row(
            f"Indicator: {clean_name}",
            f"[{p_color}]{flag}[/{p_color}]",
            f"[{p_color}]{bar:<20} {prob_pct:4.1f}%[/{p_color}]"
        )

    console.print(Panel(jev_table, border_style="blue"))

    probs = result.get("verdict_probabilities", {})
    if probs:
        prob_str = " | ".join(f"{k}: {v*100:.1f}%" for k, v in probs.items())
        console.print(f"[dim]Alternative Disposition Distribution: {prob_str}[/dim]\n")


def render_url_report(features: Dict[str, Any], result: Dict[str, Any]):
    """Renders a comprehensive Rich terminal report for scanned URLs and links."""
    from rich.markup import escape

    url = features["normalized_url"]
    hostname = features["hostname"]
    verdict = result["verdict"]
    conf = result["confidence"] * 100
    score = result["threat_score"]
    action = result["action"]

    if action == "BLOCK":
        banner_title = "🛑 MALICIOUS LINK DETECTED: ACCESS BLOCKED"
        banner_style = "bold white on red"
        v_color = "red"
    elif action == "WARNING":
        banner_title = "⚠️ SUSPICIOUS LINK: ELEVATED THREAT DETECTED"
        banner_style = "bold black on yellow"
        v_color = "yellow"
    else:
        banner_title = "✅ VERIFIED SAFE LINK: ALLOWED"
        banner_style = "bold white on green"
        v_color = "green"

    console.print()
    console.print(Panel(
        f"[bold]{banner_title}[/bold]\n"
        f"Target: [bold cyan]{escape(url[:80])}{'...' if len(url) > 80 else ''}[/bold cyan] | Action: [bold {v_color}]{action}[/bold {v_color}]",
        style=banner_style
    ))

    # Details Table
    url_table = Table(title="🌐 URL & Domain Attributes", box=None)
    url_table.add_column("Attribute", style="cyan", width=22)
    url_table.add_column("Value", style="white")

    url_table.add_row("Hostname", escape(hostname))
    url_table.add_row("Protocol / Port", f"{features['scheme'].upper()} (Port {features['port']})")
    url_table.add_row("IP Address Host", "[bold red]YES (Host is raw IP)[/bold red]" if features["is_ip_address"] else "No (Domain name)")

    if features.get("tld"):
        tld_flag = " [bold red](High-risk abuse TLD)[/bold red]" if features["is_high_risk_tld"] else ""
        url_table.add_row("Top-Level Domain", f"{features['tld']}{tld_flag}")

    url_table.add_row("Domain Entropy", f"{features['domain_entropy']} / 8.00 {'[bold red](Randomized/DGA)[/bold red]' if features['is_high_entropy_domain'] else '[green](Normal)[/green]'}")

    if features.get("phishing_keywords"):
        url_table.add_row("Suspicious Keywords", f"[bold red]{', '.join(features['phishing_keywords'])}[/bold red]")

    if features.get("has_payload_extension"):
        url_table.add_row("Direct Payload Ext", f"[bold red]{features['payload_extension']}[/bold red]")

    if features.get("has_open_redirect"):
        url_table.add_row("Open Redirect Param", "[bold yellow]Detected redirect parameter in query[/bold yellow]")

    net = features.get("network_probe", {})
    if net.get("reachable"):
        hops = net.get("redirect_count", 0)
        final_u = net.get("final_url", url)
        url_table.add_row("HTTP Status Code", str(net.get("status_code")))
        if hops > 0:
            url_table.add_row("Redirect Hops", f"{hops} hops -> {escape(final_u[:60])}")
        url_table.add_row("Content-Type", str(net.get("content_type")))

    console.print(Panel(url_table, border_style="cyan"))

    # Jev Assessment Table
    jev_table = Table(title="🧠 Jev System One Threat Assessment", box=None)
    jev_table.add_column("Decision Dimension", style="cyan", width=25)
    jev_table.add_column("Verdict / Score", style="white", width=20)
    jev_table.add_column("Confidence / Probability", style="white")

    jev_table.add_row(
        "URL Classification (Choice)",
        f"[{v_color}][bold]{verdict.upper()}[/bold][/{v_color}]",
        f"{conf:.1f}% confidence"
    )

    score_bar = "█" * int(score * 20)
    score_color = "red" if score >= 0.6 else "yellow" if score >= 0.35 else "green"
    jev_table.add_row(
        "Threat Score (0.0 - 1.0)",
        f"[{score_color}]{score:.3f}[/{score_color}]",
        f"[{score_color}]{score_bar:<20} {score*100:.1f}%[/{score_color}]"
    )

    # Noul Indicators
    def add_noul_row(label, prob):
        p_pct = prob * 100
        p_color = "red" if prob > 0.50 else "yellow" if prob > 0.20 else "green"
        bar = "█" * int(prob * 20)
        flag = "🚨 ACTIVE" if prob > 0.50 else "⚠️ SUSPICIOUS" if prob > 0.20 else "CLEAN"
        jev_table.add_row(
            label,
            f"[{p_color}]{flag}[/{p_color}]",
            f"[{p_color}]{bar:<20} {p_pct:4.1f}%[/{p_color}]"
        )

    add_noul_row("Credential Phishing", result["is_phishing_probability"])
    add_noul_row("Malware Dropper", result["is_malware_dropper_probability"])
    add_noul_row("Access Block Decision", result["should_block_probability"])

    console.print(Panel(jev_table, border_style="blue"))


def render_process_report(features: Dict[str, Any], result: Dict[str, Any]):
    """Renders a comprehensive Rich terminal report for a running process."""
    from rich.markup import escape

    pid = features["pid"]
    name = features["name"]
    verdict = result["verdict"]
    conf = result["confidence"] * 100
    score = result["threat_score"]
    action = result["action"]

    if action == "TERMINATE":
        banner_title = "🛑 HOSTILE PROCESS DETECTED: TERMINATION RECOMMENDED"
        banner_style = "bold white on red"
        v_color = "red"
    elif action == "SOC_REVIEW":
        banner_title = "⚠️ SUSPICIOUS PROCESS ANOMALY: INVESTIGATION REQUIRED"
        banner_style = "bold black on yellow"
        v_color = "yellow"
    else:
        banner_title = "✅ LEGITIMATE PROCESS: NORMAL OPERATION"
        banner_style = "bold white on green"
        v_color = "green"

    console.print()
    console.print(Panel(
        f"[bold]{banner_title}[/bold]\n"
        f"Process: [bold cyan]{escape(name)}[/bold cyan] (PID: [bold]{pid}[/bold]) | Action: [bold {v_color}]{action}[/bold {v_color}]",
        style=banner_style
    ))

    # Process Attributes Table
    proc_table = Table(title="⚙️ Process Telemetry & Lineage", box=None)
    proc_table.add_column("Attribute", style="cyan", width=22)
    proc_table.add_column("Value", style="white")

    proc_table.add_row("Process Name (PID)", f"{escape(name)} ({pid})")
    proc_table.add_row("Executable Path", escape(features.get("exe_path", "Unknown")))
    proc_table.add_row("Parent Process (PPID)", f"{escape(features.get('parent_name', 'Unknown'))} (PPID: {features.get('ppid', 0)})")

    if features.get("is_suspicious_parent_spawn"):
        proc_table.add_row("Lineage Anomaly", "[bold red]SUSPICIOUS: Spawned by Office / Browser / Server[/bold red]")
    if features.get("is_masquerading_system_binary"):
        proc_table.add_row("Masquerading", "[bold red]CRITICAL: System binary running outside System32[/bold red]")
    if features.get("is_lolbin"):
        proc_table.add_row("LOLBIN Utility", "[bold yellow]Windows Administrative Binary (Dual-Use)[/bold yellow]")

    if features.get("cmdline_anomalies"):
        proc_table.add_row("Command Anomalies", f"[bold red]{', '.join(features['cmdline_anomalies'])}[/bold red]")

    cmdline_display = escape(features.get("cmdline", ""))
    if len(cmdline_display) > 90:
        cmdline_display = cmdline_display[:87] + "..."
    proc_table.add_row("Command Line", cmdline_display or "[dim]N/A[/dim]")

    mem = features.get("memory", {})
    proc_table.add_row("Memory RSS", f"{mem.get('rss_mb', 0)} MB")

    conns = features.get("network_connections", [])
    if conns:
        conn_str = "; ".join(f"{c['type']} -> {c['remote_ip']}:{c['remote_port']} ({c['status']})" for c in conns[:3])
        proc_table.add_row("Network Sockets", f"[bold red]{conn_str}[/bold red]")
    else:
        proc_table.add_row("Network Sockets", "No active external TCP/UDP connections")

    console.print(Panel(proc_table, border_style="cyan"))

    # Jev Assessment Table
    jev_table = Table(title="🧠 Jev System One Threat Assessment", box=None)
    jev_table.add_column("Decision Dimension", style="cyan", width=25)
    jev_table.add_column("Verdict / Score", style="white", width=20)
    jev_table.add_column("Confidence / Probability", style="white")

    jev_table.add_row(
        "Process Verdict (Choice)",
        f"[{v_color}][bold]{verdict.upper()}[/bold][/{v_color}]",
        f"{conf:.1f}% confidence"
    )

    score_bar = "█" * int(score * 20)
    score_color = "red" if score >= 0.6 else "yellow" if score >= 0.35 else "green"
    jev_table.add_row(
        "Threat Score (0.0 - 1.0)",
        f"[{score_color}]{score:.3f}[/{score_color}]",
        f"[{score_color}]{score_bar:<20} {score*100:.1f}%[/{score_color}]"
    )

    def add_noul_row(label, prob):
        p_pct = prob * 100
        p_color = "red" if prob > 0.50 else "yellow" if prob > 0.20 else "green"
        bar = "█" * int(prob * 20)
        flag = "🚨 ACTIVE" if prob > 0.50 else "⚠️ SUSPICIOUS" if prob > 0.20 else "CLEAN"
        jev_table.add_row(
            label,
            f"[{p_color}]{flag}[/{p_color}]",
            f"[{p_color}]{bar:<20} {p_pct:4.1f}%[/{p_color}]"
        )

    add_noul_row("C2 Beacon / Download", result.get("is_c2_beaconing_probability", 0.0))
    add_noul_row("LOLBIN Abuse", result.get("is_living_off_the_land_probability", 0.0))
    add_noul_row("Terminate Decision", result.get("should_terminate_probability", 0.0))

    console.print(Panel(jev_table, border_style="blue"))


def render_process_table(items: List[Dict[str, Any]]):
    """Renders an interactive overview table of running processes triaged by Jev."""
    from rich.markup import escape

    table = Table(title="⚡ Active Running Processes Triage", box=None)
    table.add_column("PID", style="cyan", width=8)
    table.add_column("Process Name", style="white", width=22)
    table.add_column("Verdict", style="white", width=18)
    table.add_column("Threat Score", style="white", width=14)
    table.add_column("Action", style="white", width=12)
    table.add_column("Lineage / Flags", style="dim")

    for item in items:
        f = item["features"]
        r = item["result"]
        act = r["action"]
        sev = r["threat_score"]

        color = "red" if act == "TERMINATE" else "yellow" if act == "SOC_REVIEW" else "green"

        flags = []
        if f.get("is_lolbin"):
            flags.append("LOLBIN")
        if f.get("is_suspicious_parent_spawn"):
            flags.append("ANOMALOUS_PARENT")
        if f.get("is_masquerading_system_binary"):
            flags.append("MASQUERADING")
        if f.get("cmdline_anomalies"):
            flags.extend(f["cmdline_anomalies"])
        if f.get("has_external_network"):
            flags.append("NET_CONN")

        flag_str = ", ".join(flags) if flags else f"Parent: {f.get('parent_name', 'System')}"

        table.add_row(
            str(f["pid"]),
            escape(f["name"]),
            f"[{color}]{r['verdict'].upper()}[/{color}]",
            f"[{color}]{sev:.2f}[/{color}]",
            f"[{color}][bold]{act}[/bold][/{color}]",
            escape(flag_str)
        )

    console.print(Panel(table, border_style="cyan"))

