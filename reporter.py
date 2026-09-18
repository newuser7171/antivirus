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
