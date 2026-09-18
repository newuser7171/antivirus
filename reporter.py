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
