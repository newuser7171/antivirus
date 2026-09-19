import sys
import argparse
from pathlib import Path
from rich.console import Console

# UTF-8 Console for Windows
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

from feature_extractor import extract_features
from jev_scanner import JevFileScanner
from reporter import render_scan_report
from sentinel import start_sentinel

console = Console()

def scan_file(file_path: Path, scanner: JevFileScanner):
    try:
        console.print(f"[bold cyan]🔍 Extracting static attributes from:[/bold cyan] {file_path.name}")
        features = extract_features(file_path)
        
        console.print(f"[bold cyan]🧠 Querying Jev System One model...[/bold cyan]")
        result = scanner.scan_file_features(features)
        
        render_scan_report(features, result)
        return result
    except Exception as e:
        console.print(f"[bold red]❌ Error scanning {file_path.name}: {e}[/bold red]")
        return None

def main():
    parser = argparse.ArgumentParser(description="Jev-AV: AI-Powered File Antivirus & Threat Triage Scanner")
    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # Scan single file
    scan_parser = subparsers.add_parser("scan", help="Scan a single target file")
    scan_parser.add_argument("file_path", nargs="+", help="Path to the file to inspect")

    # Scan directory
    dir_parser = subparsers.add_parser("scan-dir", help="Scan files in a directory")
    dir_parser.add_argument("dir_path", type=str, help="Directory path to scan")
    dir_parser.add_argument("--limit", type=int, default=10, help="Max files to scan (default 10, use 0 for all)")

    # Real-time watcher
    watch_parser = subparsers.add_parser("watch", help="Start real-time file protection on a directory")
    watch_parser.add_argument("watch_dir", nargs="?", default=str(Path.home() / "Downloads"), help="Directory to monitor (default: ~/Downloads)")
    watch_parser.add_argument("--no-quarantine", action="store_true", help="Alert only without moving threats to quarantine")

    # Run demo
    subparsers.add_parser("demo", help="Run scan on built-in sample files (clean vs suspicious)")

    # Launch Desktop GUI
    subparsers.add_parser("gui", help="Launch the Jev-AV Desktop Graphical User Interface")

    # Scan URL / Link
    url_parser = subparsers.add_parser("scan-url", help="Scan a website URL or download link for phishing and malware")
    url_parser.add_argument("url", type=str, help="URL to inspect (e.g. https://suspicious-site.com/login)")
    url_parser.add_argument("--no-probe", action="store_true", help="Skip network probe and perform static lexical inspection only")

    # Bulk triage commands powered by classifier.dev
    bulk_urls_parser = subparsers.add_parser("bulk-urls", help="Triage hundreds of URLs in 1 batch HTTP call via classifier.dev")
    bulk_urls_parser.add_argument("urls", nargs="+", help="List of URLs or a .txt file containing URLs (one per line)")

    bulk_files_parser = subparsers.add_parser("bulk-files", help="Rapid pre-filtering of large folders in 1 batch call via classifier.dev")
    bulk_files_parser.add_argument("dir_path", type=str, help="Directory to pre-filter")
    bulk_files_parser.add_argument("--deep-scan", action="store_true", help="Automatically trigger deep static inspection on flagged files")

    bulk_edr_parser = subparsers.add_parser("bulk-edr", help="Audit all running system processes concurrently in 1 batch call via classifier.dev")
    bulk_edr_parser.add_argument("--tier", choices=["fast", "smart"], default="fast", help="Classifier tier (default: fast)")

    # EDR Process Commands
    edr_ps_parser = subparsers.add_parser("edr-ps", help="List active running processes triaged by Jev System One")
    edr_ps_parser.add_argument("--all", action="store_true", help="Include all benign system background processes")
    edr_ps_parser.add_argument("--limit", type=int, default=15, help="Max processes to evaluate (default 15)")

    edr_scan_parser = subparsers.add_parser("edr-scan", help="Deep forensic inspection of a running process by PID")
    edr_scan_parser.add_argument("pid", type=int, help="Target Process ID (PID) to analyze")

    edr_kill_parser = subparsers.add_parser("edr-kill", help="Safely terminate a hostile or compromised process by PID")
    edr_kill_parser.add_argument("pid", type=int, help="Target Process ID (PID) to terminate")

    args = parser.parse_args()

    if not args.command or args.command == "demo":
        scanner = JevFileScanner()
        samples_dir = Path(__file__).parent / "samples"
        console.print("[bold green]🚀 Running Jev-AV Demo Suite on Sample Files...[/bold green]\n")
        
        sample_files = list(samples_dir.glob("*"))
        if not sample_files:
            console.print("[red]No sample files found in samples/ directory.[/red]")
            return

        for sf in sample_files:
            scan_file(sf, scanner)
            console.print("=" * 80)
        return

    if args.command == "gui":
        from gui import launch_gui
        launch_gui()
        return

    scanner = JevFileScanner()

    if args.command == "scan":
        target_str = " ".join(args.file_path).replace('\\"', '').replace('"', '').replace("'", "").strip()
        target = Path(target_str)
        if not target.exists():
            console.print(f"[bold red]File not found:[/bold red] {target}")
            sys.exit(1)
        scan_file(target, scanner)

    elif args.command == "watch":
        target_dir = Path(args.watch_dir).resolve()
        if not target_dir.exists():
            target_dir.mkdir(parents=True, exist_ok=True)
        start_sentinel(target_dir, auto_quarantine=not args.no_quarantine)

    elif args.command == "scan-dir":
        target_dir = Path(args.dir_path)
        if not target_dir.exists() or not target_dir.is_dir():
            console.print(f"[bold red]Directory not found:[/bold red] {target_dir}")
            sys.exit(1)

        all_files = [f for f in target_dir.rglob("*") if f.is_file()]
        if args.limit and args.limit > 0:
            files = all_files[:args.limit]
            console.print(f"[cyan]Found {len(all_files)} total files in {target_dir}. Scanning first {len(files)} files (use --limit 0 for all):[/cyan]\n")
        else:
            files = all_files
            console.print(f"[cyan]Scanning all {len(files)} files in {target_dir}:[/cyan]\n")
        
        for f in files:
            scan_file(f, scanner)
            console.print("-" * 60)

    elif args.command == "scan-url":
        from url_scanner import JevURLScanner
        from reporter import render_url_report
        url_scanner = JevURLScanner()
        console.print(f"[bold cyan]🔍 Extracting URL attributes and probing:[/bold cyan] {args.url}")
        features, result = url_scanner.scan_url(args.url, probe_network=not args.no_probe)
        render_url_report(features, result)

    elif args.command == "bulk-urls":
        from bulk_triage import triage_urls_bulk
        from rich.table import Table
        urls = []
        for item in args.urls:
            p = Path(item)
            if p.exists() and p.is_file():
                with open(p, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            urls.append(line)
            else:
                urls.append(item)

        console.print(f"[bold cyan]⚡ Bulk triaging {len(urls)} URLs via classifier.dev (Jev System One)...[/bold cyan]")
        results = triage_urls_bulk(urls)
        
        table = Table(title="Bulk URL Triage Results")
        table.add_column("Action", style="bold")
        table.add_column("Verdict")
        table.add_column("Confidence", justify="right")
        table.add_column("URL")
        
        for r in results:
            color = "green" if r["action"] == "ALLOW" else ("red" if r["action"] == "BLOCK" else "yellow")
            table.add_row(
                f"[{color}]{r['action']}[/{color}]",
                r["verdict"],
                f"{r['confidence']:.2f}",
                r["url"][:80]
            )
        console.print(table)

    elif args.command == "bulk-files":
        from bulk_triage import triage_files_bulk
        from rich.table import Table
        target_dir = Path(args.dir_path)
        if not target_dir.exists() or not target_dir.is_dir():
            console.print(f"[bold red]Directory not found:[/bold red] {target_dir}")
            sys.exit(1)

        all_files = [f for f in target_dir.rglob("*") if f.is_file()]
        console.print(f"[bold cyan]⚡ Bulk pre-filtering {len(all_files)} files via classifier.dev (Jev System One)...[/bold cyan]")
        results = triage_files_bulk(all_files)

        table = Table(title=f"Bulk Folder Pre-Filter: {target_dir.name}")
        table.add_column("Verdict", style="bold")
        table.add_column("Confidence", justify="right")
        table.add_column("File Name")
        table.add_column("Deep Scan?")

        deep_scan_queue = []
        for r in results:
            verdict = r["verdict"]
            color = "green" if verdict == "clean" else ("red" if verdict == "malicious" else "yellow")
            deep_req = "[bold red]YES[/bold red]" if r["needs_deep_scan"] else "[dim]skip[/dim]"
            table.add_row(
                f"[{color}]{verdict.upper()}[/{color}]",
                f"{r['confidence']:.2f}",
                r["name"],
                deep_req
            )
            if r["needs_deep_scan"]:
                deep_scan_queue.append(r["path"])

        console.print(table)
        console.print(f"[bold]Summary:[/bold] {len(all_files) - len(deep_scan_queue)} files skipped safely; {len(deep_scan_queue)} require deep static analysis.")

        if args.deep_scan and deep_scan_queue:
            console.print(f"\n[bold magenta]🔬 Triggering Deep Static Analysis on {len(deep_scan_queue)} flagged files...[/bold magenta]\n")
            for f in deep_scan_queue:
                scan_file(f, scanner)
                console.print("-" * 60)

    elif args.command == "bulk-edr":
        from bulk_triage import triage_processes_bulk
        from edr_monitor import get_all_active_processes
        from rich.table import Table
        console.print("[bold cyan]⚡ Capturing running processes for bulk classifier.dev audit...[/bold cyan]")
        procs = get_all_active_processes(suspicious_only=False)
        console.print(f"[cyan]Evaluating {len(procs)} system processes in 1 batch call...[/cyan]")
        results = triage_processes_bulk(procs, tier=args.tier)

        table = Table(title="Live EDR Bulk Process Audit (classifier.dev)")
        table.add_column("Action", style="bold")
        table.add_column("PID", justify="right")
        table.add_column("Process Name")
        table.add_column("Parent")
        table.add_column("Verdict")
        table.add_column("Confidence", justify="right")

        threat_count = 0
        for r in results:
            if r["is_threat"]:
                threat_count += 1
                color = "red" if r["action"] == "TERMINATE_RECOMMENDED" else "yellow"
                table.add_row(
                    f"[{color}]{r['action']}[/{color}]",
                    str(r["pid"]),
                    r["name"],
                    r["parent_name"],
                    r["verdict"],
                    f"{r['confidence']:.2f}"
                )
        if threat_count == 0:
            console.print("[bold green]✅ All scanned processes verified benign. No active threats or LOLBIN anomalies detected![/bold green]")
        else:
            console.print(table)
            console.print(f"[bold red]⚠️ Flagged {threat_count} anomalous processes requiring investigation.[/bold red]")

    elif args.command == "edr-ps":
        from edr_monitor import JevEDRScanner, get_all_active_processes
        from reporter import render_process_table
        scanner = JevEDRScanner()
        console.print("[bold cyan]🔍 Sweeping active Windows processes...[/bold cyan]")
        procs = get_all_active_processes(suspicious_only=not args.all)
        if args.limit and args.limit > 0:
            procs = procs[:args.limit]
        
        items = []
        for p in procs:
            r = scanner._evaluate_process_features(p)
            items.append({"features": p, "result": r})
        items.sort(key=lambda x: x["result"]["threat_score"], reverse=True)
        render_process_table(items)

    elif args.command == "edr-scan":
        from edr_monitor import JevEDRScanner
        from reporter import render_process_report
        scanner = JevEDRScanner()
        try:
            console.print(f"[bold cyan]🔍 Performing deep forensic inspection on PID {args.pid}...[/bold cyan]")
            features, result = scanner.scan_process_by_pid(args.pid)
            render_process_report(features, result)
        except Exception as e:
            console.print(f"[bold red]❌ EDR scan error:[/bold red] {e}")

    elif args.command == "edr-kill":
        from edr_monitor import terminate_process_by_pid
        success, msg = terminate_process_by_pid(args.pid)
        if success:
            console.print(f"[bold green]✅ {msg}[/bold green]")
        else:
            console.print(f"[bold red]❌ {msg}[/bold red]")

if __name__ == "__main__":
    main()
