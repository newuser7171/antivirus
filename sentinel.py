import sys
import time
import shutil
from pathlib import Path
from typing import Set, Dict
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileSystemEvent

# Ensure safe UTF-8 output on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

from rich.console import Console
from rich.panel import Panel
from rich.markup import escape

from feature_extractor import extract_features
from jev_scanner import JevFileScanner
from reporter import render_scan_report

console = Console(highlight=False)

IGNORED_EXTENSIONS = {
    ".tmp", ".crdownload", ".part", ".opdownload", ".download",
    ".lock", ".swp", ".bak", ".log", ".partial"
}

class RealTimeProtectionHandler(FileSystemEventHandler):
    def __init__(self, scanner: JevFileScanner, quarantine_dir: Path, auto_quarantine: bool = True, event_callback = None):
        super().__init__()
        self.scanner = scanner
        self.quarantine_dir = quarantine_dir
        self.auto_quarantine = auto_quarantine
        self.event_callback = event_callback
        self.scanned_cache: Dict[str, float] = {} # path -> last_scanned_timestamp
        self.cooldown_seconds = 5.0

    def should_ignore(self, path: Path) -> bool:
        if path.is_dir():
            return True
        if path.suffix.lower() in IGNORED_EXTENSIONS:
            return True
        if path.name.startswith((".", "~$")):
            return True
        # Check if inside quarantine dir
        try:
            if self.quarantine_dir.resolve() in path.resolve().parents:
                return True
        except Exception:
            pass
        return False

    def on_created(self, event: FileSystemEvent):
        if not event.is_directory:
            self.process_file(Path(event.src_path))

    def on_modified(self, event: FileSystemEvent):
        if not event.is_directory:
            self.process_file(Path(event.src_path))

    def process_file(self, file_path: Path):
        path_str = str(file_path.resolve())
        now = time.time()

        if self.should_ignore(file_path):
            return

        # Deduplicate duplicate events
        if path_str in self.scanned_cache:
            if now - self.scanned_cache[path_str] < self.cooldown_seconds:
                return
        self.scanned_cache[path_str] = now

        # Wait briefly for browser/writer to release file lock
        time.sleep(0.8)
        if not file_path.exists():
            return

        console.print(f"\n[bold yellow]⚡ [REAL-TIME DETECTED][/bold yellow] New or modified file: [cyan]{file_path.name}[/cyan]")
        if self.event_callback:
            try:
                self.event_callback("detected", {"path": file_path, "name": file_path.name})
            except Exception:
                pass
        
        try:
            features = extract_features(file_path)
            result = self.scanner.scan_file_features(features)
            render_scan_report(features, result)

            if self.event_callback:
                try:
                    self.event_callback("scanned", {"path": file_path, "name": file_path.name, "features": features, "result": result})
                except Exception:
                    pass

            if result["action"] == "QUARANTINE" and self.auto_quarantine:
                self.quarantine_file(file_path, features, result)

        except PermissionError:
            # File still locked by another process, will catch on next event
            pass
        except Exception as e:
            console.print(f"[red]Error inspecting {escape(file_path.name)}: {escape(str(e))}[/red]")
            if self.event_callback:
                try:
                    self.event_callback("error", {"path": file_path, "name": file_path.name, "error": str(e)})
                except Exception:
                    pass

    def quarantine_file(self, file_path: Path, features: dict, result: dict):
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        target_name = f"{timestamp}_{file_path.name}.quarantined"
        target_dest = self.quarantine_dir / target_name

        try:
            shutil.move(str(file_path), str(target_dest))
            console.print(Panel(
                f"[bold white on red]🛡️  AUTOMATIC QUARANTINE APPLIED[/]\n\n"
                f"Threat Neutralized: [bold]{escape(file_path.name)}[/bold]\n"
                f"Moved To: [dim]{escape(str(target_dest))}[/dim]\n"
                f"Original SHA-256: [dim]{features['sha256']}[/dim]",
                border_style="red"
            ))

            # Append to log
            log_file = self.quarantine_dir / "quarantine_history.log"
            with open(log_file, "a", encoding="utf-8") as f:
                f.write(f"[{time.asctime()}] QUARANTINED: {file_path.name} | SHA256: {features['sha256']} | Severity: {result['severity_score']:.2f}\n")

            if self.event_callback:
                try:
                    self.event_callback("quarantined", {"path": file_path, "name": file_path.name, "dest": target_dest, "features": features, "result": result})
                except Exception:
                    pass

        except Exception as e:
            console.print(f"[bold red]Failed to quarantine {escape(file_path.name)}: {escape(str(e))}[/bold red]")


def start_sentinel(watch_path: Path, auto_quarantine: bool = True):
    scanner = JevFileScanner()
    quarantine_dir = Path(__file__).parent / "quarantine"
    quarantine_dir.mkdir(parents=True, exist_ok=True)

    handler = RealTimeProtectionHandler(scanner, quarantine_dir, auto_quarantine=auto_quarantine)
    observer = Observer()
    observer.schedule(handler, str(watch_path), recursive=True)
    observer.start()

    console.print(Panel(
        f"[bold green]🛡️  JEV-AV REAL-TIME PROTECTION ACTIVATED[/]\n\n"
        f"• [bold]Monitoring Folder:[/bold] [cyan]{watch_path}[/cyan]\n"
        f"• [bold]Auto-Quarantine:[/bold] [{'green' if auto_quarantine else 'yellow'}]{'ENABLED (Moves threats to quarantine/)' if auto_quarantine else 'DISABLED (Alerts only)'}[/]\n"
        f"• [bold]Engine:[/bold] TypeSafe Jev System One (`jev-latest`)\n\n"
        f"[dim]Press Ctrl+C to stop real-time monitoring.[/dim]",
        border_style="green"
    ))

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        console.print("\n[yellow]Stopping real-time protection...[/yellow]")
        observer.stop()
    observer.join()
    console.print("[green]Real-time protection stopped safely.[/green]")
