import os
import sys
import time
import shutil
import threading
import queue
from pathlib import Path
from typing import Optional, Dict, Any, List

import customtkinter as ctk
from tkinter import filedialog, messagebox

# Ensure local imports work cleanly
sys.path.insert(0, str(Path(__file__).parent))

from config import API_KEY, MODEL
from feature_extractor import extract_features
from jev_scanner import JevFileScanner
from url_scanner import JevURLScanner
from edr_monitor import JevEDRScanner, get_all_active_processes, terminate_process_by_pid, suspend_process_by_pid, resume_process_by_pid
from sentinel import RealTimeProtectionHandler
from watchdog.observers import Observer

# Set appearance and default color theme
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


class JevAVGUI(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Jev-AV | AI Autonomous Antivirus Engine")
        self.geometry("1100x720")
        self.minsize(950, 650)

        # Base directories
        self.app_dir = Path(__file__).parent
        self.quarantine_dir = self.app_dir / "quarantine"
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)

        # Core engine state
        self.scanner = JevFileScanner()
        self.url_scanner = JevURLScanner()
        self.edr_scanner = JevEDRScanner()
        self.is_scanning = False
        self.is_url_scanning = False
        self.is_edr_scanning = False
        self.current_scan_result: Optional[Dict[str, Any]] = None
        self.current_scan_features: Optional[Dict[str, Any]] = None
        self.current_file_path: Optional[Path] = None
        self.current_url_features: Optional[Dict[str, Any]] = None
        self.current_url_result: Optional[Dict[str, Any]] = None

        # EDR State
        self.edr_cached_procs: List[Dict[str, Any]] = []
        self.selected_proc_pid: Optional[int] = None
        self.selected_proc_features: Optional[Dict[str, Any]] = None
        self.selected_proc_result: Optional[Dict[str, Any]] = None

        # Sentinel state
        self.sentinel_observer: Optional[Observer] = None
        self.sentinel_running = False
        self.sentinel_events_queue = queue.Queue()

        # Statistics
        self.stats = {
            "scanned": 0,
            "threats": 0,
            "clean": 0,
            "quarantined": 0
        }
        self.recent_activities: List[Dict[str, Any]] = []

        # Configure responsive grid
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)

        # Build UI layout
        self.setup_sidebar()
        self.setup_main_container()

        # Show Dashboard initially
        self.select_view("dashboard")

        # Start periodic queue poller for sentinel events
        self.after(200, self.poll_sentinel_queue)

    def setup_sidebar(self):
        """Builds modern left-hand navigation sidebar."""
        self.sidebar_frame = ctk.CTkFrame(self, width=220, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(10, weight=1)

        # Brand header
        self.logo_label = ctk.CTkLabel(
            self.sidebar_frame,
            text="🛡️ JEV-AV",
            font=ctk.CTkFont(size=22, weight="bold")
        )
        self.logo_label.grid(row=0, column=0, padx=20, pady=(25, 2))

        self.sub_logo = ctk.CTkLabel(
            self.sidebar_frame,
            text="System One Neural Engine",
            font=ctk.CTkFont(size=11),
            text_color="gray"
        )
        self.sub_logo.grid(row=1, column=0, padx=20, pady=(0, 20))

        # Navigation Buttons
        self.nav_buttons = {}
        views = [
            ("dashboard", "📊  Dashboard"),
            ("scanner", "🔍  File Scanner"),
            ("link_scanner", "🔗  Link Scanner"),
            ("edr", "⚡  Live EDR"),
            ("folder", "📁  Folder Scanner"),
            ("sentinel", "👁️  Sentinel Guard"),
            ("vault", "🗄️  Quarantine Vault"),
            ("settings", "⚙️  Engine Settings")
        ]

        for idx, (view_name, label) in enumerate(views, start=2):
            btn = ctk.CTkButton(
                self.sidebar_frame,
                text=label,
                font=ctk.CTkFont(size=13, weight="bold"),
                anchor="w",
                height=38,
                corner_radius=8,
                fg_color="transparent",
                text_color=("gray10", "gray90"),
                hover_color=("gray70", "gray25"),
                command=lambda v=view_name: self.select_view(v)
            )
            btn.grid(row=idx, column=0, padx=15, pady=4, sticky="ew")
            self.nav_buttons[view_name] = btn

        # Bottom System Indicator
        self.status_badge = ctk.CTkLabel(
            self.sidebar_frame,
            text="🟢 Engine Active",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color="#2ecc71"
        )
        self.status_badge.grid(row=11, column=0, padx=20, pady=(0, 8))

        # Appearance mode selector
        self.appearance_menu = ctk.CTkOptionMenu(
            self.sidebar_frame,
            values=["Dark", "Light", "System"],
            command=self.change_appearance_mode,
            height=28
        )
        self.appearance_menu.grid(row=12, column=0, padx=20, pady=(0, 20), sticky="ew")
        self.appearance_menu.set("Dark")

    def setup_main_container(self):
        """Creates container for dynamically swapped view frames."""
        self.container = ctk.CTkFrame(self, corner_radius=0, fg_color=("gray95", "gray12"))
        self.container.grid(row=0, column=1, sticky="nsew", padx=0, pady=0)
        self.container.grid_rowconfigure(0, weight=1)
        self.container.grid_columnconfigure(0, weight=1)

        # Initialize view frames
        self.frames = {
            "dashboard": self.create_dashboard_view(),
            "scanner": self.create_scanner_view(),
            "link_scanner": self.create_link_scanner_view(),
            "edr": self.create_edr_view(),
            "folder": self.create_folder_view(),
            "sentinel": self.create_sentinel_view(),
            "vault": self.create_vault_view(),
            "settings": self.create_settings_view()
        }

    def select_view(self, view_name: str):
        """Switches view to the selected frame and updates sidebar active state."""
        for name, btn in self.nav_buttons.items():
            if name == view_name:
                btn.configure(fg_color=("gray75", "#1f538d"), text_color="white")
            else:
                btn.configure(fg_color="transparent", text_color=("gray10", "gray90"))

        for name, frame in self.frames.items():
            if name == view_name:
                frame.grid(row=0, column=0, sticky="nsew", padx=20, pady=20)
                if hasattr(frame, "on_show"):
                    frame.on_show()
            else:
                frame.grid_forget()

    def change_appearance_mode(self, new_mode: str):
        ctk.set_appearance_mode(new_mode.lower())

    # =========================================================================
    # VIEW: DASHBOARD
    # =========================================================================
    def create_dashboard_view(self) -> ctk.CTkFrame:
        view = ctk.CTkFrame(self.container, fg_color="transparent")
        view.grid_columnconfigure((0, 1, 2, 3), weight=1)
        view.grid_rowconfigure(4, weight=1)

        # Title Card
        title_banner = ctk.CTkFrame(view, corner_radius=12, fg_color=("#2980b9", "#1a365d"))
        title_banner.grid(row=0, column=0, columnspan=4, sticky="ew", pady=(0, 16))
        title_banner.grid_columnconfigure(0, weight=1)

        banner_title = ctk.CTkLabel(
            title_banner,
            text="AI-Powered Threat Protection is Active",
            font=ctk.CTkFont(size=20, weight="bold"),
            text_color="white"
        )
        banner_title.grid(row=0, column=0, padx=20, pady=(16, 4), sticky="w")

        banner_desc = ctk.CTkLabel(
            title_banner,
            text="Autonomous System One heuristic modeling • Real-time Sentinel • Multi-format steganography & prompt-injection shield",
            font=ctk.CTkFont(size=12),
            text_color="#cbd5e1"
        )
        banner_desc.grid(row=1, column=0, padx=20, pady=(0, 16), sticky="w")

        # Metric Cards
        self.dash_stat_scanned = self._create_stat_card(view, 1, 0, "FILES SCANNED", "0", "#3b82f6")
        self.dash_stat_threats = self._create_stat_card(view, 1, 1, "THREATS BLOCKED", "0", "#ef4444")
        self.dash_stat_clean = self._create_stat_card(view, 1, 2, "CLEAN APPROVED", "0", "#10b981")
        self.dash_stat_sentinel = self._create_stat_card(view, 1, 3, "SENTINEL GUARD", "IDLE", "#8b5cf6")

        # Quick Actions Row
        quick_frame = ctk.CTkFrame(view, corner_radius=10)
        quick_frame.grid(row=2, column=0, columnspan=4, sticky="ew", pady=(16, 16))
        quick_frame.grid_columnconfigure((0, 1, 2, 3), weight=1)

        ctk.CTkButton(
            quick_frame,
            text="🔍  Scan a File",
            height=40,
            font=ctk.CTkFont(weight="bold"),
            command=lambda: self.select_view("scanner")
        ).grid(row=0, column=0, padx=8, pady=12, sticky="ew")

        ctk.CTkButton(
            quick_frame,
            text="🔗  Scan a Link / URL",
            height=40,
            font=ctk.CTkFont(weight="bold"),
            fg_color="#0284c7",
            hover_color="#0369a1",
            command=lambda: self.select_view("link_scanner")
        ).grid(row=0, column=1, padx=8, pady=12, sticky="ew")

        ctk.CTkButton(
            quick_frame,
            text="📁  Scan Downloads",
            height=40,
            font=ctk.CTkFont(weight="bold"),
            fg_color="#059669",
            hover_color="#047857",
            command=self.quick_scan_downloads
        ).grid(row=0, column=2, padx=8, pady=12, sticky="ew")

        self.dash_guard_toggle_btn = ctk.CTkButton(
            quick_frame,
            text="👁️  Sentinel Shield",
            height=40,
            font=ctk.CTkFont(weight="bold"),
            fg_color="#7c3aed",
            hover_color="#6d28d9",
            command=self.toggle_sentinel_from_dashboard
        )
        self.dash_guard_toggle_btn.grid(row=0, column=3, padx=8, pady=12, sticky="ew")

        # Recent Activity Feed
        recent_label = ctk.CTkLabel(
            view,
            text="Recent Security Activities",
            font=ctk.CTkFont(size=16, weight="bold")
        )
        recent_label.grid(row=3, column=0, columnspan=4, sticky="w", pady=(0, 6))

        self.dash_activity_box = ctk.CTkTextbox(view, font=ctk.CTkFont(family="Consolas", size=12))
        self.dash_activity_box.grid(row=4, column=0, columnspan=4, sticky="nsew")
        self.dash_activity_box.insert("end", "[System] Jev-AV Neural Antivirus initialized.\n[Engine] Model: jev-latest ready.\n")
        self.dash_activity_box.configure(state="disabled")

        return view

    def _create_stat_card(self, parent, row, col, title, value, color) -> ctk.CTkLabel:
        card = ctk.CTkFrame(parent, corner_radius=10)
        card.grid(row=row, column=col, padx=6, pady=4, sticky="nsew")
        card.grid_columnconfigure(0, weight=1)

        t_lbl = ctk.CTkLabel(card, text=title, font=ctk.CTkFont(size=11, weight="bold"), text_color="gray")
        t_lbl.grid(row=0, column=0, padx=10, pady=(12, 2))

        val_lbl = ctk.CTkLabel(card, text=value, font=ctk.CTkFont(size=24, weight="bold"), text_color=color)
        val_lbl.grid(row=1, column=0, padx=10, pady=(0, 12))
        return val_lbl

    def update_dashboard_stats(self):
        self.dash_stat_scanned.configure(text=str(self.stats["scanned"]))
        self.dash_stat_threats.configure(text=str(self.stats["threats"]))
        self.dash_stat_clean.configure(text=str(self.stats["clean"]))
        status_text = "ACTIVE" if self.sentinel_running else "IDLE"
        self.dash_stat_sentinel.configure(text=status_text)
        if self.sentinel_running:
            self.dash_guard_toggle_btn.configure(text="🛑  Stop Sentinel Shield", fg_color="#dc2626", hover_color="#b91c1c")
        else:
            self.dash_guard_toggle_btn.configure(text="👁️  Activate Sentinel Shield", fg_color="#7c3aed", hover_color="#6d28d9")

    def log_activity(self, message: str):
        self.dash_activity_box.configure(state="normal")
        timestamp = time.strftime("%H:%M:%S")
        self.dash_activity_box.insert("end", f"[{timestamp}] {message}\n")
        self.dash_activity_box.see("end")
        self.dash_activity_box.configure(state="disabled")

    # =========================================================================
    # VIEW: FILE SCANNER
    # =========================================================================
    def create_scanner_view(self) -> ctk.CTkFrame:
        view = ctk.CTkFrame(self.container, fg_color="transparent")
        view.grid_columnconfigure(0, weight=1)
        view.grid_rowconfigure(3, weight=1)

        # Header
        header = ctk.CTkLabel(view, text="Deep File Security Inspection", font=ctk.CTkFont(size=20, weight="bold"))
        header.grid(row=0, column=0, sticky="w", pady=(0, 12))

        # Target Selector Card
        selector_card = ctk.CTkFrame(view, corner_radius=10)
        selector_card.grid(row=1, column=0, sticky="ew", pady=(0, 14))
        selector_card.grid_columnconfigure(0, weight=1)

        self.file_entry = ctk.CTkEntry(
            selector_card,
            placeholder_text="Choose a file to analyze (Executables, Scripts, Office, PDF, Archives, Shortcuts)...",
            height=38
        )
        self.file_entry.grid(row=0, column=0, padx=(14, 8), pady=14, sticky="ew")

        browse_btn = ctk.CTkButton(
            selector_card,
            text="📁 Browse...",
            width=110,
            height=38,
            command=self.browse_single_file
        )
        browse_btn.grid(row=0, column=1, padx=(0, 8), pady=14)

        self.scan_file_btn = ctk.CTkButton(
            selector_card,
            text="⚡ Analyze with Jev",
            width=150,
            height=38,
            font=ctk.CTkFont(weight="bold"),
            command=self.start_file_scan
        )
        self.scan_file_btn.grid(row=0, column=2, padx=(0, 14), pady=14)

        # Progress / Status indicator
        self.scanner_status_frame = ctk.CTkFrame(view, corner_radius=10)
        self.scanner_status_frame.grid(row=2, column=0, sticky="ew", pady=(0, 14))
        self.scanner_status_frame.grid_columnconfigure(0, weight=1)

        self.scan_status_label = ctk.CTkLabel(
            self.scanner_status_frame,
            text="Ready to inspect. Select any file above.",
            font=ctk.CTkFont(size=13)
        )
        self.scan_status_label.grid(row=0, column=0, padx=14, pady=(10, 4), sticky="w")

        self.scan_progress_bar = ctk.CTkProgressBar(self.scanner_status_frame, height=10)
        self.scan_progress_bar.grid(row=1, column=0, padx=14, pady=(0, 12), sticky="ew")
        self.scan_progress_bar.set(0)

        # Results Notebook / Card
        self.results_frame = ctk.CTkFrame(view, corner_radius=10)
        self.results_frame.grid(row=3, column=0, sticky="nsew")
        self.results_frame.grid_columnconfigure((0, 1), weight=1)
        self.results_frame.grid_rowconfigure(2, weight=1)

        # Verdict Header
        self.verdict_badge = ctk.CTkLabel(
            self.results_frame,
            text="AWAITING SCAN",
            font=ctk.CTkFont(size=18, weight="bold"),
            fg_color="gray25",
            corner_radius=8,
            padx=16,
            pady=6
        )
        self.verdict_badge.grid(row=0, column=0, padx=16, pady=16, sticky="w")

        self.score_display_label = ctk.CTkLabel(
            self.results_frame,
            text="Threat Severity: --",
            font=ctk.CTkFont(size=16, weight="bold")
        )
        self.score_display_label.grid(row=0, column=1, padx=16, pady=16, sticky="e")

        # Feature Summary Textbox
        self.features_textbox = ctk.CTkTextbox(
            self.results_frame,
            font=ctk.CTkFont(family="Consolas", size=12)
        )
        self.features_textbox.grid(row=2, column=0, columnspan=2, padx=16, pady=(0, 12), sticky="nsew")
        self.features_textbox.insert("end", "Select a file and click 'Analyze with Jev' to view complete feature analysis.\n")
        self.features_textbox.configure(state="disabled")

        # Bottom Action Bar
        action_bar = ctk.CTkFrame(self.results_frame, fg_color="transparent")
        action_bar.grid(row=3, column=0, columnspan=2, padx=16, pady=(0, 14), sticky="ew")
        action_bar.grid_columnconfigure(1, weight=1)

        self.quarantine_btn = ctk.CTkButton(
            action_bar,
            text="🛡️ Quarantine This File",
            fg_color="#dc2626",
            hover_color="#b91c1c",
            command=self.manual_quarantine_current_file,
            state="disabled"
        )
        self.quarantine_btn.grid(row=0, column=0, padx=(0, 8))

        self.open_loc_btn = ctk.CTkButton(
            action_bar,
            text="📂 Open File Directory",
            fg_color="gray30",
            hover_color="gray40",
            command=self.open_current_file_location,
            state="disabled"
        )
        self.open_loc_btn.grid(row=0, column=1, sticky="w")

        return view

    def browse_single_file(self):
        file_selected = filedialog.askopenfilename(
            title="Select File to Analyze",
            filetypes=[
                ("All Supported Files", "*.*"),
                ("Executables & Libraries", "*.exe;*.dll;*.sys;*.scr"),
                ("Scripts & Shell", "*.ps1;*.bat;*.cmd;*.vbs;*.py;*.js"),
                ("Documents & PDFs", "*.pdf;*.docm;*.xlsm;*.pptm;*.docx"),
                ("Archives & Shortcuts", "*.zip;*.rar;*.7z;*.tar;*.lnk")
            ]
        )
        if file_selected:
            self.file_entry.delete(0, "end")
            self.file_entry.insert(0, file_selected)

    def start_file_scan(self):
        target_path = self.file_entry.get().strip().strip('"').strip("'")
        if not target_path:
            messagebox.showwarning("No File Selected", "Please select or enter a file path to scan.")
            return

        path = Path(target_path)
        if not path.exists() or not path.is_file():
            messagebox.showerror("Invalid File", f"Cannot find file:\n{target_path}")
            return

        self.current_file_path = path
        self.is_scanning = True
        self.scan_file_btn.configure(state="disabled")
        self.quarantine_btn.configure(state="disabled")
        self.open_loc_btn.configure(state="disabled")
        self.scan_progress_bar.configure(mode="indeterminate")
        self.scan_progress_bar.start()
        self.scan_status_label.configure(text=f"Extracting static features from {path.name}...")

        # Run scan in background thread
        threading.Thread(target=self._file_scan_worker, args=(path,), daemon=True).start()

    def _file_scan_worker(self, path: Path):
        try:
            self.scan_status_label.configure(text=f"Analyzing {path.name} with Jev System One...")
            features = extract_features(path)
            result = self.scanner.scan_file_features(features)
            self.after(0, self._file_scan_complete, path, features, result)
        except Exception as e:
            self.after(0, self._file_scan_error, str(e))

    def _file_scan_complete(self, path: Path, features: dict, result: dict):
        self.is_scanning = False
        self.scan_progress_bar.stop()
        self.scan_progress_bar.configure(mode="determinate")
        self.scan_file_btn.configure(state="normal")
        self.open_loc_btn.configure(state="normal")

        self.current_scan_features = features
        self.current_scan_result = result

        # Update stats
        self.stats["scanned"] += 1
        severity = result.get("severity_score", 0.0)
        action = result.get("action", "ALLOW")
        threat_class = result.get("threat_classification", "clean")

        self.scan_progress_bar.set(severity)

        # Color-coded badge
        if severity >= 0.65 or action == "QUARANTINE":
            badge_color = "#dc2626"
            verdict_text = f"🚨 THREAT DETECTED: {threat_class.upper()}"
            self.stats["threats"] += 1
            self.quarantine_btn.configure(state="normal")
        elif severity >= 0.30:
            badge_color = "#d97706"
            verdict_text = f"⚠️ SUSPICIOUS: {threat_class.upper()}"
            self.stats["threats"] += 1
            self.quarantine_btn.configure(state="normal")
        else:
            badge_color = "#16a34a"
            verdict_text = "✅ CLEAN / BENIGN FILE"
            self.stats["clean"] += 1
            self.quarantine_btn.configure(state="disabled")

        self.verdict_badge.configure(text=verdict_text, fg_color=badge_color)
        self.score_display_label.configure(text=f"Threat Severity: {severity:.2f} / 1.00 ({severity*100:.1f}%)")
        self.scan_status_label.configure(text=f"Analysis complete for {path.name}. Verdict: {action}")

        # Populate features detail
        self.features_textbox.configure(state="normal")
        self.features_textbox.delete("1.0", "end")

        detail_text = f"=== JEV-AV SECURITY VERDICT ===\n"
        detail_text += f"Target File:      {path.name}\n"
        detail_text += f"Full Path:        {path}\n"
        detail_text += f"Detected Format:  {features.get('file_format', 'Unknown')}\n"
        detail_text += f"File Size:        {features.get('file_size_bytes', 0):,} bytes\n"
        detail_text += f"Entropy:          {features.get('entropy', 0.0):.3f} (High Entropy: {features.get('is_high_entropy')})\n"
        detail_text += f"SHA-256:          {features.get('sha256')}\n"
        detail_text += f"MD5:              {features.get('md5')}\n\n"
        detail_text += f"=== JEV SYSTEM ONE REASONING ===\n"
        detail_text += f"Classification:   {threat_class}\n"
        detail_text += f"Confidence:       {result.get('class_confidence', 0.0):.2%}\n"
        detail_text += f"Threat Score:     {severity:.3f}\n"
        detail_text += f"Action:           {action}\n\n"

        # Format-specific features
        fa = features.get("format_analysis", {})
        if "pe" in fa and not fa["pe"].get("error"):
            pe = fa["pe"]
            detail_text += f"=== PE EXECUTABLE IMPORTS ===\n"
            detail_text += f"Imphash:          {pe.get('imphash')}\n"
            detail_text += f"Total Imports:    {pe.get('all_imports_count', 0)}\n"
            detail_text += f"Matched Sensitive APIs:\n"
            for cat, apis in pe.get("matched_apis", {}).items():
                detail_text += f"  • {cat.upper()}: {', '.join(apis)}\n"
            if pe.get("suspicious_sections"):
                detail_text += f"Suspicious Sections: {', '.join(pe['suspicious_sections'])}\n"
            detail_text += "\n"

        if features.get("urls_detected"):
            detail_text += f"Detected URLs:    {', '.join(features['urls_detected'])}\n"
        if features.get("suspicious_keywords_found"):
            detail_text += f"Suspicious Terms: {', '.join(features['suspicious_keywords_found'])}\n"

        self.features_textbox.insert("end", detail_text)
        self.features_textbox.configure(state="disabled")

        self.update_dashboard_stats()
        self.log_activity(f"Scanned {path.name}: {verdict_text} (Score: {severity:.2f})")

    def _file_scan_error(self, err_msg: str):
        self.is_scanning = False
        self.scan_progress_bar.stop()
        self.scan_file_btn.configure(state="normal")
        self.scan_status_label.configure(text=f"Error: {err_msg}")
        messagebox.showerror("Scan Error", f"An error occurred during analysis:\n{err_msg}")

    def manual_quarantine_current_file(self):
        if not self.current_file_path or not self.current_file_path.exists():
            messagebox.showwarning("File Missing", "Target file no longer exists or was moved.")
            return

        confirm = messagebox.askyesno(
            "Confirm Quarantine",
            f"Are you sure you want to isolate and neutralize:\n\n{self.current_file_path.name}\n\nThis will move the file to the secure quarantine vault."
        )
        if not confirm:
            return

        try:
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            dest = self.quarantine_dir / f"{timestamp}_{self.current_file_path.name}.quarantined"
            shutil.move(str(self.current_file_path), str(dest))
            
            # Log
            log_file = self.quarantine_dir / "quarantine_history.log"
            with open(log_file, "a", encoding="utf-8") as f:
                f.write(f"[{time.asctime()}] MANUAL QUARANTINE: {self.current_file_path.name} -> {dest.name}\n")

            self.stats["quarantined"] += 1
            self.quarantine_btn.configure(state="disabled")
            self.verdict_badge.configure(text="🛡️ ISOLATED IN QUARANTINE", fg_color="#6b21a8")
            self.log_activity(f"Manual quarantine applied to {self.current_file_path.name}")
            messagebox.showinfo("Quarantined", f"Threat file has been neutralized and safely moved to:\n{dest.name}")
        except Exception as e:
            messagebox.showerror("Quarantine Failed", f"Failed to quarantine file:\n{e}")

    def open_current_file_location(self):
        if self.current_file_path:
            parent = self.current_file_path.parent
            if parent.exists():
                os.startfile(str(parent))

    # =========================================================================
    # VIEW: LINK SCANNER
    # =========================================================================
    def create_link_scanner_view(self) -> ctk.CTkFrame:
        view = ctk.CTkFrame(self.container, fg_color="transparent")
        view.grid_columnconfigure(0, weight=1)
        view.grid_rowconfigure(3, weight=1)

        # Header
        header = ctk.CTkLabel(view, text="Universal Link & Website Threat Scanner", font=ctk.CTkFont(size=20, weight="bold"))
        header.grid(row=0, column=0, sticky="w", pady=(0, 12))

        # Selector Card
        s_card = ctk.CTkFrame(view, corner_radius=10)
        s_card.grid(row=1, column=0, sticky="ew", pady=(0, 14))
        s_card.grid_columnconfigure(0, weight=1)

        self.url_entry = ctk.CTkEntry(
            s_card,
            placeholder_text="Enter or paste any link (e.g. https://suspicious-site.com/login or download URL)...",
            height=38
        )
        self.url_entry.grid(row=0, column=0, padx=(14, 8), pady=(14, 8), sticky="ew")

        paste_btn = ctk.CTkButton(
            s_card,
            text="📋 Paste",
            width=80,
            height=38,
            fg_color="gray30",
            hover_color="gray40",
            command=self.paste_url_from_clipboard
        )
        paste_btn.grid(row=0, column=1, padx=(0, 8), pady=(14, 8))

        self.scan_url_btn = ctk.CTkButton(
            s_card,
            text="⚡ Analyze Link",
            width=140,
            height=38,
            font=ctk.CTkFont(weight="bold"),
            fg_color="#0284c7",
            hover_color="#0369a1",
            command=self.start_url_scan
        )
        self.scan_url_btn.grid(row=0, column=2, padx=(0, 14), pady=(14, 8))

        # Options row inside card
        opts_row = ctk.CTkFrame(s_card, fg_color="transparent")
        opts_row.grid(row=1, column=0, columnspan=3, padx=14, pady=(0, 12), sticky="ew")

        self.url_probe_switch = ctk.CTkSwitch(
            opts_row,
            text="Safe Network Probe (Unmask redirect chains & inspect HTTP headers)",
            font=ctk.CTkFont(size=12)
        )
        self.url_probe_switch.grid(row=0, column=0, sticky="w")
        self.url_probe_switch.select()

        # Progress Frame
        self.url_status_frame = ctk.CTkFrame(view, corner_radius=10)
        self.url_status_frame.grid(row=2, column=0, sticky="ew", pady=(0, 14))
        self.url_status_frame.grid_columnconfigure(0, weight=1)

        self.url_status_label = ctk.CTkLabel(
            self.url_status_frame,
            text="Ready to inspect link. Paste any URL above.",
            font=ctk.CTkFont(size=13)
        )
        self.url_status_label.grid(row=0, column=0, padx=14, pady=(10, 4), sticky="w")

        self.url_progress_bar = ctk.CTkProgressBar(self.url_status_frame, height=10)
        self.url_progress_bar.grid(row=1, column=0, padx=14, pady=(0, 12), sticky="ew")
        self.url_progress_bar.set(0)

        # Results Frame
        self.url_results_frame = ctk.CTkFrame(view, corner_radius=10)
        self.url_results_frame.grid(row=3, column=0, sticky="nsew")
        self.url_results_frame.grid_columnconfigure((0, 1, 2), weight=1)
        self.url_results_frame.grid_rowconfigure(2, weight=1)

        # Verdict Header
        self.url_verdict_badge = ctk.CTkLabel(
            self.url_results_frame,
            text="AWAITING LINK SCAN",
            font=ctk.CTkFont(size=18, weight="bold"),
            fg_color="gray25",
            corner_radius=8,
            padx=16,
            pady=6
        )
        self.url_verdict_badge.grid(row=0, column=0, columnspan=2, padx=16, pady=16, sticky="w")

        self.url_score_display_label = ctk.CTkLabel(
            self.url_results_frame,
            text="Threat Score: --",
            font=ctk.CTkFont(size=16, weight="bold")
        )
        self.url_score_display_label.grid(row=0, column=2, padx=16, pady=16, sticky="e")

        # Indicators row
        ind_frame = ctk.CTkFrame(self.url_results_frame, fg_color="transparent")
        ind_frame.grid(row=1, column=0, columnspan=3, padx=16, pady=(0, 12), sticky="ew")
        ind_frame.grid_columnconfigure((0, 1, 2), weight=1)

        self.card_phish = self._create_mini_indicator(ind_frame, 0, 0, "PHISHING RISK", "--")
        self.card_dropper = self._create_mini_indicator(ind_frame, 0, 1, "MALWARE DROPPER", "--")
        self.card_action = self._create_mini_indicator(ind_frame, 0, 2, "RECOMMENDED ACTION", "--")

        # Details Textbox
        self.url_features_textbox = ctk.CTkTextbox(
            self.url_results_frame,
            font=ctk.CTkFont(family="Consolas", size=12)
        )
        self.url_features_textbox.grid(row=2, column=0, columnspan=3, padx=16, pady=(0, 12), sticky="nsew")
        self.url_features_textbox.insert("end", "Enter a URL and click 'Analyze Link' to view deep lexical and network telemetry.\n")
        self.url_features_textbox.configure(state="disabled")

        # Bottom Bar
        action_bar = ctk.CTkFrame(self.url_results_frame, fg_color="transparent")
        action_bar.grid(row=3, column=0, columnspan=3, padx=16, pady=(0, 14), sticky="ew")
        action_bar.grid_columnconfigure(1, weight=1)

        self.copy_url_btn = ctk.CTkButton(
            action_bar,
            text="📋 Copy Link",
            width=120,
            command=self.copy_current_url,
            state="disabled"
        )
        self.copy_url_btn.grid(row=0, column=0, padx=(0, 8))

        self.open_url_browser_btn = ctk.CTkButton(
            action_bar,
            text="🌐 Open Safely in Browser",
            width=180,
            fg_color="gray30",
            hover_color="gray40",
            command=self.open_current_url_in_browser,
            state="disabled"
        )
        self.open_url_browser_btn.grid(row=0, column=1, sticky="w")

        return view

    def _create_mini_indicator(self, parent, row, col, title, initial_val):
        card = ctk.CTkFrame(parent, corner_radius=8, fg_color=("gray85", "gray20"))
        card.grid(row=row, column=col, padx=4, pady=2, sticky="nsew")
        card.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(card, text=title, font=ctk.CTkFont(size=10, weight="bold"), text_color="gray").grid(row=0, column=0, padx=8, pady=(6, 1))
        val_lbl = ctk.CTkLabel(card, text=initial_val, font=ctk.CTkFont(size=14, weight="bold"))
        val_lbl.grid(row=1, column=0, padx=8, pady=(0, 6))
        return val_lbl

    def paste_url_from_clipboard(self):
        try:
            clipboard_text = self.clipboard_get()
            if clipboard_text:
                self.url_entry.delete(0, "end")
                self.url_entry.insert(0, clipboard_text.strip())
        except Exception:
            pass

    def start_url_scan(self):
        raw_url = self.url_entry.get().strip()
        if not raw_url:
            messagebox.showwarning("No URL Provided", "Please enter or paste a URL to analyze.")
            return

        probe = bool(self.url_probe_switch.get())
        self.is_url_scanning = True
        self.scan_url_btn.configure(state="disabled")
        self.copy_url_btn.configure(state="disabled")
        self.open_url_browser_btn.configure(state="disabled")
        self.url_progress_bar.configure(mode="indeterminate")
        self.url_progress_bar.start()
        self.url_status_label.configure(text=f"Extracting lexical attributes and probing: {raw_url}...")

        threading.Thread(target=self._url_scan_worker, args=(raw_url, probe), daemon=True).start()

    def _url_scan_worker(self, raw_url: str, probe: bool):
        try:
            features, result = self.url_scanner.scan_url(raw_url, probe_network=probe)
            self.after(0, self._url_scan_complete, raw_url, features, result)
        except Exception as e:
            self.after(0, self._url_scan_error, str(e))

    def _url_scan_complete(self, raw_url: str, features: dict, result: dict):
        self.is_url_scanning = False
        self.url_progress_bar.stop()
        self.url_progress_bar.configure(mode="determinate")
        self.scan_url_btn.configure(state="normal")
        self.copy_url_btn.configure(state="normal")
        self.open_url_browser_btn.configure(state="normal")

        self.current_url_features = features
        self.current_url_result = result
        self.stats["scanned"] += 1

        action = result.get("action", "ALLOW")
        verdict = result.get("verdict", "clean_benign")
        score = result.get("threat_score", 0.0)
        conf = result.get("confidence", 0.8)

        self.url_progress_bar.set(score)

        if action == "BLOCK":
            badge_color = "#dc2626"
            verdict_text = f"🛑 THREAT DETECTED: {verdict.upper()}"
            self.stats["threats"] += 1
        elif action == "WARNING":
            badge_color = "#d97706"
            verdict_text = f"⚠️ SUSPICIOUS LINK: {verdict.upper()}"
            self.stats["threats"] += 1
        else:
            badge_color = "#16a34a"
            verdict_text = "✅ CLEAN / SAFE LINK"
            self.stats["clean"] += 1

        self.url_verdict_badge.configure(text=verdict_text, fg_color=badge_color)
        self.url_score_display_label.configure(text=f"Threat Score: {score:.3f} / 1.00 ({score*100:.1f}%)")
        self.url_status_label.configure(text=f"Analysis complete for {features['hostname']}. Action: {action}")

        # Update mini cards
        p_prob = result.get("is_phishing_probability", 0.0)
        d_prob = result.get("is_malware_dropper_probability", 0.0)
        self.card_phish.configure(
            text=f"{p_prob*100:.1f}% ({'HIGH' if p_prob>0.5 else 'LOW'})",
            text_color="#ef4444" if p_prob>0.5 else ("#10b981" if p_prob<0.2 else "#f59e0b")
        )
        self.card_dropper.configure(
            text=f"{d_prob*100:.1f}% ({'HIGH' if d_prob>0.5 else 'LOW'})",
            text_color="#ef4444" if d_prob>0.5 else ("#10b981" if d_prob<0.2 else "#f59e0b")
        )
        self.card_action.configure(
            text=action,
            text_color="#ef4444" if action=="BLOCK" else ("#10b981" if action=="ALLOW" else "#f59e0b")
        )

        # Build feature text
        txt = "=== JEV-AV LINK SECURITY TELEMETRY ===\n"
        txt += f"Target URL:        {features['normalized_url']}\n"
        txt += f"Hostname:          {features['hostname']}\n"
        txt += f"Protocol:          {features['scheme'].upper()} (Port: {features['port']})\n"
        txt += f"Is Raw IP Host:    {'YES' if features['is_ip_address'] else 'No'}\n"
        if features.get("tld"):
            txt += f"Top-Level Domain:  {features['tld']} {'(HIGH ABUSE RISK)' if features['is_high_risk_tld'] else ''}\n"
        txt += f"Domain Entropy:    {features['domain_entropy']:.3f} (High Entropy: {features['is_high_entropy_domain']})\n"
        if features.get("phishing_keywords"):
            txt += f"Phishing Keywords: {', '.join(features['phishing_keywords'])}\n"
        if features.get("has_payload_extension"):
            txt += f"Direct Payload:    {features['payload_extension']}\n"
        if features.get("has_open_redirect"):
            txt += f"Open Redirect:     YES (Redirect parameter detected)\n"

        net = features.get("network_probe", {})
        if net.get("reachable"):
            txt += f"\n=== NETWORK PROBE FINDINGS ===\n"
            txt += f"HTTP Status:       {net.get('status_code')}\n"
            txt += f"Redirect Hops:     {net.get('redirect_count')}\n"
            if net.get("redirect_chain"):
                txt += f"Redirect Chain:\n"
                for idx, hop in enumerate(net["redirect_chain"], 1):
                    txt += f"  [{idx}] {hop}\n"
            txt += f"Content-Type:      {net.get('content_type')}\n"
            txt += f"Server:            {net.get('server')}\n"

        txt += f"\n=== JEV SYSTEM ONE REASONING ===\n"
        txt += f"Classification:    {verdict} ({conf*100:.1f}% confidence)\n"
        txt += f"Threat Score:      {score:.3f} / 1.00\n"
        txt += f"Block Decision:    {action} (Block prob: {result.get('should_block_probability', 0.0)*100:.1f}%)\n"

        self.url_features_textbox.configure(state="normal")
        self.url_features_textbox.delete("1.0", "end")
        self.url_features_textbox.insert("end", txt)
        self.url_features_textbox.configure(state="disabled")

        self.update_dashboard_stats()
        self.log_activity(f"Scanned URL {features['hostname']}: {verdict_text} (Score: {score:.2f})")

    def _url_scan_error(self, err_msg: str):
        self.is_url_scanning = False
        self.url_progress_bar.stop()
        self.scan_url_btn.configure(state="normal")
        self.url_status_label.configure(text=f"Error: {err_msg}")
        messagebox.showerror("URL Scan Error", f"An error occurred while scanning URL:\n{err_msg}")

    def copy_current_url(self):
        if self.current_url_features:
            self.clipboard_clear()
            self.clipboard_append(self.current_url_features["normalized_url"])
            messagebox.showinfo("Copied", "URL copied to clipboard.")

    def open_current_url_in_browser(self):
        if not self.current_url_features:
            return
        target = self.current_url_features["normalized_url"]
        action = self.current_url_result.get("action", "ALLOW") if self.current_url_result else "ALLOW"

        if action == "BLOCK":
            confirm = messagebox.askyesno(
                "⚠️ WARNING: HIGH RISK LINK",
                f"This link was classified as MALICIOUS / PHISHING:\n\n{target}\n\nOpening it may compromise your credentials or computer.\n\nAre you sure you want to proceed?"
            )
            if not confirm:
                return

        import webbrowser
        webbrowser.open(target)

    # =========================================================================
    # VIEW: LIVE EDR & PROCESS MONITOR
    # =========================================================================
    def create_edr_view(self) -> ctk.CTkFrame:
        view = ctk.CTkFrame(self.container, fg_color="transparent")
        view.grid_columnconfigure((0, 1), weight=1)
        view.grid_rowconfigure(2, weight=1)

        # Header
        header = ctk.CTkLabel(view, text="Live Process & Memory EDR Monitor", font=ctk.CTkFont(size=20, weight="bold"))
        header.grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 12))

        # Top Control Bar Card
        ctrl_card = ctk.CTkFrame(view, corner_radius=10)
        ctrl_card.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(0, 14))
        ctrl_card.grid_columnconfigure(1, weight=1)

        self.edr_refresh_btn = ctk.CTkButton(
            ctrl_card,
            text="🔄 Refresh Processes",
            width=150,
            height=36,
            font=ctk.CTkFont(weight="bold"),
            command=self.refresh_edr_processes
        )
        self.edr_refresh_btn.grid(row=0, column=0, padx=(14, 10), pady=12)

        self.edr_search_entry = ctk.CTkEntry(
            ctrl_card,
            placeholder_text="Filter by Process Name or PID...",
            height=36
        )
        self.edr_search_entry.grid(row=0, column=1, padx=(0, 10), pady=12, sticky="ew")
        self.edr_search_entry.bind("<KeyRelease>", lambda e: self.filter_edr_processes())

        self.edr_suspicious_only_switch = ctk.CTkSwitch(
            ctrl_card,
            text="Only Anomalies & Network Connections",
            font=ctk.CTkFont(size=12, weight="bold"),
            command=self.refresh_edr_processes
        )
        self.edr_suspicious_only_switch.grid(row=0, column=2, padx=(0, 14), pady=12)
        self.edr_suspicious_only_switch.select()

        # Left Column: Process List
        list_container = ctk.CTkFrame(view, corner_radius=10)
        list_container.grid(row=2, column=0, sticky="nsew", padx=(0, 8))
        list_container.grid_columnconfigure(0, weight=1)
        list_container.grid_rowconfigure(1, weight=1)

        self.edr_list_title = ctk.CTkLabel(
            list_container,
            text="Active Monitored Processes (0)",
            font=ctk.CTkFont(size=14, weight="bold")
        )
        self.edr_list_title.grid(row=0, column=0, padx=14, pady=(12, 6), sticky="w")

        self.edr_proc_scroll = ctk.CTkScrollableFrame(list_container, corner_radius=8)
        self.edr_proc_scroll.grid(row=1, column=0, padx=10, pady=(0, 10), sticky="nsew")
        self.edr_proc_scroll.grid_columnconfigure(0, weight=1)

        # Right Column: Deep Forensic & Telemetry Card
        self.edr_detail_card = ctk.CTkFrame(view, corner_radius=10)
        self.edr_detail_card.grid(row=2, column=1, sticky="nsew", padx=(8, 0))
        self.edr_detail_card.grid_columnconfigure((0, 1, 2), weight=1)
        self.edr_detail_card.grid_rowconfigure(3, weight=1)

        self.edr_detail_header = ctk.CTkLabel(
            self.edr_detail_card,
            text="Select a process to inspect",
            font=ctk.CTkFont(size=16, weight="bold")
        )
        self.edr_detail_header.grid(row=0, column=0, columnspan=3, padx=16, pady=(14, 4), sticky="w")

        # Telemetry Verdict Badges
        self.edr_verdict_badge = ctk.CTkLabel(
            self.edr_detail_card,
            text="AWAITING PROCESS SELECTION",
            font=ctk.CTkFont(size=15, weight="bold"),
            fg_color="gray25",
            corner_radius=8,
            padx=12,
            pady=4
        )
        self.edr_verdict_badge.grid(row=1, column=0, columnspan=2, padx=16, pady=(0, 8), sticky="w")

        self.edr_score_label = ctk.CTkLabel(
            self.edr_detail_card,
            text="Threat: --",
            font=ctk.CTkFont(size=14, weight="bold")
        )
        self.edr_score_label.grid(row=1, column=2, padx=16, pady=(0, 8), sticky="e")

        # Mini Indicators
        ind_frame = ctk.CTkFrame(self.edr_detail_card, fg_color="transparent")
        ind_frame.grid(row=2, column=0, columnspan=3, padx=16, pady=(0, 8), sticky="ew")
        ind_frame.grid_columnconfigure((0, 1, 2), weight=1)

        self.edr_c2_card = self._create_mini_indicator(ind_frame, 0, 0, "C2 BEACONING", "--")
        self.edr_lolbin_card = self._create_mini_indicator(ind_frame, 0, 1, "LOLBIN ABUSE", "--")
        self.edr_action_card = self._create_mini_indicator(ind_frame, 0, 2, "ACTION", "--")

        # Forensic details textbox
        self.edr_cmdline_box = ctk.CTkTextbox(self.edr_detail_card, font=ctk.CTkFont(family="Consolas", size=11))
        self.edr_cmdline_box.grid(row=3, column=0, columnspan=3, padx=16, pady=(0, 12), sticky="nsew")
        self.edr_cmdline_box.insert("end", "Click on any active process from the left list to run a live forensic inspection with Jev.\n")
        self.edr_cmdline_box.configure(state="disabled")

        # Process Action Bar
        action_bar = ctk.CTkFrame(self.edr_detail_card, fg_color="transparent")
        action_bar.grid(row=4, column=0, columnspan=3, padx=16, pady=(0, 14), sticky="ew")
        action_bar.grid_columnconfigure(2, weight=1)

        self.edr_kill_btn = ctk.CTkButton(
            action_bar,
            text="🛑 Terminate Process",
            fg_color="#dc2626",
            hover_color="#b91c1c",
            command=self.edr_kill_selected,
            state="disabled"
        )
        self.edr_kill_btn.grid(row=0, column=0, padx=(0, 8))

        self.edr_suspend_btn = ctk.CTkButton(
            action_bar,
            text="⏸️ Suspend",
            width=90,
            fg_color="#d97706",
            hover_color="#b45309",
            command=self.edr_suspend_selected,
            state="disabled"
        )
        self.edr_suspend_btn.grid(row=0, column=1, padx=(0, 8))

        self.edr_resume_btn = ctk.CTkButton(
            action_bar,
            text="▶️ Resume",
            width=90,
            fg_color="gray30",
            hover_color="gray40",
            command=self.edr_resume_selected,
            state="disabled"
        )
        self.edr_resume_btn.grid(row=0, column=2, sticky="w")

        view.on_show = self.refresh_edr_processes
        return view

    def refresh_edr_processes(self):
        if self.is_edr_scanning:
            return
        self.is_edr_scanning = True
        self.edr_refresh_btn.configure(state="disabled")
        self.edr_list_title.configure(text="Sweeping active Windows processes...")

        suspicious_only = bool(self.edr_suspicious_only_switch.get())
        threading.Thread(target=self._edr_fetch_worker, args=(suspicious_only,), daemon=True).start()

    def _edr_fetch_worker(self, suspicious_only: bool):
        try:
            procs = get_all_active_processes(suspicious_only=suspicious_only)
            self.after(0, self._edr_fetch_complete, procs)
        except Exception as e:
            self.after(0, self._edr_fetch_error, str(e))

    def _edr_fetch_complete(self, procs: list):
        self.is_edr_scanning = False
        self.edr_refresh_btn.configure(state="normal")
        self.edr_cached_procs = procs
        self.filter_edr_processes()

    def _edr_fetch_error(self, err_msg: str):
        self.is_edr_scanning = False
        self.edr_refresh_btn.configure(state="normal")
        self.edr_list_title.configure(text=f"Error refreshing processes: {err_msg}")

    def filter_edr_processes(self):
        query = self.edr_search_entry.get().strip().lower()
        
        filtered = []
        for p in self.edr_cached_procs:
            if not query:
                filtered.append(p)
            elif query in p["name"].lower() or query in str(p["pid"]) or query in p.get("parent_name", "").lower():
                filtered.append(p)

        self.edr_list_title.configure(text=f"Active Monitored Processes ({len(filtered)})")

        for widget in self.edr_proc_scroll.winfo_children():
            widget.destroy()

        if not filtered:
            empty_lbl = ctk.CTkLabel(self.edr_proc_scroll, text="No processes match the selected criteria.", text_color="gray")
            empty_lbl.grid(row=0, column=0, pady=20)
            return

        for idx, p in enumerate(filtered):
            row_frame = ctk.CTkFrame(self.edr_proc_scroll, corner_radius=6)
            row_frame.grid(row=idx, column=0, padx=4, pady=3, sticky="ew")
            row_frame.grid_columnconfigure(1, weight=1)

            # PID badge
            pid_badge = ctk.CTkLabel(
                row_frame,
                text=f"{p['pid']}",
                font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
                fg_color="gray25",
                corner_radius=4,
                width=55
            )
            pid_badge.grid(row=0, column=0, padx=(8, 8), pady=6)

            # Name and details
            anomalies = []
            if p.get("is_lolbin"):
                anomalies.append("LOLBIN")
            if p.get("is_suspicious_parent_spawn"):
                anomalies.append("PARENT_ANOMALY")
            if p.get("has_external_network"):
                anomalies.append("NET_CONN")
            if p.get("cmdline_anomalies"):
                anomalies.extend(p["cmdline_anomalies"])

            flag_txt = f" • [{', '.join(anomalies)}]" if anomalies else ""
            desc = f"{p['name']} (Parent: {p.get('parent_name', 'System')}){flag_txt}"

            lbl_color = "#f87171" if ("LOLBIN" in flag_txt or "ANOMALY" in flag_txt) else ("gray90", "gray10")
            name_lbl = ctk.CTkLabel(
                row_frame,
                text=desc,
                font=ctk.CTkFont(size=12, weight="bold" if anomalies else "normal"),
                text_color=lbl_color,
                anchor="w"
            )
            name_lbl.grid(row=0, column=1, sticky="w", pady=6)

            # Inspect Button
            btn = ctk.CTkButton(
                row_frame,
                text="Inspect",
                width=70,
                height=26,
                fg_color="#0284c7",
                hover_color="#0369a1",
                command=lambda proc_dict=p: self.inspect_selected_proc(proc_dict)
            )
            btn.grid(row=0, column=2, padx=(6, 8), pady=6)

    def inspect_selected_proc(self, proc_dict: dict):
        self.selected_proc_pid = proc_dict["pid"]
        self.selected_proc_features = proc_dict
        self.edr_kill_btn.configure(state="normal")
        self.edr_suspend_btn.configure(state="normal")
        self.edr_resume_btn.configure(state="normal")

        self.edr_detail_header.configure(text=f"Process: {proc_dict['name']} (PID: {proc_dict['pid']})")
        self.edr_verdict_badge.configure(text="EVALUATING WITH JEV...", fg_color="#3b82f6")
        self.edr_score_label.configure(text="Threat: Calculating...")

        threading.Thread(target=self._edr_eval_worker, args=(proc_dict,), daemon=True).start()

    def _edr_eval_worker(self, proc_dict: dict):
        try:
            result = self.edr_scanner._evaluate_process_features(proc_dict)
            self.after(0, self._edr_eval_complete, proc_dict, result)
        except Exception as e:
            self.after(0, self._edr_eval_error, str(e))

    def _edr_eval_complete(self, features: dict, result: dict):
        self.selected_proc_result = result
        verdict = result.get("verdict", "clean_user_app")
        score = result.get("threat_score", 0.0)
        action = result.get("action", "ALLOW")
        conf = result.get("confidence", 0.8)

        if action == "TERMINATE":
            badge_color = "#dc2626"
            verdict_text = f"🛑 HOSTILE THREAT: {verdict.upper()}"
        elif action == "SOC_REVIEW":
            badge_color = "#d97706"
            verdict_text = f"⚠️ SUSPICIOUS ANOMALY: {verdict.upper()}"
        else:
            badge_color = "#16a34a"
            verdict_text = f"✅ LEGITIMATE: {verdict.upper()}"

        self.edr_verdict_badge.configure(text=verdict_text, fg_color=badge_color)
        self.edr_score_label.configure(text=f"Threat Score: {score:.2f} / 1.00 ({score*100:.1f}%)")

        # Mini Cards
        c2 = result.get("is_c2_beaconing_probability", 0.0)
        lol = result.get("is_living_off_the_land_probability", 0.0)
        term = result.get("should_terminate_probability", 0.0)

        self.edr_c2_card.configure(
            text=f"{c2*100:.1f}% ({'HIGH' if c2>0.5 else 'LOW'})",
            text_color="#ef4444" if c2>0.5 else ("#10b981" if c2<0.2 else "#f59e0b")
        )
        self.edr_lolbin_card.configure(
            text=f"{lol*100:.1f}% ({'HIGH' if lol>0.5 else 'LOW'})",
            text_color="#ef4444" if lol>0.5 else ("#10b981" if lol<0.2 else "#f59e0b")
        )
        self.edr_action_card.configure(
            text=action,
            text_color="#ef4444" if action=="TERMINATE" else ("#10b981" if action=="ALLOW" else "#f59e0b")
        )

        # Build detailed telemetry text
        txt = f"=== LIVE EDR PROCESS TELEMETRY ===\n"
        txt += f"Process Name:      {features['name']}\n"
        txt += f"Process ID (PID):  {features['pid']}\n"
        txt += f"Parent Name:       {features.get('parent_name', 'Unknown')} (PPID: {features.get('ppid', 0)})\n"
        txt += f"Executable Path:   {features.get('exe_path', 'Unknown')}\n"
        txt += f"Memory (RSS):      {features.get('memory', {}).get('rss_mb', 0)} MB\n"

        conns = features.get("network_connections", [])
        if conns:
            txt += f"Network Sockets:\n"
            for c in conns:
                txt += f"  • {c['type']} -> {c['remote_ip']}:{c['remote_port']} ({c['status']})\n"
        else:
            txt += f"Network Sockets:   No active external connections\n"

        if features.get("cmdline_anomalies"):
            txt += f"Command Anomalies: {', '.join(features['cmdline_anomalies'])}\n"

        txt += f"\nFull Command Line:\n{features.get('cmdline', 'N/A')}\n"

        txt += f"\n=== JEV SYSTEM ONE REASONING ===\n"
        txt += f"Classification:    {verdict} ({conf*100:.1f}% confidence)\n"
        txt += f"Threat Score:      {score:.3f} / 1.00\n"
        txt += f"Termination Prob:  {term*100:.1f}%\n"

        self.edr_cmdline_box.configure(state="normal")
        self.edr_cmdline_box.delete("1.0", "end")
        self.edr_cmdline_box.insert("end", txt)
        self.edr_cmdline_box.configure(state="disabled")

        self.log_activity(f"EDR Inspected PID {features['pid']} ({features['name']}): {verdict_text} (Score: {score:.2f})")

    def _edr_eval_error(self, err_msg: str):
        self.edr_verdict_badge.configure(text="INSPECTION ERROR", fg_color="#dc2626")
        self.edr_cmdline_box.configure(state="normal")
        self.edr_cmdline_box.delete("1.0", "end")
        self.edr_cmdline_box.insert("end", f"Error during process evaluation:\n{err_msg}")
        self.edr_cmdline_box.configure(state="disabled")

    def edr_kill_selected(self):
        if not self.selected_proc_pid:
            return
        name = self.selected_proc_features.get("name", "Unknown") if self.selected_proc_features else "Process"
        confirm = messagebox.askyesno(
            "Confirm Process Termination",
            f"Are you sure you want to terminate:\n\n{name} (PID: {self.selected_proc_pid})?\n\nThis will immediately stop execution."
        )
        if not confirm:
            return

        success, msg = terminate_process_by_pid(self.selected_proc_pid)
        if success:
            messagebox.showinfo("Terminated", msg)
            self.log_activity(f"EDR Terminated {name} (PID: {self.selected_proc_pid})")
            self.refresh_edr_processes()
        else:
            messagebox.showerror("Termination Failed", msg)

    def edr_suspend_selected(self):
        if not self.selected_proc_pid:
            return
        success, msg = suspend_process_by_pid(self.selected_proc_pid)
        if success:
            messagebox.showinfo("Suspended", msg)
            self.log_activity(f"EDR Suspended PID {self.selected_proc_pid}")
        else:
            messagebox.showerror("Suspend Failed", msg)

    def edr_resume_selected(self):
        if not self.selected_proc_pid:
            return
        success, msg = resume_process_by_pid(self.selected_proc_pid)
        if success:
            messagebox.showinfo("Resumed", msg)
            self.log_activity(f"EDR Resumed PID {self.selected_proc_pid}")
        else:
            messagebox.showerror("Resume Failed", msg)

    # =========================================================================
    # VIEW: FOLDER SCANNER
    # =========================================================================
    def create_folder_view(self) -> ctk.CTkFrame:
        view = ctk.CTkFrame(self.container, fg_color="transparent")
        view.grid_columnconfigure(0, weight=1)
        view.grid_rowconfigure(3, weight=1)

        # Header
        header = ctk.CTkLabel(view, text="Bulk Directory Scanner", font=ctk.CTkFont(size=20, weight="bold"))
        header.grid(row=0, column=0, sticky="w", pady=(0, 12))

        # Folder Selector Card
        f_card = ctk.CTkFrame(view, corner_radius=10)
        f_card.grid(row=1, column=0, sticky="ew", pady=(0, 14))
        f_card.grid_columnconfigure(0, weight=1)

        self.folder_entry = ctk.CTkEntry(
            f_card,
            placeholder_text="Select a folder to scan recursively...",
            height=38
        )
        self.folder_entry.grid(row=0, column=0, padx=(14, 8), pady=14, sticky="ew")

        # Set default to Downloads
        default_dl = Path.home() / "Downloads"
        if default_dl.exists():
            self.folder_entry.insert(0, str(default_dl))

        f_browse_btn = ctk.CTkButton(
            f_card,
            text="📁 Browse...",
            width=110,
            height=38,
            command=self.browse_folder
        )
        f_browse_btn.grid(row=0, column=1, padx=(0, 8), pady=14)

        self.folder_scan_btn = ctk.CTkButton(
            f_card,
            text="🚀 Scan Directory",
            width=150,
            height=38,
            font=ctk.CTkFont(weight="bold"),
            command=self.start_folder_scan
        )
        self.folder_scan_btn.grid(row=0, column=2, padx=(0, 14), pady=14)

        # Progress Frame
        f_prog_frame = ctk.CTkFrame(view, corner_radius=10)
        f_prog_frame.grid(row=2, column=0, sticky="ew", pady=(0, 14))
        f_prog_frame.grid_columnconfigure(0, weight=1)

        self.folder_status_label = ctk.CTkLabel(
            f_prog_frame,
            text="Ready to scan folder.",
            font=ctk.CTkFont(size=13)
        )
        self.folder_status_label.grid(row=0, column=0, padx=14, pady=(10, 4), sticky="w")

        self.folder_progress_bar = ctk.CTkProgressBar(f_prog_frame, height=10)
        self.folder_progress_bar.grid(row=1, column=0, padx=14, pady=(0, 12), sticky="ew")
        self.folder_progress_bar.set(0)

        # Results table
        self.folder_results_box = ctk.CTkTextbox(view, font=ctk.CTkFont(family="Consolas", size=12))
        self.folder_results_box.grid(row=3, column=0, sticky="nsew")
        self.folder_results_box.insert("end", "Scan results will appear here as each file is evaluated...\n")
        self.folder_results_box.configure(state="disabled")

        return view

    def browse_folder(self):
        f_selected = filedialog.askdirectory(title="Select Directory to Scan")
        if f_selected:
            self.folder_entry.delete(0, "end")
            self.folder_entry.insert(0, f_selected)

    def quick_scan_downloads(self):
        self.select_view("folder")
        dl = Path.home() / "Downloads"
        if dl.exists():
            self.folder_entry.delete(0, "end")
            self.folder_entry.insert(0, str(dl))
            self.start_folder_scan()

    def start_folder_scan(self):
        target_dir = self.folder_entry.get().strip().strip('"').strip("'")
        if not target_dir:
            messagebox.showwarning("No Folder Selected", "Please choose a directory to scan.")
            return

        path = Path(target_dir)
        if not path.exists() or not path.is_dir():
            messagebox.showerror("Invalid Directory", f"Cannot find directory:\n{target_dir}")
            return

        self.folder_scan_btn.configure(state="disabled")
        self.folder_results_box.configure(state="normal")
        self.folder_results_box.delete("1.0", "end")
        self.folder_results_box.insert("end", f"Scanning directory: {path} ...\n\n")
        self.folder_results_box.configure(state="disabled")

        threading.Thread(target=self._folder_scan_worker, args=(path,), daemon=True).start()

    def _folder_scan_worker(self, path: Path):
        files_to_scan = [f for f in path.rglob("*") if f.is_file() and not f.name.startswith((".", "~$"))]
        total = len(files_to_scan)

        if total == 0:
            self.after(0, lambda: self.folder_status_label.configure(text="No files found in selected directory."))
            self.after(0, lambda: self.folder_scan_btn.configure(state="normal"))
            return

        for idx, file_path in enumerate(files_to_scan, start=1):
            progress = idx / total
            self.after(0, self._update_folder_progress, idx, total, file_path.name, progress)
            try:
                features = extract_features(file_path)
                result = self.scanner.scan_file_features(features)
                self.after(0, self._append_folder_result, file_path, result)
            except Exception as e:
                self.after(0, self._append_folder_error, file_path, str(e))

        self.after(0, self._folder_scan_finished, total)

    def _update_folder_progress(self, current, total, filename, progress):
        self.folder_status_label.configure(text=f"Scanning [{current}/{total}]: {filename}")
        self.folder_progress_bar.set(progress)

    def _append_folder_result(self, file_path: Path, result: dict):
        self.stats["scanned"] += 1
        sev = result.get("severity_score", 0.0)
        action = result.get("action", "ALLOW")
        t_class = result.get("threat_classification", "clean")

        icon = "✅" if action == "ALLOW" else "🚨"
        if action == "ALLOW":
            self.stats["clean"] += 1
        else:
            self.stats["threats"] += 1

        line = f"{icon} [{action:10}] Score: {sev:.2f} | {t_class:20} | {file_path.name}\n"

        self.folder_results_box.configure(state="normal")
        self.folder_results_box.insert("end", line)
        self.folder_results_box.see("end")
        self.folder_results_box.configure(state="disabled")
        self.update_dashboard_stats()

    def _append_folder_error(self, file_path: Path, error: str):
        line = f"⚠️ [ERROR     ] Skipped: {file_path.name} ({error})\n"
        self.folder_results_box.configure(state="normal")
        self.folder_results_box.insert("end", line)
        self.folder_results_box.configure(state="disabled")

    def _folder_scan_finished(self, total: int):
        self.folder_scan_btn.configure(state="normal")
        self.folder_status_label.configure(text=f"Directory scan finished! Inspected {total} files.")
        self.log_activity(f"Completed folder scan ({total} files).")

    # =========================================================================
    # VIEW: SENTINEL GUARD
    # =========================================================================
    def create_sentinel_view(self) -> ctk.CTkFrame:
        view = ctk.CTkFrame(self.container, fg_color="transparent")
        view.grid_columnconfigure(0, weight=1)
        view.grid_rowconfigure(3, weight=1)

        # Header
        header = ctk.CTkLabel(view, text="Sentinel Real-Time File System Guard", font=ctk.CTkFont(size=20, weight="bold"))
        header.grid(row=0, column=0, sticky="w", pady=(0, 12))

        # Controls Card
        ctrl_card = ctk.CTkFrame(view, corner_radius=10)
        ctrl_card.grid(row=1, column=0, sticky="ew", pady=(0, 14))
        ctrl_card.grid_columnconfigure(0, weight=1)

        # Target directory to watch
        self.sentinel_path_entry = ctk.CTkEntry(
            ctrl_card,
            placeholder_text="Directory to monitor in real-time...",
            height=38
        )
        self.sentinel_path_entry.grid(row=0, column=0, padx=(14, 8), pady=(14, 8), sticky="ew")

        default_dl = Path.home() / "Downloads"
        if default_dl.exists():
            self.sentinel_path_entry.insert(0, str(default_dl))

        browse_s_btn = ctk.CTkButton(
            ctrl_card,
            text="📁 Browse...",
            width=110,
            height=38,
            command=self.browse_sentinel_folder
        )
        browse_s_btn.grid(row=0, column=1, padx=(0, 14), pady=(14, 8))

        # Toggles Row
        toggles_frame = ctk.CTkFrame(ctrl_card, fg_color="transparent")
        toggles_frame.grid(row=1, column=0, columnspan=2, padx=14, pady=(0, 14), sticky="ew")

        self.auto_quar_switch = ctk.CTkSwitch(
            toggles_frame,
            text="Auto-Isolate Threats to Quarantine Vault",
            font=ctk.CTkFont(size=13, weight="bold")
        )
        self.auto_quar_switch.grid(row=0, column=0, sticky="w")
        self.auto_quar_switch.select()

        self.sentinel_toggle_btn = ctk.CTkButton(
            toggles_frame,
            text="▶️ Start Real-Time Guard",
            width=180,
            height=36,
            font=ctk.CTkFont(weight="bold"),
            fg_color="#059669",
            hover_color="#047857",
            command=self.toggle_sentinel
        )
        self.sentinel_toggle_btn.grid(row=0, column=1, padx=(20, 0), sticky="e")
        toggles_frame.grid_columnconfigure(1, weight=1)

        # Status Bar
        self.sentinel_status_label = ctk.CTkLabel(
            view,
            text="Sentinel Guard is currently IDLE. Click 'Start Real-Time Guard' to begin.",
            font=ctk.CTkFont(size=13)
        )
        self.sentinel_status_label.grid(row=2, column=0, sticky="w", pady=(0, 8))

        # Live Stream Log
        self.sentinel_stream_box = ctk.CTkTextbox(view, font=ctk.CTkFont(family="Consolas", size=12))
        self.sentinel_stream_box.grid(row=3, column=0, sticky="nsew")
        self.sentinel_stream_box.insert("end", "[Sentinel] System waiting for real-time activation...\n")
        self.sentinel_stream_box.configure(state="disabled")

        return view

    def browse_sentinel_folder(self):
        f = filedialog.askdirectory(title="Select Folder for Real-Time Protection")
        if f:
            self.sentinel_path_entry.delete(0, "end")
            self.sentinel_path_entry.insert(0, f)

    def toggle_sentinel_from_dashboard(self):
        self.select_view("sentinel")
        self.toggle_sentinel()

    def toggle_sentinel(self):
        if not self.sentinel_running:
            target_str = self.sentinel_path_entry.get().strip().strip('"').strip("'")
            watch_path = Path(target_str)
            if not watch_path.exists() or not watch_path.is_dir():
                messagebox.showerror("Invalid Directory", f"Watch folder does not exist:\n{target_str}")
                return

            auto_quar = bool(self.auto_quar_switch.get())

            # Define event callback that feeds our queue
            def on_sentinel_event(event_type, details):
                self.sentinel_events_queue.put((event_type, details))

            handler = RealTimeProtectionHandler(
                scanner=self.scanner,
                quarantine_dir=self.quarantine_dir,
                auto_quarantine=auto_quar,
                event_callback=on_sentinel_event
            )

            self.sentinel_observer = Observer()
            self.sentinel_observer.schedule(handler, str(watch_path), recursive=True)
            self.sentinel_observer.start()

            self.sentinel_running = True
            self.sentinel_toggle_btn.configure(text="⏹️ Stop Real-Time Guard", fg_color="#dc2626", hover_color="#b91c1c")
            self.sentinel_status_label.configure(
                text=f"🟢 Sentinel ACTIVE. Actively guarding: {watch_path}",
                text_color="#10b981"
            )
            self.log_sentinel_stream(f"Real-time protection activated on: {watch_path}")
            self.log_activity(f"Sentinel activated on {watch_path.name}")
        else:
            if self.sentinel_observer:
                self.sentinel_observer.stop()
                self.sentinel_observer.join(timeout=1.5)
                self.sentinel_observer = None

            self.sentinel_running = False
            self.sentinel_toggle_btn.configure(text="▶️ Start Real-Time Guard", fg_color="#059669", hover_color="#047857")
            self.sentinel_status_label.configure(
                text="Sentinel Guard is currently IDLE.",
                text_color=("gray10", "gray90")
            )
            self.log_sentinel_stream("Real-time protection stopped.")
            self.log_activity("Sentinel stopped.")

        self.update_dashboard_stats()

    def log_sentinel_stream(self, text: str):
        timestamp = time.strftime("%H:%M:%S")
        self.sentinel_stream_box.configure(state="normal")
        self.sentinel_stream_box.insert("end", f"[{timestamp}] {text}\n")
        self.sentinel_stream_box.see("end")
        self.sentinel_stream_box.configure(state="disabled")

    def poll_sentinel_queue(self):
        """Processes events dispatched by the background watchdog thread."""
        try:
            while not self.sentinel_events_queue.empty():
                event_type, details = self.sentinel_events_queue.get_nowait()
                if event_type == "detected":
                    self.log_sentinel_stream(f"⚡ File detected: {details['name']}")
                elif event_type == "scanned":
                    res = details["result"]
                    sev = res.get("severity_score", 0.0)
                    act = res.get("action", "ALLOW")
                    self.stats["scanned"] += 1
                    if act == "ALLOW":
                        self.stats["clean"] += 1
                        self.log_sentinel_stream(f"✅ Approved clean: {details['name']} (Score: {sev:.2f})")
                    else:
                        self.stats["threats"] += 1
                        self.log_sentinel_stream(f"🚨 Threat detected in real-time: {details['name']} (Score: {sev:.2f})")
                    self.update_dashboard_stats()
                elif event_type == "quarantined":
                    self.stats["quarantined"] += 1
                    self.log_sentinel_stream(f"🛡️ Auto-quarantined threat: {details['name']} -> Vault")
                    self.update_dashboard_stats()
                elif event_type == "error":
                    self.log_sentinel_stream(f"⚠️ Inspection error on {details['name']}: {details['error']}")
        except Exception:
            pass

        self.after(200, self.poll_sentinel_queue)

    # =========================================================================
    # VIEW: QUARANTINE VAULT
    # =========================================================================
    def create_vault_view(self) -> ctk.CTkFrame:
        view = ctk.CTkFrame(self.container, fg_color="transparent")
        view.grid_columnconfigure(0, weight=1)
        view.grid_rowconfigure(2, weight=1)

        # Header
        header = ctk.CTkLabel(view, text="Quarantine Vault", font=ctk.CTkFont(size=20, weight="bold"))
        header.grid(row=0, column=0, sticky="w", pady=(0, 12))

        # Top Bar
        bar = ctk.CTkFrame(view, fg_color="transparent")
        bar.grid(row=1, column=0, sticky="ew", pady=(0, 12))
        bar.grid_columnconfigure(0, weight=1)

        self.vault_count_label = ctk.CTkLabel(
            bar,
            text="0 neutralized threats currently isolated.",
            font=ctk.CTkFont(size=13)
        )
        self.vault_count_label.grid(row=0, column=0, sticky="w")

        refresh_btn = ctk.CTkButton(
            bar,
            text="🔄 Refresh Vault",
            width=120,
            command=self.refresh_quarantine_list
        )
        refresh_btn.grid(row=0, column=1, padx=(0, 8))

        open_vault_btn = ctk.CTkButton(
            bar,
            text="📂 Open Vault Directory",
            width=150,
            fg_color="gray30",
            hover_color="gray40",
            command=lambda: os.startfile(str(self.quarantine_dir))
        )
        open_vault_btn.grid(row=0, column=2)

        # Scrollable list frame
        self.vault_scroll_frame = ctk.CTkScrollableFrame(view, corner_radius=10)
        self.vault_scroll_frame.grid(row=2, column=0, sticky="nsew")
        self.vault_scroll_frame.grid_columnconfigure(0, weight=1)

        view.on_show = self.refresh_quarantine_list
        return view

    def refresh_quarantine_list(self):
        # Clear existing children
        for widget in self.vault_scroll_frame.winfo_children():
            widget.destroy()

        quarantined_files = list(self.quarantine_dir.glob("*.quarantined"))
        self.vault_count_label.configure(text=f"{len(quarantined_files)} neutralized threats currently isolated.")

        if not quarantined_files:
            empty_lbl = ctk.CTkLabel(
                self.vault_scroll_frame,
                text="The Quarantine Vault is clean. No threats currently quarantined.",
                font=ctk.CTkFont(size=14),
                text_color="gray"
            )
            empty_lbl.grid(row=0, column=0, pady=40)
            return

        for idx, q_path in enumerate(quarantined_files):
            item_frame = ctk.CTkFrame(self.vault_scroll_frame, corner_radius=8)
            item_frame.grid(row=idx, column=0, padx=6, pady=4, sticky="ew")
            item_frame.grid_columnconfigure(1, weight=1)

            # Icon
            icon_lbl = ctk.CTkLabel(item_frame, text="🔒", font=ctk.CTkFont(size=18))
            icon_lbl.grid(row=0, column=0, padx=(12, 8), pady=10)

            # Details
            size_kb = q_path.stat().st_size / 1024
            mtime = time.ctime(q_path.stat().st_mtime)
            info_lbl = ctk.CTkLabel(
                item_frame,
                text=f"{q_path.name}\nSize: {size_kb:.1f} KB • Quarantined: {mtime}",
                font=ctk.CTkFont(size=12),
                justify="left",
                anchor="w"
            )
            info_lbl.grid(row=0, column=1, sticky="w", pady=8)

            # Action Buttons
            restore_btn = ctk.CTkButton(
                item_frame,
                text="Restore",
                width=80,
                height=28,
                fg_color="#0284c7",
                hover_color="#0369a1",
                command=lambda p=q_path: self.restore_quarantined_file(p)
            )
            restore_btn.grid(row=0, column=2, padx=4, pady=8)

            delete_btn = ctk.CTkButton(
                item_frame,
                text="Delete",
                width=80,
                height=28,
                fg_color="#dc2626",
                hover_color="#b91c1c",
                command=lambda p=q_path: self.delete_quarantined_file(p)
            )
            delete_btn.grid(row=0, column=3, padx=(4, 12), pady=8)

    def restore_quarantined_file(self, q_path: Path):
        confirm = messagebox.askyesno(
            "Restore Quarantined File",
            f"Are you sure you want to restore:\n{q_path.name}?\n\nIt will be restored to your Downloads folder."
        )
        if not confirm:
            return

        try:
            original_name = q_path.name
            if "_" in original_name:
                original_name = original_name.split("_", 1)[1]
            if original_name.endswith(".quarantined"):
                original_name = original_name[:-12]

            restore_dest = Path.home() / "Downloads" / original_name
            shutil.move(str(q_path), str(restore_dest))
            messagebox.showinfo("Restored", f"File restored safely to:\n{restore_dest}")
            self.refresh_quarantine_list()
            self.log_activity(f"Restored file {original_name} from vault")
        except Exception as e:
            messagebox.showerror("Restore Failed", f"Failed to restore file:\n{e}")

    def delete_quarantined_file(self, q_path: Path):
        confirm = messagebox.askyesno(
            "Permanently Delete",
            f"Permanently delete:\n{q_path.name}?\n\nThis action cannot be undone."
        )
        if not confirm:
            return

        try:
            q_path.unlink()
            messagebox.showinfo("Deleted", "Threat has been permanently purged.")
            self.refresh_quarantine_list()
            self.log_activity(f"Permanently deleted {q_path.name}")
        except Exception as e:
            messagebox.showerror("Delete Failed", f"Failed to delete file:\n{e}")

    # =========================================================================
    # VIEW: SETTINGS
    # =========================================================================
    def create_settings_view(self) -> ctk.CTkFrame:
        view = ctk.CTkFrame(self.container, fg_color="transparent")
        view.grid_columnconfigure(0, weight=1)

        # Header
        header = ctk.CTkLabel(view, text="Engine Configuration & Model Settings", font=ctk.CTkFont(size=20, weight="bold"))
        header.grid(row=0, column=0, sticky="w", pady=(0, 16))

        # API & Engine Info Card
        card = ctk.CTkFrame(view, corner_radius=10)
        card.grid(row=1, column=0, sticky="ew", pady=(0, 16))
        card.grid_columnconfigure(1, weight=1)

        # API Key Status
        ctk.CTkLabel(card, text="TypeSafe API Key:", font=ctk.CTkFont(weight="bold")).grid(row=0, column=0, padx=16, pady=14, sticky="w")
        masked_key = f"{API_KEY[:6]}...{API_KEY[-4:]}" if API_KEY and len(API_KEY) > 10 else "NOT CONFIGURED"
        key_lbl = ctk.CTkLabel(card, text=masked_key, font=ctk.CTkFont(family="Consolas"))
        key_lbl.grid(row=0, column=1, padx=16, pady=14, sticky="w")

        # Model
        ctk.CTkLabel(card, text="System One Model:", font=ctk.CTkFont(weight="bold")).grid(row=1, column=0, padx=16, pady=14, sticky="w")
        ctk.CTkLabel(card, text=MODEL, font=ctk.CTkFont(family="Consolas")).grid(row=1, column=1, padx=16, pady=14, sticky="w")

        # Primitives
        ctk.CTkLabel(card, text="Inference Primitives:", font=ctk.CTkFont(weight="bold")).grid(row=2, column=0, padx=16, pady=14, sticky="w")
        ctk.CTkLabel(card, text="Choice (Threat Class) • Score (Severity) • Noul (Quarantine Action)").grid(row=2, column=1, padx=16, pady=14, sticky="w")

        # Sensitivity Card
        sens_card = ctk.CTkFrame(view, corner_radius=10)
        sens_card.grid(row=2, column=0, sticky="ew", pady=(0, 16))
        sens_card.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(sens_card, text="Threat Sensitivity Threshold", font=ctk.CTkFont(size=14, weight="bold")).grid(row=0, column=0, padx=16, pady=(14, 4), sticky="w")
        ctk.CTkLabel(
            sens_card,
            text="Adjusts the score cutoff where Jev automatically flags or isolates incoming files.",
            font=ctk.CTkFont(size=12),
            text_color="gray"
        ).grid(row=1, column=0, padx=16, pady=(0, 10), sticky="w")

        self.sens_slider = ctk.CTkSlider(sens_card, from_=0.20, to=0.80, number_of_steps=12)
        self.sens_slider.grid(row=2, column=0, padx=16, pady=(0, 8), sticky="ew")
        self.sens_slider.set(0.50)

        self.sens_val_lbl = ctk.CTkLabel(sens_card, text="Balanced (Threshold: 0.50)", font=ctk.CTkFont(weight="bold"))
        self.sens_val_lbl.grid(row=3, column=0, padx=16, pady=(0, 14), sticky="w")
        self.sens_slider.configure(command=self._on_slider_change)

        return view

    def _on_slider_change(self, value):
        val = float(value)
        if val < 0.35:
            tier = "Strict Protection"
        elif val < 0.60:
            tier = "Balanced Protection"
        else:
            tier = "Permissive / Developer Mode"
        self.sens_val_lbl.configure(text=f"{tier} (Threshold: {val:.2f})")

    def on_closing(self):
        if self.sentinel_running and self.sentinel_observer:
            self.sentinel_observer.stop()
        self.destroy()


def launch_gui():
    app = JevAVGUI()
    app.protocol("WM_DELETE_WINDOW", app.on_closing)
    app.mainloop()


if __name__ == "__main__":
    launch_gui()
