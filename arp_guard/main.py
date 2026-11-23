import queue
import tkinter as tk
from tkinter import ttk, messagebox

from detector import ARPDetector
from sniffer import BackgroundARPSniffer
from utils import export_logs_to_csv, get_prevention_recommendations


class ARPGuardDashboard:
    def __init__(self, root):
        self.root = root
        self.root.title("ARP Guard — Enterprise ARP Spoofing Detection & Prevention System")
        self.root.geometry("1180x740")
        self.root.minsize(1024, 660)

        # Modern SOC Dark Palette
        self.bg_main = "#0b1120"
        self.bg_card = "#111827"
        self.bg_header = "#1e293b"
        self.border_col = "#334155"
        self.text_primary = "#f8fafc"
        self.text_muted = "#94a3b8"
        self.accent_blue = "#38bdf8"
        self.accent_green = "#22c55e"
        self.accent_yellow = "#eab308"
        self.accent_red = "#ef4444"

        self.root.configure(bg=self.bg_main)

        # Core components
        self.detector = ARPDetector()
        self.packet_queue = queue.Queue()
        self.sniffer = None
        self.alert_popup_shown = False

        self._setup_styles()
        self._build_ui()
        self._poll_packet_queue()

    def _setup_styles(self):
        style = ttk.Style()
        style.theme_use("clam")

        style.configure(
            "Treeview",
            background=self.bg_card,
            foreground=self.text_primary,
            fieldbackground=self.bg_card,
            borderwidth=0,
            rowheight=28,
            font=("Consolas", 10),
        )
        style.configure(
            "Treeview.Heading",
            background=self.bg_header,
            foreground=self.accent_blue,
            relief="flat",
            font=("Segoe UI", 10, "bold"),
        )
        style.map("Treeview", background=[("selected", "#1d4ed8")])

    def _build_ui(self):
        # 1. Top Navigation & Control Bar
        top_bar = tk.Frame(self.root, bg=self.bg_header, height=64, padx=18, pady=10)
        top_bar.pack(fill="x")

        title_frame = tk.Frame(top_bar, bg=self.bg_header)
        title_frame.pack(side="left")

        tk.Label(
            title_frame,
            text="🛡️ ARP GUARD SOC",
            font=("Segoe UI", 16, "bold"),
            fg=self.accent_blue,
            bg=self.bg_header,
        ).pack(side="left")

        gw_text = (
            f"   |   Gateway: {self.detector.gateway_ip} ({self.detector.gateway_mac})"
            if self.detector.gateway_ip
            else "   |   Gateway: Auto-Detecting..."
        )
        tk.Label(
            title_frame,
            text=gw_text,
            font=("Consolas", 10),
            fg=self.text_muted,
            bg=self.bg_header,
        ).pack(side="left", pady=(4, 0))

        # Right-side controls
        ctrl_frame = tk.Frame(top_bar, bg=self.bg_header)
        ctrl_frame.pack(side="right")

        tk.Label(
            ctrl_frame, text="Interface:", font=("Segoe UI", 10, "bold"), fg=self.text_primary, bg=self.bg_header
        ).pack(side="left", padx=(0, 6))

        self.iface_var = tk.StringVar(value="eth0")
        iface_entry = tk.Entry(
            ctrl_frame,
            textvariable=self.iface_var,
            width=10,
            font=("Consolas", 10, "bold"),
            bg=self.bg_main,
            fg=self.accent_blue,
            insertbackground=self.text_primary,
            relief="flat",
        )
        iface_entry.pack(side="left", ipady=4, padx=(0, 12))

        self.start_btn = tk.Button(
            ctrl_frame,
            text="▶ Start Monitoring",
            command=self.start_monitoring,
            bg=self.accent_green,
            fg="#052e16",
            font=("Segoe UI", 10, "bold"),
            relief="flat",
            padx=12,
            pady=5,
            cursor="hand2",
        )
        self.start_btn.pack(side="left", padx=4)

        self.stop_btn = tk.Button(
            ctrl_frame,
            text="■ Stop",
            command=self.stop_monitoring,
            bg="#475569",
            fg=self.text_primary,
            font=("Segoe UI", 10, "bold"),
            relief="flat",
            padx=12,
            pady=5,
            state="disabled",
            cursor="hand2",
        )
        self.stop_btn.pack(side="left", padx=4)

        tk.Button(
            ctrl_frame,
            text="📥 Export CSV",
            command=self.export_csv,
            bg="#0284c7",
            fg=self.text_primary,
            font=("Segoe UI", 10, "bold"),
            relief="flat",
            padx=12,
            pady=5,
            cursor="hand2",
        ).pack(side="left", padx=4)

        tk.Button(
            ctrl_frame,
            text="🔒 Prevention Guide",
            command=self.show_prevention_modal,
            bg="#7c3aed",
            fg=self.text_primary,
            font=("Segoe UI", 10, "bold"),
            relief="flat",
            padx=12,
            pady=5,
            cursor="hand2",
        ).pack(side="left", padx=(4, 0))

        # 2. Alert Banner (Hidden until attack detected)
        self.alert_banner = tk.Label(
            self.root,
            text="",
            bg=self.accent_red,
            fg="#ffffff",
            font=("Segoe UI", 11, "bold"),
            pady=8,
        )

        # 3. KPI Metrics Row
        kpi_container = tk.Frame(self.root, bg=self.bg_main, padx=18, pady=14)
        kpi_container.pack(fill="x")

        self.kpi_devices_var = tk.StringVar(value="0")
        self.kpi_total_var = tk.StringVar(value="0")
        self.kpi_suspicious_var = tk.StringVar(value="0")
        self.kpi_normal_var = tk.StringVar(value="0")

        self._create_kpi_card(kpi_container, "TOTAL DEVICES DETECTED", self.kpi_devices_var, self.accent_blue, 0)
        self._create_kpi_card(kpi_container, "TOTAL ARP PACKETS", self.kpi_total_var, self.text_primary, 1)
        self._create_kpi_card(kpi_container, "SUSPICIOUS EVENTS", self.kpi_suspicious_var, self.accent_red, 2)
        self._create_kpi_card(kpi_container, "NORMAL ACTIVITY", self.kpi_normal_var, self.accent_green, 3)

        for col in range(4):
            kpi_container.grid_columnconfigure(col, weight=1)

        # 4. Main Content Split: Device Table (Top) + Real-Time Event Log (Bottom)
        content_frame = tk.Frame(self.root, bg=self.bg_main, padx=18)
        content_frame.pack(fill="both", expand=True)

        # Device Monitoring Table Section
        dev_header = tk.Frame(content_frame, bg=self.bg_main)
        dev_header.pack(fill="x", pady=(0, 6))
        tk.Label(
            dev_header,
            text="LIVE NETWORK DEVICE INVENTORY (IP-TO-MAC MAPPING)",
            font=("Segoe UI", 10, "bold"),
            fg=self.text_muted,
            bg=self.bg_main,
        ).pack(side="left")

        self.status_indicator = tk.Label(
            dev_header,
            text="● IDLE (Click Start Monitoring)",
            font=("Segoe UI", 10, "bold"),
            fg=self.accent_yellow,
            bg=self.bg_main,
        )
        self.status_indicator.pack(side="right")

        table_frame = tk.Frame(content_frame, bg=self.border_col, bd=1)
        table_frame.pack(fill="both", expand=True, pady=(0, 14))

        columns = ("ip", "mac", "role", "status")
        self.device_tree = ttk.Treeview(table_frame, columns=columns, show="headings", height=7)
        self.device_tree.heading("ip", text="Device IP Address")
        self.device_tree.heading("mac", text="Hardware MAC Address")
        self.device_tree.heading("role", text="Network Role")
        self.device_tree.heading("status", text="Security Status")

        self.device_tree.column("ip", width=220, anchor="center")
        self.device_tree.column("mac", width=260, anchor="center")
        self.device_tree.column("role", width=220, anchor="center")
        self.device_tree.column("status", width=240, anchor="center")

        self.device_tree.tag_configure("Normal", foreground=self.accent_green)
        self.device_tree.tag_configure("Suspicious", foreground=self.accent_yellow)
        self.device_tree.tag_configure("Attack Detected", foreground=self.accent_red)

        dev_scroll = ttk.Scrollbar(table_frame, orient="vertical", command=self.device_tree.yview)
        self.device_tree.configure(yscrollcommand=dev_scroll.set)
        self.device_tree.pack(side="left", fill="both", expand=True)
        dev_scroll.pack(side="right", fill="y")

        # Real-Time Event Log Section
        log_header = tk.Frame(content_frame, bg=self.bg_main)
        log_header.pack(fill="x", pady=(0, 6))
        tk.Label(
            log_header,
            text="REAL-TIME SECURITY EVENT LOG & PACKET TELEMETRY",
            font=("Segoe UI", 10, "bold"),
            fg=self.text_muted,
            bg=self.bg_main,
        ).pack(side="left")

        tk.Button(
            log_header,
            text="Clear View",
            command=self._clear_log_widget,
            bg=self.bg_header,
            fg=self.text_muted,
            font=("Segoe UI", 8, "bold"),
            relief="flat",
            padx=8,
            cursor="hand2",
        ).pack(side="right")

        log_frame = tk.Frame(content_frame, bg=self.border_col, bd=1)
        log_frame.pack(fill="both", expand=True, pady=(0, 16))

        self.log_text = tk.Text(
            log_frame,
            height=10,
            bg="#060a14",
            fg=self.text_primary,
            font=("Consolas", 10),
            relief="flat",
            padx=10,
            pady=8,
            state="disabled",
        )
        self.log_text.tag_config("NORMAL", foreground=self.accent_green)
        self.log_text.tag_config("INFO", foreground=self.text_muted)
        self.log_text.tag_config("WARNING", foreground=self.accent_yellow)
        self.log_text.tag_config("ALERT", foreground=self.accent_red, font=("Consolas", 10, "bold"))

        log_scroll = ttk.Scrollbar(log_frame, orient="vertical", command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=log_scroll.set)
        self.log_text.pack(side="left", fill="both", expand=True)
        log_scroll.pack(side="right", fill="y")

    def _create_kpi_card(self, parent, title, var, value_color, col):
        card = tk.Frame(
            parent,
            bg=self.bg_card,
            highlightbackground=self.border_col,
            highlightthickness=1,
            padx=16,
            pady=12,
        )
        padx = (0, 10) if col < 3 else (0, 0)
        card.grid(row=0, column=col, sticky="nsew", padx=padx)

        tk.Label(card, text=title, font=("Segoe UI", 9, "bold"), fg=self.text_muted, bg=self.bg_card).pack(anchor="w")
        tk.Label(card, textvariable=var, font=("Segoe UI", 24, "bold"), fg=value_color, bg=self.bg_card).pack(
            anchor="w", pady=(4, 0)
        )

    def start_monitoring(self):
        iface = self.iface_var.get().strip()
        if not iface:
            messagebox.showwarning("Input Required", "Please specify a valid network interface (e.g., eth0).")
            return

        self.alert_banner.pack_forget()
        self.alert_popup_shown = False

        self.sniffer = BackgroundARPSniffer(
            interface=iface,
            packet_callback=lambda op, sip, smac, dip: self.packet_queue.put((op, sip, smac, dip)),
            error_callback=lambda err: self.root.after(0, lambda: self._handle_sniffer_error(err)),
        )
        self.sniffer.start()

        self.start_btn.config(state="disabled", bg="#334155")
        self.stop_btn.config(state="normal", bg=self.accent_red)
        self.status_indicator.config(text=f"● LIVE CAPTURE ACTIVE ON {iface.upper()}", fg=self.accent_green)
        self._append_log(f"[SYSTEM] Started live ARP traffic monitoring on interface '{iface}'...", "INFO")

    def stop_monitoring(self):
        if self.sniffer:
            self.sniffer.stop()
        self.start_btn.config(state="normal", bg=self.accent_green)
        self.stop_btn.config(state="disabled", bg="#475569")
        self.status_indicator.config(text="● MONITORING STOPPED", fg=self.accent_yellow)
        self._append_log("[SYSTEM] Monitoring stopped by user.", "INFO")

    def _handle_sniffer_error(self, error_msg):
        self.stop_monitoring()
        messagebox.showerror("Capture Error", error_msg)

    def _poll_packet_queue(self):
        """Safely processes captured packets from the background thread onto the GUI."""
        while not self.packet_queue.empty():
            op, src_ip, src_mac, dst_ip = self.packet_queue.get_nowait()
            event = self.detector.analyze_packet(op, src_ip, src_mac, dst_ip)
            self._update_dashboard(event)

        self.root.after(150, self._poll_packet_queue)

    def _update_dashboard(self, event):
        # Update KPI counters
        self.kpi_devices_var.set(str(len(self.detector.ip_mac_map)))
        self.kpi_total_var.set(str(self.detector.total_packets))
        self.kpi_suspicious_var.set(str(self.detector.suspicious_events))
        self.kpi_normal_var.set(str(self.detector.normal_packets))

        # Refresh device table
        for item in self.device_tree.get_children():
            self.device_tree.delete(item)

        for ip, mac in self.detector.ip_mac_map.items():
            role = "Default Gateway" if ip == self.detector.gateway_ip else "Local Host"
            status = self.detector.device_status.get(ip, "Normal")
            self.device_tree.insert("", "end", values=(ip, mac, role, status), tags=(status,))

        # Append to real-time log
        log_line = f"[{event['timestamp']}] [{event['severity']}] {event['message']}"
        self._append_log(log_line, event["severity"])

        # Trigger prominent visual alert if an ARP Spoofing attack is detected
        if event["severity"] == "ALERT":
            self.alert_banner.config(text=f"🚨 {event['message']}")
            self.alert_banner.pack(fill="x", after=self.root.winfo_children()[0])
            if not self.alert_popup_shown:
                self.alert_popup_shown = True
                messagebox.showwarning("ARP SPOOFING ATTACK DETECTED!", event["message"])

    def _append_log(self, text, tag="INFO"):
        self.log_text.config(state="normal")
        self.log_text.insert("end", text + "\n", tag)
        self.log_text.see("end")
        self.log_text.config(state="disabled")

    def _clear_log_widget(self):
        self.log_text.config(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.config(state="disabled")

    def export_csv(self):
        filepath, msg = export_logs_to_csv(self.detector.event_logs)
        if filepath:
            messagebox.showinfo("Export Successful", msg)
        else:
            messagebox.showwarning("Export Notice", msg)

    def show_prevention_modal(self):
        modal = tk.Toplevel(self.root)
        modal.title("ARP Spoofing Prevention & Mitigation Recommendations")
        modal.geometry("760x540")
        modal.configure(bg=self.bg_main)

        tk.Label(
            modal,
            text="🛡️ ARP Spoofing Prevention & Hardening Guide",
            font=("Segoe UI", 14, "bold"),
            fg=self.accent_blue,
            bg=self.bg_main,
            pady=12,
        ).pack()

        canvas = tk.Canvas(modal, bg=self.bg_main, highlightthickness=0)
        scrollbar = ttk.Scrollbar(modal, orient="vertical", command=canvas.yview)
        scroll_frame = tk.Frame(canvas, bg=self.bg_main, padx=18)

        scroll_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=scroll_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        for title, desc in get_prevention_recommendations():
            card = tk.Frame(
                scroll_frame,
                bg=self.bg_card,
                highlightbackground=self.border_col,
                highlightthickness=1,
                padx=14,
                pady=10,
            )
            card.pack(fill="x", pady=6)
            tk.Label(
                card, text=title, font=("Segoe UI", 10, "bold"), fg=self.accent_green, bg=self.bg_card, anchor="w"
            ).pack(fill="x")
            tk.Label(
                card,
                text=desc,
                font=("Segoe UI", 9),
                fg=self.text_primary,
                bg=self.bg_card,
                wraplength=680,
                justify="left",
                anchor="w",
            ).pack(fill="x", pady=(4, 0))

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")


if __name__ == "__main__":
    root = tk.Tk()
    app = ARPGuardDashboard(root)
    root.mainloop()
