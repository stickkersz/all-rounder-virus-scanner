#!/usr/bin/env python3
"""USB Virus Scanner — desktop GUI for end users.

Tkinter (ships with Python on every Windows) so there is nothing extra to
install for the front-end. Pick a drive, click Scan, watch progress, see
threats. Infected files are quarantined; the Quarantine window lists them and
can restore. Scanning runs on a worker thread so the window stays responsive.

Run:  python gui.py
"""

from __future__ import annotations

import os
import queue
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from scanner.config import Config
from scanner.engine import ScanEngine
from scanner.paths import app_base_dir
from scanner.quarantine import Quarantine
from scanner.reporter import log_result, setup_logging, write_report
from scanner.watcher import list_removable

BASE_DIR = app_base_dir()

SEV_COLOR = {
    "infected": "#c0392b",
    "suspicious": "#d68910",
    "clean": "#1e8449",
    "error": "#7f8c8d",
}


class ScannerGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("USB Virus Scanner")
        self.geometry("820x560")
        self.minsize(720, 480)

        self.cfg = Config.load(os.path.join(BASE_DIR, "config.yaml"))
        self.logger = setup_logging(self.cfg["logging"])
        self.engine = ScanEngine(self.cfg, BASE_DIR)

        self._events: "queue.Queue[tuple]" = queue.Queue()
        self._scanning = False

        self._build_ui()
        self._refresh_drives()
        self.after(100, self._drain_events)

    # ------------------------------------------------------------------ UI
    def _build_ui(self) -> None:
        pad = {"padx": 8, "pady": 6}

        top = ttk.Frame(self)
        top.pack(fill="x", **pad)

        ttk.Label(top, text="Target:").pack(side="left")
        self.target_var = tk.StringVar()
        self.drive_box = ttk.Combobox(top, textvariable=self.target_var, width=42)
        self.drive_box.pack(side="left", padx=6)

        ttk.Button(top, text="Refresh", command=self._refresh_drives).pack(side="left")
        ttk.Button(top, text="Browse…", command=self._browse).pack(side="left", padx=4)

        opts = ttk.Frame(self)
        opts.pack(fill="x", padx=8)
        self.report_only = tk.BooleanVar(value=False)
        ttk.Checkbutton(opts, text="Report only (do not move files)",
                        variable=self.report_only).pack(side="left")
        self.scan_btn = ttk.Button(opts, text="▶  Scan", command=self._start_scan)
        self.scan_btn.pack(side="right")
        ttk.Button(opts, text="Quarantine…",
                   command=self._open_quarantine).pack(side="right", padx=6)

        # status + progress
        status = ttk.Frame(self)
        status.pack(fill="x", **pad)
        self.status_var = tk.StringVar(value="Ready.")
        ttk.Label(status, textvariable=self.status_var).pack(side="left")
        self.progress = ttk.Progressbar(status, mode="indeterminate", length=200)
        self.progress.pack(side="right")

        # verdict banner
        self.banner = tk.Label(self, text="", font=("Segoe UI", 12, "bold"),
                               fg="white", pady=6)
        self.banner.pack(fill="x", padx=8)
        self.banner.pack_forget()

        # results table
        cols = ("severity", "threat", "source", "file")
        self.tree = ttk.Treeview(self, columns=cols, show="headings", height=14)
        for c, w in zip(cols, (100, 240, 90, 340)):
            self.tree.heading(c, text=c.capitalize())
            self.tree.column(c, width=w, anchor="w")
        self.tree.pack(fill="both", expand=True, padx=8, pady=6)
        for sev, col in SEV_COLOR.items():
            self.tree.tag_configure(sev, foreground=col)

        yscroll = ttk.Scrollbar(self.tree, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=yscroll.set)
        yscroll.pack(side="right", fill="y")

    # -------------------------------------------------------------- actions
    def _refresh_drives(self) -> None:
        drives = list_removable()
        self.drive_box["values"] = drives
        if drives and not self.target_var.get():
            self.target_var.set(drives[0])
        n = len(drives)
        self.status_var.set(f"{n} removable drive(s) detected." if n else
                            "No removable drive detected — plug in a USB or Browse.")

    def _browse(self) -> None:
        path = filedialog.askdirectory(title="Choose a drive or folder to scan")
        if path:
            self.target_var.set(path)

    def _start_scan(self) -> None:
        if self._scanning:
            return
        target = self.target_var.get().strip()
        if not target or not os.path.exists(target):
            messagebox.showwarning("USB Virus Scanner",
                                   "Pick a valid drive or folder first.")
            return
        self._scanning = True
        self.scan_btn.config(state="disabled")
        self.tree.delete(*self.tree.get_children())
        self.banner.pack_forget()
        self.progress.start(12)
        self.status_var.set(f"Scanning {target} …")

        # Read Tk variables here on the main thread — Tcl is not thread-safe,
        # so the worker must not touch any tkinter object.
        do_quarantine = not self.report_only.get()
        t = threading.Thread(target=self._scan_worker,
                             args=(target, do_quarantine), daemon=True)
        t.start()

    def _scan_worker(self, target: str, do_quarantine: bool) -> None:
        try:
            result = self.engine.scan(
                target,
                progress=lambda m: self._events.put(("progress", m)),
                quarantine=do_quarantine,
            )
            log_result(self.logger, result)
            report = write_report(self.cfg["reporting"], result)
            self._events.put(("done", result, report))
        except Exception as exc:  # surface, don't crash the UI thread
            self._events.put(("error", str(exc)))

    # ---------------------------------------------------- event pump (UI thread)
    def _drain_events(self) -> None:
        try:
            while True:
                evt = self._events.get_nowait()
                kind = evt[0]
                if kind == "progress":
                    self.status_var.set(str(evt[1])[:90])
                elif kind == "done":
                    self._on_done(evt[1], evt[2])
                elif kind == "error":
                    self._finish()
                    messagebox.showerror("Scan error", evt[1])
        except queue.Empty:
            pass
        self.after(100, self._drain_events)

    def _on_done(self, result, report: str) -> None:
        self._finish()
        for d in result.detections:
            self.tree.insert("", "end",
                             values=(d.severity.value, d.threat, d.source, d.path),
                             tags=(d.severity.value,))
        clean = result.clean
        self.banner.config(
            text=(f"✔  CLEAN — {result.files_scanned} files scanned, no threats."
                  if clean else
                  f"⚠  {len(result.infected)} infected, {len(result.suspicious)} "
                  f"suspicious — infected files quarantined."),
            bg=SEV_COLOR["clean"] if clean else SEV_COLOR["infected"])
        self.banner.pack(fill="x", padx=8, before=self.tree)
        self.status_var.set(f"Done. Report: {report}")
        if not clean and result.infected and not self.report_only.get():
            messagebox.showwarning(
                "Threats found",
                f"{len(result.infected)} infected file(s) found and moved to "
                f"quarantine.\n\nReport:\n{report}")

    def _finish(self) -> None:
        self._scanning = False
        self.progress.stop()
        self.scan_btn.config(state="normal")

    # -------------------------------------------------------- quarantine window
    def _open_quarantine(self) -> None:
        QuarantineWindow(self, self.cfg)


class QuarantineWindow(tk.Toplevel):
    def __init__(self, master, cfg):
        super().__init__(master)
        self.title("Quarantine")
        self.geometry("760x400")
        self.q = Quarantine(cfg["quarantine"])

        cols = ("id", "threat", "original")
        self.tree = ttk.Treeview(self, columns=cols, show="headings")
        for c, w in zip(cols, (250, 200, 300)):
            self.tree.heading(c, text=c.capitalize())
            self.tree.column(c, width=w)
        self.tree.pack(fill="both", expand=True, padx=8, pady=8)

        bar = ttk.Frame(self)
        bar.pack(fill="x", padx=8, pady=(0, 8))
        ttk.Button(bar, text="Refresh", command=self._reload).pack(side="left")
        ttk.Button(bar, text="Restore selected…",
                   command=self._restore).pack(side="right")
        self._reload()

    def _reload(self) -> None:
        self.tree.delete(*self.tree.get_children())
        for e in self.q.list_entries():
            self.tree.insert("", "end",
                             values=(e["id"], e.get("threat", ""),
                                     e.get("original", "")))

    def _restore(self) -> None:
        sel = self.tree.selection()
        if not sel:
            return
        qid = self.tree.item(sel[0], "values")[0]
        if not messagebox.askyesno(
                "Restore file",
                "Restore this file to its original location?\n\n"
                "Only do this if you are sure it is safe — it was flagged as malware."):
            return
        dest = self.q.restore(qid)
        if dest:
            messagebox.showinfo("Restored", f"Restored to:\n{dest}")
            self._reload()
        else:
            messagebox.showerror("Restore failed", "Could not restore this item.")


def main() -> None:
    ScannerGUI().mainloop()


if __name__ == "__main__":
    main()
