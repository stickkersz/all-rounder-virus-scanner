#!/usr/bin/env python3
"""All-Round Virus Scanner - desktop GUI (modern, smooth, real-time).

Tkinter/ttk (ships with Python on every Windows) so there is nothing extra to
install for the front-end. Scanning runs on a worker thread; progress events are
coalesced on the UI thread (one redraw per tick) so a drive with 100k files
can't flood the window - that was the old lag. A determinate progress bar shows
"scanning file X of Y" live.

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
from scanner.profiles import FULL, QUICK, resolve_targets
from scanner.quarantine import Quarantine
from scanner.realtime import RealtimeMonitor
from scanner.reporter import log_result, setup_logging, write_report
from scanner.drives import FIXED, REMOVABLE, list_drives

BASE_DIR = app_base_dir()

# Modern flat palette (kept readable on Windows default theme).
COL = {
    "bg": "#eef1f6", "card": "#ffffff", "text": "#1f2937", "muted": "#6b7280",
    "accent": "#2563eb", "accent_dark": "#1d4ed8",
    "clean": "#16a34a", "infected": "#dc2626", "suspicious": "#d97706",
    "error": "#6b7280", "border": "#d1d5db", "track": "#e5e7eb",
}
SEV_COLOR = {"infected": COL["infected"], "suspicious": COL["suspicious"],
             "clean": COL["clean"], "error": COL["error"]}


def _truncate_middle(text: str, width: int = 72) -> str:
    if len(text) <= width:
        return text
    keep = (width - 3) // 2
    return f"{text[:keep]}...{text[-keep:]}"


class ScannerGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("All-Round Virus Scanner")
        self.geometry("880x620")
        self.minsize(760, 540)
        self.configure(bg=COL["bg"])

        self.cfg = Config.load(os.path.join(BASE_DIR, "config.yaml"))
        self.logger = setup_logging(self.cfg["logging"])
        self.engine = ScanEngine(self.cfg, BASE_DIR)

        self._events: "queue.Queue[tuple]" = queue.Queue()
        self._scanning = False
        self._pending_progress = None      # coalesced: only the latest is drawn
        self._bar_mode = None
        self._monitor = None               # RealtimeMonitor when toggled on
        self._scan_thread = None           # in-flight manual scan worker

        self._init_style()
        self._build_ui()
        self._refresh_drives()
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        # realtime.enabled: true in config means protection starts with the
        # app — otherwise the config switch would be a knob that does nothing.
        if self.monitor_var.get():
            self._toggle_monitor()
        self.after(80, self._drain_events)

    # ------------------------------------------------------------------ style
    def _init_style(self) -> None:
        style = ttk.Style(self)
        try:
            style.theme_use("clam")            # allows color theming
        except tk.TclError:
            pass
        base_font = ("Segoe UI", 10)
        style.configure(".", font=base_font, background=COL["bg"],
                        foreground=COL["text"])
        style.configure("Card.TFrame", background=COL["card"])
        style.configure("TFrame", background=COL["bg"])
        style.configure("TLabel", background=COL["bg"], foreground=COL["text"])
        style.configure("Card.TLabel", background=COL["card"])
        style.configure("Muted.TLabel", background=COL["card"],
                        foreground=COL["muted"], font=("Segoe UI", 9))
        style.configure("Mono.TLabel", background=COL["card"],
                        foreground=COL["muted"], font=("Consolas", 9))
        style.configure("Title.TLabel", background=COL["bg"],
                        foreground=COL["text"], font=("Segoe UI Semibold", 15))
        style.configure("TCheckbutton", background=COL["card"])
        # Accent button
        style.configure("Accent.TButton", font=("Segoe UI Semibold", 10),
                        foreground="white", background=COL["accent"],
                        borderwidth=0, focusthickness=0, padding=(16, 8))
        style.map("Accent.TButton",
                  background=[("active", COL["accent_dark"]),
                              ("disabled", COL["muted"])])
        style.configure("TButton", padding=(10, 6))
        # Progress bar
        style.configure("Scan.Horizontal.TProgressbar", thickness=14,
                        troughcolor=COL["track"], background=COL["accent"],
                        borderwidth=0)
        # Treeview
        style.configure("Treeview", rowheight=26, fieldbackground=COL["card"],
                        background=COL["card"], font=("Segoe UI", 9))
        style.configure("Treeview.Heading", font=("Segoe UI Semibold", 9),
                        background=COL["bg"])

    def _card(self, parent) -> ttk.Frame:
        f = ttk.Frame(parent, style="Card.TFrame")
        return f

    # ------------------------------------------------------------------ UI
    def _build_ui(self) -> None:
        root = ttk.Frame(self, padding=14)
        root.pack(fill="both", expand=True)

        ttk.Label(root, text="🛡  All-Round Virus Scanner", style="Title.TLabel")\
            .pack(anchor="w", pady=(0, 10))

        # --- controls card ---
        ctrl = self._card(root)
        ctrl.pack(fill="x")
        inner = ttk.Frame(ctrl, style="Card.TFrame", padding=12)
        inner.pack(fill="x")

        row1 = ttk.Frame(inner, style="Card.TFrame")
        row1.pack(fill="x")
        ttk.Label(row1, text="Target", style="Card.TLabel").pack(side="left")
        self.target_var = tk.StringVar()
        self.drive_box = ttk.Combobox(row1, textvariable=self.target_var, width=44)
        self.drive_box.pack(side="left", padx=8)
        ttk.Button(row1, text="Refresh", command=self._refresh_drives)\
            .pack(side="left")
        ttk.Button(row1, text="Browse…", command=self._browse)\
            .pack(side="left", padx=(6, 0))

        row2 = ttk.Frame(inner, style="Card.TFrame")
        row2.pack(fill="x", pady=(12, 0))
        self.report_only = tk.BooleanVar(value=False)
        ttk.Checkbutton(row2, text="Report only (don't move files)",
                        variable=self.report_only,
                        command=self._sync_report_only).pack(side="left")
        self.monitor_var = tk.BooleanVar(
            value=bool(self.cfg["realtime"].get("enabled", False)))
        ttk.Checkbutton(row2, text="Real-time protection",
                        variable=self.monitor_var,
                        command=self._toggle_monitor).pack(side="left",
                                                           padx=(14, 0))
        self.scan_btn = ttk.Button(row2, text="▶  Scan", style="Accent.TButton",
                                   command=self._start_scan)
        self.scan_btn.pack(side="right")
        self.full_btn = ttk.Button(row2, text="Full Scan",
                                   command=lambda: self._start_profile(FULL))
        self.full_btn.pack(side="right", padx=(0, 8))
        self.quick_btn = ttk.Button(row2, text="Quick Scan",
                                    command=lambda: self._start_profile(QUICK))
        self.quick_btn.pack(side="right", padx=(0, 8))
        ttk.Button(row2, text="Quarantine…", command=self._open_quarantine)\
            .pack(side="right", padx=(0, 8))
        # Defined where the buttons are built: a new scan button added here
        # must join this tuple, or it stays clickable mid-scan.
        self.scan_buttons = (self.scan_btn, self.quick_btn, self.full_btn)

        # --- progress card ---
        prog = self._card(root)
        prog.pack(fill="x", pady=12)
        pin = ttk.Frame(prog, style="Card.TFrame", padding=12)
        pin.pack(fill="x")
        head = ttk.Frame(pin, style="Card.TFrame")
        head.pack(fill="x")
        self.phase_var = tk.StringVar(value="Ready.")
        ttk.Label(head, textvariable=self.phase_var, style="Card.TLabel")\
            .pack(side="left")
        self.count_var = tk.StringVar(value="")
        ttk.Label(head, textvariable=self.count_var, style="Muted.TLabel")\
            .pack(side="right")
        self.progress = ttk.Progressbar(pin, style="Scan.Horizontal.TProgressbar",
                                        mode="determinate", maximum=100)
        self.progress.pack(fill="x", pady=(8, 6))
        self.file_var = tk.StringVar(value="")
        ttk.Label(pin, textvariable=self.file_var, style="Mono.TLabel")\
            .pack(anchor="w")

        # --- verdict banner ---
        self.banner = tk.Label(root, text="", font=("Segoe UI Semibold", 12),
                               fg="white", bg=COL["bg"], pady=8)
        self.banner.pack(fill="x")
        self.banner.pack_forget()

        # --- results table ---
        table_wrap = ttk.Frame(root)
        table_wrap.pack(fill="both", expand=True)
        cols = ("severity", "threat", "source", "file")
        self.tree = ttk.Treeview(table_wrap, columns=cols, show="headings")
        for c, w, anc in (("severity", 90, "w"), ("threat", 240, "w"),
                          ("source", 80, "w"), ("file", 360, "w")):
            self.tree.heading(c, text=c.capitalize())
            self.tree.column(c, width=w, anchor=anc)
        vs = ttk.Scrollbar(table_wrap, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vs.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vs.grid(row=0, column=1, sticky="ns")
        table_wrap.rowconfigure(0, weight=1)
        table_wrap.columnconfigure(0, weight=1)
        for sev, col in SEV_COLOR.items():
            self.tree.tag_configure(sev, foreground=col)

        # --- status bar ---
        self.status_var = tk.StringVar(value="")
        ttk.Label(root, textvariable=self.status_var, style="Muted.TLabel")\
            .pack(anchor="w", pady=(6, 0))

    # -------------------------------------------------------------- actions
    def _refresh_drives(self) -> None:
        # Every scannable disk, not just removable — removable first so the USB
        # flow still puts a stick at the top of the list.
        found = sorted(list_drives((REMOVABLE, FIXED)),
                       key=lambda d: (d.kind != REMOVABLE, d.root))
        self.drive_box["values"] = [d.root for d in found]
        # Auto-fill ONLY a removable drive. Pre-selecting C:\ when no USB is
        # attached would turn a habitual "click Scan" into an hours-long
        # system-disk walk with quarantine on; fixed disks must be a
        # deliberate pick from the dropdown.
        if (found and not self.target_var.get()
                and found[0].kind == REMOVABLE):
            self.target_var.set(found[0].root)
        n = len(found)
        self.status_var.set(f"{n} drive(s) detected." if n else
                            "No drive detected - plug in a USB or Browse.")

    def _browse(self) -> None:
        path = filedialog.askdirectory(title="Choose a drive or folder to scan")
        if path:
            self.target_var.set(path)

    def _start_scan(self) -> None:
        target = self.target_var.get().strip()
        if not target or not os.path.exists(target):
            messagebox.showwarning("All-Round Virus Scanner",
                                   "Pick a valid drive or folder first.")
            return
        # A path the user picked themselves -> explicit (overrides an
        # exclusion blanketing it, like the CLI's positional-path behavior).
        self._launch(lambda q: self.engine.scan(
            target, progress=self._progress_cb, quarantine=q, explicit=True))

    def _start_profile(self, profile: str) -> None:
        try:
            targets = resolve_targets(
                profile,
                include_network=self.cfg["scanner"].get("scan_network_drives",
                                                        False))
        except ValueError as exc:
            messagebox.showerror("All-Round Virus Scanner", str(exc))
            return
        if not targets:
            messagebox.showwarning("All-Round Virus Scanner",
                                   "No scan targets found for this profile.")
            return
        if profile == FULL and not messagebox.askyesno(
                "Full scan",
                "Scan every drive on this computer?\n\n"
                f"Targets: {', '.join(targets)}\n\n"
                "This can take hours on a large disk."):
            return
        # Profile-resolved roots are machine-generated -> exclusions apply
        # fully (explicit=False), matching the CLI.
        self._launch(lambda q: self.engine.scan_many(
            targets, progress=self._progress_cb, quarantine=q,
            explicit=False))

    def _progress_cb(self, ev) -> None:
        self._events.put(("progress", ev))

    def _insert_detections(self, detections) -> None:
        """The results-table column contract, in one place: manual and
        real-time rows must always agree on column order."""
        for d in detections:
            self.tree.insert("", "end",
                             values=(d.severity.value, d.threat, d.source,
                                     d.path),
                             tags=(d.severity.value,))

    def _launch(self, scan_fn) -> None:
        """Common scan startup: lock the UI, then run `scan_fn(quarantine)`
        on a worker thread through the shared log/report/done pipeline."""
        if self._scanning:
            return
        self._scanning = True
        for b in self.scan_buttons:
            b.config(state="disabled")
        self.tree.delete(*self.tree.get_children())
        self.banner.pack_forget()
        self._pending_progress = None
        self._set_indeterminate(True)
        self.phase_var.set("Starting…")
        self.count_var.set("")
        self.file_var.set("")

        do_quarantine = not self.report_only.get()   # read Tk var on main thread
        # Keep the handle: a worker still holding a reference to this window
        # can end up running the GC that finalizes Tk widgets, and finalizing
        # them off the main thread aborts Tcl. Shutdown joins it.
        self._scan_thread = threading.Thread(
            target=self._scan_worker, args=(scan_fn, do_quarantine), daemon=True)
        self._scan_thread.start()

    def _scan_worker(self, scan_fn, do_quarantine: bool) -> None:
        try:
            result = scan_fn(do_quarantine)
            log_result(self.logger, result)
            report = write_report(self.cfg["reporting"], result)
            self._events.put(("done", result, report))
        except Exception as exc:  # surface, don't crash the UI thread
            self._events.put(("error", str(exc)))

    # -------------------------------------------------- real-time protection
    def _sync_report_only(self) -> None:
        """Keep a running monitor in step with the Report-only checkbox.

        "Report only (don't move files)" is the ONE visible move-nothing
        control; a real-time hit must honor it too, or the app quarantines a
        file the user was promised it would leave alone.
        """
        if self._monitor:
            self._monitor.quarantine = self._realtime_quarantine()

    def _realtime_quarantine(self) -> bool:
        return (not self.report_only.get()) and \
            self.cfg["realtime"].get("quarantine", True)

    def _toggle_monitor(self) -> None:
        if self.monitor_var.get():
            # from_config derives watch roots + the ignore list (our own
            # quarantine/log/report/feeds dirs) so the GUI and CLI can't drift.
            self._monitor = RealtimeMonitor.from_config(
                self.engine, self.cfg,
                on_result=lambda r: self._events.put(("rt", r)),
                quarantine=self._realtime_quarantine())
            try:
                self._monitor.start()
            except RuntimeError as exc:
                self._monitor = None
                self.monitor_var.set(False)
                messagebox.showerror("Real-time protection", str(exc))
                return
            warning = self._monitor.clamd_warning()
            if warning:
                messagebox.showwarning("Real-time protection", warning)
            self.status_var.set(
                f"Real-time protection ON — watching "
                f"{len(self._monitor.roots)} folder(s).")
        elif self._monitor:
            self._monitor.stop()          # stop() drains + flushes the cache
            self._monitor = None
            self.status_var.set("Real-time protection off.")

    def _on_rt_result(self, result) -> None:
        """A real-time batch finished: same log/report/table path as manual
        scans (spec: one notification path, one quarantine, one log)."""
        log_result(self.logger, result)
        self._insert_detections(result.detections)
        if result.detections:
            write_report(self.cfg["reporting"], result)
        if result.infected:
            self.banner.config(
                text=(f"⚠  Real-time: {len(result.infected)} infected "
                      f"file(s) quarantined."),
                bg=COL["infected"])
            self.banner.pack(fill="x", pady=(0, 8), before=self.tree.master)

    def _on_close(self) -> None:
        if self._monitor:
            self._monitor.stop()          # drains + flushes the cache
            self._monitor = None
        self.destroy()

    # ---------------------------------------------------- event pump (UI thread)
    def _drain_events(self) -> None:
        """Drain the whole queue but only KEEP the latest progress event, then
        apply it once. This is what keeps the UI smooth under a file firehose."""
        try:
            while True:
                evt = self._events.get_nowait()
                kind = evt[0]
                if kind == "progress":
                    self._pending_progress = evt[1]     # coalesce
                elif kind == "done":
                    self._pending_progress = None
                    self._on_done(evt[1], evt[2])
                elif kind == "rt":
                    self._on_rt_result(evt[1])
                elif kind == "error":
                    self._pending_progress = None
                    self._finish()
                    messagebox.showerror("Scan error", evt[1])
        except queue.Empty:
            pass
        if self._pending_progress is not None:
            self._render_progress(self._pending_progress)
            self._pending_progress = None
        self.after(80, self._drain_events)

    def _set_indeterminate(self, on: bool) -> None:
        if on and self._bar_mode != "indeterminate":
            self.progress.config(mode="indeterminate")
            self.progress.start(12)
            self._bar_mode = "indeterminate"
        elif not on and self._bar_mode != "determinate":
            self.progress.stop()
            self.progress.config(mode="determinate")
            self._bar_mode = "determinate"

    def _render_progress(self, ev) -> None:
        if ev.phase in ("indexing", "clamav"):
            self._set_indeterminate(True)
            self.phase_var.set(ev.message)
            self.count_var.set("")
            self.file_var.set("")
        elif ev.phase == "scanning":
            self._set_indeterminate(False)
            pct = int(ev.current * 100 / ev.total) if ev.total else 0
            self.progress.config(maximum=ev.total or 100, value=ev.current)
            self.phase_var.set("Scanning…")
            self.count_var.set(f"{ev.current} / {ev.total}  ({pct}%)")
            self.file_var.set(_truncate_middle(ev.message))
        elif ev.phase == "done":
            self.phase_var.set(ev.message)

    def _on_done(self, result, report: str) -> None:
        self._finish()
        self._insert_detections(result.detections)
        clean = result.clean
        report_only = self.report_only.get()
        if clean:
            text = f"✔  CLEAN — {result.files_scanned} files scanned, no threats."
        else:
            action = ("NOT moved (report-only)" if report_only
                      else "infected files quarantined")
            text = (f"⚠  {len(result.infected)} infected, "
                    f"{len(result.suspicious)} suspicious — {action}.")
        self.banner.config(text=text,
                           bg=COL["clean"] if clean else COL["infected"])
        self.banner.pack(fill="x", pady=(0, 8), before=self.tree.master)
        self.status_var.set(f"Done. Report saved: {report}")
        if not clean and result.infected and not report_only:
            messagebox.showwarning(
                "Threats found",
                f"{len(result.infected)} infected file(s) found and moved to "
                f"quarantine.\n\nReport:\n{report}")

    def _finish(self) -> None:
        self._scanning = False
        self._set_indeterminate(False)
        self.progress.config(value=self.progress["maximum"])
        for b in self.scan_buttons:
            b.config(state="normal")
        self.phase_var.set("Done.")

    # -------------------------------------------------------- quarantine window
    def _open_quarantine(self) -> None:
        QuarantineWindow(self, self.cfg)


class QuarantineWindow(tk.Toplevel):
    def __init__(self, master, cfg):
        super().__init__(master)
        self.title("Quarantine")
        self.geometry("780x420")
        self.configure(bg=COL["bg"])
        self.q = Quarantine(cfg["quarantine"])

        wrap = ttk.Frame(self, padding=12)
        wrap.pack(fill="both", expand=True)
        cols = ("id", "threat", "original")
        self.tree = ttk.Treeview(wrap, columns=cols, show="headings")
        for c, w in (("id", 250, ), ("threat", 210,), ("original", 300,)):
            self.tree.heading(c, text=c.capitalize())
            self.tree.column(c, width=w)
        self.tree.pack(fill="both", expand=True)

        bar = ttk.Frame(wrap)
        bar.pack(fill="x", pady=(8, 0))
        ttk.Button(bar, text="Refresh", command=self._reload).pack(side="left")
        # Danger zone: permanent deletion (irreversible).
        self._danger = tk.Button(bar, text="🗑 Delete ALL", fg="white",
                                 bg=COL["infected"], activebackground="#b91c1c",
                                 activeforeground="white", relief="flat",
                                 font=("Segoe UI Semibold", 9), padx=12, pady=5,
                                 command=self._delete_all)
        self._danger.pack(side="left", padx=(8, 0))
        ttk.Button(bar, text="Restore selected…",
                   command=self._restore).pack(side="right")
        self._del_btn = tk.Button(bar, text="Delete selected", fg="white",
                                  bg=COL["infected"], activebackground="#b91c1c",
                                  activeforeground="white", relief="flat",
                                  font=("Segoe UI Semibold", 9), padx=12, pady=5,
                                  command=self._delete_selected)
        self._del_btn.pack(side="right", padx=(0, 8))
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
                "Only do this if you are sure it is safe - it was flagged as malware."):
            return
        try:
            dest = self.q.restore(qid)
        except Exception as exc:
            messagebox.showerror("Restore failed", str(exc))
            return
        if dest:
            messagebox.showinfo("Restored", f"Restored to:\n{dest}")
            self._reload()
        else:
            messagebox.showerror(
                "Restore failed",
                "Could not restore this item (original location unavailable?).")

    def _delete_selected(self) -> None:
        sel = self.tree.selection()
        if not sel:
            return
        qid = self.tree.item(sel[0], "values")[0]
        if not messagebox.askyesno(
                "Delete permanently",
                "Permanently delete this malware file?\n\n"
                "This CANNOT be undone.", icon="warning", default="no"):
            return
        if self.q.delete(qid):
            self._reload()
        else:
            messagebox.showerror("Delete failed", "Could not delete this item.")

    def _delete_all(self) -> None:
        n = len(self.q.list_entries())
        if n == 0:
            messagebox.showinfo("Quarantine", "Quarantine is already empty.")
            return
        if not messagebox.askyesno(
                "Delete ALL permanently",
                f"Permanently delete ALL {n} quarantined malware file(s)?\n\n"
                "This CANNOT be undone.", icon="warning", default="no"):
            return
        deleted = self.q.delete_all()
        messagebox.showinfo("Done", f"Permanently deleted {deleted} file(s).")
        self._reload()


def main() -> None:
    ScannerGUI().mainloop()


if __name__ == "__main__":
    main()
