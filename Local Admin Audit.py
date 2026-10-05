#!/usr/bin/env python3
"""
Local Admin Audit
-----------------
Run on a Windows server. Queries a list of remote machines for the members of
their local "Administrators" group, writes the results to a CSV, and retries
any failed machines on a timer (default: once an hour) until they all succeed
or you press Stop.

Method: PowerShell + ADSI WinNT provider (uses RPC/SMB, so WinRM is NOT
required). The account running this script needs local admin rights on the
target machines.

Requirements: Python 3.8+ (tkinter ships with the standard Windows installer).
"""

import csv
import os
import queue
import re
import subprocess
import threading
import time
import tkinter as tk
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from tkinter import filedialog, messagebox, scrolledtext, ttk

# --------------------------------------------------------------------------
# Settings
# --------------------------------------------------------------------------
MAX_WORKERS = 10             # machines queried in parallel
PER_MACHINE_TIMEOUT = 60     # seconds before a single query is abandoned
DEFAULT_RETRY_MINUTES = 60   # how often failed machines are retried
CSV_HEADERS = ["ComputerName", "Member", "MemberType", "Source", "Collected"]

# Looks up the group by its well-known SID (S-1-5-32-544) so it still works
# if the group was renamed or the OS is not English.
PS_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$c = $env:TARGET_COMPUTER
$sid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
$name = $sid.Translate([System.Security.Principal.NTAccount]).Value.Split('\')[1]
try {
    # Resolve the group name as it exists on the REMOTE machine
    $local = [ADSI]"WinNT://$c"
    $grp = $null
    foreach ($child in $local.Children) {
        if ($child.SchemaClassName -eq 'Group') {
            $sidBytes = $child.objectSid.Value
            $s = New-Object System.Security.Principal.SecurityIdentifier($sidBytes, 0)
            if ($s.Value -eq 'S-1-5-32-544') { $grp = $child; break }
        }
    }
    if (-not $grp) { throw "Administrators group not found" }
} catch { throw $_ }
$grp.Invoke('Members') | ForEach-Object {
    $t = $_.GetType()
    $cls  = $t.InvokeMember('Class',   'GetProperty', $null, $_, $null)
    $path = $t.InvokeMember('AdsPath', 'GetProperty', $null, $_, $null)
    "$cls|$path"
}
"""


def valid_hostname(name: str) -> bool:
    """Allow only hostnames / FQDNs / IPv4 so nothing odd reaches PowerShell."""
    return bool(re.fullmatch(r"[A-Za-z0-9]([A-Za-z0-9\-\.]{0,251}[A-Za-z0-9])?", name))


def query_admins(computer: str):
    """Return a list of (member, type, source) tuples or raise Exception."""
    if not valid_hostname(computer):
        raise ValueError("Invalid computer name")

    env = os.environ.copy()
    env["TARGET_COMPUTER"] = computer  # passed via env var -> no injection risk

    creation = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        proc = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive",
             "-ExecutionPolicy", "Bypass", "-Command", PS_SCRIPT],
            capture_output=True, text=True, timeout=PER_MACHINE_TIMEOUT,
            env=env, creationflags=creation,
        )
    except subprocess.TimeoutExpired:
        raise TimeoutError(f"Timed out after {PER_MACHINE_TIMEOUT}s")

    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "Unknown error").strip().splitlines()
        raise RuntimeError(err[0][:200] if err else "Unknown error")

    members = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if "|" not in line:
            continue
        cls, path = line.split("|", 1)
        path = re.sub(r"^WinNT://", "", path, flags=re.I)
        parts = path.split("/")
        # Local account  -> WinNT://COMPUTER/name   (or DOMAIN-less, 2 parts w/ computer)
        # Domain account -> WinNT://DOMAIN/name
        # Local via full path -> WinNT://DOMAIN/COMPUTER/name (3 parts)
        if len(parts) >= 3:
            member = f"{parts[0]}\\{parts[-1]}"
            source = "Local" if parts[1].lower() == computer.split(".")[0].lower() else "Domain"
            if source == "Local":
                member = f"{parts[1]}\\{parts[-1]}"
        elif len(parts) == 2:
            member = f"{parts[0]}\\{parts[1]}"
            source = "Local" if parts[0].lower() == computer.split(".")[0].lower() else "Domain"
        else:
            member, source = path, "Unknown"
        members.append((member, cls, source))
    return members


# --------------------------------------------------------------------------
# GUI
# --------------------------------------------------------------------------
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Local Admin Audit")
        self.geometry("950x720")
        self.minsize(800, 600)

        self.ui_queue = queue.Queue()
        self.stop_event = threading.Event()
        self.worker = None
        self.csv_lock = threading.Lock()

        self.completed = []          # list of computer names
        self.failed = {}             # computer -> last error

        self._build_ui()
        self.after(150, self._drain_queue)

    # ---------------- UI construction ----------------
    def _build_ui(self):
        pad = {"padx": 8, "pady": 4}
        root = ttk.Frame(self, padding=8)
        root.pack(fill="both", expand=True)
        root.columnconfigure(0, weight=1)
        root.columnconfigure(1, weight=1)
        root.rowconfigure(1, weight=1)
        root.rowconfigure(3, weight=1)

        # Input list
        ttk.Label(root, text="Computers to query (one per line, or comma/space separated):")\
            .grid(row=0, column=0, columnspan=2, sticky="w", **pad)
        self.input_box = scrolledtext.ScrolledText(root, height=8, wrap="word")
        self.input_box.grid(row=1, column=0, columnspan=2, sticky="nsew", **pad)

        # Output + settings
        opts = ttk.Frame(root)
        opts.grid(row=2, column=0, columnspan=2, sticky="ew")
        opts.columnconfigure(1, weight=1)

        ttk.Label(opts, text="Save results to (CSV):").grid(row=0, column=0, sticky="w", **pad)
        default_path = os.path.join(os.path.expanduser("~"), "Documents",
                                    f"LocalAdmins_{datetime.now():%Y%m%d}.csv")
        self.output_var = tk.StringVar(value=default_path)
        ttk.Entry(opts, textvariable=self.output_var).grid(row=0, column=1, sticky="ew", **pad)
        ttk.Button(opts, text="Browse...", command=self._browse).grid(row=0, column=2, **pad)

        # Retry interval, right-aligned under the Browse button
        retry_frame = ttk.Frame(opts)
        retry_frame.grid(row=1, column=0, columnspan=3, sticky="e", **pad)
        ttk.Label(retry_frame, text="Retry failed every (minutes):").pack(side="left", padx=(0, 6))
        self.retry_var = tk.StringVar(value=str(DEFAULT_RETRY_MINUTES))
        ttk.Spinbox(retry_frame, from_=1, to=1440, width=8, textvariable=self.retry_var)\
            .pack(side="left")

        # Results panes: completed (left) and failed (right)
        self.completed_label_var = tk.StringVar(value="Completed machines")
        self.failed_label_var = tk.StringVar(value="Failed machines (retried automatically)")
        ttk.Label(root, textvariable=self.completed_label_var)\
            .grid(row=2, column=0, sticky="sw", padx=8, pady=(40, 0))
        ttk.Label(root, textvariable=self.failed_label_var)\
            .grid(row=2, column=1, sticky="sw", padx=8, pady=(40, 0))

        self.completed_list = self._make_listbox(root, row=3, col=0)
        self.failed_list = self._make_listbox(root, row=3, col=1)

        # Controls + status
        bottom = ttk.Frame(root)
        bottom.grid(row=4, column=0, columnspan=2, sticky="ew", pady=(8, 0))
        bottom.columnconfigure(2, weight=1)

        self.start_btn = ttk.Button(bottom, text="Start", command=self.start)
        self.start_btn.grid(row=0, column=0, padx=8)
        self.stop_btn = ttk.Button(bottom, text="Stop", command=self.stop, state="disabled")
        self.stop_btn.grid(row=0, column=1, padx=8)
        self.status_var = tk.StringVar(value="Idle")
        ttk.Label(bottom, textvariable=self.status_var, anchor="w").grid(row=0, column=2, sticky="ew", padx=8)

        self.progress = ttk.Progressbar(root, mode="determinate")
        self.progress.grid(row=5, column=0, columnspan=2, sticky="ew", padx=8, pady=(6, 0))

    def _make_listbox(self, parent, row, col):
        frame = ttk.Frame(parent)
        frame.grid(row=row, column=col, sticky="nsew", padx=8, pady=4)
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        lb = tk.Listbox(frame, activestyle="none")
        sb = ttk.Scrollbar(frame, orient="vertical", command=lb.yview)
        lb.configure(yscrollcommand=sb.set)
        lb.grid(row=0, column=0, sticky="nsew")
        sb.grid(row=0, column=1, sticky="ns")
        return lb

    def _browse(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".csv", filetypes=[("CSV files", "*.csv")],
            initialfile=os.path.basename(self.output_var.get()),
            initialdir=os.path.dirname(self.output_var.get()) or None)
        if path:
            self.output_var.set(path)

    # ---------------- Start / stop ----------------
    def start(self):
        computers = self._parse_computers(self.input_box.get("1.0", "end"))
        if not computers:
            messagebox.showwarning("No computers", "Enter at least one computer name.")
            return

        out_path = self.output_var.get().strip()
        if not out_path:
            messagebox.showwarning("No output path", "Choose where to save the CSV.")
            return
        try:
            os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
            with self.csv_lock:
                if not os.path.exists(out_path) or os.path.getsize(out_path) == 0:
                    with open(out_path, "w", newline="", encoding="utf-8") as f:
                        csv.writer(f).writerow(CSV_HEADERS)
        except OSError as e:
            messagebox.showerror("Cannot write output file", str(e))
            return

        try:
            retry_secs = max(1, int(float(self.retry_var.get()))) * 60
        except ValueError:
            messagebox.showwarning("Invalid retry interval", "Retry interval must be a number of minutes.")
            return

        # Reset state
        self.completed.clear()
        self.failed.clear()
        self.completed_list.delete(0, "end")
        self.failed_list.delete(0, "end")
        self.completed_label_var.set("Completed machines (0)")
        self.failed_label_var.set("Failed machines (0) - retried automatically")
        self.stop_event.clear()
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")

        self.worker = threading.Thread(
            target=self._run, args=(computers, out_path, retry_secs), daemon=True)
        self.worker.start()

    def stop(self):
        self.stop_event.set()
        self.status_var.set("Stopping...")

    @staticmethod
    def _parse_computers(text):
        seen, result = set(), []
        for token in re.split(r"[,\s;]+", text):
            token = token.strip()
            if token and token.lower() not in seen:
                seen.add(token.lower())
                result.append(token)
        return result

    # ---------------- Background worker ----------------
    def _run(self, computers, out_path, retry_secs):
        try:
            self._post("status", f"Initial pass: querying {len(computers)} computer(s)...")
            failed = self._process(computers, out_path, label="Initial pass")

            # Hourly retry loop for failures
            while failed and not self.stop_event.is_set():
                resume_at = time.time() + retry_secs
                while time.time() < resume_at and not self.stop_event.is_set():
                    remaining = int(resume_at - time.time())
                    m, s = divmod(remaining, 60)
                    h, m = divmod(m, 60)
                    self._post("status",
                               f"{len(failed)} failed. Next retry in {h:d}:{m:02d}:{s:02d}")
                    self.stop_event.wait(1)
                if self.stop_event.is_set():
                    break
                self._post("status", f"Retrying {len(failed)} failed computer(s)...")
                failed = self._process(failed, out_path, label="Retry")

            if self.stop_event.is_set():
                self._post("status", f"Stopped. {len(self.completed)} completed, {len(self.failed)} still failed.")
            else:
                self._post("status", f"Done. All {len(self.completed)} computer(s) completed successfully.")
        except Exception as e:  # last-resort guard so the UI never hangs
            self._post("status", f"Fatal error: {e}")
        finally:
            self._post("finished", None)

    def _process(self, computers, out_path, label):
        """Query a batch of computers in parallel. Returns list of still-failed names."""
        still_failed = []
        total = len(computers)
        self._post("progress_max", total)
        done = 0

        def task(comp):
            if self.stop_event.is_set():
                return comp, None, "Cancelled"
            try:
                members = query_admins(comp)
                self._append_csv(out_path, comp, members)
                return comp, members, None
            except Exception as e:
                return comp, None, str(e)

        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
            for comp, members, err in pool.map(task, computers):
                done += 1
                self._post("progress", done)
                if err is None:
                    self._post("success", (comp, len(members)))
                elif err == "Cancelled":
                    still_failed.append(comp)
                else:
                    still_failed.append(comp)
                    self._post("fail", (comp, err))
                self._post("status", f"{label}: {done}/{total} processed")
        return still_failed

    def _append_csv(self, path, computer, members):
        stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        rows = [[computer, m, t, s, stamp] for (m, t, s) in members]
        if not rows:
            rows = [[computer, "(no members returned)", "", "", stamp]]
        with self.csv_lock:
            with open(path, "a", newline="", encoding="utf-8") as f:
                csv.writer(f).writerows(rows)

    # ---------------- UI updates (main thread only) ----------------
    def _post(self, kind, payload):
        self.ui_queue.put((kind, payload))

    def _drain_queue(self):
        try:
            while True:
                kind, payload = self.ui_queue.get_nowait()
                if kind == "status":
                    self.status_var.set(payload)
                elif kind == "progress_max":
                    self.progress.config(maximum=payload, value=0)
                elif kind == "progress":
                    self.progress.config(value=payload)
                elif kind == "success":
                    comp, count = payload
                    self.completed.append(comp)
                    self.completed_list.insert("end", f"{comp}  ({count} members)")
                    self.completed_label_var.set(
                        f"Completed machines ({len(self.completed)})")
                    if comp in self.failed:
                        del self.failed[comp]
                        self._refresh_failed()
                elif kind == "fail":
                    comp, err = payload
                    self.failed[comp] = err
                    self._refresh_failed()
                elif kind == "finished":
                    self.start_btn.config(state="normal")
                    self.stop_btn.config(state="disabled")
        except queue.Empty:
            pass
        self.after(150, self._drain_queue)

    def _refresh_failed(self):
        self.failed_list.delete(0, "end")
        for comp, err in sorted(self.failed.items()):
            self.failed_list.insert("end", f"{comp}  -  {err}")
        self.failed_label_var.set(
            f"Failed machines ({len(self.failed)}) - retried automatically")


if __name__ == "__main__":
    App().mainloop()