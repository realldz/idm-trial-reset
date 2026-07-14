#!/usr/bin/env python3
"""reset_trial_gui.py - tkinter frontend for reset_trial.py

Reset the IDM 30-day trial on this machine. Wipes the on-disk + registry trial
anchors (SYSTEM helper handles the DENY-ACE ConfigTime key), optionally keeping
the download list + settings and relaunching IDM. Requires Administrator; the
GUI self-elevates on launch.
"""

import ctypes
import os
import queue
import sys
import threading
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext

import reset_trial as rt


def _relaunch_elevated() -> None:
    params = " ".join(f'"{a}"' for a in [os.path.abspath(__file__)] + sys.argv[1:])
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)


class ResetGUI:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        root.title("IDM Trial Reset")
        root.geometry("720x560")
        root.minsize(600, 440)

        self.keep = tk.BooleanVar(value=True)
        self.launch = tk.BooleanVar(value=True)
        self._q: queue.Queue[str] = queue.Queue()
        self._running = False

        self._build_ui()
        self._pump_log()

    def _build_ui(self) -> None:
        info = ttk.LabelFrame(self.root, text="What this does", padding=8)
        info.pack(fill="x", padx=10, pady=(10, 0))
        ttk.Label(
            info, justify="left", wraplength=680,
            text=("Kills IDM, deletes the on-disk anchors (%AppData%\\IDM, "
                  "%AppData%\\DMCache, %ProgramData%\\IDM) and the registry stores "
                  "(HKCU\\Software\\DownloadManager + Backup_IDM). IDM then treats "
                  "this machine as a new install and grants a fresh 30-day trial."),
        ).pack(anchor="w")

        opt = ttk.LabelFrame(self.root, text="Options", padding=8)
        opt.pack(fill="x", padx=10, pady=5)
        ttk.Checkbutton(
            opt, variable=self.keep,
            text="Keep download list + settings (backup, wipe, restore with trial anchors stripped)",
        ).pack(anchor="w")
        ttk.Checkbutton(
            opt, variable=self.launch,
            text="Relaunch IDM after reset (writes the fresh 30-day trial)",
        ).pack(anchor="w")
        ttk.Label(
            opt, foreground="#a00", justify="left", wraplength=680,
            text=("Unchecking 'Keep' performs a full clean wipe — download history "
                  "and settings are lost."),
        ).pack(anchor="w", pady=(4, 0))

        act = ttk.Frame(self.root)
        act.pack(fill="x", padx=10, pady=(0, 5))
        self.btn = ttk.Button(act, text="Reset Trial", command=self._start)
        self.btn.pack(side="left")

        outf = ttk.LabelFrame(self.root, text="Output", padding=8)
        outf.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        self.output = scrolledtext.ScrolledText(
            outf, height=12, font=("Consolas", 9), wrap="word", state="disabled")
        self.output.pack(fill="both", expand=True)

    def _log(self, msg: str) -> None:
        self.output.configure(state="normal")
        self.output.insert("end", msg + "\n")
        self.output.see("end")
        self.output.configure(state="disabled")

    def _pump_log(self) -> None:
        try:
            while True:
                self._log(self._q.get_nowait())
        except queue.Empty:
            pass
        self.root.after(100, self._pump_log)

    def _start(self) -> None:
        if self._running:
            return
        keep = self.keep.get()
        warn = ("Full clean wipe — download history and settings will be lost.\n\nContinue?"
                if not keep else "Reset the IDM trial now?")
        if not messagebox.askyesno("Confirm", warn):
            return
        self._running = True
        self.btn.configure(state="disabled")
        self.output.configure(state="normal")
        self.output.delete("1.0", "end")
        self.output.configure(state="disabled")
        threading.Thread(
            target=self._worker, args=(self.launch.get(), keep), daemon=True).start()

    def _worker(self, launch: bool, keep: bool) -> None:
        try:
            rt.run_reset(launch, keep, keep, log=self._q.put)
        except Exception as e:
            self._q.put(f"ERROR: {e}")
        finally:
            self.root.after(0, self._done)

    def _done(self) -> None:
        self._running = False
        self.btn.configure(state="normal")


def main() -> None:
    if not rt.is_admin():
        _relaunch_elevated()
        return
    root = tk.Tk()
    ResetGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
