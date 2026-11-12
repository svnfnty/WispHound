#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WispHound GUI 2.1.2 — Tkinter frontend for the WispHound engine.

Requires the original wisphound.py module in the same directory.
Run as root:  sudo python3 wisphound_gui.py
"""
import os
import queue
import sys
import threading
import time
import tkinter as tk
from datetime import datetime
from tkinter import ttk, messagebox, filedialog, simpledialog

# --------------------------------------------------------------------------
# Import the engine. The original file has a `if __name__ == '__main__'`
# block, so importing it is safe — no CLI side-effects run.
# --------------------------------------------------------------------------
try:
    import wisphound as engine  # rename your script to wisphound.py
except ImportError:
    # Fallback: load by path (rename not required)
    import importlib.util, pathlib
    for cand in ("wisphound.py", "wisphound.txt"):
        p = pathlib.Path(__file__).with_name(cand)
        if p.exists():
            spec = importlib.util.spec_from_file_location("wisphound", p)
            engine = importlib.util.module_from_spec(spec)
            sys.modules["wisphound"] = engine
            spec.loader.exec_module(engine)
            break
    else:
        raise SystemExit("Place wisphound.py (or .txt) next to this GUI file.")


# ==========================================================================
# Theme
# ==========================================================================
BG        = "#0e1116"
BG_ALT    = "#161b22"
BG_INPUT  = "#0b0e13"
FG        = "#d7dde5"
FG_DIM    = "#7d8794"
ACCENT    = "#00d4ff"
ACCENT_2  = "#7c5cff"
OK        = "#22c55e"
WARN      = "#f59e0b"
ERR       = "#ef4444"
BORDER    = "#2a3038"

MONO = ("Consolas", 10) if sys.platform.startswith("win") else ("Monospace", 10)
UI_FONT = ("Segoe UI", 10) if sys.platform.startswith("win") else ("Helvetica", 10)


def _style_init(root):
    s = ttk.Style(root)
    try:
        s.theme_use("clam")
    except tk.TclError:
        pass
    s.configure(".", background=BG, foreground=FG, font=UI_FONT,
                fieldbackground=BG_INPUT, bordercolor=BORDER)
    s.configure("TFrame", background=BG)
    s.configure("Alt.TFrame", background=BG_ALT)
    s.configure("TLabel", background=BG, foreground=FG)
    s.configure("Dim.TLabel", background=BG, foreground=FG_DIM)
    s.configure("Head.TLabel", background=BG, foreground=ACCENT,
                font=(UI_FONT[0], 11, "bold"))
    s.configure("TButton", background=BG_ALT, foreground=FG,
                borderwidth=1, focusthickness=0, padding=(10, 6))
    s.map("TButton",
          background=[("active", BORDER), ("disabled", BG_ALT)],
          foreground=[("disabled", FG_DIM)])
    s.configure("Accent.TButton", background=ACCENT_2, foreground="white")
    s.map("Accent.TButton", background=[("active", "#9a7bff")])
    s.configure("Danger.TButton", background="#7f1d1d", foreground="white")
    s.map("Danger.TButton", background=[("active", "#991b1b")])
    s.configure("TEntry", fieldbackground=BG_INPUT, foreground=FG,
                insertcolor=ACCENT, bordercolor=BORDER)
    s.configure("TCombobox", fieldbackground=BG_INPUT, foreground=FG,
                background=BG_ALT, arrowcolor=FG)
    s.map("TCombobox", fieldbackground=[("readonly", BG_INPUT)],
          foreground=[("readonly", FG)])
    s.configure("TCheckbutton", background=BG, foreground=FG)
    s.map("TCheckbutton", background=[("active", BG)])
    s.configure("Treeview", background=BG_INPUT, fieldbackground=BG_INPUT,
                foreground=FG, bordercolor=BORDER, borderwidth=0, rowheight=24)
    s.configure("Treeview.Heading", background=BG_ALT, foreground=ACCENT,
                font=(UI_FONT[0], 9, "bold"), relief="flat")
    s.map("Treeview", background=[("selected", ACCENT_2)],
          foreground=[("selected", "white")])
    s.map("Treeview.Heading", background=[("active", BORDER)])
    s.configure("TNotebook", background=BG, borderwidth=0)
    s.configure("TNotebook.Tab", background=BG_ALT, foreground=FG_DIM,
                padding=(14, 6))
    s.map("TNotebook.Tab",
          background=[("selected", BG)],
          foreground=[("selected", ACCENT)])
    s.configure("Vertical.TScrollbar", background=BG_ALT,
                troughcolor=BG, arrowcolor=FG_DIM)
    s.configure("TProgressbar", background=ACCENT_2, troughcolor=BG_INPUT,
                bordercolor=BORDER)
    s.configure("TSeparator", background=BORDER)


# ==========================================================================
# Log pane
# ==========================================================================
class LogPane(tk.Frame):
    """Colored, thread-safe scrollback console."""

    TAGS = {
        "info":   FG,
        "ok":     OK,
        "warn":   WARN,
        "err":    ERR,
        "accent": ACCENT,
        "dim":    FG_DIM,
        "pixie":  "#c084fc",
    }

    def __init__(self, master):
        super().__init__(master, bg=BG)
        self.q = queue.Queue()
        self.text = tk.Text(self, bg=BG_INPUT, fg=FG, insertbackground=ACCENT,
                            font=MONO, wrap="word", relief="flat",
                            borderwidth=1, highlightthickness=1,
                            highlightbackground=BORDER, highlightcolor=ACCENT,
                            padx=10, pady=8, state="disabled")
        sb = ttk.Scrollbar(self, orient="vertical", command=self.text.yview)
        self.text.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self.text.pack(side="left", fill="both", expand=True)

        for tag, color in self.TAGS.items():
            self.text.tag_configure(tag, foreground=color)
        self.text.tag_configure("ts", foreground=FG_DIM)

        self.after(60, self._drain)

    def write(self, msg, tag="info"):
        self.q.put((msg, tag))

    # thread-safe entry point
    def _drain(self):
        try:
            while True:
                msg, tag = self.q.get_nowait()
                self._append(msg, tag)
        except queue.Empty:
            pass
        self.after(60, self._drain)

    def _append(self, msg, tag):
        self.text.configure(state="normal")
        ts = datetime.now().strftime("%H:%M:%S")
        self.text.insert("end", f"[{ts}] ", "ts")
        self.text.insert("end", str(msg).rstrip("\n") + "\n",
                         tag if tag in self.TAGS else "info")
        self.text.see("end")
        # cap scrollback
        if int(self.text.index("end-1c").split(".")[0]) > 4000:
            self.text.delete("1.0", "500.0")
        self.text.configure(state="disabled")

    def clear(self):
        self.text.configure(state="normal")
        self.text.delete("1.0", "end")
        self.text.configure(state="disabled")


# ==========================================================================
# Network table
# ==========================================================================
COLS = ("sel", "bssid", "essid", "sec", "pwr", "ch", "wps",
        "pixie", "vendor", "model")

COL_W = {
    "sel": 40, "bssid": 145, "essid": 190, "sec": 80, "pwr": 55,
    "ch": 45, "wps": 55, "pixie": 60, "vendor": 130, "model": 200,
}


class NetTable(ttk.Frame):
    def __init__(self, master, on_double):
        super().__init__(master)
        self.on_double = on_double
        self.nets = []          # list of dicts from scanner
        self.tree = ttk.Treeview(self, columns=COLS, show="headings",
                                 selectmode="browse")
        heads = {
            "sel": "#", "bssid": "BSSID", "essid": "ESSID",
            "sec": "Security", "pwr": "PWR", "ch": "Ch",
            "wps": "WPS", "pixie": "Pixie", "vendor": "Vendor",
            "model": "WSC Model",
        }
        for c in COLS:
            self.tree.heading(c, text=heads[c])
            self.tree.column(c, width=COL_W[c],
                             anchor="center" if c in
                             ("sel", "pwr", "ch", "wps", "pixie") else "w",
                             stretch=(c in ("essid", "vendor", "model")))

        self.tree.tag_configure("vuln", foreground="#c084fc")
        self.tree.tag_configure("locked", foreground=ERR)
        self.tree.tag_configure("nowps", foreground=FG_DIM)
        self.tree.tag_configure("stored", foreground=WARN)

        vs = ttk.Scrollbar(self, orient="vertical", command=self.tree.yview)
        hs = ttk.Scrollbar(self, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vs.set, xscrollcommand=hs.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vs.grid(row=0, column=1, sticky="ns")
        hs.grid(row=1, column=0, sticky="ew")
        self.rowconfigure(0, weight=1)
        self.columnconfigure(0, weight=1)
        self.tree.bind("<Double-1>", self._dbl)

    def populate(self, nets, stored_pairs=None):
        self.nets = nets
        self.tree.delete(*self.tree.get_children())
        stored_pairs = set(stored_pairs or [])
        for i, n in enumerate(nets, 1):
            pixie = "●" if n.get("Pixie vulnerable") else "—"
            wps = "yes" if n.get("WPS") else "no"
            tag = ()
            if not n.get("WPS"):
                tag = ("nowps",)
            elif n.get("WPS locked"):
                tag = ("locked",)
            elif n.get("Pixie vulnerable"):
                tag = ("vuln",)
            elif (n["BSSID"], n.get("ESSID", "HIDDEN")) in stored_pairs:
                tag = ("stored",)
            self.tree.insert(
                "", "end", iid=str(i), tags=tag,
                values=(i, n["BSSID"], n.get("ESSID", "HIDDEN"),
                        n.get("Security type", "?"), n.get("Level", ""),
                        n.get("Channel", ""), wps, pixie,
                        n.get("Vendor", ""),
                        f"{n.get('Model', '')} {n.get('Model number', '')}".strip()))

    def selected(self):
        sel = self.tree.selection()
        if not sel:
            return None
        try:
            return self.nets[int(sel[0]) - 1]
        except (ValueError, IndexError):
            return None

    def _dbl(self, _evt):
        n = self.selected()
        if n:
            self.on_double(n)


# ==========================================================================
# Main window
# ==========================================================================
class WispHoundGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("WispHound 2.1.2 — GUI")
        self.geometry("1280x820")
        self.minsize(1050, 700)
        self.configure(bg=BG)
        _style_init(self)

        # state
        self.db = None
        self.interface = tk.StringVar(value=self._guess_iface())
        self.backend = tk.StringVar(value="internal")
        self.target_bssid = tk.StringVar()
        self.target_channel = tk.StringVar()
        self.pixie_mode = tk.BooleanVar(value=True)
        self.bruteforce = tk.BooleanVar(value=False)
        self.save_creds = tk.BooleanVar(value=True)
        self.verbose = tk.BooleanVar(value=False)
        self.write_json = tk.BooleanVar(value=False)
        self.delay = tk.StringVar(value="")
        self.pixie_force = tk.BooleanVar(value=False)
        self.auto_attack = tk.BooleanVar(value=False)

        self.companion = None
        self.attacker = None
        self.busy = False
        self._stop_evt = threading.Event()

        self._build()
        self._init_db()
        self.log.write("WispHound GUI ready.", "ok")
        if os.getuid() != 0:
            self.log.write("WARNING: not running as root — wireless ops will fail.",
                           "warn")

    # ---- helpers ---------------------------------------------------------
    @staticmethod
    def _guess_iface():
        for n in ("wlan0", "wlp2s0", "wlp3s0", "wlan1"):
            if os.path.exists(f"/sys/class/net/{n}"):
                return n
        return "wlan0"

    def _init_db(self):
        try:
            path = os.path.expanduser("~/.WispHound/targets.db")
            self.db = engine.TargetDB(path)
            self.log.write(f"Target DB: {path}", "dim")
        except Exception as e:
            self.log.write(f"DB init failed: {e}", "err")

    def _set_busy(self, state: bool):
        self.busy = state
        self.scan_btn.configure(state="disabled" if state else "normal")
        self.attack_btn.configure(state="disabled" if state else "normal")
        self.pbc_btn.configure(state="disabled" if state else "normal")
        self.stop_btn.configure(state="normal" if state else "disabled")
        if state:
            self.progress.start(12)
        else:
            self.progress.stop()
            self.progress["value"] = 0

    def _set_progress(self, value, maximum=None):
        if maximum:
            self.progress["mode"] = "determinate"
            self.progress["maximum"] = maximum
        self.progress["value"] = value

    def _run_bg(self, fn):
        if self.busy:
            messagebox.showwarning("Busy", "An operation is already running.")
            return

        def runner():
            self._set_busy(True)
            try:
                fn()
            except Exception as e:
                self.log.write(f"FATAL: {e}", "err")
            finally:
                self._set_busy(False)
        threading.Thread(target=runner, daemon=True).start()

    # ---- layout ----------------------------------------------------------
    def _build(self):
        # header
        header = ttk.Frame(self)
        header.pack(fill="x", padx=14, pady=(12, 6))
        ttk.Label(header, text="WispHound", style="Head.TLabel",
                  font=(UI_FONT[0], 16, "bold")).pack(side="left")
        ttk.Label(header, text="  WPS reconnaissance & Pixie Dust auditor",
                  style="Dim.TLabel").pack(side="left", pady=(6, 0))
        ttk.Label(header, text="v2.1.2",
                  style="Dim.TLabel").pack(side="right")

        # top controls
        ctrl = ttk.Frame(self)
        ctrl.pack(fill="x", padx=14, pady=4)

        ttk.Label(ctrl, text="Interface").grid(row=0, column=0, sticky="w")
        iface_cb = ttk.Combobox(ctrl, textvariable=self.interface, width=14,
                                values=self._ifaces())
        iface_cb.grid(row=0, column=1, padx=(6, 14))

        ttk.Label(ctrl, text="Backend").grid(row=0, column=2, sticky="w")
        ttk.Combobox(ctrl, textvariable=self.backend, width=10, state="readonly",
                     values=("internal", "reaver", "bully")).grid(
            row=0, column=3, padx=(6, 14))

        self.scan_btn = ttk.Button(ctrl, text="  Scan networks  ",
                                   style="Accent.TButton",
                                   command=self.on_scan)
        self.scan_btn.grid(row=0, column=4, padx=(6, 6))

        self.attack_btn = ttk.Button(ctrl, text="  Attack target  ",
                                     command=self.on_attack)
        self.attack_btn.grid(row=0, column=5, padx=6)

        self.pbc_btn = ttk.Button(ctrl, text="  PBC  ",
                                  command=self.on_pbc)
        self.pbc_btn.grid(row=0, column=6, padx=6)

        self.stop_btn = ttk.Button(ctrl, text="  Stop  ", style="Danger.TButton",
                                   state="disabled", command=self.on_stop)
        self.stop_btn.grid(row=0, column=7, padx=6)

        self.progress = ttk.Progressbar(ctrl, mode="indeterminate", length=180)
        self.progress.grid(row=0, column=8, padx=(18, 0), sticky="e")
        ctrl.columnconfigure(8, weight=1)

        ttk.Separator(self, orient="horizontal").pack(fill="x", padx=14, pady=8)

        # body: notebook
        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=14, pady=(0, 12))

        # -- targets tab
        t_targets = ttk.Frame(nb)
        nb.add(t_targets, text="  Targets  ")
        self.table = NetTable(t_targets, on_double=self._target_dbl)
        self.table.pack(fill="both", expand=True, padx=4, pady=4)
        self.table.tree.bind("<<TreeviewSelect>>", self._on_select)

        # -- attack options tab
        t_opts = ttk.Frame(nb)
        nb.add(t_opts, text="  Attack Options  ")
        self._build_opts(t_opts)

        # -- pixiewps tab
        t_pix = ttk.Frame(nb)
        nb.add(t_pix, text="  Pixiewps Data  ")
        self._build_pixie(t_pix)

        # -- log tab
        t_log = ttk.Frame(nb)
        nb.add(t_log, text="  Log  ")
        bar = ttk.Frame(t_log)
        bar.pack(fill="x", pady=(2, 4))
        ttk.Button(bar, text="Clear", command=lambda: self.log.clear()).pack(side="right")
        ttk.Button(bar, text="Save…", command=self._save_log).pack(side="right", padx=6)
        self.log = LogPane(t_log)
        self.log.pack(fill="both", expand=True)

        # status bar
        self.status = tk.StringVar(value="Ready.")
        tk.Label(self, textvariable=self.status, bg=BG_ALT, fg=FG_DIM,
                 anchor="w", padx=12, pady=5).pack(fill="x", side="bottom")

    def _ifaces(self):
        try:
            return sorted(os.listdir("/sys/class/net"))
        except Exception:
            return ["wlan0"]

    def _build_opts(self, parent):
        wrap = ttk.Frame(parent)
        wrap.pack(fill="both", expand=True, padx=12, pady=12)

        # target card
        card = ttk.LabelFrame(wrap, text=" Target ")
        card.pack(fill="x", pady=(0, 10))
        ttk.Label(card, text="BSSID").grid(row=0, column=0, sticky="w",
                                           padx=8, pady=6)
        ttk.Entry(card, textvariable=self.target_bssid, width=22).grid(
            row=0, column=1, padx=6)
        ttk.Label(card, text="Channel").grid(row=0, column=2, sticky="w",
                                             padx=8)
        ttk.Entry(card, textvariable=self.target_channel, width=6).grid(
            row=0, column=3, padx=6)
        card.columnconfigure(4, weight=1)

        # attack mode card
        mode = ttk.LabelFrame(wrap, text=" Attack Mode ")
        mode.pack(fill="x", pady=(0, 10))
        ttk.Checkbutton(mode, text="Pixie Dust (-K)",
                        variable=self.pixie_mode).grid(
            row=0, column=0, sticky="w", padx=12, pady=4)
        ttk.Checkbutton(mode, text="Brute-force (-B)",
                        variable=self.bruteforce).grid(
            row=0, column=1, sticky="w", padx=12, pady=4)
        ttk.Checkbutton(mode, text="Pixie --force (-F)",
                        variable=self.pixie_force).grid(
            row=0, column=2, sticky="w", padx=12, pady=4)
        ttk.Checkbutton(mode, text="Auto-attack all Pixie targets (-A)",
                        variable=self.auto_attack).grid(
            row=1, column=0, columnspan=2, sticky="w", padx=12, pady=4)

        ttk.Label(mode, text="Delay (s)").grid(row=1, column=2, sticky="e")
        ttk.Entry(mode, textvariable=self.delay, width=8).grid(
            row=1, column=3, padx=6, sticky="w")

        # output card
        out = ttk.LabelFrame(wrap, text=" Output ")
        out.pack(fill="x", pady=(0, 10))
        ttk.Checkbutton(out, text="Save credentials (-w)",
                        variable=self.save_creds).grid(
            row=0, column=0, sticky="w", padx=12, pady=4)
        ttk.Checkbutton(out, text="Verbose",
                        variable=self.verbose).grid(
            row=0, column=1, sticky="w", padx=12, pady=4)
        ttk.Checkbutton(out, text="JSON lines",
                        variable=self.write_json).grid(
            row=0, column=2, sticky="w", padx=12, pady=4)

        # suggested pins card
        pins = ttk.LabelFrame(wrap, text=" Suggested PINs (from BSSID) ")
        pins.pack(fill="both", expand=True)
        self.pin_tree = ttk.Treeview(pins, columns=("pin", "algo"),
                                     show="headings", height=6)
        self.pin_tree.heading("pin", text="PIN")
        self.pin_tree.heading("algo", text="Algorithm")
        self.pin_tree.column("pin", width=110, anchor="center")
        self.pin_tree.column("algo", width=340, anchor="w")
        self.pin_tree.pack(side="left", fill="both", expand=True, padx=8, pady=8)
        bf = ttk.Frame(pins)
        bf.pack(side="right", fill="y", padx=8, pady=8)
        ttk.Button(bf, text="Generate", command=self.on_gen_pins).pack(fill="x")
        ttk.Button(bf, text="Copy PIN", command=self.on_copy_pin).pack(
            fill="x", pady=6)

    def _build_pixie(self, parent):
        top = ttk.Frame(parent)
        top.pack(fill="x", padx=12, pady=10)
        ttk.Label(top, text="Pixiewps captured fields",
                  style="Head.TLabel").pack(side="left")
        ttk.Button(top, text="Load JSON…",
                   command=self._load_pixie_json).pack(side="right", padx=4)
        ttk.Button(top, text="Save JSON…",
                   command=self._save_pixie_json).pack(side="right", padx=4)
        ttk.Button(top, text="Run Pixiewps",
                   style="Accent.TButton",
                   command=self.on_run_pixiewps).pack(side="right", padx=4)
        ttk.Button(top, text="Clear",
                   command=self._clear_pixie).pack(side="right", padx=4)

        self.pixie_fields = {}
        body = ttk.Frame(parent)
        body.pack(fill="both", expand=True, padx=12, pady=6)
        req = list(engine.PixiewpsData._REQUIRED_HEX_FIELDS.items())
        opt = list(engine.PixiewpsData._OPTIONAL_HEX_FIELDS.items())
        for i, (name, length) in enumerate(req + opt):
            row, col = divmod(i, 2)
            required = i < len(req)
            lbl = ("* " if required else "") + name
            ttk.Label(body, text=lbl,
                      style="Head.TLabel" if required else "Dim.TLabel").grid(
                row=row * 2, column=col, sticky="w", padx=8, pady=(6, 0))
            e = ttk.Entry(body, width=64, font=MONO)
            e.grid(row=row * 2 + 1, column=col, sticky="we", padx=8, pady=(0, 4))
            self.pixie_fields[name] = e
        body.columnconfigure(0, weight=1)
        body.columnconfigure(1, weight=1)

        ttk.Label(parent,
                  text=f"* required  ({sum(engine.PixiewpsData._REQUIRED_HEX_FIELDS.values())} hex chars for PKE/PKR, "
                       "32 for nonces, 64 for hashes/authkey)",
                  style="Dim.TLabel").pack(anchor="w", padx=20, pady=(0, 8))

    # ---- engine glue -----------------------------------------------------
    def _args_shim(self):
        """Return a lightweight argparse.Namespace-ish object."""
        class A:
            pass
        a = A()
        a.interface = self.interface.get()
        a.backend = self.backend.get()
        a.verbose = self.verbose.get()
        a.timeout = 120
        a.delay = float(self.delay.get()) if self.delay.get().strip() else None
        a.json = self.write_json.get()
        a.write = self.save_creds.get()
        a.trace_log = None
        a.cool = 60
        a.show_pixie_cmd = False
        a.pixie_force = self.pixie_force.get()
        a.pixie_only = self.pixie_mode.get()
        a.min_rssi = None
        a.band = None
        return a

    def _make_companion(self):
        a = self._args_shim()
        comp = engine.Companion(
            a.interface,
            save_result=a.write,
            print_debug=a.verbose,
            db=self.db,
            json_mode=a.json,
            trace_log=a.trace_log,
            pixiewps_timeout=a.timeout,
            cool_down=a.cool,
            auto_mode=True)
        # route Companion's prints into our log
        original_print = comp.__dict__.get("print", None)
        return comp

    # ---- scanning --------------------------------------------------------
    def on_scan(self):
        iface = self.interface.get()
        if not os.path.exists(f"/sys/class/net/{iface}"):
            messagebox.showerror("Interface", f"{iface} does not exist.")
            return

        def job():
            self.status.set(f"Scanning on {iface}…")
            self.log.write(f"Scanning on {iface}…", "accent")
            scanner = engine.WiFiScanner(iface, db=self.db)
            try:
                engine.ifaceUp(iface)
                result = scanner.iw_scanner()
            except Exception as e:
                self.log.write(f"Scan error: {e}", "err")
                return
            if not result:
                self.log.write("No networks found.", "warn")
                self.status.set("No networks.")
                return
            nets = list(result.values())
            # annotate vendor
            for n in nets:
                n.setdefault("Vendor", self.db.vendor_for(n["BSSID"]))
            stored = scanner.stored
            self.after(0, lambda: self.table.populate(nets, stored))
            self.log.write(f"Found {len(nets)} AP(s).", "ok")
            self.status.set(f"{len(nets)} AP(s) — double-click a row to target.")
        self._run_bg(job)

    def _on_select(self, _evt):
        n = self.table.selected()
        if not n:
            return
        self.target_bssid.set(n["BSSID"])
        if n.get("Channel"):
            self.target_channel.set(str(n["Channel"]))
        self.log.write(f"Selected {n['BSSID']} "
                       f"({n.get('ESSID', 'HIDDEN')}) ch={n.get('Channel', '?')}",
                       "info")

    def _target_dbl(self, net):
        self._on_select(None)
        self.on_attack()

    # ---- attack ----------------------------------------------------------
    def on_attack(self):
        bssid = self.target_bssid.get().strip()
        if not bssid:
            messagebox.showinfo("Target", "Pick a target first (double-click a row).")
            return
        if self.backend.get() != "internal":
            messagebox.showinfo(
                "Backend",
                f"{self.backend.get()} backend requires monitor mode and is "
                "not exposed in the GUI yet — using internal wpa_supplicant.")
            self.backend.set("internal")
        self._run_bg(lambda: self._attack_job(bssid))

    def _attack_job(self, bssid):
        self.status.set(f"Attacking {bssid}…")
        self.log.write(f"─── Attack {bssid} ───", "accent")

        net = next((n for n in self.table.nets if n["BSSID"] == bssid), None)
        channel = self.target_channel.get().strip()
        try:
            channel = int(channel) if channel else 0
        except ValueError:
            channel = 0

        comp = engine.Companion(
            self.interface.get(),
            save_result=self.save_creds.get(),
            print_debug=self.verbose.get(),
            db=self.db,
            json_mode=self.write_json.get(),
            trace_log=None,
            pixiewps_timeout=120,
            cool_down=60,
            auto_mode=True)
        self.companion = comp
        try:
            if net:
                comp.target_is_pixie_vuln = bool(net.get("Pixie vulnerable"))
                comp.target_chipset = net.get("Chipset", "")

            # 1) Pixie dust
            if self.pixie_mode.get():
                self.log.write("Trying Pixie Dust…", "pixie")
                ok = comp.single_connection(
                    bssid,
                    pixiemode=True,
                    showpixiecmd=self.verbose.get(),
                    pixieforce=self.pixie_force.get(),
                    store_pin_on_fail=False)
                if ok:
                    self._report_success(comp, bssid)
                    return

            # 2) Brute-force
            if self.bruteforce.get():
                self.log.write("Starting brute-force (this can take hours)…",
                               "warn")
                comp.smart_bruteforce(bssid, delay=None, loop=False,
                                      auto_resume=False)
                if comp.connection_status.status == "GOT_PSK":
                    self._report_success(comp, bssid)
                    return

            self.log.write(f"Attack finished without success for {bssid}.",
                           "err")
            self.status.set("Attack finished — no credentials.")
        except KeyboardInterrupt:
            self.log.write("Attack interrupted.", "warn")
        finally:
            self.companion = None
            try:
                comp.cleanup()
            except Exception:
                pass

    def _report_success(self, comp, bssid):
        pin = ""
        psk = comp.connection_status.wpa_psk
        essid = comp.connection_status.essid
        self.log.write("SUCCESS", "ok")
        self.log.write(f"  BSSID : {bssid}", "ok")
        self.log.write(f"  ESSID : {essid}", "ok")
        self.log.write(f"  PSK   : {psk}", "ok")
        self.status.set(f"Credentials recovered for {essid or bssid}")
        messagebox.showinfo(
            "Credentials recovered",
            f"BSSID: {bssid}\nESSID: {essid}\nPSK: {psk}")

    def on_pbc(self):
        bssid = self.target_bssid.get().strip() or None
        if not bssid:
            if not messagebox.askyesno(
                    "PBC", "No BSSID set — try PBC against ANY AP? "
                           "This can connect to unintended networks."):
                return
        if self.backend.get() == "bully":
            messagebox.showerror("PBC", "bully does not support PBC.")
            return

        def job():
            self.log.write(f"PBC → {bssid or 'any'}", "accent")
            comp = engine.Companion(
                self.interface.get(),
                save_result=self.save_creds.get(),
                print_debug=self.verbose.get(),
                db=self.db,
                json_mode=self.write_json.get(),
                auto_mode=True)
            self.companion = comp
            try:
                comp.single_connection(bssid=bssid, pbc_mode=True)
            finally:
                self.companion = None
                try:
                    comp.cleanup()
                except Exception:
                    pass
            if comp.connection_status.status == "GOT_PSK":
                self._report_success(comp, bssid or "PBC-AP")
            else:
                self.log.write("PBC finished without success.", "err")
        self._run_bg(job)

    def on_stop(self):
        self.log.write("Stop requested…", "warn")
        self._stop_evt.set()
        if self.companion:
            try:
                self.companion.sendOnly("WPS_CANCEL")
            except Exception:
                pass

    # ---- pins ------------------------------------------------------------
    def on_gen_pins(self):
        bssid = self.target_bssid.get().strip()
        if not bssid:
            messagebox.showinfo("PINs", "Select a target first.")
            return
        try:
            gen = engine.WPSpin()
            pins = gen.getSuggestedUnique(bssid)
        except Exception as e:
            messagebox.showerror("PINs", str(e))
            return
        self.pin_tree.delete(*self.pin_tree.get_children())
        for p in pins:
            self.pin_tree.insert("", "end", values=(p["pin"], p["name"]))
        self.log.write(f"Generated {len(pins)} suggested PIN(s) for {bssid}",
                       "info")

    def on_copy_pin(self):
        sel = self.pin_tree.selection()
        if not sel:
            return
        pin = self.pin_tree.item(sel[0], "values")[0]
        self.clipboard_clear()
        self.clipboard_append(pin)
        self.log.write(f"PIN {pin} copied to clipboard.", "info")

    # ---- pixiewps --------------------------------------------------------
    def _read_pixie_fields(self):
        return {k: e.get().strip() for k, e in self.pixie_fields.items() if e.get().strip()}

    def _clear_pixie(self):
        for e in self.pixie_fields.values():
            e.delete(0, "end")

    def _load_pixie_json(self):
        path = filedialog.askopenfilename(filetypes=[("JSON", "*.json"), ("All", "*.*")])
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = engine.json.load(f)
            obj = engine.PixiewpsData.from_dict(data)
            for k, e in self.pixie_fields.items():
                e.delete(0, "end")
                v = getattr(obj, k, "")
                if v:
                    e.insert(0, v)
            self.log.write(f"Loaded pixiewps data from {path}", "ok")
        except Exception as e:
            messagebox.showerror("Load", str(e))

    def _save_pixie_json(self):
        path = filedialog.asksaveasfilename(defaultextension=".json",
                                            filetypes=[("JSON", "*.json")])
        if not path:
            return
        try:
            obj = engine.PixiewpsData.from_dict(self._read_pixie_fields())
            with open(path, "w", encoding="utf-8") as f:
                f.write(obj.to_json())
            self.log.write(f"Saved pixiewps data to {path}", "ok")
        except Exception as e:
            messagebox.showerror("Save", str(e))

    def on_run_pixiewps(self):
        if not engine.shutil.which("pixiewps"):
            messagebox.showerror("pixiewps", "pixiewps not found in PATH.")
            return
        data = self._read_pixie_fields()
        if not data:
            messagebox.showinfo("pixiewps", "Fill in the required fields first.")
            return

        def job():
            obj = engine.PixiewpsData.from_dict(data)
            if not obj.got_all():
                self.log.write("Not all required fields captured: "
                               + ", ".join(obj.missing_fields()), "err")
                return
            self.log.write("Running pixiewps…", "pixie")
            pin, psk = obj.run_pixiewps(
                full_range=self.pixie_force.get(),
                timeout=120, verbose=self.verbose.get())
            if pin:
                self.log.write(f"WPS PIN recovered: {pin}", "ok")
                self.pixie_fields.setdefault("_pin", None)  # no-op
                messagebox.showinfo("Pixiewps", f"WPS PIN: {pin}")
            elif psk:
                self.log.write(f"PSK recovered: {psk}", "ok")
            else:
                self.log.write("Pixiewps did not recover a PIN.", "err")
        self._run_bg(job)

    # ---- misc ------------------------------------------------------------
    def _save_log(self):
        path = filedialog.asksaveasfilename(defaultextension=".log",
                                            filetypes=[("Log", "*.log")])
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(self.log.text.get("1.0", "end"))
            self.log.write(f"Log saved to {path}", "ok")
        except Exception as e:
            messagebox.showerror("Save", str(e))

    def destroy(self):
        try:
            if self.db:
                self.db.close()
        except Exception:
            pass
        super().destroy()


# ==========================================================================
if __name__ == "__main__":
    if os.getuid() != 0:
        print("[!] Run as root: sudo python3 wisphound_gui.py", file=sys.stderr)
    app = WispHoundGUI()
    app.mainloop()
