# SPDX-License-Identifier: GPL-3.0-or-later

# utils - Utilities module.

# Copyright (C) 2022-2023 Sergio Chica Manjarrez @ pervasive.it.uc3m.es.
# Universidad Carlos III de Madrid.

# This file is part of netauditor.

# netauditor is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# netauditor is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

from mac_vendor_lookup import VendorNotFoundError
from pathlib import Path

import scapy.all as scp
import threading
import base64
import nmap3
import json
import time
import os
import re

DIRS = {}
SUBNET_TIME = 5
COLORS = {
    'R': '\033[91m',
    'Y': '\033[93m',
    'B': '\033[94m',
    'G': '\033[92m',
    'N': '\033[0m',
    'E': ''
}
LOG = {
    'normal': '',
    'succ': '[+] ', 'info': '[*] ',
    'warn': '[!] ', 'error': '[!] ',
    'enabled': False}
UID = None


def disable_ansi_colors():
    COLORS['R'] = COLORS['E']
    COLORS['Y'] = COLORS['E']
    COLORS['B'] = COLORS['E']
    COLORS['G'] = COLORS['E']
    COLORS['N'] = COLORS['E']


def log_verbose():
    LOG['enabled'] = True


def log(ltype, msg, end='\n', err=None):
    color = LOG[ltype]
    if ltype == 'succ':
        color = f'{COLORS["G"]}{color}{COLORS["N"]}'
    elif ltype == 'info':
        color = f'{COLORS["B"]}{color}{COLORS["N"]}'
    elif ltype == 'warn':
        color = f'{COLORS["Y"]}{color}{COLORS["N"]}'
    elif ltype == 'error':
        color = f'{COLORS["R"]}{color}{COLORS["N"]}'
    if LOG['enabled']:
        print(f"{color}{msg}", end=end, flush=True)


def uid():
    global UID
    if UID is None:
        uidenv = os.getenv('SUDO_UID')
        if uidenv is not None:
            UID = int(uidenv)
        else:
            UID = os.getuid()


def create_dirs(output):
    DIRS['log'] = f'{output}/log'
    DIRS['raw'] = f'{output}/raw'
    DIRS['json'] = f'{output}/json'
    uid()
    try:
        for dr in DIRS:
            Path(DIRS[dr]).mkdir(parents=True, exist_ok=True)
            os.chown(DIRS[dr], UID, UID)
        os.chown(output, UID, UID)
    except PermissionError as ex:
        log('error', f"{ex.strerror}: {ex.filename}.", err=ex.errno)


class ARPPacket:
    OP = {
        1: 'who-has',
        2: 'is-at'
    }

    def __init__(self, packet):
        self.packet = packet

    def __getattr__(self, name):
        if name == 'op':
            return self.OP[getattr(self.packet, name)]
        else:
            return getattr(self.packet, name)

    def hwdst_null(self):
        return self.packet.hwdst == '00:00:00:00:00:00'


class ARPPing(threading.Thread):
    def __init__(self, iface, subnet, timer):
        threading.Thread.__init__(self)
        self.iface = iface
        self.subnet = subnet
        self.timer = timer
        self.daemon = True

    def run(self):
        time.sleep(self.timer)
        log('info', f"Scanning subnet: {self.subnet}")
        scp.sendp(
            scp.Ether(dst="ff:ff:ff:ff:ff:ff") /
            scp.ARP(pdst=self.subnet), iface=self.iface, verbose=0)


class NmapScanner(threading.Thread):
    elem = re.compile(r'.*?: (.*)')
    cve = re.compile(r'\s*([A-Z0-9-]*)\s*([0-9.]*)\s*([0-9.-]*)'
                     r'\s*([A-Za-z]*)\s*([A-Za-z]*)')
    nonce_sz = 3

    def __init__(self, lookup, mac, target):
        threading.Thread.__init__(self)
        self.lookup = lookup
        self.mac = mac
        self.target = target
        self.daemon = True

    def run(self):
        nonce = self.nonce()
        for dr in DIRS:
            open(f'{DIRS[dr]}/{self.mac}_{nonce}.{dr}', 'w').close()
            os.chown(f'{DIRS[dr]}/{self.mac}_{nonce}.{dr}', UID, UID)
        nm = nmap3.Nmap()
        nm.run_command(['/usr/bin/nmap',
                        '-oN', f'{DIRS["raw"]}/{self.mac}_{nonce}.raw',
                        '-sV', self.target,
                        '--script', 'cvescannerv2',
                        '--script-args',
                        f'log={DIRS["log"]}/{self.mac}_{nonce}.log,'
                        f'json={DIRS["json"]}/{self.mac}_{nonce}.json'])
        with open(f'{DIRS["json"]}/{self.mac}_{nonce}.json', 'r+') as f:
            data = json.load(f)
            try:
                data[self.target]['manufacturer'] = self.lookup(self.mac)
            except VendorNotFoundError:
                data[self.target]['manufacturer'] = "unknown"
            f.seek(0)
            json.dump(data, f)

    def nonce(self):
        return base64.b64encode(os.urandom(self.nonce_sz),
                                altchars=b'-:').decode()
