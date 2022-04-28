# SPDX-License-Identifier: GPL-3.0-or-later

# utils - Utilities module.

# Copyright (C) 2022 Sergio Chica Manjarrez @ pervasive.it.uc3m.es.
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
# along with GNU Emacs.  If not, see <https://www.gnu.org/licenses/>.

from pathlib import Path

import scapy.all as scp
import threading
import nmap3
import time
import re

CVE_LOG = 'output/log'
CVE_RAW = 'output/raw'
CVE_JSON = 'output/json'
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
    'warn': '[-] ', 'error': '[!] ',
    'enabled': False}


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


def create_dirs():
    try:
        Path(CVE_LOG).mkdir(parents=True, exist_ok=True)
        Path(CVE_RAW).mkdir(parents=True, exist_ok=True)
        Path(CVE_JSON).mkdir(parents=True, exist_ok=True)
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

    def __init__(self, mac, target):
        threading.Thread.__init__(self)
        self.mac = mac
        self.target = target
        self.daemon = True

    def run(self):
        nm = nmap3.Nmap()
        nm.run_command(['/usr/bin/nmap',
                        '-oN', f'{CVE_RAW}/{self.mac}.raw',
                        '-sV', self.target,
                        '--script', 'cvescannerv2',
                        '--script-args',
                        f'log={CVE_LOG}/{self.mac}.log,'
                        f'json={CVE_JSON}/{self.mac}.json'])
