#!/usr/bin/env python3

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

# from zerconf import ServiceBrowser, ZeroConf  # apple devices
from apscheduler.schedulers.background import BackgroundScheduler

import scapy.all as scp
import utils as ut
import threading
import ipaddress
import netifaces
import datetime
import argparse


class ARPMonitor(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.cache = {}
        self.daemon = True

    def run(self):
        scp.sniff(prn=self.arp_monitor, filter="arp", store=0)

    def arp_monitor(self, packet):
        if scp.ARP in packet:
            arp = ut.ARPPacket(packet[scp.ARP])
            target = None
            if arp.hwsrc not in self.cache and not arp.hwdst_null():
                self.cache[arp.hwsrc] = arp.psrc
                ut.log('succ',
                       f"New device detected ({arp.op}): "
                       f"{arp.hwsrc} - {arp.psrc}")
                target = (arp.hwsrc, arp.psrc)
            if arp.op == 'is-at':
                if arp.hwdst not in self.cache and not arp.hwdst_null():
                    self.cache[arp.hwdst] = arp.pdst
                    ut.log('succ',
                           f"New device detected ({arp.op}): "
                           f"{arp.hwdst} - {arp.pdst}")
                    target = (arp.hwdst, arp.pdst)
                elif (arp.hwdst in self.cache and
                      arp.pdst != self.cache[arp.hwdst]):
                    ut.log('warn',
                           f"Inconsistency detected ({arp.op}): "
                           f"{arp.hwdst} - {self.cache[arp.hwdst]} -> "
                           f"{arp.pdst}")
                    target = (arp.hwdst, arp.pdst)
            if target is not None:
                ut.log('info',
                       f"Starting analysis: {target[0]} - {target[1]}")
                th = ut.NmapScanner(*target)
                th.start()


def arp_scanner():
    ut.log('info', "Running scheduled job...")
    subnets = []
    for name in netifaces.interfaces():
        if (name != 'lo' and
            not name.startswith('docker') and
            not name.startswith('vmnet')):  # noqa
            if netifaces.AF_INET in netifaces.ifaddresses(name):
                iface = netifaces.ifaddresses(name)[netifaces.AF_INET]
                for sn in iface:
                    ip = ipaddress.ip_interface(
                        f'{sn["addr"]}/{sn["netmask"]}')
                    subnet = str(ip.network)
                    if subnet not in subnets:
                        subnets.append(subnet)
                        ans, unans = scp.srp(
                            scp.Ether(dst="ff:ff:ff:ff:ff:ff") /
                            scp.ARP(pdst=subnet), timeout=2, verbose=0)
                        # ans.summary(
                        #     lambda src, recv:
                        #     recv.sprintf("%Ether.src% %ARP.psrc%"))


def main():
    parser = argparse.ArgumentParser(
        prog='python netuaditor.py',
        description="Network scanner and analyzer.")
    parser.add_argument('--verbose', action='store_true',
                        help="Verbose output.")
    args = parser.parse_args()
    if args.verbose:
        ut.log_verbose()

    ut.create_dirs()

    monitor = ARPMonitor()
    monitor.start()
    scheduler = BackgroundScheduler(timezone="Europe/Madrid")
    scheduler.add_job(arp_scanner, 'interval', minutes=5,
                      next_run_time=datetime.datetime.now())
    scheduler.start()

    import time
    time.sleep(240)


if __name__ == '__main__':
    main()
