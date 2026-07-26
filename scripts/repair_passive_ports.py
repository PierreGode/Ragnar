#!/usr/bin/env python3
"""Repair phantom open ports written by passive host discovery.

Until this was fixed, Traffic Analysis credited a host with a "listening port"
whenever it saw a packet sent *to* that port. Ragnar's own scanner sweeps the
configured portlist against every LAN host, so a capture running during a scan
wrote that entire portlist into the hosts DB for every host — turning the
dashboard's Open Ports count into a four-digit number of ports nothing was
listening on.

The signature is unmistakable, because the capture filter (`not port 22 and not
port 8000`) hid two of the scanned ports: an affected host carries dozens of
ports dominated by the scanner's portlist, with 22 and 8000 conspicuously
absent. Real hosts do not answer on 20, 69, 111, 119, 179, 515 and 520 at once,
and certainly not while refusing SSH.

This clears the ports/services columns of matching hosts. The next active scan
repopulates them with real results — nmap replaces that field wholesale — so a
false positive costs one scan cycle, not data.

    python3 scripts/repair_passive_ports.py            # report only (default)
    python3 scripts/repair_passive_ports.py --apply    # write the fix
    python3 scripts/repair_passive_ports.py --min-ports 15 --apply

Runs against every network DB under data/networks/*/db/*.db unless --db is given.
"""

import argparse
import glob
import json
import os
import shutil
import sqlite3
import sys
from datetime import datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Ports the capture filter hides, so passive discovery can never have seen them.
# Their absence from an otherwise-complete portlist is the tell.
FILTERED_PORTS = {22, 8000}
DEFAULT_MIN_PORTS = 15

# Ports the passive recorder was allowed to write: anything privileged, plus
# the high-value ports it tracks by name. Nothing outside this set can have
# come from passive discovery.
RECORDABLE_CEILING = 1024
HIGH_VALUE_PORTS = {
    1433, 1521, 2375, 2376, 2379, 2380, 3306, 3389, 5432, 5601, 5672, 15672,
    5900, 5901, 5984, 5985, 5986, 6379, 7474, 7687, 8000, 8008, 8086, 8080,
    8443, 8888, 9000, 9090, 9091, 9042, 9092, 9200, 9300, 11211, 27017, 27018,
}

# Services essentially nobody runs, and never together: a host "listening" on
# three or more of these is reporting a scan, not a service. This is what keeps
# the repair off a genuinely busy server (a Windows DC answers on 88/135/389/445,
# but not on ftp-data, tftp, nntp, bgp and rip at once).
IMPLAUSIBLE_TOGETHER = {20, 69, 111, 119, 179, 515, 520, 554, 631, 1024, 1025}
MIN_IMPLAUSIBLE = 3

# How much of a row must look swept before it counts as swept.
DOMINANCE = 0.8


def load_portlist():
    """The scanner's port list — the exact set the sweep wrote."""
    for path in (os.path.join(ROOT, 'config', 'shared_config.json'),
                 os.path.join(ROOT, 'data', 'shared_config.json')):
        try:
            with open(path) as fh:
                ports = json.load(fh).get('portlist')
            if ports:
                return {int(p) for p in ports}
        except (OSError, ValueError, TypeError):
            continue
    return set()


def parse_ports(field):
    out = set()
    for chunk in (field or '').split(','):
        chunk = chunk.strip()
        if chunk.isdigit():
            out.add(int(chunk))
    return out


def is_poisoned(ports, portlist, min_ports):
    """Does this host's port list look like a recorded scan sweep?

    Four things have to hold at once, because clearing a real scan result is
    the one outcome worth avoiding:

    1. a big set — a swept host carries dozens of ports;
    2. three or more ports nobody runs together (ftp-data, tftp, nntp, bgp…);
    3. 22 and 8000 absent — the capture filter hid them, so the sweep could
       never have recorded them, while a real host that busy would answer SSH;
    4. the set is dominated by ports passive discovery could write (privileged
       or high-value) and by ports the scanner sweeps.

    Dominance rather than purity, because passive discovery *merged* its
    phantom ports into whatever an earlier real scan had found: a swept row can
    still carry a few genuine ports from outside both sets. Those come back on
    the next scan, which is why clearing the whole row is safe.
    """
    if len(ports) < min_ports:
        return False
    if ports & FILTERED_PORTS:
        return False
    if len(ports & IMPLAUSIBLE_TOGETHER) < MIN_IMPLAUSIBLE:
        return False
    recordable = {p for p in ports if p < RECORDABLE_CEILING or p in HIGH_VALUE_PORTS}
    if len(recordable) < DOMINANCE * len(ports):
        return False
    if portlist and len(ports & portlist) < DOMINANCE * len(ports):
        return False
    return True


def repair_db(db_path, portlist, min_ports, apply_changes):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            "SELECT mac, ip, ports FROM hosts WHERE ports IS NOT NULL AND ports != ''"
        ).fetchall()
    except sqlite3.Error as exc:
        print(f"  ! cannot read {db_path}: {exc}")
        conn.close()
        return 0, 0

    hits = [(r['mac'], r['ip'], parse_ports(r['ports'])) for r in rows]
    hits = [h for h in hits if is_poisoned(h[2], portlist, min_ports)]
    cleared_ports = sum(len(p) for _, _, p in hits)

    if hits and apply_changes:
        backup = f"{db_path}.bak-{datetime.now():%Y%m%d%H%M%S}"
        shutil.copy2(db_path, backup)
        print(f"  backup: {backup}")
        conn.executemany(
            "UPDATE hosts SET ports = '', services = '' WHERE mac = ?",
            [(mac,) for mac, _, _ in hits],
        )
        conn.commit()

    for mac, ip, ports in hits:
        print(f"  {'cleared' if apply_changes else 'would clear'} "
              f"{len(ports):3d} ports  {ip or '?':<15} {mac}")

    conn.close()
    return len(hits), cleared_ports


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--apply', action='store_true',
                    help='write the changes (default: report only)')
    ap.add_argument('--db', action='append',
                    help='specific hosts DB to repair (repeatable)')
    ap.add_argument('--min-ports', type=int, default=DEFAULT_MIN_PORTS,
                    help=f'ports a host needs before it looks swept '
                         f'(default: {DEFAULT_MIN_PORTS})')
    args = ap.parse_args()

    portlist = load_portlist()
    if not portlist:
        print("Could not read the scanner portlist from config — aborting, "
              "since without it every host would look clean.")
        return 2
    print(f"Scanner portlist: {len(portlist)} ports; "
          f"treating >= {args.min_ports} of them (without "
          f"{'/'.join(str(p) for p in sorted(FILTERED_PORTS))}) as a recorded sweep.")

    dbs = args.db or sorted(glob.glob(os.path.join(ROOT, 'data', 'networks', '*', 'db', '*.db')))
    if not dbs:
        print("No hosts databases found.")
        return 1

    total_hosts = total_ports = 0
    for db_path in dbs:
        print(f"\n{db_path}")
        hosts, ports = repair_db(db_path, portlist, args.min_ports, args.apply)
        if not hosts:
            print("  clean")
        total_hosts += hosts
        total_ports += ports

    verb = 'Cleared' if args.apply else 'Would clear'
    print(f"\n{verb} {total_ports} phantom ports across {total_hosts} hosts.")
    if total_hosts and not args.apply:
        print("Re-run with --apply to write the fix.")
    elif total_hosts:
        print("The next active scan will repopulate real open ports.")
    return 0


if __name__ == '__main__':
    sys.exit(main())
