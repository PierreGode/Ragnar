"""igmpwatch CLI:  python3 -m igmpwatch -c igmpwatch.yaml  (or -i eth0)."""

import argparse
import json
import os
import sys

from . import config as _config
from . import snmp as _snmp


def _snmp_probe(args):
    cfg, _note = _config.load(args.config)
    scfg = cfg['snmp']
    host = args.snmp_host or scfg.get('host')
    community = args.snmp_community or scfg.get('community', 'public')
    if not host:
        sys.stderr.write('error: --snmp-host (or snmp.host in config) required\n')
        return 2
    if not _snmp.have_snmp():
        sys.stderr.write('note: snmpbulkwalk not found (apt install snmp) — probe will '
                         'report unreachable\n')
    res = _snmp.probe(host, community, scfg)
    print(json.dumps(res, indent=2))
    # Seed the capability cache unless --no-cache.
    if not args.no_cache and args.db:
        try:
            from .storage import Storage
            store = Storage(args.db)
            cache = _snmp.CapabilityCache(store, scfg.get('capability_strikes', 3),
                                          scfg.get('capability_ttl', 3600))
            cache.seed(host, res.get('group_table_supported', False))
            store.close()
            sys.stderr.write('seeded capability cache for {}: group_table_supported={}\n'
                             .format(host, res.get('group_table_supported')))
        except Exception as e:
            sys.stderr.write('cache seed failed: {}\n'.format(e))
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(prog='igmpwatch',
                                 description='Passive IGMP snooping security monitor (detection-only).')
    ap.add_argument('-c', '--config', help='YAML config path')
    ap.add_argument('-i', '--iface', help='capture interface (overrides config)')
    ap.add_argument('--enforce', action='store_true', help='policy enforce mode')
    ap.add_argument('--db', help='SQLite path (overrides config)')
    ap.add_argument('-v', '--verbose', action='store_true')
    ap.add_argument('--duration', type=int, help='stop after N seconds')
    ap.add_argument('--self-test', action='store_true', help='run the offline self-test')
    ap.add_argument('--snmp-probe', action='store_true',
                    help='probe a switch for supported SNMP OIDs and seed the cache')
    ap.add_argument('--snmp-host')
    ap.add_argument('--snmp-community')
    ap.add_argument('--no-cache', action='store_true', help='snmp-probe: report without writing cache')
    args = ap.parse_args(argv)

    if args.self_test:
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        import selftest
        return selftest.run(verbose=True)

    if args.snmp_probe:
        return _snmp_probe(args)

    cfg, note = _config.load(args.config)
    if note:
        sys.stderr.write('igmpwatch: {}\n'.format(note))
    if args.iface:
        cfg['iface'] = args.iface
    if args.enforce:
        cfg['mode'] = 'enforce'
        cfg['detectors']['mode'] = 'enforce'
    if args.db:
        cfg['db'] = args.db
    if not cfg.get('iface'):
        ap.error('an interface is required (-i or iface: in config)')
    if os.geteuid() != 0:
        sys.stderr.write('error: live capture needs root / CAP_NET_RAW.\n')
        return 2

    storage = None
    if cfg.get('db'):
        try:
            os.makedirs(os.path.dirname(cfg['db']) or '.', exist_ok=True)
            from .storage import Storage
            storage = Storage(cfg['db'])
        except Exception as e:
            sys.stderr.write('igmpwatch: storage disabled ({})\n'.format(e))

    from .pipeline import Pipeline
    pipe = Pipeline(cfg, storage=storage, verbose=args.verbose)
    if args.duration:
        import threading
        threading.Timer(args.duration, pipe.stop).start()
    try:
        pipe.run_live(cfg['iface'])
    except KeyboardInterrupt:
        pipe.stop()
    n = len(pipe.alerts)
    snap = pipe.state.snapshot()
    sys.stderr.write('igmpwatch: {} alerts, {} groups, {} queriers, querier={}\n'.format(
        n, len(snap['groups']), len(snap['queriers']), snap['elected_querier']))
    if storage:
        storage.close()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
