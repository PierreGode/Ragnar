# traffic_analyzer.py
"""
Traffic Analysis Module

Real-time network traffic analysis. The engine is a `tcpdump` pipe read line by
line in Python — measured on a Pi 5 at ~90 packets/sec it costs 0.4% of one core
and 18MB RSS (plus 8MB for tcpdump), so it runs on any board Ragnar runs on,
down to a Pi Zero 2 W. Tracked state is capped and evicted (see _prune_state) so
a long capture cannot grow into a small board's RAM.

The one server-class part is the optional JA3/IRC sidecars, which each spawn a
full tshark dissector; those stay gated (traffic_sidecars_enabled).

Features:
- Real-time packet capture with tcpdump
- Connection tracking and statistics
- Protocol analysis
- Bandwidth monitoring per host
- Suspicious traffic detection
- DNS query logging
- C2 beacon detection patterns
"""

import os
import re
import json
import time
import threading
import subprocess
import signal
import queue
import logging
import statistics
import ipaddress
from typing import Dict, List, Optional, Any, Callable, Tuple
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from collections import defaultdict, deque
from enum import Enum

from logger import Logger
from server_capabilities import (
    ServerCapabilities,
    get_server_capabilities,
    is_server_mode,
)

logger = Logger(name="traffic_analyzer", level=logging.INFO)


class TrafficAlertLevel(Enum):
    """Alert severity levels for traffic anomalies"""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertCategory(Enum):
    """Standardized alert categories for filtering and reporting"""
    SUSPICIOUS_PORT = "suspicious_port"
    PORT_SCAN = "port_scan"
    DNS_TUNNELING = "dns_tunneling"
    C2_BEACON = "c2_beacon"
    DATA_EXFIL = "data_exfiltration"
    BRUTE_FORCE = "brute_force"
    HIGH_BANDWIDTH = "high_bandwidth"
    PROTOCOL_ANOMALY = "protocol_anomaly"


@dataclass
class ConnectionStats:
    """Statistics for a single connection"""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    packets_sent: int = 0
    packets_recv: int = 0
    bytes_sent: int = 0
    bytes_recv: int = 0
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    flags: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d['first_seen'] = self.first_seen.isoformat()
        d['last_seen'] = self.last_seen.isoformat()
        d['duration_seconds'] = (self.last_seen - self.first_seen).total_seconds()
        return d


@dataclass
class TrafficAlert:
    """Alert for suspicious traffic pattern"""
    alert_id: str
    level: TrafficAlertLevel
    category: str
    message: str
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)
    acknowledged: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'alert_id': self.alert_id,
            'level': self.level.value,
            'category': self.category,
            'message': self.message,
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'details': self.details,
            'timestamp': self.timestamp.isoformat(),
            'acknowledged': self.acknowledged
        }


@dataclass  
class HostTrafficStats:
    """Traffic statistics for a single host"""
    ip: str
    hostname: Optional[str] = None
    mac: Optional[str] = None
    total_packets: int = 0
    total_bytes: int = 0
    packets_in: int = 0
    packets_out: int = 0
    bytes_in: int = 0
    bytes_out: int = 0
    protocols: Dict[str, int] = field(default_factory=dict)
    ports_contacted: set = field(default_factory=set)
    ports_targeted: set = field(default_factory=set)
    sweep_targets: Dict[int, set] = field(default_factory=dict)
    connections_active: int = 0
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    dns_queries: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'ip': self.ip,
            'hostname': self.hostname,
            'mac': self.mac,
            'total_packets': self.total_packets,
            'total_bytes': self.total_bytes,
            'packets_in': self.packets_in,
            'packets_out': self.packets_out,
            'bytes_in': self.bytes_in,
            'bytes_out': self.bytes_out,
            'protocols': self.protocols,
            'ports_contacted': list(self.ports_contacted)[:100],  # Limit for API
            'ports_targeted': list(self.ports_targeted)[:100],
            'connections_active': self.connections_active,
            'first_seen': self.first_seen.isoformat(),
            'last_seen': self.last_seen.isoformat(),
            'dns_queries': self.dns_queries[-50:],  # Last 50 queries
        }


class TrafficAnalyzer:
    """
    Real-time traffic analyzer.

    Uses tcpdump for packet capture and provides:
    - Live connection tracking
    - Per-host bandwidth statistics
    - Protocol distribution analysis
    - Suspicious pattern detection
    """
    
    # Suspicious ports with descriptions for analyst context
    SUSPICIOUS_PORTS = {
        4444: "Metasploit default listener",
        5555: "Android ADB / common backdoor",
        6666: "IRC backdoor / DarkComet",
        1234: "Generic backdoor",
        31337: "Back Orifice / 'elite' port",
        12345: "NetBus trojan",
        65535: "Uncommon max port (evasion)",
        6667: "IRC (C2 channel)",
        6697: "IRC over TLS",
        8080: "HTTP proxy (if unexpected)",
        9001: "Tor default",
        9050: "Tor SOCKS proxy",
        1337: "Common hacker port",
        5900: "VNC (if unauthorized)",
        2222: "SSH alternate (dropbear)",
    }

    # Ports whose "suspicious" classification only makes sense over TCP +
    # unicast. UDP broadcasts on these are almost always a custom IoT /
    # discovery protocol that happened to pick the port — not C2.
    TCP_UNICAST_ONLY_PORTS = frozenset({
        4444, 5555, 6666, 6667, 6697, 9001, 9050, 5900, 2222,
    })

    # DNS tunneling detection threshold
    DNS_TUNNEL_THRESHOLD = 100  # Queries per minute from single host
    DNS_QUERY_TRACKING_WINDOW = 60  # Seconds to track DNS query rate

    # C2 beacon detection
    # A flow is considered a beacon candidate when a local host repeatedly
    # contacts the same external (ip, port) at low-jitter intervals with
    # similar payload sizes. See _sweep_beacons() for the scoring.
    BEACON_MIN_SAMPLES = 6           # Need this many hits before scoring
    BEACON_HISTORY_MAX = 64          # Ring buffer length per flow
    BEACON_MIN_INTERVAL = 5.0        # Ignore sub-5s noise (HTTP keepalive)
    BEACON_MAX_INTERVAL = 3600.0     # Ignore very rare flows (>1h)
    BEACON_INTERVAL_CV_MAX = 0.25    # Coefficient of variation threshold
    BEACON_SIZE_CV_REF = 0.15        # Reference for size-consistency score
    BEACON_SWEEP_INTERVAL = 30.0     # Re-score flows every N seconds
    BEACON_SCORE_ALERT = 0.70        # Minimum score to raise an alert
    BEACON_SCORE_CRITICAL = 0.85     # Score threshold for HIGH severity
    BEACON_SCORE_IMPROVE = 0.05      # Re-alert only if score climbs by this
    # Ports excluded from beacon detection (legitimate periodic traffic)
    BEACON_PORT_DENYLIST = frozenset({
        53,    # DNS
        67, 68,  # DHCP
        123,   # NTP
        137, 138, 139,  # NetBIOS
        546, 547,  # DHCPv6
        1900,  # SSDP
        5353,  # mDNS
        5355,  # LLMNR
    })

    # Service source ports: when a packet's src_port is one of these, the
    # dst_port is a client's ephemeral socket (response), not a scan target.
    SERVICE_SOURCE_PORTS = frozenset({
        53, 67, 68, 69, 80, 443, 88, 123,
        137, 138, 139, 161, 162, 389, 636,
        445, 25, 465, 587, 514, 546, 547,
        993, 995, 1900, 5353, 5355, 8080, 8443,
    })

    # High-value reconnaissance targets >1024. These always count as
    # "targeted" even if src_port looks like a service port — closes the
    # `nmap -g 53` evasion against common DB/admin/orchestrator ports.
    HIGH_VALUE_HIGH_PORTS = frozenset({
        1433, 1521,             # MS-SQL, Oracle
        2375, 2376,             # Docker (TLS)
        2379, 2380,             # etcd
        3306,                   # MySQL
        3389,                   # RDP
        5432,                   # Postgres
        5601,                   # Kibana
        5672, 15672,            # RabbitMQ + management
        5900, 5901,             # VNC
        5984,                   # CouchDB
        5985, 5986,             # WinRM
        6379,                   # Redis
        7474, 7687,             # Neo4j
        8000, 8008, 8086,       # Common admin / InfluxDB
        8080, 8443, 8888,       # HTTP-alt / admin
        9000, 9090, 9091,       # Grafana, Prometheus
        9042,                   # Cassandra
        9092,                   # Kafka
        9200, 9300,             # Elasticsearch
        11211,                  # memcached
        27017, 27018,           # MongoDB
    })

    PORTSCAN_LOW_PORT_THRESHOLD = 20
    PORTSCAN_TOTAL_THRESHOLD = 150
    PORTSCAN_EPHEMERAL_FLOOR = 1024
    PORTSCAN_GATEWAY_MULTIPLIER = 5      # softer threshold for default gateway

    # Horizontal sweep: same port across many distinct destination hosts.
    SWEEP_HOST_THRESHOLD = 10            # distinct dst IPs on one port
    SWEEP_MAX_TRACKED_PORTS = 200        # cap memory per source host
    SWEEP_MAX_TRACKED_IPS = 500          # cap memory per port

    # Passive host discovery: periodically flush observed LAN hosts into the
    # hosts DB so traffic-only hosts (firewalled, never scanned) get tracked.
    PASSIVE_SYNC_INTERVAL = 30.0         # seconds between DB flushes
    PASSIVE_MIN_PACKETS = 5              # min packets to upsert if no MAC yet
    PASSIVE_MAX_LISTEN_PORTS = 100       # cap per host
    PASSIVE_LAN_PREFIX = 24              # /24 around each known local/gateway IP

    # Bounded state. Alerts and DNS queries are ring buffers already, but
    # host_stats, connections and the beacon flow history gain an entry per new
    # peer/flow seen and have no natural ceiling — on a box left capturing for a
    # week they are the only thing that grows without limit. Cap them and evict
    # the least-recently-seen entries.
    #
    # The caps are what makes this feature honest on a 512MB Pi Zero 2 W: at the
    # low-memory numbers below the tracked state tops out around 3MB, on top of
    # ~18MB for the analyzer itself and ~8MB for tcpdump.
    STATE_PRUNE_INTERVAL = 60.0          # seconds between eviction sweeps
    MAX_TRACKED_HOSTS = 4000
    MAX_TRACKED_CONNECTIONS = 8000
    MAX_TRACKED_FLOWS = 2000             # each holds a 64-sample ring buffer
    LOW_MEMORY_RAM_GB = 1.0              # below this, use the divided caps
    LOW_MEMORY_DIVISOR = 8

    # Rate limiting
    MAX_ALERTS_PER_MINUTE = 10
    STATS_RETENTION_HOURS = 24

    def __init__(self, shared_data=None, interface: str = None):
        self.shared_data = shared_data
        self.interface = interface or self._detect_interface()
        
        self._running = False
        self._capture_process: Optional[subprocess.Popen] = None
        self._capture_thread: Optional[threading.Thread] = None
        self._analysis_thread: Optional[threading.Thread] = None
        
        self._packet_queue: queue.Queue = queue.Queue(maxsize=10000)
        self._lock = threading.Lock()
        
        # Local IP addresses to exclude from alerts (Ragnar's own IPs)
        self._local_ips: set = self._detect_local_ips()

        # Default gateway IPs: exempt from port-scan heuristic.
        self._gateway_ips: set = self._detect_gateway_ips()

        # LAN networks for passive host discovery (derived from local+gateway IPs).
        self._lan_networks: List[ipaddress.IPv4Network] = self._derive_lan_networks()

        # Passive discovery state:
        # _mac_by_ip: IP -> MAC (from ARP replies)
        # _listening_ports: IP -> set of service ports it appears to serve
        # _hostname_by_ip: IP -> hostname (from observed DNS replies)
        self._mac_by_ip: Dict[str, str] = {}
        self._listening_ports: Dict[str, set] = {}
        self._hostname_by_ip: Dict[str, str] = {}
        self._last_passive_sync: float = time.time()
        
        # Statistics storage
        self.host_stats: Dict[str, HostTrafficStats] = {}
        self.connections: Dict[str, ConnectionStats] = {}
        self.alerts: deque = deque(maxlen=1000)
        self.dns_queries: deque = deque(maxlen=5000)
        
        # Metrics
        self.total_packets = 0
        self.total_bytes = 0
        self._raw_packet_count = 0  # Raw count from capture thread (for debugging)
        self.packets_per_second = 0.0
        self.bytes_per_second = 0.0
        self._last_metrics_time = time.time()
        self._last_packet_count = 0
        self._last_byte_count = 0
        
        # Alert rate limiting and deduplication
        self._alert_timestamps: deque = deque(maxlen=100)
        self._alert_counter = 0
        self._alert_hashes: set = set()  # Track seen alerts to prevent duplicates
        self._alert_hash_expiry: Dict[str, float] = {}  # Expiry time for each hash
        self._alert_dedup_window = 300  # Seconds before same alert can fire again

        # Capture timing
        self._start_time: Optional[datetime] = None

        # DNS query timestamps for rate detection
        self._dns_query_times: Dict[str, deque] = defaultdict(lambda: deque(maxlen=200))

        # Beacon detection state.
        # _flow_history: (src_ip, dst_ip, dst_port) -> deque[(ts, bytes_out)]
        # _beacon_scored: same key -> last confidence score that fired an alert
        self._flow_history: Dict[Tuple[str, str, int], deque] = defaultdict(
            lambda: deque(maxlen=self.BEACON_HISTORY_MAX)
        )
        self._beacon_scored: Dict[Tuple[str, str, int], Dict[str, Any]] = {}
        self._last_beacon_sweep = time.time()

        # State caps, sized for the board this is actually running on
        caps_obj = get_server_capabilities(shared_data).capabilities
        self._max_hosts, self._max_connections, self._max_flows = self._state_caps(
            caps_obj.total_ram_gb
        )
        self._last_state_prune = time.time()

        # Optional sidecar subsystems (lazy, only spawned if tshark exists)
        self._ja3_collector = None
        self._irc_parser = None

        # Callbacks
        self._on_alert_callbacks: List[Callable] = []
        
        # Check if feature is available
        if not caps_obj.traffic_analysis_enabled:
            logger.warning("Traffic analysis not available: "
                           f"{caps_obj.traffic_block_reason or 'missing requirements'}")

    @classmethod
    def _state_caps(cls, total_ram_gb: float) -> Tuple[int, int, int]:
        """(hosts, connections, flows) caps for a board with this much RAM.

        A RAM read of 0 means detection failed, which is exactly when the
        conservative numbers are wanted — so it lands in the low-memory branch.
        """
        if total_ram_gb < cls.LOW_MEMORY_RAM_GB:
            d = cls.LOW_MEMORY_DIVISOR
            return (cls.MAX_TRACKED_HOSTS // d,
                    cls.MAX_TRACKED_CONNECTIONS // d,
                    cls.MAX_TRACKED_FLOWS // d)
        return (cls.MAX_TRACKED_HOSTS, cls.MAX_TRACKED_CONNECTIONS, cls.MAX_TRACKED_FLOWS)

    def _prune_state(self):
        """Evict least-recently-seen tracked state back down to the caps.

        Called from the analysis loop, not per packet: eviction is a sort over
        the whole map, so doing it every STATE_PRUNE_INTERVAL keeps the cost off
        the packet path entirely.
        """
        with self._lock:
            if len(self.connections) > self._max_connections:
                for key in sorted(self.connections,
                                  key=lambda k: self.connections[k].last_seen
                                  )[:len(self.connections) - self._max_connections]:
                    del self.connections[key]

            if len(self._flow_history) > self._max_flows:
                def flow_last_seen(key):
                    samples = self._flow_history[key]
                    return samples[-1][0] if samples else 0.0
                for key in sorted(self._flow_history, key=flow_last_seen
                                  )[:len(self._flow_history) - self._max_flows]:
                    del self._flow_history[key]
                    self._beacon_scored.pop(key, None)

            if len(self.host_stats) > self._max_hosts:
                for ip in sorted(self.host_stats,
                                 key=lambda k: self.host_stats[k].last_seen
                                 )[:len(self.host_stats) - self._max_hosts]:
                    del self.host_stats[ip]

            # Per-IP side tables only make sense for hosts still tracked. They
            # are rebuilt from the next packet, so dropping them is free.
            live = self.host_stats.keys()
            for table in (self._mac_by_ip, self._listening_ports,
                          self._hostname_by_ip, self._dns_query_times):
                for ip in [k for k in table if k not in live]:
                    del table[ip]

    def _detect_interface(self) -> str:
        """Detect the primary network interface"""
        try:
            # Try to get default route interface
            result = subprocess.run(
                ['ip', 'route', 'get', '8.8.8.8'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                # Parse: "8.8.8.8 via 192.168.1.1 dev eth0 src 192.168.1.100"
                match = re.search(r'dev\s+(\S+)', result.stdout)
                if match:
                    return match.group(1)
        except Exception as e:
            logger.debug(f"Interface detection error: {e}")
        
        # Fallback to common interfaces
        for iface in ['eth0', 'wlan0', 'enp0s3', 'ens33']:
            if os.path.exists(f'/sys/class/net/{iface}'):
                return iface
        
        return 'any'
    
    def _detect_local_ips(self) -> set:
        """Detect all local IP addresses (Ragnar's own IPs to exclude from alerts)"""
        local_ips = {'127.0.0.1', '::1', 'localhost'}

        # Method 1: Try Linux 'ip' command
        try:
            result = subprocess.run(
                ['ip', '-4', 'addr', 'show'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                # Parse: inet 192.168.1.192/24 ...
                for match in re.finditer(r'inet\s+(\d+\.\d+\.\d+\.\d+)', result.stdout):
                    local_ips.add(match.group(1))
                    logger.debug(f"Detected local IP (ip cmd): {match.group(1)}")
        except Exception as e:
            logger.debug(f"Linux IP detection error: {e}")

        # Method 2: Try hostname resolution (cross-platform)
        try:
            import socket
            hostname = socket.gethostname()
            # Get all IPs for this hostname
            try:
                host_ips = socket.gethostbyname_ex(hostname)[2]
                for ip in host_ips:
                    local_ips.add(ip)
                    logger.debug(f"Detected local IP (hostname): {ip}")
            except socket.gaierror:
                pass

            # Also try to get the IP used for outbound connections
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                outbound_ip = s.getsockname()[0]
                local_ips.add(outbound_ip)
                logger.debug(f"Detected local IP (outbound): {outbound_ip}")
                s.close()
            except Exception:
                pass
        except Exception as e:
            logger.debug(f"Socket IP detection error: {e}")

        # Method 3: Try to get IPs from shared_data if available (Flask config)
        if self.shared_data:
            try:
                # Check if there's a configured host IP
                host = self.shared_data.get('host', '')
                if host and host not in ['0.0.0.0', '']:
                    local_ips.add(host)
                    logger.debug(f"Detected local IP (config): {host}")
            except Exception:
                pass

        # Add common local network ranges that might be Ragnar
        # These are private IP patterns that are likely to be the host
        try:
            for ip in list(local_ips):
                if ip.startswith('192.168.') or ip.startswith('10.') or ip.startswith('172.'):
                    # This is a private IP, likely the actual machine IP
                    logger.info(f"Ragnar local IP detected: {ip}")
        except Exception:
            pass

        logger.info(f"Local IPs (excluded from alerts): {local_ips}")
        return local_ips

    def _detect_gateway_ips(self) -> set:
        gateways: set = set()
        try:
            result = subprocess.run(
                ['ip', 'route', 'show', 'default'],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                for match in re.finditer(
                    r'default\s+via\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
                    result.stdout
                ):
                    gateways.add(match.group(1))
        except Exception as e:
            logger.debug(f"Gateway detection error: {e}")
        if gateways:
            logger.info(f"Default gateway(s) (port-scan exempt): {gateways}")
        return gateways

    def _derive_lan_networks(self) -> List[ipaddress.IPv4Network]:
        nets: set = set()
        candidates: set = set()
        candidates.update(getattr(self, '_local_ips', set()) or set())
        candidates.update(getattr(self, '_gateway_ips', set()) or set())
        for ip in candidates:
            try:
                addr = ipaddress.IPv4Address(ip)
            except (ValueError, ipaddress.AddressValueError):
                continue
            if addr.is_loopback or addr.is_link_local or addr.is_multicast:
                continue
            try:
                net = ipaddress.IPv4Network(
                    f"{ip}/{self.PASSIVE_LAN_PREFIX}", strict=False)
                nets.add(net)
            except (ValueError, ipaddress.NetmaskValueError):
                continue
        result = sorted(nets, key=lambda n: int(n.network_address))
        if result:
            logger.info(f"LAN networks for passive discovery: "
                        f"{[str(n) for n in result]}")
        return result

    def _is_lan_ip(self, ip: str) -> bool:
        if not ip:
            return False
        try:
            addr = ipaddress.IPv4Address(ip)
        except (ValueError, ipaddress.AddressValueError):
            return False
        if addr.is_loopback or addr.is_link_local or addr.is_multicast:
            return False
        if int(addr) == 0 or int(addr) == 0xFFFFFFFF:
            return False
        return any(addr in net for net in self._lan_networks)

    def is_available(self) -> bool:
        """Check if traffic analysis is available"""
        return get_server_capabilities().capabilities.traffic_analysis_enabled

    def unavailable_reason(self) -> str:
        """Why traffic analysis cannot run here ('' when it can).

        Shown verbatim in the web UI, so it names what is actually missing —
        almost always an uninstalled tcpdump rather than the hardware.
        """
        return get_server_capabilities().capabilities.traffic_block_reason

    def start(self) -> bool:
        """Start traffic capture and analysis"""
        if not self.is_available():
            logger.error("Traffic analysis not available: "
                         f"{self.unavailable_reason() or 'requirements not met'}")
            return False
        
        if self._running:
            logger.warning("Traffic analyzer already running")
            return True
        
        self._running = True
        self._start_time = datetime.now()

        # Start capture thread
        self._capture_thread = threading.Thread(
            target=self._capture_loop,
            name="TrafficCapture",
            daemon=True
        )
        self._capture_thread.start()
        
        # Start analysis thread
        self._analysis_thread = threading.Thread(
            target=self._analysis_loop,
            name="TrafficAnalysis",
            daemon=True
        )
        self._analysis_thread.start()

        # Best-effort: spawn JA3/IRC sidecars (no-op if tshark missing)
        try:
            self._start_sidecars()
        except Exception as exc:
            logger.debug(f"Sidecar startup failed: {exc}")

        logger.info(f"Traffic analyzer started on interface {self.interface}")
        return True
    
    def stop(self):
        """Stop traffic capture and analysis"""
        self._running = False

        try:
            self._stop_sidecars()
        except Exception as exc:
            logger.debug(f"Sidecar shutdown failed: {exc}")

        if self._capture_process:
            try:
                self._capture_process.terminate()
                self._capture_process.wait(timeout=5)
            except Exception as e:
                logger.error(f"Error stopping capture: {e}")
                try:
                    self._capture_process.kill()
                except Exception:
                    pass
        
        logger.info("Traffic analyzer stopped")
    
    def _capture_loop(self):
        """Main capture loop using tcpdump"""
        try:
            # Build tcpdump command
            # -l: line-buffered, -n: no DNS resolution, -q: quiet (brief output)
            # -tttt: timestamp format
            cmd = [
                'sudo', 'tcpdump',
                '-i', self.interface,
                '-l', '-n', '-q',
                '-tttt',
                'not port 22 and not port 8000'  # Exclude SSH and web UI traffic
            ]
            
            logger.info(f"Starting tcpdump: {' '.join(cmd)}")
            
            self._capture_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )
            
            # Start stderr reader thread to capture errors
            def read_stderr():
                try:
                    for line in self._capture_process.stderr:
                        line = line.strip()
                        if line:
                            logger.debug(f"tcpdump stderr: {line}")
                            # Log important messages as warnings
                            if 'error' in line.lower() or 'permission' in line.lower():
                                logger.warning(f"tcpdump: {line}")
                            elif 'listening on' in line.lower():
                                logger.info(f"tcpdump: {line}")
                except Exception as e:
                    logger.debug(f"Stderr reader error: {e}")
            
            stderr_thread = threading.Thread(target=read_stderr, daemon=True)
            stderr_thread.start()
            
            # Wait briefly and check if process started successfully
            time.sleep(0.5)
            if self._capture_process.poll() is not None:
                # Process already terminated
                stderr_output = self._capture_process.stderr.read()
                logger.error(f"tcpdump failed to start: {stderr_output}")
                self._running = False
                return
            
            logger.info("tcpdump capture started successfully")
            
            while self._running and self._capture_process.poll() is None:
                try:
                    line = self._capture_process.stdout.readline()
                    if line:
                        self._raw_packet_count += 1
                        try:
                            self._packet_queue.put_nowait(line.strip())
                        except queue.Full:
                            pass  # Drop packet if queue is full
                except Exception as e:
                    logger.debug(f"Capture read error: {e}")
                    break
            
            # Log exit reason
            if self._capture_process.poll() is not None:
                rc = self._capture_process.returncode
                logger.info(f"tcpdump exited with code {rc}")
                    
        except Exception as e:
            logger.error(f"Capture loop error: {e}")
        finally:
            self._running = False
    
    def _analysis_loop(self):
        """Process captured packets and generate statistics"""
        batch = []
        batch_size = 100
        last_metrics_update = time.time()
        
        while self._running:
            try:
                # Collect batch of packets
                try:
                    packet = self._packet_queue.get(timeout=1)
                    batch.append(packet)
                except queue.Empty:
                    pass
                
                # Process batch when full or on timeout
                if len(batch) >= batch_size or (batch and time.time() - last_metrics_update > 1):
                    self._process_packet_batch(batch)
                    batch = []
                    
                    # Update metrics
                    current_time = time.time()
                    if current_time - last_metrics_update >= 1:
                        self._update_metrics()
                        last_metrics_update = current_time

                # Periodically score flows for beacon behaviour
                self._sweep_beacons()

                # Periodically flush passive host discoveries to the DB
                if time.time() - self._last_passive_sync >= self.PASSIVE_SYNC_INTERVAL:
                    try:
                        self._passive_sync_to_db()
                    except Exception as exc:
                        logger.debug(f"Passive host sync error: {exc}")
                    self._last_passive_sync = time.time()

                # Periodically evict stale tracked state back under the caps
                if time.time() - self._last_state_prune >= self.STATE_PRUNE_INTERVAL:
                    try:
                        self._prune_state()
                    except Exception as exc:
                        logger.debug(f"State prune error: {exc}")
                    self._last_state_prune = time.time()

            except Exception as e:
                logger.error(f"Analysis error: {e}")
    
    def _process_packet_batch(self, packets: List[str]):
        """Process a batch of captured packets"""
        with self._lock:
            for packet_line in packets:
                self._parse_and_record_packet(packet_line)
    
    def _parse_and_record_packet(self, line: str):
        """Parse a tcpdump line and record statistics"""
        # tcpdump -q -tttt output examples:
        # 2024-01-15 10:30:45.123456 IP 192.168.1.100.443 > 192.168.1.1.54321: tcp 52
        # 2024-01-15 10:30:45.123456 IP 192.168.1.100 > 192.168.1.1: ICMP echo request
        # 2024-01-15 10:30:45.123456 ARP, Request who-has 192.168.1.1 tell 192.168.1.100
        try:
            # Always count this as a packet
            self.total_packets += 1
            
            # Skip if too short
            if not line or len(line) < 20:
                return
            
            parts = line.split()
            if len(parts) < 5:
                return
            
            # Find protocol indicator (IP, IP6, ARP, etc.)
            protocol = 'unknown'
            proto_idx = -1
            for i, part in enumerate(parts[2:6], start=2):  # Start after timestamp
                part_upper = part.upper().rstrip(',')
                if part_upper in ['IP', 'IP6', 'ARP', 'ICMP', 'ICMP6']:
                    protocol = part_upper.lower()
                    proto_idx = i
                    break
            
            if proto_idx == -1:
                # Try to detect from content
                if 'tcp' in line.lower():
                    protocol = 'tcp'
                elif 'udp' in line.lower():
                    protocol = 'udp'
                else:
                    protocol = 'other'

            # ARP harvesting: pull IP↔MAC mappings for passive host discovery.
            if protocol == 'arp':
                self._parse_arp_line(line)
                return

            # Extract IP addresses with regex - more flexible
            # Match patterns like: 192.168.1.100.443 or 192.168.1.100
            ip_pattern = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:\.(\d+))?'
            ip_matches = re.findall(ip_pattern, line)
            
            if len(ip_matches) < 2:
                # At least count the packet
                self.total_bytes += 64  # Estimate
                return
            
            src_ip = ip_matches[0][0]
            src_port = int(ip_matches[0][1]) if ip_matches[0][1] else 0
            dst_ip = ip_matches[1][0]
            dst_port = int(ip_matches[1][1]) if ip_matches[1][1] else 0
            
            # Extract size if available
            size_match = re.search(r'length\s+(\d+)|:\s+(?:tcp|udp)\s+(\d+)|(?:tcp|udp)\s+(\d+)', line.lower())
            if size_match:
                packet_size = int(next(g for g in size_match.groups() if g))
            else:
                packet_size = 64  # Default estimate
            
            # Update global stats  
            self.total_bytes += packet_size
            
            # Flow-direction inference: if we've already seen the reverse
            # flow, this packet is a response (the src_ip is the responder).
            conn_key = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"
            reverse_key = f"{dst_ip}:{dst_port}->{src_ip}:{src_port}"
            is_response_flow = (reverse_key in self.connections
                                and conn_key not in self.connections)

            # Update host stats
            self._update_host_stats(src_ip, 'out', packet_size, protocol,
                                    my_port=src_port, peer_port=dst_port,
                                    peer_ip=dst_ip,
                                    is_response_flow=is_response_flow)
            self._update_host_stats(dst_ip, 'in', packet_size, protocol,
                                    my_port=dst_port, peer_port=src_port,
                                    peer_ip=src_ip,
                                    is_response_flow=False)

            # Update connection tracking
            if conn_key not in self.connections:
                self.connections[conn_key] = ConnectionStats(
                    src_ip=src_ip, dst_ip=dst_ip,
                    src_port=src_port, dst_port=dst_port,
                    protocol=protocol
                )
            conn = self.connections[conn_key]
            conn.packets_sent += 1
            conn.bytes_sent += packet_size
            conn.last_seen = datetime.now()
            
            # Record listening ports (a host using a service port = listener).
            self._record_listening_port(src_ip, src_port)
            self._record_listening_port(dst_ip, dst_port)

            # Check for suspicious patterns
            self._check_suspicious_patterns(src_ip, dst_ip, src_port, dst_port, protocol)

            # Sample outbound flows from local hosts for beacon detection
            if (src_ip in self._local_ips
                    or dst_ip in self._local_ips
                    or dst_port in self.BEACON_PORT_DENYLIST
                    or self._is_broadcast_or_multicast(dst_ip)):
                pass
            else:
                # Only outbound from internal hosts (skip pure external<->external)
                if self._is_internal(src_ip) and not self._is_internal(dst_ip):
                    self._record_flow_sample(src_ip, dst_ip, dst_port,
                                             time.time(), packet_size)

            # Check for DNS queries
            if dst_port == 53 or src_port == 53:
                self._record_dns_query(line, src_ip, dst_ip)
                
        except Exception as e:
            logger.debug(f"Packet parse error: {e}")
    
    def _update_host_stats(self, ip: str, direction: str, size: int, protocol: str,
                           my_port: int, peer_port: int,
                           peer_ip: str = '',
                           is_response_flow: bool = False):
        """Update statistics for a host.

        ports_contacted: every peer-port this host's traffic involved (UI view).
        ports_targeted: only peer-ports this host actively initiated to.
        sweep_targets: per-port set of distinct dst-IPs this host initiated to,
            used for horizontal-sweep detection.
        """
        if ip not in self.host_stats:
            self.host_stats[ip] = HostTrafficStats(ip=ip)

        stats = self.host_stats[ip]
        stats.total_packets += 1
        stats.total_bytes += size
        stats.last_seen = datetime.now()

        if direction == 'in':
            stats.packets_in += 1
            stats.bytes_in += size
        else:
            stats.packets_out += 1
            stats.bytes_out += size

        stats.protocols[protocol] = stats.protocols.get(protocol, 0) + 1

        if peer_port and len(stats.ports_contacted) < 1000:
            stats.ports_contacted.add(peer_port)

        if (direction == 'out'
                and peer_port
                and not is_response_flow
                and not self._looks_like_response(my_port, peer_port)):
            if len(stats.ports_targeted) < 1000:
                stats.ports_targeted.add(peer_port)

            if peer_ip and self._is_sweep_relevant_port(peer_port):
                bucket = stats.sweep_targets.get(peer_port)
                if bucket is None:
                    if len(stats.sweep_targets) >= self.SWEEP_MAX_TRACKED_PORTS:
                        return
                    bucket = set()
                    stats.sweep_targets[peer_port] = bucket
                if len(bucket) < self.SWEEP_MAX_TRACKED_IPS:
                    bucket.add(peer_ip)

    def _is_sweep_relevant_port(self, port: int) -> bool:
        if port <= 0:
            return False
        if port < self.PORTSCAN_EPHEMERAL_FLOOR:
            return True
        return port in self.HIGH_VALUE_HIGH_PORTS

    def _looks_like_response(self, my_port: int, peer_port: int) -> bool:
        if peer_port in self.HIGH_VALUE_HIGH_PORTS:
            return False
        return (my_port in self.SERVICE_SOURCE_PORTS
                and peer_port >= self.PORTSCAN_EPHEMERAL_FLOOR)
    
    def _record_dns_query(self, line: str, src_ip: str, dst_ip: str):
        """Record DNS queries for analysis and check for tunneling"""
        self.dns_queries.append({
            'timestamp': datetime.now().isoformat(),
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'raw': line[:200]
        })

        # Update host DNS queries
        if src_ip in self.host_stats:
            host = self.host_stats[src_ip]
            if len(host.dns_queries) < 100:
                host.dns_queries.append(line[:100])

        # Check for DNS tunneling (high query rate)
        if src_ip not in self._local_ips:
            self._check_dns_tunneling(src_ip)

    _ARP_REPLY_RE = re.compile(
        r'ARP,\s+Reply\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+is-at\s+'
        r'([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})'
    )
    _ARP_AT_RE = re.compile(
        r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+is-at\s+'
        r'([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})'
    )

    def _parse_arp_line(self, line: str):
        match = self._ARP_REPLY_RE.search(line) or self._ARP_AT_RE.search(line)
        if not match:
            return
        ip, mac = match.group(1), match.group(2).lower()
        if not self._is_lan_ip(ip):
            return
        self._mac_by_ip[ip] = mac
        if ip not in self.host_stats:
            self.host_stats[ip] = HostTrafficStats(ip=ip, mac=mac)
        elif not self.host_stats[ip].mac:
            self.host_stats[ip].mac = mac

    def _record_listening_port(self, ip: str, port: int):
        if not ip or not port or port <= 0:
            return
        # A host using a service port (<1024 or high-value) = it's a listener.
        if port >= self.PORTSCAN_EPHEMERAL_FLOOR and port not in self.HIGH_VALUE_HIGH_PORTS:
            return
        if not self._is_lan_ip(ip):
            return
        bucket = self._listening_ports.setdefault(ip, set())
        if len(bucket) < self.PASSIVE_MAX_LISTEN_PORTS:
            bucket.add(port)

    # Port -> well-known service name for `services` column enrichment.
    PORT_SERVICE_NAMES = {
        20: 'ftp-data', 21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp',
        53: 'dns', 67: 'dhcp-server', 68: 'dhcp-client', 80: 'http',
        110: 'pop3', 123: 'ntp', 135: 'msrpc', 137: 'netbios-ns',
        138: 'netbios-dgm', 139: 'netbios-ssn', 143: 'imap', 161: 'snmp',
        162: 'snmptrap', 389: 'ldap', 443: 'https', 445: 'smb',
        465: 'smtps', 514: 'syslog', 587: 'submission', 636: 'ldaps',
        993: 'imaps', 995: 'pop3s', 1433: 'mssql', 1521: 'oracle',
        2375: 'docker', 2376: 'docker-tls', 2379: 'etcd', 2380: 'etcd-peer',
        3306: 'mysql', 3389: 'rdp', 5432: 'postgresql', 5601: 'kibana',
        5672: 'amqp', 5900: 'vnc', 5901: 'vnc', 5984: 'couchdb',
        5985: 'winrm', 5986: 'winrm-ssl', 6379: 'redis', 7474: 'neo4j',
        7687: 'neo4j-bolt', 8000: 'http-alt', 8008: 'http-alt',
        8080: 'http-alt', 8086: 'influxdb', 8443: 'https-alt',
        8888: 'http-alt', 9000: 'grafana', 9042: 'cassandra',
        9090: 'prometheus', 9091: 'prometheus-push', 9092: 'kafka',
        9200: 'elasticsearch', 9300: 'elasticsearch-transport',
        11211: 'memcached', 15672: 'rabbitmq-mgmt', 27017: 'mongodb',
        27018: 'mongodb-shard',
    }

    @staticmethod
    def _ip_to_pseudo_mac(ip: str) -> str:
        parts = ip.split('.')
        if len(parts) != 4:
            return ''
        try:
            return '00:00:' + ':'.join(f'{int(p):02x}' for p in parts)
        except ValueError:
            return ''

    def _passive_sync_to_db(self):
        """Flush passively-observed LAN hosts into the hosts DB.

        For each LAN IP that meets the discovery threshold (real MAC seen via
        ARP, or >= PASSIVE_MIN_PACKETS observed), upsert into `hosts`. Merges
        listening ports with any existing port list — never replaces.
        """
        db = getattr(self.shared_data, 'db', None) if self.shared_data else None
        if not db or not hasattr(db, 'upsert_host'):
            return
        if not self._lan_networks:
            return

        with self._lock:
            snapshot: List[Tuple[str, str, set]] = []
            for ip, stats in self.host_stats.items():
                if not self._is_lan_ip(ip):
                    continue
                if ip in self._local_ips:
                    continue
                mac = self._mac_by_ip.get(ip) or stats.mac or ''
                if not mac and stats.total_packets < self.PASSIVE_MIN_PACKETS:
                    continue
                listening = set(self._listening_ports.get(ip, set()))
                snapshot.append((ip, mac, listening))

        for ip, mac, listening in snapshot:
            try:
                self._upsert_passive_host(db, ip, mac, listening)
            except Exception as exc:
                logger.debug(f"Passive upsert failed for {ip}: {exc}")

    def _upsert_passive_host(self, db, ip: str, mac: str, listening_ports: set):
        existing = db.get_host_by_ip(ip)

        if mac:
            target_mac = mac.lower()
        elif existing and existing.get('mac'):
            target_mac = existing['mac']
        else:
            target_mac = self._ip_to_pseudo_mac(ip)
        if not target_mac:
            return

        existing_ports: set = set()
        existing_services: Dict[str, str] = {}
        if existing:
            for chunk in (existing.get('ports') or '').split(','):
                chunk = chunk.strip()
                if chunk.isdigit():
                    existing_ports.add(int(chunk))
            raw_services = existing.get('services') or ''
            if raw_services:
                try:
                    parsed = json.loads(raw_services)
                    if isinstance(parsed, dict):
                        existing_services = {str(k): str(v) for k, v in parsed.items()}
                except (ValueError, TypeError):
                    pass

        merged_ports = existing_ports | listening_ports
        new_ports = listening_ports - existing_ports
        if not existing and not merged_ports:
            return  # nothing useful to write yet

        services = dict(existing_services)
        for port in merged_ports:
            key = str(port)
            if key not in services or not services[key]:
                services[key] = self.PORT_SERVICE_NAMES.get(port, '')

        ports_str = ','.join(str(p) for p in sorted(merged_ports))
        # Only pass services if we have something to add — avoid clobbering
        # richer service descriptions an active scan may have written.
        services_arg = services if new_ports or not existing else None

        db.upsert_host(
            mac=target_mac,
            ip=ip,
            ports=ports_str if (new_ports or not existing) else None,
            services=services_arg,
        )

        # Observed traffic = host is alive. Resurrects 'degraded' hosts that
        # were wiped by a transient wifi flap or have simply stopped
        # responding to active pings while still talking on the network.
        if hasattr(db, 'update_ping_status'):
            try:
                db.update_ping_status(target_mac, success=True)
            except Exception as exc:
                logger.debug(f"update_ping_status failed for {target_mac}: {exc}")

    def _check_suspicious_patterns(self, src_ip: str, dst_ip: str,
                                   src_port: int, dst_port: int, protocol: str):
        """Check for suspicious traffic patterns"""
        # Skip alerts for traffic from OR to Ragnar itself (local IPs)
        # This prevents false positives from Ragnar's own scanning/network activity
        if src_ip in self._local_ips or dst_ip in self._local_ips:
            return

        # Check suspicious ports (only for external traffic)
        if dst_port in self.SUSPICIOUS_PORTS or src_port in self.SUSPICIOUS_PORTS:
            suspicious_port = dst_port if dst_port in self.SUSPICIOUS_PORTS else src_port
            port_description = self.SUSPICIOUS_PORTS.get(suspicious_port, "Unknown")

            proto_lc = (protocol or '').lower()
            is_broadcast = self._is_broadcast_or_multicast(dst_ip)
            # Suppress noise: TCP-only "C2 channel" ports over UDP/broadcast
            # are almost always LAN discovery on a coincidentally-spicy port,
            # not actual C2. Skip the alert entirely in that case.
            if suspicious_port in self.TCP_UNICAST_ONLY_PORTS:
                if proto_lc not in ('tcp', 'ip') or is_broadcast:
                    logger.debug(
                        f"Suppressing suspicious-port alert for "
                        f"{dst_ip}:{suspicious_port} ({proto_lc}, "
                        f"broadcast={is_broadcast}) - "
                        f"'{port_description}' requires TCP unicast"
                    )
                    return

            self._create_alert(
                level=TrafficAlertLevel.MEDIUM,
                category=AlertCategory.SUSPICIOUS_PORT.value,
                message=(f"Suspicious port {suspicious_port}/{proto_lc or '?'} "
                         f"({port_description}): {src_ip} -> {dst_ip}"),
                src_ip=src_ip,
                dst_ip=dst_ip,
                details={
                    'port': suspicious_port,
                    'port_description': port_description,
                    'protocol': proto_lc or 'unknown',
                    'broadcast': is_broadcast,
                    'direction': 'outbound' if dst_port == suspicious_port else 'inbound'
                }
            )

        # Port-scan: score *targeted* ports (initiated to), weighted toward
        # well-known service ports. Default gateway gets a softer threshold
        # (5x) rather than full exemption — compromised routers still alert.
        if src_ip in self.host_stats and src_ip not in self._local_ips:
            stats = self.host_stats[src_ip]
            targeted = stats.ports_targeted
            low_ports = {p for p in targeted if 0 < p < self.PORTSCAN_EPHEMERAL_FLOOR}
            high_value = {p for p in targeted if p in self.HIGH_VALUE_HIGH_PORTS}
            total = len(targeted)
            n_low = len(low_ports)
            n_hv = len(high_value)
            # Count high-value-high ports toward the "weighted" low-port score.
            n_weighted = n_low + n_hv

            mult = (self.PORTSCAN_GATEWAY_MULTIPLIER
                    if src_ip in self._gateway_ips else 1)
            low_threshold = self.PORTSCAN_LOW_PORT_THRESHOLD * mult
            total_threshold = self.PORTSCAN_TOTAL_THRESHOLD * mult

            level = None
            if n_weighted >= low_threshold:
                level = TrafficAlertLevel.HIGH
                message = (f"Port scan detected: {src_ip} initiated to "
                           f"{n_low} well-known + {n_hv} high-value ports "
                           f"(+{total - n_weighted} other)")
            elif total >= total_threshold:
                level = TrafficAlertLevel.MEDIUM
                message = (f"Heavy port activity: {src_ip} initiated to "
                           f"{total} unique ports")

            if level is not None:
                self._create_alert(
                    level=level,
                    category=AlertCategory.PORT_SCAN.value,
                    message=message,
                    src_ip=src_ip,
                    details={
                        'ports_scanned': total,
                        'low_ports_count': n_low,
                        'high_value_ports_count': n_hv,
                        'sample_low_ports': sorted(low_ports)[:20],
                        'sample_high_value_ports': sorted(high_value)[:20],
                        'sample_ports': sorted(targeted)[:20],
                        'is_gateway': src_ip in self._gateway_ips,
                        'scan_duration_seconds': (stats.last_seen - stats.first_seen).total_seconds()
                    }
                )

            # Horizontal sweep: one port across many distinct destination hosts.
            for port, dst_ips in stats.sweep_targets.items():
                if len(dst_ips) < self.SWEEP_HOST_THRESHOLD * mult:
                    continue
                self._create_alert(
                    level=TrafficAlertLevel.HIGH,
                    category=AlertCategory.PORT_SCAN.value,
                    message=(f"Horizontal sweep: {src_ip} hit "
                             f"{len(dst_ips)} hosts on port {port}"),
                    src_ip=src_ip,
                    dedup_key=f"sweep:{src_ip}:{port}",
                    details={
                        'sweep_port': port,
                        'hosts_targeted': len(dst_ips),
                        'sample_hosts': sorted(dst_ips)[:20],
                        'is_gateway': src_ip in self._gateway_ips,
                    }
                )

    # ------------------------------------------------------------------ #
    # C2 beacon detection
    # ------------------------------------------------------------------ #

    @staticmethod
    def _is_internal(ip: str) -> bool:
        """Cheap RFC1918 / loopback / link-local check (IPv4 only)."""
        if not ip:
            return False
        if ip.startswith('127.') or ip.startswith('169.254.'):
            return True
        if ip.startswith('10.') or ip.startswith('192.168.'):
            return True
        if ip.startswith('172.'):
            try:
                second = int(ip.split('.', 2)[1])
                return 16 <= second <= 31
            except (ValueError, IndexError):
                return False
        return False

    @staticmethod
    def _is_broadcast_or_multicast(ip: str) -> bool:
        """Detect IPv4 broadcast (limited or directed) and multicast.

        Used to suppress C2/beacon classifications for LAN discovery
        chatter that happens to hit a 'suspicious' port (e.g. an ESP
        sending UDP broadcasts on port 6667 — not actually IRC).
        """
        if not ip:
            return False
        if ip == '255.255.255.255' or ip == '0.0.0.0':
            return True
        # Subnet-directed broadcasts commonly end in .255 on /24 nets.
        if ip.endswith('.255'):
            return True
        # IPv4 multicast: 224.0.0.0/4
        try:
            first = int(ip.split('.', 1)[0])
        except (ValueError, IndexError):
            return False
        return 224 <= first <= 239

    def _record_flow_sample(self, src_ip: str, dst_ip: str, dst_port: int,
                            ts: float, bytes_out: int) -> None:
        """Append one outbound packet to the per-flow ring buffer.

        Called from the packet parser for every outbound packet from an
        internal host to an external destination on a non-denylisted port.
        """
        if dst_port <= 0:
            return
        key = (src_ip, dst_ip, dst_port)
        self._flow_history[key].append((ts, max(1, int(bytes_out))))

    def _score_flow(self, samples: List[Tuple[float, int]]) -> Optional[Dict[str, Any]]:
        """Score a single flow's beacon-likeness.

        Returns a dict with score and metrics if the flow qualifies as a
        beacon candidate, or None if it doesn't meet the minimum bar.

        Score in [0,1]:
            0.6 * (interval regularity) + 0.4 * (size regularity)
        Interval regularity = 1 - clamp(CV_interval / CV_MAX, 0, 1)
        Size regularity     = 1 - clamp(CV_size     / SIZE_REF, 0, 1)
        """
        if len(samples) < self.BEACON_MIN_SAMPLES:
            return None

        times = [s[0] for s in samples]
        sizes = [s[1] for s in samples]
        intervals = [b - a for a, b in zip(times, times[1:])]
        if not intervals:
            return None

        mean_i = statistics.fmean(intervals)
        if not (self.BEACON_MIN_INTERVAL <= mean_i <= self.BEACON_MAX_INTERVAL):
            return None

        # Population stdev (we have the full sample, not a draw from a dist)
        stdev_i = statistics.pstdev(intervals) if len(intervals) > 1 else 0.0
        cv_i = stdev_i / mean_i if mean_i > 0 else 1.0
        if cv_i > self.BEACON_INTERVAL_CV_MAX:
            return None

        mean_s = statistics.fmean(sizes) or 1.0
        stdev_s = statistics.pstdev(sizes) if len(sizes) > 1 else 0.0
        cv_s = stdev_s / mean_s if mean_s > 0 else 1.0

        interval_score = 1.0 - min(cv_i / self.BEACON_INTERVAL_CV_MAX, 1.0)
        size_score = 1.0 - min(cv_s / self.BEACON_SIZE_CV_REF, 1.0)
        score = 0.6 * interval_score + 0.4 * size_score

        return {
            'score': score,
            'mean_interval_s': mean_i,
            'interval_cv': cv_i,
            'mean_size_bytes': mean_s,
            'size_cv': cv_s,
            'samples': len(samples),
            'first_seen': times[0],
            'last_seen': times[-1],
        }

    def _sweep_beacons(self, force: bool = False) -> List[Tuple[Tuple[str, str, int], Dict[str, Any]]]:
        """Score every tracked flow and raise alerts for new/improved beacons.

        Returns the list of (key, metrics) pairs that triggered an alert
        during this sweep (useful for tests and the /api/traffic/beacons
        endpoint).
        """
        now = time.time()
        if not force and now - self._last_beacon_sweep < self.BEACON_SWEEP_INTERVAL:
            return []
        self._last_beacon_sweep = now

        fired: List[Tuple[Tuple[str, str, int], Dict[str, Any]]] = []
        # Snapshot keys so we can mutate _beacon_scored while iterating
        for key in list(self._flow_history.keys()):
            samples = list(self._flow_history[key])
            metrics = self._score_flow(samples)
            if metrics is None:
                continue
            score = metrics['score']
            if score < self.BEACON_SCORE_ALERT:
                continue

            prev = self._beacon_scored.get(key, {}).get('score', 0.0)
            if score < prev + self.BEACON_SCORE_IMPROVE:
                # Already alerted at (approximately) this score; don't spam
                continue

            self._beacon_scored[key] = {**metrics, 'alerted_at': now}
            src_ip, dst_ip, dst_port = key
            level = (TrafficAlertLevel.HIGH
                     if score >= self.BEACON_SCORE_CRITICAL
                     else TrafficAlertLevel.MEDIUM)
            self._create_alert(
                level=level,
                category=AlertCategory.C2_BEACON.value,
                message=(
                    f"Periodic beacon: {src_ip} -> {dst_ip}:{dst_port} "
                    f"every ~{metrics['mean_interval_s']:.1f}s "
                    f"(score={score:.2f})"
                ),
                src_ip=src_ip,
                dst_ip=dst_ip,
                details={
                    'dst_port': dst_port,
                    'score': round(score, 3),
                    'mean_interval_s': round(metrics['mean_interval_s'], 2),
                    'interval_cv': round(metrics['interval_cv'], 3),
                    'mean_size_bytes': round(metrics['mean_size_bytes'], 1),
                    'size_cv': round(metrics['size_cv'], 3),
                    'samples': metrics['samples'],
                    'first_seen': metrics['first_seen'],
                    'last_seen': metrics['last_seen'],
                    'mitre': ['T1071', 'T1573'],
                },
            )
            fired.append((key, self._beacon_scored[key]))
        return fired

    def get_beacons(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Return current beacon candidates sorted by score (descending)."""
        with self._lock:
            items = []
            for (src_ip, dst_ip, dst_port), metrics in self._beacon_scored.items():
                items.append({
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'dst_port': dst_port,
                    'score': round(metrics['score'], 3),
                    'mean_interval_s': round(metrics['mean_interval_s'], 2),
                    'interval_cv': round(metrics['interval_cv'], 3),
                    'mean_size_bytes': round(metrics['mean_size_bytes'], 1),
                    'size_cv': round(metrics['size_cv'], 3),
                    'samples': metrics['samples'],
                    'first_seen': metrics['first_seen'],
                    'last_seen': metrics['last_seen'],
                })
            items.sort(key=lambda x: x['score'], reverse=True)
            return items[:limit]

    # ------------------------------------------------------------------ #
    # Optional sidecars: JA3 collector and IRC DPI
    # ------------------------------------------------------------------ #

    def _start_sidecars(self) -> None:
        """Best-effort start of tshark-based JA3 and IRC sidecars.

        Both modules degrade gracefully if tshark is missing.

        These are the one genuinely heavy part of Traffic Analysis: each spawns
        a full tshark dissector (~290MB RSS plus a ~155MB dumpcap child), so the
        pair alone outweighs everything a Pi Zero has. The tcpdump core runs on
        any board; the sidecars need a big one, hence the separate capability.
        """
        caps = get_server_capabilities(self.shared_data).capabilities
        if not caps.traffic_sidecars_enabled:
            logger.info(
                f"JA3/IRC sidecars skipped: they need tshark and a board with at "
                f"least {ServerCapabilities.TRAFFIC_SIDECAR_MIN_RAM_GB:.1f}GB RAM "
                f"(this one reports {caps.total_ram_gb:.2f}GB). Packet capture, "
                f"beacon and port-scan detection are unaffected.")
            return

        try:
            from tls_fingerprint import JA3Collector
        except Exception as exc:
            logger.debug(f"JA3 collector unavailable: {exc}")
            JA3Collector = None  # type: ignore

        if JA3Collector is not None and self._ja3_collector is None:
            self._ja3_collector = JA3Collector(
                interface=self.interface,
                on_match=self._on_ja3_match,
            )
            if not self._ja3_collector.start():
                self._ja3_collector = None

        try:
            from irc_dpi import IRCDPIParser
        except Exception as exc:
            logger.debug(f"IRC DPI unavailable: {exc}")
            IRCDPIParser = None  # type: ignore

        if IRCDPIParser is not None and self._irc_parser is None:
            self._irc_parser = IRCDPIParser(
                interface=self.interface,
                on_session_event=self._on_irc_event,
            )
            if not self._irc_parser.start():
                self._irc_parser = None

    def _stop_sidecars(self) -> None:
        for attr in ('_ja3_collector', '_irc_parser'):
            sidecar = getattr(self, attr, None)
            if sidecar is not None:
                try:
                    sidecar.stop()
                except Exception:
                    pass
                setattr(self, attr, None)

    def _on_ja3_match(self, record) -> None:
        """Callback: a TLS fingerprint matched a known signature."""
        m = record.match
        if not m:
            return
        if m.category == 'malware' or m.confidence == 'high':
            level = TrafficAlertLevel.HIGH
        elif m.confidence == 'medium':
            level = TrafficAlertLevel.MEDIUM
        else:
            level = TrafficAlertLevel.LOW
        self._create_alert(
            level=level,
            category=AlertCategory.PROTOCOL_ANOMALY.value,
            message=(f"JA3 match: {record.src_ip} uses '{m.label}' "
                     f"(JA3={record.ja3[:12]}…)"),
            src_ip=record.src_ip,
            details={
                'ja3': record.ja3,
                'label': m.label,
                'confidence': m.confidence,
                'category': m.category,
                'source': m.source,
                'sni': record.sni,
                'dst_ips': sorted(record.dst_ips)[:10],
                'dst_ports': sorted(record.dst_ports),
            },
        )

    def _on_irc_event(self, session, message) -> None:
        """Callback: a notable IRC event was parsed off the wire."""
        cmd = message.command
        # The first NICK or JOIN on a session is enough to raise the flag —
        # IRC on the wire in 2026 is almost always worth investigating.
        if cmd == 'JOIN':
            channels = ', '.join(sorted(session.channels)[:5])
            self._create_alert(
                level=TrafficAlertLevel.HIGH,
                category=AlertCategory.C2_BEACON.value,
                message=(f"IRC JOIN: {session.client_ip} -> "
                         f"{session.server_ip}:{session.server_port} "
                         f"as '{session.nick}' on {channels or '?'}"),
                src_ip=session.client_ip,
                dst_ip=session.server_ip,
                details={
                    'protocol': 'IRC',
                    'nick': session.nick,
                    'user': session.user,
                    'channels': sorted(session.channels),
                    'server_port': session.server_port,
                    'server_banner': session.server_banner[:3],
                    'mitre': ['T1071.001', 'T1102'],
                },
            )

    def get_tls_fingerprints(self, limit: int = 100) -> List[Dict[str, Any]]:
        if self._ja3_collector is None:
            return []
        return self._ja3_collector.get_records(limit=limit)

    def get_irc_sessions(self, limit: int = 50) -> List[Dict[str, Any]]:
        if self._irc_parser is None:
            return []
        return self._irc_parser.get_sessions(limit=limit)

    def _check_dns_tunneling(self, src_ip: str):
        """Detect potential DNS tunneling based on query frequency"""
        current_time = time.time()

        # Track this query timestamp
        self._dns_query_times[src_ip].append(current_time)

        # Count queries in the tracking window
        window_start = current_time - self.DNS_QUERY_TRACKING_WINDOW
        recent_queries = sum(1 for t in self._dns_query_times[src_ip] if t > window_start)

        if recent_queries > self.DNS_TUNNEL_THRESHOLD:
            self._create_alert(
                level=TrafficAlertLevel.HIGH,
                category=AlertCategory.DNS_TUNNELING.value,
                message=f"Potential DNS tunneling: {src_ip} made {recent_queries} queries in {self.DNS_QUERY_TRACKING_WINDOW}s",
                src_ip=src_ip,
                details={
                    'queries_per_minute': recent_queries,
                    'threshold': self.DNS_TUNNEL_THRESHOLD,
                    'window_seconds': self.DNS_QUERY_TRACKING_WINDOW
                }
            )
    
    def _create_alert(self, level: TrafficAlertLevel, category: str,
                      message: str, src_ip: str = None, dst_ip: str = None,
                      details: Dict = None, dedup_key: str = None):
        """Create a traffic alert with rate limiting and deduplication.

        dedup_key: optional override for the dedup hash. Use when the default
            (category, src, dst) tuple would collapse distinct alerts — e.g.
            sweep alerts that vary by port rather than dst_ip.
        """
        current_time = time.time()

        # Alert deduplication - prevent same alert from firing repeatedly
        alert_hash = dedup_key if dedup_key else f"{category}:{src_ip}:{dst_ip}"
        if alert_hash in self._alert_hashes:
            # Check if dedup window has expired
            if current_time < self._alert_hash_expiry.get(alert_hash, 0):
                return  # Skip duplicate alert within window

        # Rate limiting (global)
        self._alert_timestamps.append(current_time)
        recent_alerts = sum(1 for t in self._alert_timestamps if current_time - t < 60)
        if recent_alerts > self.MAX_ALERTS_PER_MINUTE:
            return  # Skip alert if rate limited

        # Mark this alert as seen with expiry
        self._alert_hashes.add(alert_hash)
        self._alert_hash_expiry[alert_hash] = current_time + self._alert_dedup_window

        # Clean up old hash entries periodically
        if len(self._alert_hash_expiry) > 1000:
            expired = [h for h, exp in self._alert_hash_expiry.items() if exp < current_time]
            for h in expired:
                self._alert_hashes.discard(h)
                del self._alert_hash_expiry[h]

        self._alert_counter += 1
        alert = TrafficAlert(
            alert_id=f"TA-{self._alert_counter:06d}",
            level=level,
            category=category,
            message=message,
            src_ip=src_ip,
            dst_ip=dst_ip,
            details=details or {}
        )

        self.alerts.append(alert)

        # Trigger callbacks
        for callback in self._on_alert_callbacks:
            try:
                callback(alert)
            except Exception as e:
                logger.error(f"Alert callback error: {e}")
    
    def _update_metrics(self):
        """Update packets/bytes per second metrics"""
        current_time = time.time()
        elapsed = current_time - self._last_metrics_time
        
        if elapsed > 0:
            packets_delta = self.total_packets - self._last_packet_count
            bytes_delta = self.total_bytes - self._last_byte_count
            
            self.packets_per_second = packets_delta / elapsed
            self.bytes_per_second = bytes_delta / elapsed
            
            self._last_packet_count = self.total_packets
            self._last_byte_count = self.total_bytes
            self._last_metrics_time = current_time
    
    def on_alert(self, callback: Callable):
        """Register a callback for alerts"""
        self._on_alert_callbacks.append(callback)

    def _format_bytes(self, bytes_val: int) -> str:
        """Convert bytes to human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_val < 1024:
                return f"{bytes_val:.1f} {unit}"
            bytes_val /= 1024
        return f"{bytes_val:.1f} PB"

    def _count_alerts_by_severity(self) -> Dict[str, int]:
        """Count alerts grouped by severity level"""
        counts = {level.value: 0 for level in TrafficAlertLevel}
        for alert in self.alerts:
            counts[alert.level.value] += 1
        return counts

    def _count_alerts_by_category(self) -> Dict[str, int]:
        """Count alerts grouped by category"""
        counts = defaultdict(int)
        for alert in self.alerts:
            counts[alert.category] += 1
        return dict(counts)

    def get_summary(self) -> Dict[str, Any]:
        """Get traffic analysis summary with security-focused metrics"""
        with self._lock:
            unacked_alerts = [a for a in self.alerts if not a.acknowledged]
            uptime_seconds = None
            if self._start_time:
                uptime_seconds = (datetime.now() - self._start_time).total_seconds()

            return {
                # Capture status
                'status': 'running' if self._running else 'stopped',
                'interface': self.interface,
                'capture_started': self._start_time.isoformat() if self._start_time else None,
                'uptime_seconds': uptime_seconds,

                # Traffic metrics
                'total_packets': self.total_packets,
                'total_bytes': self.total_bytes,
                'total_bytes_human': self._format_bytes(self.total_bytes),
                'packets_per_second': round(self.packets_per_second, 2),
                'bytes_per_second': round(self.bytes_per_second, 2),
                'throughput_mbps': round(self.bytes_per_second * 8 / 1_000_000, 2),

                # Network inventory
                'unique_hosts': len(self.host_stats),
                'active_connections': len(self.connections),

                # Security metrics
                'total_alerts': len(self.alerts),
                'unacknowledged_alerts': len(unacked_alerts),
                'alerts_by_severity': self._count_alerts_by_severity(),
                'alerts_by_category': self._count_alerts_by_category(),

                # DNS monitoring
                'dns_queries_captured': len(self.dns_queries),

                # Beacon detection
                'tracked_flows': len(self._flow_history),
                'beacon_candidates': len(self._beacon_scored),

                # Configuration
                'excluded_local_ips': list(self._local_ips),
                'alert_dedup_window_seconds': self._alert_dedup_window,
                'sidecars_active': bool(self._ja3_collector or self._irc_parser),
                'tracked_state_caps': {
                    'hosts': self._max_hosts,
                    'connections': self._max_connections,
                    'flows': self._max_flows,
                },
            }
    
    def get_top_hosts(self, limit: int = 10, sort_by: str = 'bytes') -> List[Dict]:
        """Get top hosts by traffic"""
        with self._lock:
            hosts = list(self.host_stats.values())
            
            if sort_by == 'bytes':
                hosts.sort(key=lambda h: h.total_bytes, reverse=True)
            elif sort_by == 'packets':
                hosts.sort(key=lambda h: h.total_packets, reverse=True)
            elif sort_by == 'connections':
                hosts.sort(key=lambda h: len(h.ports_contacted), reverse=True)
            
            return [h.to_dict() for h in hosts[:limit]]
    
    def get_active_connections(self, limit: int = 50) -> List[Dict]:
        """Get active connections sorted by last activity"""
        with self._lock:
            conns = list(self.connections.values())
            conns.sort(key=lambda c: c.last_seen, reverse=True)
            return [c.to_dict() for c in conns[:limit]]
    
    def get_alerts(self, limit: int = 100, level: str = None) -> List[Dict]:
        """Get recent alerts"""
        with self._lock:
            alerts = list(self.alerts)
            if level:
                try:
                    level_enum = TrafficAlertLevel(level)
                    alerts = [a for a in alerts if a.level == level_enum]
                except ValueError:
                    pass
            return [a.to_dict() for a in alerts[-limit:]]
    
    def get_protocol_distribution(self) -> Dict[str, int]:
        """Get protocol distribution across all hosts"""
        with self._lock:
            distribution = defaultdict(int)
            for host in self.host_stats.values():
                for proto, count in host.protocols.items():
                    distribution[proto] += count
            return dict(distribution)
    
    def get_host_details(self, ip: str) -> Optional[Dict]:
        """Get detailed stats for a specific host"""
        with self._lock:
            if ip in self.host_stats:
                return self.host_stats[ip].to_dict()
            return None
    
    def acknowledge_alert(self, alert_id: str) -> bool:
        """Acknowledge an alert"""
        with self._lock:
            for alert in self.alerts:
                if alert.alert_id == alert_id:
                    alert.acknowledged = True
                    return True
            return False
    
    def clear_stats(self):
        """Clear all statistics and reset state"""
        with self._lock:
            self.host_stats.clear()
            self.connections.clear()
            self.alerts.clear()
            self.dns_queries.clear()
            self.total_packets = 0
            self.total_bytes = 0
            self._last_packet_count = 0
            self._last_byte_count = 0
            # Clear deduplication tracking
            self._alert_hashes.clear()
            self._alert_hash_expiry.clear()
            self._dns_query_times.clear()
            self._flow_history.clear()
            self._beacon_scored.clear()
            self._alert_counter = 0


# Global instance
_traffic_analyzer: Optional[TrafficAnalyzer] = None


def get_traffic_analyzer(shared_data=None, interface: str = None) -> TrafficAnalyzer:
    """Get or create the global TrafficAnalyzer instance"""
    global _traffic_analyzer
    if _traffic_analyzer is None:
        _traffic_analyzer = TrafficAnalyzer(shared_data, interface)
    return _traffic_analyzer
