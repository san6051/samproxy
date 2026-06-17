#!/usr/bin/env python3
"""
rsocks_server.py — Reverse SOCKS5 Operator Server
Single file. Standard library only. No pip install.

Usage:
  python3 rsocks_server.py --control 0.0.0.0:4433 --socks 127.0.0.1:1080 --pass 'RedTeam!'

Then use proxychains pointing at 127.0.0.1:1080.
"""
import argparse
import hashlib
import hmac
import socket
import struct
import threading
import time

# ── Protocol constants (inlined) ────────────────────────────────────────────
CHAN_OPEN, CHAN_DATA, CHAN_CLOSE = 0x01, 0x02, 0x03
CHAN_OPEN_OK, CHAN_OPEN_ERR     = 0x04, 0x05
KEEPALIVE                       = 0x06
HELLO, HELLO_OK, HELLO_ERR      = 0x07, 0x08, 0x09

FRAME_FMT  = '!BIH8s'                        # type(1)+chan(4)+len(2)+hmac(8)
FRAME_SIZE = struct.calcsize(FRAME_FMT)       # 15 bytes
SOCKS5     = 5


def _derive_key(passphrase: str) -> bytes:
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
        if not chunk:
            raise ConnectionError('socket closed')
        buf += chunk
    return buf


def _recv_frame(sock, key):
    tb, cid, length, rmac = struct.unpack(FRAME_FMT, _recvall(sock, FRAME_SIZE))
    payload = _recvall(sock, length) if length else b''
    if not hmac.compare_digest(rmac, _hmac8(key, tb, cid, length, payload)):
        raise ValueError('HMAC mismatch')
    return tb, cid, payload


def _encode_open(dst_addr, dst_port, atyp):
    if atyp == 0x01:
        return struct.pack('!BB', atyp, 4) + socket.inet_aton(dst_addr) + struct.pack('!H', dst_port)
    enc = dst_addr.encode()
    return struct.pack('!BB', atyp, len(enc)) + enc + struct.pack('!H', dst_port)


# ── Control channel multiplexer ──────────────────────────────────────────────
class ControlChannel:
    def __init__(self, sock, key):
        self.sock, self.key = sock, key
        self._channels = {}          # cid -> client socket
        self._pending  = {}          # cid -> Event
        self._pstatus  = {}          # cid -> bool
        self._nid      = 1
        self._lock     = threading.Lock()
        self._wlock    = threading.Lock()
        self.alive     = True

    def _send(self, tb, cid, payload=b''):
        frame = _encode(self.key, tb, cid, payload)
        with self._wlock:
            self.sock.sendall(frame)

    def open_channel(self, dst_addr, dst_port, atyp, client_sock):
        with self._lock:
            cid = self._nid; self._nid += 1
            ev  = threading.Event()
            self._pending[cid]  = ev
            self._pstatus[cid]  = False
            self._channels[cid] = client_sock
        self._send(CHAN_OPEN, cid, _encode_open(dst_addr, dst_port, atyp))
        if not ev.wait(10.0):
            with self._lock:
                self._pending.pop(cid, None)
                self._channels.pop(cid, None)
            return None
        ok = self._pstatus.pop(cid, False)
        if not ok:
            with self._lock: self._channels.pop(cid, None)
            return None
        return cid

    def close_channel(self, cid):
        with self._lock: sock = self._channels.pop(cid, None)
        if sock:
            try: self._send(CHAN_CLOSE, cid)
            except Exception: pass
            try: sock.close()
            except Exception: pass

    def send_data(self, cid, data):  self._send(CHAN_DATA, cid, data)

    def _deliver(self, cid, data):
        with self._lock: s = self._channels.get(cid)
        if s:
            try: s.sendall(data)
            except Exception: self.close_channel(cid)

    def reader_loop(self):
        try:
            while self.alive:
                tb, cid, payload = _recv_frame(self.sock, self.key)
                if   tb == CHAN_OPEN_OK:
                    with self._lock:
                        ev = self._pending.get(cid)
                        self._pstatus[cid] = True
                    if ev: ev.set()
                elif tb == CHAN_OPEN_ERR:
                    with self._lock:
                        ev = self._pending.get(cid)
                        self._pstatus[cid] = False
                        self._channels.pop(cid, None)
                    if ev: ev.set()
                elif tb == CHAN_DATA:  self._deliver(cid, payload)
                elif tb == CHAN_CLOSE:
                    with self._lock: s = self._channels.pop(cid, None)
                    if s:
                        try: s.close()
                        except Exception: pass
                elif tb == KEEPALIVE:
                    try: self._send(KEEPALIVE, 0)
                    except Exception: pass
        except Exception as e:
            print(f'[!] Control reader: {e}')
        finally:
            self.alive = False
            with self._lock:
                for s in self._channels.values():
                    try: s.close()
                    except Exception: pass
                self._channels.clear()
            for ev in self._pending.values(): ev.set()


# ── SOCKS5 helpers ───────────────────────────────────────────────────────────
def _s5_reply(sock, rep):
    try: sock.sendall(struct.pack('!BBBBIH', SOCKS5, rep, 0, 1, 0, 0))
    except Exception: pass


def _socks5_handshake(sock):
    hdr = sock.recv(2)
    if len(hdr) < 2 or hdr[0] != SOCKS5: return None
    sock.recv(hdr[1])  # discard methods
    sock.sendall(struct.pack('!BB', SOCKS5, 0x00))  # NO_AUTH
    req = sock.recv(4)
    if len(req) < 4 or req[0] != SOCKS5: return None
    _, cmd, _, atyp = struct.unpack('!BBBB', req)
    if atyp == 0x01:
        dst_addr = socket.inet_ntoa(sock.recv(4))
    elif atyp == 0x03:
        dst_addr = sock.recv(ord(sock.recv(1))).decode()
    elif atyp == 0x04:
        dst_addr = socket.inet_ntop(socket.AF_INET6, sock.recv(16))
    else:
        _s5_reply(sock, 0x08); return None
    dst_port = struct.unpack('!H', sock.recv(2))[0]
    if cmd != 0x01: _s5_reply(sock, 0x07); return None
    return dst_addr, dst_port, atyp


def _handle_client(client_sock, ctrl):
    try:
        result = _socks5_handshake(client_sock)
        if not result: client_sock.close(); return
        dst_addr, dst_port, atyp = result
        print(f'[>] CONNECT {dst_addr}:{dst_port}')
        if not ctrl.alive: _s5_reply(client_sock, 0x01); client_sock.close(); return
        cid = ctrl.open_channel(dst_addr, dst_port, atyp, client_sock)
        if cid is None: _s5_reply(client_sock, 0x04); client_sock.close(); return
        _s5_reply(client_sock, 0x00)
        client_sock.setblocking(True)
        try:
            while ctrl.alive:
                data = client_sock.recv(65536)
                if not data: break
                ctrl.send_data(cid, data)
        except Exception: pass
        finally: ctrl.close_channel(cid)
    except Exception as e:
        print(f'[!] Client error: {e}')
        try: client_sock.close()
        except Exception: pass


# ── Auth ─────────────────────────────────────────────────────────────────────
def _auth_agent(sock, key):
    try:
        tb, _, payload = _recv_frame(sock, key)
        if tb != HELLO or len(payload) < 8:
            sock.sendall(_encode(key, HELLO_ERR, 0, b'bad'))
            return False
        ts = struct.unpack('!Q', payload[:8])[0]
        if abs(int(time.time()) - ts) > 60:
            sock.sendall(_encode(key, HELLO_ERR, 0, b'replay'))
            return False
        sock.sendall(_encode(key, HELLO_OK, 0, b'ok'))
        return True
    except Exception:
        return False


# ── Main ─────────────────────────────────────────────────────────────────────
def run(ctrl_host, ctrl_port, socks_host, socks_port, password):
    key = _derive_key(password)
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((ctrl_host, ctrl_port))
    srv.listen(1)
    print(f'[*] Waiting for agent on {ctrl_host}:{ctrl_port}...')

    while True:
        agent_sock, addr = srv.accept()
        agent_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        print(f'[+] Agent from {addr[0]}:{addr[1]}')
        if not _auth_agent(agent_sock, key):
            print('[-] Auth failed'); agent_sock.close(); continue
        print(f'[+] Auth OK — SOCKS5 on {socks_host}:{socks_port}')

        ctrl = ControlChannel(agent_sock, key)
        threading.Thread(target=ctrl.reader_loop, daemon=True).start()

        ss = socket.socket()
        ss.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        ss.bind((socks_host, socks_port))
        ss.listen(128)
        ss.settimeout(1.0)

        while ctrl.alive:
            try:
                cs, _ = ss.accept()
                cs.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                threading.Thread(target=_handle_client, args=(cs, ctrl), daemon=True).start()
            except socket.timeout: continue
            except Exception as e:
                if ctrl.alive: print(f'[!] Accept: {e}')
                break

        ss.close()
        print('[-] Agent gone. Waiting...')


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--control', default='0.0.0.0:4433')
    p.add_argument('--socks',   default='127.0.0.1:1080')
    p.add_argument('--pass',    dest='password', required=True)
    a = p.parse_args()
    ch, cp = a.control.rsplit(':', 1)
    sh, sp = a.socks.rsplit(':', 1)
    run(ch, int(cp), sh, int(sp), a.password)
