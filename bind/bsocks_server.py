#!/usr/bin/env python3
"""
SOCKS5 Server with USERNAME/PASSWORD authentication
Based on RFC 1928 and RFC 1929

Fully fixed for YouTube streaming:
- Fixed dst_port tuple unpacking bug.
- Optimised with high-bandwidth blocking dual-thread relay.
- Properly handles HTTPS and forces TCP fallback for UDP/QUIC streams.
"""
import sys
import hmac
import socket
import struct
import threading
from socketserver import ThreadingMixIn, TCPServer, StreamRequestHandler

SOCKS_VERSION = 5
#PROXY_USER = 'proxyadmin'
#PROXY_PASS = 'securepassword123'
PROXY_USER = sys.argv[1]
PROXY_PASS = sys.argv[2]

class ThreadingTCPServer(ThreadingMixIn, TCPServer):
    daemon_threads = True
    allow_reuse_address = True

class SocksProxy(StreamRequestHandler):

    def handle(self):
        try:
            # --- Phase 1: Greeting ---
            header = self.connection.recv(2)
            if len(header) < 2:
                return
            version, nmethods = struct.unpack('!BB', header)

            if version != SOCKS_VERSION:
                return

            # Read supported methods from client
            methods = [ord(self.connection.recv(1)) for _ in range(nmethods)]

            # We only accept USERNAME/PASSWORD (0x02)
            if 2 not in methods:
                # Tell client no acceptable method, close
                self.connection.sendall(struct.pack('!BB', SOCKS_VERSION, 0xFF))
                return

            # Respond: use method 0x02
            self.connection.sendall(struct.pack('!BB', SOCKS_VERSION, 0x02))

            # --- Phase 2: Authentication (RFC 1929) ---
            if not self._authenticate():
                return

            # --- Phase 3: Connection Request ---
            req_header = self.connection.recv(4)
            if len(req_header) < 4:
                return
            version, cmd, _, atyp = struct.unpack('!BBBB', req_header)

            if version != SOCKS_VERSION:
                return

            # Parse destination address
            if atyp == 0x01:  # IPv4
                dst_addr = socket.inet_ntoa(self.connection.recv(4))
            elif atyp == 0x03:  # Domain name
                domain_len_bytes = self.connection.recv(1)
                if not domain_len_bytes:
                    return
                domain_len = ord(domain_len_bytes)
                dst_addr = self.connection.recv(domain_len).decode('utf-8')
            elif atyp == 0x04:  # IPv6
                dst_addr = socket.inet_ntop(socket.AF_INET6, self.connection.recv(16))
            else:
                self._send_reply(0x08)  # Address type not supported
                return

            port_bytes = self.connection.recv(2)
            if len(port_bytes) < 2:
                return
            # FIX: Extracted [0] to get integer instead of a tuple tuple (e.g. 443 instead of (443,))
            dst_port = struct.unpack('!H', port_bytes)[0]

            if cmd == 0x01:  # CONNECT
                self._handle_connect(dst_addr, dst_port, atyp)
            else:
                # Explicitly decline BIND and UDP ASSOCIATE (0x07: Command not supported)
                # Forces browsers (like Chrome) to instantly fall back from QUIC to HTTPS/TCP.
                self._send_reply(0x07)
        except Exception as e:
            print(f'[!] Request error from {self.client_address}: {e}')

    def _authenticate(self):
        """RFC 1929 Username/Password sub-negotiation"""
        try:
            ver_bytes = self.connection.recv(1)
            if not ver_bytes:
                return False
            version = ord(ver_bytes)
            if version != 1:
                return False

            ulen_bytes = self.connection.recv(1)
            if not ulen_bytes:
                return False
            ulen = ord(ulen_bytes)
            username = self.connection.recv(ulen).decode('utf-8')

            plen_bytes = self.connection.recv(1)
            if not plen_bytes:
                return False
            plen = ord(plen_bytes)
            password = self.connection.recv(plen).decode('utf-8')

            # Constant-time comparison to prevent timing attacks
            if (hmac.compare_digest(username, PROXY_USER) and
                    hmac.compare_digest(password, PROXY_PASS)):
                self.connection.sendall(struct.pack('!BB', 1, 0x00))  # Success
                print(f'[+] Auth OK for user: {username} from {self.client_address}')
                return True
            else:
                self.connection.sendall(struct.pack('!BB', 1, 0xFF))  # Failure
                print(f'[-] Auth FAILED for user: {username} from {self.client_address}')
                return False
        except Exception:
            return False

    def _handle_connect(self, dst_addr, dst_port, atyp):
        """Establish upstream connection and relay data"""
        print(f'[*] CONNECT {dst_addr}:{dst_port} from {self.client_address}')
        try:
            # Resolved via OS routing, handles HTTPS properly
            remote = socket.create_connection((dst_addr, dst_port), timeout=10)
            bind_addr, bind_port = remote.getsockname()

            # Generate standard SOCKS5 success reply
            if remote.family == socket.AF_INET:
                reply = struct.pack(
                    '!BBBBIH',
                    SOCKS_VERSION, 0x00, 0x00, 0x01,
                    struct.unpack('!I', socket.inet_aton(bind_addr))[0],
                    bind_port
                )
            else:
                # IPv6 response template fallback if required
                reply = struct.pack(
                    '!BBBBIH', SOCKS_VERSION, 0x00, 0x00, 0x01, 0, 0
                )

            self.connection.sendall(reply)

            # Relay data bidirectionally
            self._relay(self.connection, remote)

        except socket.timeout:
            self._send_reply(0x04)  # Host unreachable
        except ConnectionRefusedError:
            self._send_reply(0x05)  # Connection refused
        except Exception as e:
            print(f'[!] Connection Error to {dst_addr}:{dst_port} -> {e}')
            self._send_reply(0x01)  # General failure

    def _relay(self, client, remote):
        """
        Bidirectional data relay using two blocking threads.
        Leverages OS TCP window size for automatic backpressure.
        """
        client.setblocking(True)
        remote.setblocking(True)

        def forward(src, dst):
            try:
                while True:
                    # 64KB buffer size optimized for high-throughput streaming
                    data = src.recv(65536)
                    if not data:
                        break
                    dst.sendall(data)
            except Exception:
                pass
            finally:
                try: src.close()
                except Exception: pass
                try: dst.close()
                except Exception: pass

        # Downstream Thread: Remote -> Client (Crucial for streaming download performance)
        downstream_thread = threading.Thread(target=forward, args=(remote, client))
        downstream_thread.daemon = True
        downstream_thread.start()

        # Upstream Thread: Client -> Remote (Handles requests/ACKs in main request context)
        forward(client, remote)

    def _send_reply(self, rep_code):
        try:
            reply = struct.pack(
                '!BBBBIH',
                SOCKS_VERSION, rep_code, 0x00, 0x01, 0, 0
            )
            self.connection.sendall(reply)
        except Exception:
            pass

if __name__ == '__main__':
    HOST = sys.argv[3]
    PORT = int(sys.argv[4])

    print(f'[*] SOCKS5 proxy listening on {HOST}:{PORT}')
    with ThreadingTCPServer((HOST, PORT), SocksProxy) as server:
        server.serve_forever()
