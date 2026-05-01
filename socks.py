#!/usr/bin/env python3

from twisted.internet import reactor, protocol
from twisted.internet.protocol import Protocol, Factory, DatagramProtocol
from twisted.python import log

import struct
import socket
import sys
import time

# SOCKS5 constants
SOCKS5_VERSION = 5
NO_AUTH = 0
CMD_CONNECT = 1
CMD_UDP_ASSOCIATE = 3

ATYP_IPV4 = 1
ATYP_DOMAIN = 3
ATYP_IPV6 = 4

REP_SUCCESS = 0
REP_FAIL = 1


# ================= UDP RELAY =================

class UDPRelay(DatagramProtocol):
    def __init__(self):
        self.client_addr = None
        self.nat = {}  # (ip, port) -> client

    def datagramReceived(self, data, addr):
        try:
            if self.client_addr is None:
                self.client_addr = addr
                log.msg(f"[UDP] Client: {addr}")

            if addr == self.client_addr:
                self.from_client(data)
            else:
                self.from_remote(data, addr)

        except Exception as e:
            log.msg(f"[UDP ERROR] {e}")

    def from_client(self, data):
        if len(data) < 10:
            return

        rsv, frag, atyp = struct.unpack("!HBB", data[:4])
        if frag != 0:
            return

        offset = 4

        if atyp == ATYP_IPV4:
            dst_addr = socket.inet_ntoa(data[offset:offset+4])
            offset += 4
        elif atyp == ATYP_DOMAIN:
            ln = data[offset]
            offset += 1
            dst_addr = data[offset:offset+ln].decode()
            offset += ln
        elif atyp == ATYP_IPV6:
            dst_addr = socket.inet_ntop(socket.AF_INET6, data[offset:offset+16])
            offset += 16
        else:
            return

        dst_port = struct.unpack("!H", data[offset:offset+2])[0]
        payload = data[offset+2:]

        # NAT
        self.nat[(dst_addr, dst_port)] = self.client_addr

        self.transport.write(payload, (dst_addr, dst_port))
        log.msg(f"[UDP] → {dst_addr}:{dst_port} ({len(payload)}B)")

    def from_remote(self, data, addr):
        client = self.nat.get(addr)

        if not client:
            log.msg(f"[UDP] Unknown remote {addr}")
            return

        try:
            addr_bytes = socket.inet_aton(addr[0])
            atyp = ATYP_IPV4
        except:
            atyp = ATYP_DOMAIN
            addr_bytes = bytes([len(addr[0])]) + addr[0].encode()

        header = struct.pack("!HBB", 0, 0, atyp)
        header += addr_bytes
        header += struct.pack("!H", addr[1])

        self.transport.write(header + data, client)
        log.msg(f"[UDP] ← {addr}")


# ================= TCP =================

class Remote(Protocol):
    def __init__(self, client):
        self.client = client

    def connectionMade(self):
        self.client.transport.write(self.client.reply_success())
        log.msg("[TCP] Connected")

    def dataReceived(self, data):
        self.client.transport.write(data)

    def connectionLost(self, reason):
        self.client.transport.loseConnection()


class SOCKS5(Protocol):
    def __init__(self):
        self.state = 0
        self.buffer = b''
        self.remote = None

    def dataReceived(self, data):
        self.buffer += data

        if self.state == 0:
            if len(self.buffer) < 2:
                return
            self.transport.write(struct.pack("!BB", 5, 0))
            self.buffer = b''
            self.state = 1

        elif self.state == 1:
            if len(self.buffer) < 7:
                return

            ver, cmd, _, atyp = struct.unpack("!BBBB", self.buffer[:4])
            offset = 4

            if atyp == ATYP_IPV4:
                addr = socket.inet_ntoa(self.buffer[offset:offset+4])
                offset += 4
            elif atyp == ATYP_DOMAIN:
                ln = self.buffer[offset]
                offset += 1
                addr = self.buffer[offset:offset+ln].decode()
                offset += ln
            else:
                return

            port = struct.unpack("!H", self.buffer[offset:offset+2])[0]

            log.msg(f"[REQ] {addr}:{port}")

            if cmd == CMD_CONNECT:
                self.connect(addr, port)

            elif cmd == CMD_UDP_ASSOCIATE:
                self.udp_associate()

            self.buffer = b''

    def connect(self, host, port):
        factory = protocol.ClientFactory()

        def build(_):
            return Remote(self)

        factory.buildProtocol = build

        reactor.connectTCP(host, port, factory)

    def udp_associate(self):
        relay = UDPRelay()
        port = reactor.listenUDP(0, relay)
        p = port.getHost().port

        log.msg(f"[UDP] Started on {p}")

        self.transport.write(self.reply_success("0.0.0.0", p))

    def reply_success(self, host="0.0.0.0", port=0):
        return struct.pack("!BBBB", 5, 0, 0, 1) + socket.inet_aton(host) + struct.pack("!H", port)


class SOCKSFactory(Factory):
    def buildProtocol(self, addr):
        log.msg(f"[NEW] {addr.host}:{addr.port}")
        return SOCKS5()


# ================= MAIN =================

if __name__ == "__main__":
    log.startLogging(sys.stdout)

    PORT = 1080

    reactor.listenTCP(PORT, SOCKSFactory())

    log.msg("="*50)
    log.msg("SOCKS5 + UDP (iSH READY)")
    log.msg(f"PORT: {PORT}")
    log.msg("Supports Discord / TeamSpeak")
    log.msg("="*50)

    reactor.run()
