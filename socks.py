#!/usr/bin/env python3

from twisted.internet import reactor, protocol
from twisted.internet.protocol import Protocol, Factory, DatagramProtocol
from twisted.python import log

import struct
import socket
import sys

SOCKS5_VERSION = 5
NO_AUTH = 0
CMD_CONNECT = 1
CMD_UDP_ASSOCIATE = 3

ATYP_IPV4 = 1
ATYP_DOMAIN = 3

# ================= UDP =================

class UDPRelay(DatagramProtocol):
    def __init__(self):
        self.client_addr = None
        self.nat = {}

    def datagramReceived(self, data, addr):
        try:
            if self.client_addr is None:
                self.client_addr = addr
                log.msg(f"[UDP] Client: {addr}")

            if addr == self.client_addr:
                self.handle_client(data)
            else:
                self.handle_remote(data, addr)

        except Exception as e:
            log.msg(f"[UDP ERROR] {e}")

    def handle_client(self, data):
        if len(data) < 10:
            return

        _, frag, atyp = struct.unpack("!HBB", data[:4])
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
        else:
            return

        dst_port = struct.unpack("!H", data[offset:offset+2])[0]
        payload = data[offset+2:]

        self.nat[(dst_addr, dst_port)] = self.client_addr
        self.transport.write(payload, (dst_addr, dst_port))

        log.msg(f"[UDP] → {dst_addr}:{dst_port}")

    def handle_remote(self, data, addr):
        client = self.nat.get(addr)
        if not client:
            return

        addr_bytes = socket.inet_aton(addr[0])
        header = struct.pack("!HBB", 0, 0, 1) + addr_bytes + struct.pack("!H", addr[1])

        self.transport.write(header + data, client)
        log.msg(f"[UDP] ← {addr}")


# ================= TCP =================

class Remote(Protocol):
    def __init__(self, client):
        self.client = client

    def connectionMade(self):
        self.client.transport.write(self.client.reply())
        log.msg("[TCP] Connected")

    def dataReceived(self, data):
        self.client.transport.write(data)

    def connectionLost(self, reason):
        self.client.transport.loseConnection()


class SOCKS5(Protocol):
    def __init__(self):
        self.state = 0
        self.buffer = b''

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

            _, cmd, _, atyp = struct.unpack("!BBBB", self.buffer[:4])
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
                self.udp()

            self.buffer = b''

    def connect(self, host, port):
        factory = protocol.ClientFactory()

        def build(_):
            return Remote(self)

        factory.buildProtocol = build

        reactor.connectTCP(host, port, factory)

    def udp(self):
        relay = UDPRelay()
        port = reactor.listenUDP(0, relay)
        p = port.getHost().port

        log.msg(f"[UDP] START {p}")

        self.transport.write(self.reply("0.0.0.0", p))

    def reply(self, host="0.0.0.0", port=0):
        return struct.pack("!BBBB", 5, 0, 0, 1) + socket.inet_aton(host) + struct.pack("!H", port)


class SOCKSFactory(Factory):
    def buildProtocol(self, addr):
        log.msg(f"[NEW] {addr.host}:{addr.port}")
        return SOCKS5()


# ================= MAIN =================

def start_server(port):
    try:
        reactor.listenTCP(port, SOCKSFactory())
        return port
    except:
        return None


if __name__ == "__main__":
    log.startLogging(sys.stdout)

    ports = [1098, 1081, 1082, 1083]

    used_port = None
    for p in ports:
        if start_server(p):
            used_port = p
            break

    if not used_port:
        log.msg("❌ No free ports!")
        sys.exit(1)

    log.msg("="*50)
    log.msg("SOCKS5 + UDP (FIXED iSH)")
    log.msg(f"PORT: {used_port}")
    log.msg("="*50)

    reactor.run()
