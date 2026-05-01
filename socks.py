#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from twisted.internet import reactor, endpoints
from twisted.internet.protocol import Protocol, Factory, ClientFactory, DatagramProtocol
from twisted.python import log

import struct
import socket
import sys
from enum import Enum
from typing import Optional


SOCKS5_VERSION = 5
NO_AUTH = 0

CMD_CONNECT = 1
CMD_UDP_ASSOCIATE = 3

ATYP_IPV4 = 1
ATYP_DOMAIN = 3
ATYP_IPV6 = 4

REP_SUCCESS = 0
REP_GENERAL_FAILURE = 1
REP_HOST_UNREACHABLE = 4
REP_CONNECTION_REFUSED = 5


class ConnState(Enum):
    INIT = 0
    READY = 1
    RELAY = 2
    UDP = 3


def build_reply(rep, addr="0.0.0.0", port=0):
    try:
        packed = socket.inet_aton(addr)
        atyp = ATYP_IPV4
    except OSError:
        packed = socket.inet_pton(socket.AF_INET6, addr)
        atyp = ATYP_IPV6

    return struct.pack("!BBBB", SOCKS5_VERSION, rep, 0, atyp) + packed + struct.pack("!H", port)


# =========================
# UDP RELAY
# =========================

class UDPRelay(DatagramProtocol):
    def __init__(self):
        self.client_addr = None

    def datagramReceived(self, data, addr):
        if self.client_addr is None:
            self.client_addr = addr
            log.msg(f"[UDP] client {addr}")

        if addr == self.client_addr:
            self.handle_client(data)
        else:
            self.handle_remote(data, addr)

    def handle_client(self, data):
        try:
            rsv, frag, atyp = struct.unpack("!HBB", data[:4])
            if frag != 0:
                return

            offset = 4

            if atyp == ATYP_IPV4:
                dst = socket.inet_ntoa(data[offset:offset+4])
                offset += 4

            elif atyp == ATYP_DOMAIN:
                ln = data[offset]
                offset += 1
                dst = data[offset:offset+ln].decode()
                offset += ln

            elif atyp == ATYP_IPV6:
                dst = socket.inet_ntop(socket.AF_INET6, data[offset:offset+16])
                offset += 16

            else:
                return

            port = struct.unpack("!H", data[offset:offset+2])[0]
            payload = data[offset+2:]

            self.transport.write(payload, (dst, port))

        except Exception as e:
            log.msg(f"[UDP] error {e}")

    def handle_remote(self, data, addr):
        try:
            try:
                addr_bytes = socket.inet_aton(addr[0])
                atyp = ATYP_IPV4
            except:
                addr_bytes = socket.inet_pton(socket.AF_INET6, addr[0])
                atyp = ATYP_IPV6

            header = struct.pack("!HBB", 0, 0, atyp)
            header += addr_bytes
            header += struct.pack("!H", addr[1])

            packet = header + data
            self.transport.write(packet, self.client_addr)

        except Exception as e:
            log.msg(f"[UDP] error {e}")


# =========================
# MAIN SERVER
# =========================

class SOCKS5Server(Protocol):

    def __init__(self):
        self.state = ConnState.INIT
        self.buffer = b''
        self.remote: Optional[Protocol] = None
        self.udp_port = None

    def connectionMade(self):
        peer = self.transport.getPeer()
        log.msg(f"[+] {peer.host}:{peer.port}")

    def dataReceived(self, data):
        self.buffer += data

        while True:
            if self.state == ConnState.INIT:
                if not self.handle_greeting():
                    break

            elif self.state == ConnState.READY:
                if not self.handle_request():
                    break

            elif self.state == ConnState.RELAY:
                if self.remote:
                    self.remote.transport.write(self.buffer)
                    self.buffer = b''
                break

            else:
                break

    # =====================
    # HANDSHAKE
    # =====================

    def handle_greeting(self):
        if len(self.buffer) < 2:
            return False

        ver, nmethods = struct.unpack("!BB", self.buffer[:2])

        if len(self.buffer) < 2 + nmethods:
            return False

        methods = self.buffer[2:2+nmethods]
        self.buffer = self.buffer[2+nmethods:]

        if NO_AUTH in methods:
            self.transport.write(struct.pack("!BB", SOCKS5_VERSION, NO_AUTH))
            self.state = ConnState.READY
            return True

        self.transport.write(struct.pack("!BB", SOCKS5_VERSION, 0xFF))
        self.transport.loseConnection()
        return False

    # =====================
    # REQUEST
    # =====================

    def handle_request(self):
        if len(self.buffer) < 7:
            return False

        try:
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

            elif atyp == ATYP_IPV6:
                addr = socket.inet_ntop(socket.AF_INET6, self.buffer[offset:offset+16])
                offset += 16

            else:
                raise Exception()

            port = struct.unpack("!H", self.buffer[offset:offset+2])[0]

        except Exception:
            self.transport.write(build_reply(REP_GENERAL_FAILURE))
            self.transport.loseConnection()
            return False

        self.buffer = b''

        if cmd == CMD_CONNECT:
            reactor.connectTCP(addr, port, RemoteFactory(self))

        elif cmd == CMD_UDP_ASSOCIATE:
            self.start_udp()

        else:
            self.transport.write(build_reply(REP_GENERAL_FAILURE))

        return True

    # =====================
    # UDP SUPPORT
    # =====================

    def start_udp(self):
        relay = UDPRelay()
        port = reactor.listenUDP(0, relay)
        udp_port = port.getHost().port

        log.msg(f"[UDP] listening {udp_port}")

        self.transport.write(build_reply(REP_SUCCESS, "0.0.0.0", udp_port))
        self.state = ConnState.UDP

    # =====================
    # TCP RELAY
    # =====================

    def start_relay(self, remote):
        self.remote = remote
        self.state = ConnState.RELAY

        peer = remote.getPeer()
        self.transport.write(build_reply(REP_SUCCESS, peer.host, peer.port))

    def connectionLost(self, reason):
        if self.remote:
            self.remote.loseConnection()


# =====================
# REMOTE
# =====================

class RemoteFactory(ClientFactory):
    def __init__(self, server):
        self.server = server

    def buildProtocol(self, addr):
        return RemoteClient(self.server)

    def clientConnectionFailed(self, connector, reason):
        self.server.transport.write(build_reply(REP_CONNECTION_REFUSED))
        self.server.transport.loseConnection()


class RemoteClient(Protocol):
    def __init__(self, server):
        self.server = server

    def connectionMade(self):
        self.server.start_relay(self.transport)

    def dataReceived(self, data):
        if self.server.transport.connected:
            self.server.transport.write(data)

    def connectionLost(self, reason):
        if self.server.transport.connected:
            self.server.transport.loseConnection()


# =====================
# FACTORY
# =====================

class SOCKSFactory(Factory):
    def buildProtocol(self, addr):
        return SOCKS5Server()


# =====================
# MAIN
# =====================

def main():
    log.startLogging(sys.stdout)

    port = 1080
    endpoint = endpoints.TCP4ServerEndpoint(reactor, port)

    log.msg(f"SOCKS5 + UDP running on :{port}")

    endpoint.listen(SOCKSFactory())
    reactor.run()


if __name__ == "__main__":
    main()
