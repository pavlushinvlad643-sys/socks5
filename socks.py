#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Improved SOCKS5 Proxy Server (clean architecture version)
- safer buffer handling
- cleaner state machine
- better logging
- typing support
"""

from twisted.internet import reactor, protocol, endpoints
from twisted.internet.protocol import Protocol, Factory, ClientFactory
from twisted.python import log

import struct
import socket
import sys
import time
from enum import Enum
from typing import Optional, Dict, Tuple


# =====================
# CONSTANTS
# =====================

SOCKS5_VERSION = 5

NO_AUTH = 0
USER_PASS_AUTH = 2

CMD_CONNECT = 1

ATYP_IPV4 = 1
ATYP_DOMAIN = 3
ATYP_IPV6 = 4

REP_SUCCESS = 0
REP_GENERAL_FAILURE = 1
REP_HOST_UNREACHABLE = 4
REP_CONNECTION_REFUSED = 5


# =====================
# STATE MACHINE
# =====================

class ConnState(Enum):
    INIT = 0
    AUTH = 1
    READY = 2
    RELAY = 3


# =====================
# DNS CACHE
# =====================

class DNSCache:
    def __init__(self, ttl: int = 300):
        self.cache: Dict[str, Tuple[str, float]] = {}
        self.ttl = ttl

    def get(self, host: str) -> Optional[str]:
        entry = self.cache.get(host)
        if not entry:
            return None

        ip, ts = entry
        if time.time() - ts > self.ttl:
            del self.cache[host]
            return None

        return ip

    def set(self, host: str, ip: str):
        self.cache[host] = (ip, time.time())


# =====================
# PARSER
# =====================

class SocksRequest:
    def __init__(self, cmd: int, addr: str, port: int):
        self.cmd = cmd
        self.addr = addr
        self.port = port


def parse_request(data: bytes) -> SocksRequest:
    if len(data) < 7:
        raise ValueError("Packet too short")

    version, cmd, _, atyp = struct.unpack("!BBBB", data[:4])
    offset = 4

    if version != SOCKS5_VERSION:
        raise ValueError("Invalid version")

    if atyp == ATYP_IPV4:
        addr = socket.inet_ntoa(data[offset:offset+4])
        offset += 4

    elif atyp == ATYP_DOMAIN:
        ln = data[offset]
        offset += 1
        addr = data[offset:offset+ln].decode()
        offset += ln

    elif atyp == ATYP_IPV6:
        addr = socket.inet_ntop(socket.AF_INET6, data[offset:offset+16])
        offset += 16

    else:
        raise ValueError("Unsupported ATYP")

    port = struct.unpack("!H", data[offset:offset+2])[0]

    return SocksRequest(cmd, addr, port)


def build_reply(rep: int, addr="0.0.0.0", port=0) -> bytes:
    try:
        packed = socket.inet_aton(addr)
        atyp = ATYP_IPV4
    except OSError:
        packed = socket.inet_pton(socket.AF_INET6, addr)
        atyp = ATYP_IPV6

    return struct.pack("!BBBB", SOCKS5_VERSION, rep, 0, atyp) + packed + struct.pack("!H", port)


# =====================
# MAIN PROTOCOL
# =====================

class SOCKS5Server(Protocol):

    def __init__(self, dns_cache: DNSCache):
        self.state = ConnState.INIT
        self.buffer = b''
        self.remote: Optional[Protocol] = None
        self.dns_cache = dns_cache

    def connectionMade(self):
        peer = self.transport.getPeer()
        log.msg(f"[+] Client {peer.host}:{peer.port}")

        try:
            sock = self.transport.getHandle()
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except Exception as e:
            log.msg(f"[WARN] sockopt: {e}")

    def dataReceived(self, data: bytes):
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
    # HANDLERS
    # =====================

    def handle_greeting(self) -> bool:
        if len(self.buffer) < 2:
            return False

        version, nmethods = struct.unpack("!BB", self.buffer[:2])

        if len(self.buffer) < 2 + nmethods:
            return False

        methods = self.buffer[2:2+nmethods]
        self.buffer = self.buffer[2+nmethods:]

        if NO_AUTH in methods:
            self.transport.write(struct.pack("!BB", SOCKS5_VERSION, NO_AUTH))
            self.state = ConnState.READY
        else:
            self.transport.loseConnection()

        return True

    def handle_request(self) -> bool:
        if len(self.buffer) < 7:
            return False

        try:
            req = parse_request(self.buffer)
        except Exception as e:
            log.msg(f"[ERROR] parse: {e}")
            self.transport.write(build_reply(REP_GENERAL_FAILURE))
            self.transport.loseConnection()
            return False

        self.buffer = b''

        log.msg(f"[REQ] {req.addr}:{req.port}")

        self.resolve_and_connect(req)
        return True

    # =====================
    # CONNECT
    # =====================

    def resolve_and_connect(self, req: SocksRequest):
        if self.is_ip(req.addr):
            self.connect(req.addr, req.port)
            return

        cached = self.dns_cache.get(req.addr)
        if cached:
            self.connect(cached, req.port)
            return

        def resolved(ip):
            self.dns_cache.set(req.addr, ip)
            self.connect(ip, req.port)

        d = reactor.resolve(req.addr)
        d.addCallback(resolved)
        d.addErrback(lambda _: self.fail())

    def connect(self, host: str, port: int):
        factory = RemoteFactory(self)
        reactor.connectTCP(host, port, factory)

    def fail(self):
        self.transport.write(build_reply(REP_HOST_UNREACHABLE))
        self.transport.loseConnection()

    @staticmethod
    def is_ip(addr: str) -> bool:
        try:
            socket.inet_aton(addr)
            return True
        except OSError:
            return False

    def start_relay(self, remote):
        self.remote = remote
        self.state = ConnState.RELAY

        peer = remote.getPeer()
        self.transport.write(build_reply(REP_SUCCESS, peer.host, peer.port))
        log.msg(f"[OK] Connected {peer.host}:{peer.port}")

    def connectionLost(self, reason):
        if self.remote:
            self.remote.loseConnection()


# =====================
# REMOTE SIDE
# =====================

class RemoteFactory(ClientFactory):
    def __init__(self, server: SOCKS5Server):
        self.server = server

    def buildProtocol(self, addr):
        return RemoteClient(self.server)

    def clientConnectionFailed(self, connector, reason):
        self.server.transport.write(build_reply(REP_CONNECTION_REFUSED))
        self.server.transport.loseConnection()


class RemoteClient(Protocol):
    def __init__(self, server: SOCKS5Server):
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
    def __init__(self):
        self.dns_cache = DNSCache()

    def buildProtocol(self, addr):
        return SOCKS5Server(self.dns_cache)


# =====================
# MAIN
# =====================

def main():
    log.startLogging(sys.stdout)

    port = 1080
    endpoint = endpoints.TCP4ServerEndpoint(reactor, port)

    log.msg(f"🚀 SOCKS5 running on :{port}")

    endpoint.listen(SOCKSFactory())
    reactor.run()


if __name__ == "__main__":
    main()
