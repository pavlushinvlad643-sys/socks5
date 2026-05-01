#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from twisted.internet import reactor, endpoints
from twisted.internet.protocol import Protocol, Factory, ClientFactory
from twisted.python import log

import struct
import socket
import sys
from enum import Enum
from typing import Optional


SOCKS5_VERSION = 5
NO_AUTH = 0

CMD_CONNECT = 1

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


def build_reply(rep, addr="0.0.0.0", port=0):
    try:
        packed = socket.inet_aton(addr)
        atyp = ATYP_IPV4
    except OSError:
        packed = socket.inet_pton(socket.AF_INET6, addr)
        atyp = ATYP_IPV6

    return struct.pack("!BBBB", SOCKS5_VERSION, rep, 0, atyp) + packed + struct.pack("!H", port)


class SOCKS5Server(Protocol):

    def __init__(self):
        self.state = ConnState.INIT
        self.buffer = b''
        self.remote: Optional[Protocol] = None

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
    # FIXED HANDSHAKE
    # =====================

    def handle_greeting(self):
        if len(self.buffer) < 2:
            return False

        version, nmethods = struct.unpack("!BB", self.buffer[:2])

        if len(self.buffer) < 2 + nmethods:
            return False

        methods = self.buffer[2:2 + nmethods]
        self.buffer = self.buffer[2 + nmethods:]

        if version != SOCKS5_VERSION:
            self.transport.loseConnection()
            return False

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
            version, cmd, _, atyp = struct.unpack("!BBBB", self.buffer[:4])
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

        log.msg(f"[REQ] {addr}:{port}")

        reactor.connectTCP(addr, port, RemoteFactory(self))
        return True

    def start_relay(self, remote):
        self.remote = remote
        self.state = ConnState.RELAY

        peer = remote.getPeer()
        self.transport.write(build_reply(REP_SUCCESS, peer.host, peer.port))

    def connectionLost(self, reason):
        if self.remote:
            self.remote.loseConnection()


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


class SOCKSFactory(Factory):
    def buildProtocol(self, addr):
        return SOCKS5Server()


def main():
    log.startLogging(sys.stdout)

    port = 1080
    endpoint = endpoints.TCP4ServerEndpoint(reactor, port)

    log.msg(f"SOCKS5 running on :{port}")

    endpoint.listen(SOCKSFactory())
    reactor.run()


if __name__ == "__main__":
    main()
