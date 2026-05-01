#!/usr/bin/env python3

from twisted.internet import reactor
from twisted.internet.protocol import Protocol, Factory, DatagramProtocol, ClientFactory
import struct
import socket

SOCKS5_VERSION = 0x05
NO_AUTH = 0x00

CMD_CONNECT = 0x01
CMD_UDP_ASSOCIATE = 0x03

ATYP_IPV4 = 0x01
ATYP_DOMAIN = 0x03

REP_SUCCESS = 0x00
REP_GENERAL_FAILURE = 0x01
REP_COMMAND_NOT_SUPPORTED = 0x07


# ================= TCP =================

class RemoteProtocol(Protocol):
    def connectionMade(self):
        self.factory.client.remote = self.transport
        self.factory.client.send_reply(REP_SUCCESS)

    def dataReceived(self, data):
        self.factory.client.transport.write(data)

    def connectionLost(self, reason):
        if self.factory.client.transport.connected:
            self.factory.client.transport.loseConnection()


class RemoteFactory(ClientFactory):
    def __init__(self, client):
        self.client = client

    def buildProtocol(self, addr):
        p = RemoteProtocol()
        p.factory = self
        return p

    def clientConnectionFailed(self, connector, reason):
        self.client.send_reply(REP_GENERAL_FAILURE)
        self.client.transport.loseConnection()


# ================= UDP =================

class UDPRelay(DatagramProtocol):
    def __init__(self):
        self.client = None

    def datagramReceived(self, data, addr):
        try:
            if self.client is None:
                self.client = addr

            if addr == self.client:
                # from client
                rsv, frag, atyp = struct.unpack("!HBB", data[:4])
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

                self.transport.write(payload, (dst_addr, dst_port))

            else:
                # from remote
                addr_bytes = socket.inet_aton(addr[0])

                header = struct.pack("!HBB", 0, 0, ATYP_IPV4)
                header += addr_bytes
                header += struct.pack("!H", addr[1])

                self.transport.write(header + data, self.client)

        except Exception as e:
            print("[UDP ERROR]", e)


# ================= SOCKS =================

class SOCKS5(Protocol):

    def connectionMade(self):
        self.state = 0
        self.buffer = b""

    def dataReceived(self, data):
        self.buffer += data

        if self.state == 0:
            if len(self.buffer) < 3:
                return

            self.transport.write(struct.pack("!BB", SOCKS5_VERSION, NO_AUTH))
            self.buffer = b""
            self.state = 1

        elif self.state == 1:
            if len(self.buffer) < 10:
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
                self.send_reply(REP_COMMAND_NOT_SUPPORTED)
                return

            port = struct.unpack("!H", self.buffer[offset:offset+2])[0]

            if cmd == CMD_CONNECT:
                reactor.connectTCP(addr, port, RemoteFactory(self))

            elif cmd == CMD_UDP_ASSOCIATE:
                self.handle_udp()

            else:
                self.send_reply(REP_COMMAND_NOT_SUPPORTED)

            self.buffer = b""

    def handle_udp(self):
        try:
            self.udp = UDPRelay()
            port = reactor.listenUDP(0, self.udp)
            udp_port = port.getHost().port

            # ВАЖНО: возвращаем IP клиента
            host = self.transport.getHost().host

            self.send_reply(REP_SUCCESS, host, udp_port)

            print("[UDP OK]", host, udp_port)

        except Exception as e:
            print("[UDP FAIL]", e)
            self.send_reply(REP_GENERAL_FAILURE)

    def send_reply(self, rep, addr="0.0.0.0", port=0):
        try:
            ip = socket.inet_aton(addr)
        except:
            return

        reply = struct.pack("!BBBB", SOCKS5_VERSION, rep, 0, ATYP_IPV4)
        reply += ip
        reply += struct.pack("!H", port)

        self.transport.write(reply)


class SOCKSFactory(Factory):
    def buildProtocol(self, addr):
        return SOCKS5()


# ================= RUN =================

if __name__ == "__main__":
    print("🚀 SOCKS5 CLEAN START :1098")
    reactor.listenTCP(1098, SOCKSFactory())
    reactor.run()
