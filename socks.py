#!/usr/bin/env python3

from twisted.internet import reactor
from twisted.internet.protocol import Protocol, Factory, DatagramProtocol, ClientFactory
import struct
import socket
import time

SOCKS5_VERSION = 0x05
NO_AUTH = 0x00

CMD_CONNECT = 0x01
CMD_UDP_ASSOCIATE = 0x03

ATYP_IPV4 = 0x01
ATYP_DOMAIN = 0x03

REP_SUCCESS = 0x00
REP_GENERAL_FAILURE = 0x01
REP_COMMAND_NOT_SUPPORTED = 0x07


# ================= UDP RELAY =================

class UDPRelay(DatagramProtocol):
    def __init__(self):
        self.client_addr = None
        self.client_ip = None
        self.sessions = {}
        self.last_cleanup = time.time()

    def datagramReceived(self, data, addr):
        try:
            # от клиента
            if self.client_ip and addr[0] == self.client_ip:
                self.handle_client(data, addr)
            else:
                self.handle_remote(data, addr)
        except Exception as e:
            print("[UDP ERROR]", e)

    def handle_client(self, data, addr):
        if len(data) < 10:
            return

        if self.client_addr is None:
            self.client_addr = addr
            print("[UDP] client:", addr)

        try:
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
            else:
                return

            dst_port = struct.unpack("!H", data[offset:offset+2])[0]
            payload = data[offset+2:]

            self.sessions[(dst_addr, dst_port)] = addr

            self.transport.write(payload, (dst_addr, dst_port))

        except Exception as e:
            print("[UDP CLIENT ERROR]", e)

    def handle_remote(self, data, addr):
        try:
            client = self.sessions.get(addr) or self.client_addr
            if not client:
                return

            try:
                addr_bytes = socket.inet_aton(addr[0])
                atyp = ATYP_IPV4
            except:
                return

            header = struct.pack("!HBB", 0, 0, atyp)
            header += addr_bytes
            header += struct.pack("!H", addr[1])

            self.transport.write(header + data, client)

        except Exception as e:
            print("[UDP REMOTE ERROR]", e)


# ================= TCP RELAY =================

class Remote(Protocol):
    def connectionMade(self):
        if not hasattr(self.factory, "client") or self.factory.client is None:
            print("[TCP ERROR] client None")
            self.transport.loseConnection()
            return

        self.factory.client.remote = self.transport
        self.factory.client.send_reply(REP_SUCCESS)

    def dataReceived(self, data):
        if self.factory.client and self.factory.client.transport.connected:
            self.factory.client.transport.write(data)

    def connectionLost(self, reason):
        if self.factory.client and self.factory.client.transport.connected:
            self.factory.client.transport.loseConnection()


class RemoteFactory(ClientFactory):
    def __init__(self, client, host, port):
        self.client = client
        self.host = host
        self.port = port

    def buildProtocol(self, addr):
        proto = Remote()
        proto.factory = self
        return proto

    def clientConnectionFailed(self, connector, reason):
        print("[TCP FAIL]", reason)
        if self.client:
            self.client.send_reply(REP_GENERAL_FAILURE)
            self.client.transport.loseConnection()


# ================= SOCKS5 =================

class SOCKS5(Protocol):

    def connectionMade(self):
        self.state = 0
        self.buffer = b""
        self.remote = None
        self.client_addr = self.transport.getPeer()

    def dataReceived(self, data):
        self.buffer += data

        # handshake
        if self.state == 0:
            if len(self.buffer) < 3:
                return
            self.transport.write(struct.pack("!BB", SOCKS5_VERSION, NO_AUTH))
            self.buffer = b""
            self.state = 1

        # request
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
                reactor.connectTCP(addr, port, RemoteFactory(self, addr, port))

            elif cmd == CMD_UDP_ASSOCIATE:
                self.handle_udp()

            else:
                self.send_reply(REP_COMMAND_NOT_SUPPORTED)

            self.buffer = b""

    def handle_udp(self):
        try:
            self.udp = UDPRelay()
            self.udp.client_ip = self.client_addr.host

            port = reactor.listenUDP(0, self.udp)
            udp_port = port.getHost().port

            # КЛЮЧЕВОЙ ФИКС
            self.send_reply(REP_SUCCESS, self.client_addr.host, udp_port)

            print("[UDP READY]", self.client_addr.host, udp_port)

        except Exception as e:
            print("[UDP FAIL]", e)
            self.send_reply(REP_GENERAL_FAILURE)

    def send_reply(self, rep, bind_addr="0.0.0.0", bind_port=0):
        try:
            addr = socket.inet_aton(bind_addr)
            atyp = ATYP_IPV4
        except:
            return

        reply = struct.pack("!BBBB", SOCKS5_VERSION, rep, 0, atyp)
        reply += addr
        reply += struct.pack("!H", bind_port)

        self.transport.write(reply)


class SOCKSFactory(Factory):
    def buildProtocol(self, addr):
        return SOCKS5()


# ================= RUN =================

if __name__ == "__main__":
    print("🚀 SOCKS5 WORKING (TCP+UDP) :1098")
    reactor.listenTCP(1098, SOCKSFactory())
    reactor.run()
