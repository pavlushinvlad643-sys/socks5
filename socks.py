#!/usr/bin/env python3

from twisted.internet import reactor, protocol
from twisted.internet.protocol import DatagramProtocol
import struct
import socket
import sys

SOCKS_VERSION = 5

class UDPRelay(DatagramProtocol):
    def __init__(self, client_addr):
        self.client_addr = client_addr

    def datagramReceived(self, data, addr):
        if addr == self.client_addr:
            # from client → internet
            try:
                _, _, atyp = struct.unpack("!HBB", data[:4])
                offset = 4

                if atyp == 1:  # IPv4
                    dst_addr = socket.inet_ntoa(data[offset:offset+4])
                    offset += 4
                elif atyp == 3:  # domain
                    length = data[offset]
                    offset += 1
                    dst_addr = data[offset:offset+length].decode()
                    offset += length
                else:
                    return

                dst_port = struct.unpack("!H", data[offset:offset+2])[0]
                payload = data[offset+2:]

                self.transport.write(payload, (dst_addr, dst_port))

            except:
                pass
        else:
            # from internet → client
            try:
                addr_bytes = socket.inet_aton(addr[0])
                header = struct.pack("!HBB", 0, 0, 1)
                header += addr_bytes
                header += struct.pack("!H", addr[1])

                self.transport.write(header + data, self.client_addr)
            except:
                pass


class SOCKS5(protocol.Protocol):

    def connectionMade(self):
        self.state = "init"
        self.client = self.transport.getPeer()
        print(f"[+] Client {self.client.host}:{self.client.port}")

    def dataReceived(self, data):

        if self.state == "init":
            # greeting
            self.transport.write(struct.pack("!BB", 5, 0))
            self.state = "request"

        elif self.state == "request":
            version, cmd, _, atyp = struct.unpack("!BBBB", data[:4])
            offset = 4

            if atyp == 1:
                addr = socket.inet_ntoa(data[offset:offset+4])
                offset += 4
            elif atyp == 3:
                length = data[offset]
                offset += 1
                addr = data[offset:offset+length].decode()
                offset += length

            port = struct.unpack("!H", data[offset:offset+2])[0]

            if cmd == 1:
                self.handle_tcp(addr, port)
            elif cmd == 3:
                self.handle_udp()

    def handle_tcp(self, addr, port):
        print(f"[TCP] {addr}:{port}")

        try:
            remote = socket.create_connection((addr, port))
        except:
            self.transport.loseConnection()
            return

        bind_addr = remote.getsockname()

        reply = struct.pack("!BBBB", 5, 0, 0, 1)
        reply += socket.inet_aton(bind_addr[0])
        reply += struct.pack("!H", bind_addr[1])

        self.transport.write(reply)

        self.state = "stream"

        self.remote = remote
        reactor.addReader(self)

    def doRead(self):
        try:
            data = self.remote.recv(4096)
            if data:
                self.transport.write(data)
        except:
            self.transport.loseConnection()

    def handle_udp(self):
        port = reactor.listenUDP(0, UDPRelay(self.client)).getHost().port

        reply = struct.pack("!BBBB", 5, 0, 0, 1)
        reply += socket.inet_aton("0.0.0.0")
        reply += struct.pack("!H", port)

        self.transport.write(reply)

        print(f"[UDP] relay on port {port}")


class Factory(protocol.Factory):
    def buildProtocol(self, addr):
        return SOCKS5()


if __name__ == "__main__":
    port = 1081   # ⚠️ НОВЫЙ ПОРТ

    reactor.listenTCP(port, Factory())
    print(f"SOCKS5 running on 0.0.0.0:{port}")

    reactor.run()
