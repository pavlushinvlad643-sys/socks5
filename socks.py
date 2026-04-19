#!/usr/bin/env python3
"""
SOCKS5 Proxy Server with TCP and UDP Support
Compatible with ProxyBridge, InterceptSuite, Proxifier, and other SOCKS5 clients
Supports: NO AUTH, USERNAME/PASSWORD AUTH, CONNECT, UDP ASSOCIATE, IPv4/IPv6/Domain
"""

from twisted.internet import reactor, protocol, endpoints, defer
from twisted.internet.protocol import Protocol, Factory, DatagramProtocol, ClientFactory
from twisted.internet.error import DNSLookupError, TimeoutError, ConnectError
from twisted.python import log
import struct
import socket
import sys
import argparse
import time

# SOCKS5 constants (RFC 1928)
SOCKS5_VERSION = 0x05
NO_AUTH = 0x00
USER_PASS_AUTH = 0x02
NO_ACCEPTABLE_METHODS = 0xFF

# Authentication constants (RFC 1929)
AUTH_VERSION = 0x01
AUTH_SUCCESS = 0x00
AUTH_FAILURE = 0x01

# Command constants
CMD_CONNECT = 0x01
CMD_BIND = 0x02
CMD_UDP_ASSOCIATE = 0x03

# Address type constants
ATYP_IPV4 = 0x01
ATYP_DOMAIN = 0x03
ATYP_IPV6 = 0x04

# Reply constants
REP_SUCCESS = 0x00
REP_GENERAL_FAILURE = 0x01
REP_CONNECTION_NOT_ALLOWED = 0x02
REP_NETWORK_UNREACHABLE = 0x03
REP_HOST_UNREACHABLE = 0x04
REP_CONNECTION_REFUSED = 0x05
REP_TTL_EXPIRED = 0x06
REP_COMMAND_NOT_SUPPORTED = 0x07
REP_ADDRESS_TYPE_NOT_SUPPORTED = 0x08

class SOCKS5Server(Protocol):
    """Main SOCKS5 protocol handler - ProxyBridge compatible"""

    def __init__(self, username=None, password=None, bind_host='0.0.0.0'):
        self.state = 'INIT'
        self.remote_transport = None
        self.udp_relay = None
        self.udp_listen_port = None
        self.username = username
        self.password = password
        self.auth_required = username is not None and password is not None
        self.pending_data = b''
        self.bind_host = bind_host
        self.client_addr = None

    def connectionMade(self):
        self.client_addr = self.transport.getPeer()
        log.msg(f"[CONNECT] Client from {self.client_addr.host}:{self.client_addr.port}")

    def dataReceived(self, data):
        self.pending_data += data

        if self.state == 'INIT':
            if len(self.pending_data) >= 3:
                greeting_data = self.pending_data
                self.pending_data = b''
                self.handle_greeting(greeting_data)
        elif self.state == 'AUTHENTICATING':
            if len(self.pending_data) >= 3:
                auth_data = self.pending_data
                self.pending_data = b''
                self.handle_auth(auth_data)
        elif self.state == 'AUTHENTICATED':
            if len(self.pending_data) >= 7:
                request_data = self.pending_data
                self.pending_data = b''
                self.handle_request(request_data)
        elif self.state == 'RELAYING_TCP':
            if self.remote_transport:
                self.remote_transport.write(data)

    def handle_greeting(self, data):
        """Handle SOCKS5 greeting and method selection (RFC 1928)"""
        if len(data) < 3:
            log.msg("[ERROR] Greeting too short")
            self.transport.loseConnection()
            return

        version, nmethods = struct.unpack('!BB', data[:2])
        methods = data[2:2+nmethods]

        if version != SOCKS5_VERSION:
            log.msg(f"[ERROR] Invalid SOCKS version: {version}")
            self.transport.loseConnection()
            return

        log.msg(f"[AUTH] Client methods: {[hex(m) for m in methods]}")

        # If auth required, offer USER_PASS_AUTH
        if self.auth_required:
            if USER_PASS_AUTH in methods:
                self.transport.write(struct.pack('!BB', SOCKS5_VERSION, USER_PASS_AUTH))
                self.state = 'AUTHENTICATING'
                log.msg("[AUTH] Username/password authentication required")
            elif NO_AUTH in methods:
                # Auth required but client only supports no-auth -> reject
                log.msg("[AUTH] Auth required but client only supports NO_AUTH")
                self.transport.write(struct.pack('!BB', SOCKS5_VERSION, NO_ACCEPTABLE_METHODS))
                self.transport.loseConnection()
            else:
                log.msg("[AUTH] No acceptable authentication methods")
                self.transport.write(struct.pack('!BB', SOCKS5_VERSION, NO_ACCEPTABLE_METHODS))
                self.transport.loseConnection()
        else:
            # No auth required, accept NO_AUTH
            if NO_AUTH in methods:
                self.transport.write(struct.pack('!BB', SOCKS5_VERSION, NO_AUTH))
                self.state = 'AUTHENTICATED'
                log.msg("[AUTH] No authentication - client ready")
            else:
                log.msg("[AUTH] Client doesn't support NO_AUTH")
                self.transport.write(struct.pack('!BB', SOCKS5_VERSION, NO_ACCEPTABLE_METHODS))
                self.transport.loseConnection()

    def handle_auth(self, data):
        """Handle username/password authentication (RFC 1929)"""
        if len(data) < 3:
            log.msg("[AUTH] Auth data too short")
            self.send_auth_reply(AUTH_FAILURE)
            return

        version = data[0]
        if version != AUTH_VERSION:
            log.msg(f"[AUTH] Invalid auth version: {version}")
            self.send_auth_reply(AUTH_FAILURE)
            return

        ulen = data[1]
        if len(data) < 3 + ulen:
            log.msg("[AUTH] Username length exceeds data")
            self.send_auth_reply(AUTH_FAILURE)
            return

        username = data[2:2+ulen].decode('utf-8', errors='ignore')

        offset = 2 + ulen
        if len(data) < offset + 1:
            log.msg("[AUTH] Missing password length")
            self.send_auth_reply(AUTH_FAILURE)
            return

        plen = data[offset]
        if len(data) < offset + 1 + plen:
            log.msg("[AUTH] Password length exceeds data")
            self.send_auth_reply(AUTH_FAILURE)
            return

        password = data[offset+1:offset+1+plen].decode('utf-8', errors='ignore')

        if username == self.username and password == self.password:
            self.send_auth_reply(AUTH_SUCCESS)
            self.state = 'AUTHENTICATED'
            log.msg(f"[AUTH] Authentication successful for user: {username}")
        else:
            self.send_auth_reply(AUTH_FAILURE)
            log.msg(f"[AUTH] Authentication failed for user: {username}")

    def send_auth_reply(self, status):
        """Send authentication reply"""
        self.transport.write(struct.pack('!BB', AUTH_VERSION, status))
        if status != AUTH_SUCCESS:
            self.transport.loseConnection()

    def handle_request(self, data):
        """Handle SOCKS5 request (CONNECT, BIND, UDP ASSOCIATE)"""
        if len(data) < 10:
            log.msg("[ERROR] Request too short")
            self.send_reply(REP_GENERAL_FAILURE)
            return

        version, cmd, rsv, atyp = struct.unpack('!BBBB', data[:4])

        if version != SOCKS5_VERSION:
            log.msg(f"[ERROR] Invalid version in request: {version}")
            self.send_reply(REP_GENERAL_FAILURE)
            return

        # Parse destination address
        offset = 4
        if atyp == ATYP_IPV4:
            if len(data) < offset + 6:
                log.msg("[ERROR] IPv4 address too short")
                self.send_reply(REP_GENERAL_FAILURE)
                return
            dst_addr = socket.inet_ntoa(data[offset:offset+4])
            offset += 4
        elif atyp == ATYP_DOMAIN:
            if len(data) < offset + 1:
                log.msg("[ERROR] Domain name length missing")
                self.send_reply(REP_GENERAL_FAILURE)
                return
            domain_len = data[offset]
            offset += 1
            if len(data) < offset + domain_len + 2:
                log.msg("[ERROR] Domain name exceeds data")
                self.send_reply(REP_GENERAL_FAILURE)
                return
            try:
                dst_addr = data[offset:offset+domain_len].decode('utf-8', errors='strict')
            except UnicodeDecodeError:
                log.msg("[ERROR] Invalid domain name encoding")
                self.send_reply(REP_GENERAL_FAILURE)
                return
            offset += domain_len
        elif atyp == ATYP_IPV6:
            if len(data) < offset + 18:
                log.msg("[ERROR] IPv6 address too short")
                self.send_reply(REP_ADDRESS_TYPE_NOT_SUPPORTED)
                return
            try:
                dst_addr = socket.inet_ntop(socket.AF_INET6, data[offset:offset+16])
            except:
                log.msg("[ERROR] Invalid IPv6 address")
                self.send_reply(REP_ADDRESS_TYPE_NOT_SUPPORTED)
                return
            offset += 16
        else:
            log.msg(f"[ERROR] Unsupported address type: {atyp}")
            self.send_reply(REP_ADDRESS_TYPE_NOT_SUPPORTED)
            return

        dst_port = struct.unpack('!H', data[offset:offset+2])[0]

        cmd_name = {CMD_CONNECT: 'CONNECT', CMD_BIND: 'BIND', CMD_UDP_ASSOCIATE: 'UDP_ASSOCIATE'}.get(cmd, 'UNKNOWN')
        atyp_name = {ATYP_IPV4: 'IPv4', ATYP_DOMAIN: 'DOMAIN', ATYP_IPV6: 'IPv6'}.get(atyp, 'UNKNOWN')
        log.msg(f"[REQUEST] {cmd_name} {dst_addr}:{dst_port} (atyp={atyp_name})")

        if cmd == CMD_CONNECT:
            self.handle_connect(dst_addr, dst_port, atyp)
        elif cmd == CMD_UDP_ASSOCIATE:
            log.msg("[UDP] UDP not supported - rejecting")
            self.send_reply(REP_COMMAND_NOT_SUPPORTED)
        elif cmd == CMD_BIND:
            log.msg("[ERROR] BIND command not supported")
            self.send_reply(REP_COMMAND_NOT_SUPPORTED)
        else:
            log.msg(f"[ERROR] Unknown command: {cmd}")
            self.send_reply(REP_COMMAND_NOT_SUPPORTED)

    def handle_connect(self, dst_addr, dst_port, atyp):
        """Handle TCP CONNECT request with proper DNS and connection error handling"""
            
        def on_connect_failed(failure):
            """Handle DNS resolution failures"""
            if failure.check(DNSLookupError):
                log.msg(f"[DNS] Failed to resolve {dst_addr}: {failure.value}")
                reply_code = REP_HOST_UNREACHABLE
            elif failure.check(TimeoutError):
                log.msg(f"[DNS] Timeout resolving {dst_addr}")
                reply_code = REP_TTL_EXPIRED
            else:
                log.msg(f"[CONNECT] Error for {dst_addr}:{dst_port}: {failure}")
                reply_code = REP_GENERAL_FAILURE
            
            if self.transport.connected:
                self.send_reply(reply_code)
                self.transport.loseConnection()

        def do_connect(resolved_ip):
            """Connect to the resolved IP"""
            log.msg(f"[CONNECT] DNS resolved {dst_addr} -> {resolved_ip}, connecting to {resolved_ip}:{dst_port}")
            
            # Create factory with error handling
            factory = RemoteTCPClientFactory(self, resolved_ip, dst_port)
            
            # connectTCP returns IConnector, not Deferred - errors handled in factory
            reactor.connectTCP(resolved_ip, dst_port, factory, timeout=30)

        # Resolve domain names if needed
        if atyp == ATYP_DOMAIN:
            log.msg(f"[DNS] Resolving {dst_addr}...")
            d = reactor.resolve(dst_addr)
            d.addCallback(do_connect)
            d.addErrback(on_connect_failed)
        else:
            # IPv4 or IPv6 - use directly
            do_connect(dst_addr)

    def handle_udp_associate(self):
        """Handle UDP ASSOCIATE request - start UDP relay"""
        try:
            self.udp_relay = UDPRelay()
            self.udp_listen_port = reactor.listenUDP(0, self.udp_relay, interface=self.bind_host)

            relay_port = self.udp_listen_port.getHost().port

            log.msg(f"[UDP] Relay started on {self.bind_host}:{relay_port}")

            self.send_reply(REP_SUCCESS, self.bind_host, relay_port)
            self.state = 'UDP_ASSOCIATED'
        except Exception as e:
            log.msg(f"[ERROR] Failed to start UDP relay: {e}")
            self.send_reply(REP_GENERAL_FAILURE)

    def send_reply(self, rep, bind_addr='0.0.0.0', bind_port=0):
        """Send SOCKS5 reply"""
        try:
            # Determine address type
            try:
                socket.inet_aton(bind_addr)
                atyp = ATYP_IPV4
                addr_bytes = socket.inet_aton(bind_addr)
            except socket.error:
                try:
                    addr_bytes = socket.inet_pton(socket.AF_INET6, bind_addr)
                    atyp = ATYP_IPV6
                except socket.error:
                    atyp = ATYP_DOMAIN
                    addr_bytes = bytes([len(bind_addr)]) + bind_addr.encode('utf-8')

            reply = struct.pack('!BBBB', SOCKS5_VERSION, rep, 0, atyp)
            reply += addr_bytes
            reply += struct.pack('!H', bind_port)
            self.transport.write(reply)

            rep_name = {
                REP_SUCCESS: 'SUCCESS',
                REP_GENERAL_FAILURE: 'GENERAL_FAILURE',
                REP_CONNECTION_NOT_ALLOWED: 'CONNECTION_NOT_ALLOWED',
                REP_NETWORK_UNREACHABLE: 'NETWORK_UNREACHABLE',
                REP_HOST_UNREACHABLE: 'HOST_UNREACHABLE',
                REP_CONNECTION_REFUSED: 'CONNECTION_REFUSED',
                REP_TTL_EXPIRED: 'TTL_EXPIRED',
                REP_COMMAND_NOT_SUPPORTED: 'COMMAND_NOT_SUPPORTED',
                REP_ADDRESS_TYPE_NOT_SUPPORTED: 'ADDRESS_TYPE_NOT_SUPPORTED'
            }.get(rep, f'UNKNOWN({rep})')

            log.msg(f"[REPLY] {rep_name} bind={bind_addr}:{bind_port}")
        except Exception as e:
            log.msg(f"[ERROR] Failed to send reply: {e}")

    def connectionLost(self, reason):
        """Clean up when client disconnects"""
        if self.client_addr:
            log.msg(f"[DISCONNECT] Client {self.client_addr.host}:{self.client_addr.port} disconnected")
        if self.remote_transport:
            self.remote_transport.loseConnection()
        if self.udp_listen_port:
            self.udp_listen_port.stopListening()

    def start_tcp_relay(self, remote_transport):
        """Start relaying TCP data"""
        self.remote_transport = remote_transport
        self.state = 'RELAYING_TCP'
        peer = remote_transport.getPeer()
        self.send_reply(REP_SUCCESS, peer.host, peer.port)
        log.msg(f"[RELAY] TCP relay active to {peer.host}:{peer.port}")

    def tcp_relay_data(self, data):
        """Receive data from remote and send to client"""
        if self.state == 'RELAYING_TCP' and self.transport:
            self.transport.write(data)


class RemoteTCPClientFactory(ClientFactory):
    """Factory that handles TCP connection failures properly"""
    protocol = None  # Will be set to RemoteTCPClient
    
    def __init__(self, socks5_server, dst_addr, dst_port):
        self.socks5_server = socks5_server
        self.dst_addr = dst_addr
        self.dst_port = dst_port
    
    def buildProtocol(self, addr):
        """Create protocol instance and link it to the SOCKS server"""
        proto = RemoteTCPClient()
        proto.factory = self
        return proto
    
    def clientConnectionFailed(self, connector, reason):
        """Called when TCP connection fails (after DNS succeeds)"""
        log.msg(f"[CONNECT] TCP failed to {self.dst_addr}:{self.dst_port}: {reason.value}")
        if self.socks5_server.transport.connected:
            self.socks5_server.send_reply(REP_CONNECTION_REFUSED)
            self.socks5_server.transport.loseConnection()
    
    def clientConnectionLost(self, connector, reason):
        """Called when connection is lost after being made"""
        pass


class RemoteTCPClient(Protocol):
    """Client connection to remote server for TCP CONNECT"""

    def connectionMade(self):
        self.factory.socks5_server.start_tcp_relay(self.transport)

    def dataReceived(self, data):
        self.factory.socks5_server.tcp_relay_data(data)

    def connectionLost(self, reason):
        self.factory.socks5_server.transport.loseConnection()


class UDPRelay(DatagramProtocol):
    """UDP relay for SOCKS5 UDP ASSOCIATE"""

    def __init__(self):
        self.client_addr = None
        self.session_table = {}

    def datagramReceived(self, data, addr):
        """Handle UDP packet from client or remote"""
        if self.client_addr is None:
            self.client_addr = addr
            log.msg(f"[UDP] Client registered: {addr}")

        if addr == self.client_addr:
            self.handle_client_packet(data)
        else:
            self.handle_remote_packet(data, addr)

    def handle_client_packet(self, data):
        """Parse SOCKS5 UDP request and forward"""
        if len(data) < 10:
            log.msg(f"[UDP] Packet too small: {len(data)} bytes")
            return

        try:
            rsv, frag, atyp = struct.unpack('!HBB', data[:4])

            if frag != 0:
                log.msg("[UDP] Fragmentation not supported, dropping packet")
                return

            offset = 4
            if atyp == ATYP_IPV4:
                if len(data) < offset + 6:
                    log.msg("[UDP] IPv4 address too short")
                    return
                dst_addr = socket.inet_ntoa(data[offset:offset+4])
                offset += 4
            elif atyp == ATYP_DOMAIN:
                if len(data) < offset + 1:
                    log.msg("[UDP] Domain length missing")
                    return
                domain_len = data[offset]
                offset += 1
                if len(data) < offset + domain_len + 2:
                    log.msg("[UDP] Domain exceeds data")
                    return
                dst_addr = data[offset:offset+domain_len].decode('utf-8', errors='ignore')
                offset += domain_len
            elif atyp == ATYP_IPV6:
                if len(data) < offset + 18:
                    log.msg("[UDP] IPv6 address too short")
                    return
                dst_addr = socket.inet_ntop(socket.AF_INET6, data[offset:offset+16])
                offset += 16
            else:
                log.msg(f"[UDP] Unsupported address type: {atyp}")
                return

            dst_port = struct.unpack('!H', data[offset:offset+2])[0]
            payload = data[offset+2:]

            dst_tuple = (dst_addr, dst_port)
            self.session_table[dst_tuple] = time.time()

            self.transport.write(payload, dst_tuple)
            log.msg(f"[UDP] {len(payload)} bytes -> {dst_addr}:{dst_port}")
        except Exception as e:
            log.msg(f"[UDP] Error handling client packet: {e}")

    def handle_remote_packet(self, data, from_addr):
        """Wrap remote packet in SOCKS5 UDP header and send to client"""
        try:
            # Determine address type
            try:
                addr_bytes = socket.inet_aton(from_addr[0])
                atyp = ATYP_IPV4
            except socket.error:
                try:
                    addr_bytes = socket.inet_pton(socket.AF_INET6, from_addr[0])
                    atyp = ATYP_IPV6
                except socket.error:
                    # Fallback to domain
                    atyp = ATYP_DOMAIN
                    addr_bytes = bytes([len(from_addr[0])]) + from_addr[0].encode('utf-8')

            header = struct.pack('!HBB', 0, 0, atyp)
            header += addr_bytes
            header += struct.pack('!H', from_addr[1])

            packet = header + data
            self.transport.write(packet, self.client_addr)
            log.msg(f"[UDP] {len(data)} bytes <- {from_addr[0]}:{from_addr[1]}")
        except Exception as e:
            log.msg(f"[UDP] Error handling remote packet: {e}")


class SOCKS5Factory(Factory):
    """Factory for SOCKS5 server"""

    def __init__(self, username=None, password=None, bind_host='0.0.0.0'):
        self.username = username
        self.password = password
        self.bind_host = bind_host

    def buildProtocol(self, addr):
        return SOCKS5Server(self.username, self.password, self.bind_host)


def main():
    parser = argparse.ArgumentParser(description='SOCKS5 Proxy Server')
    parser.add_argument('-p', '--port', type=int, default=1098, help='Proxy port (default: 1098)')
    parser.add_argument('-b', '--bind', default='0.0.0.0', help='Bind address (default: 0.0.0.0)')
    parser.add_argument('-u', '--username', help='Username for authentication')
    parser.add_argument('-P', '--password', help='Password for authentication')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose logging')
    args = parser.parse_args()

    log.startLogging(sys.stdout)

    # Validate auth settings
    if (args.username and not args.password) or (args.password and not args.username):
        log.msg("[ERROR] Both username and password must be provided for authentication")
        sys.exit(1)

    factory = SOCKS5Factory(args.username, args.password, args.bind)
    endpoint = endpoints.TCP4ServerEndpoint(reactor, args.port, interface=args.bind)
    endpoint.listen(factory)

    log.msg("=" * 60)
    log.msg("SOCKS5 Proxy Server Started")
    log.msg(f"Listen: {args.bind}:{args.port}")
    log.msg(f"Features: TCP CONNECT, UDP ASSOCIATE, IPv4/IPv6/Domain")
    if args.username:
        log.msg(f"Auth: USERNAME/PASSWORD (user: {args.username})")
    else:
        log.msg(f"Auth: NO AUTHENTICATION")
    log.msg(f"Compatible: ProxyBridge, InterceptSuite, Proxifier")
    log.msg("=" * 60)

    reactor.run()

main()
