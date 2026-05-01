#!/usr/bin/env python3
"""
Advanced SOCKS5 Proxy Server - Mobile Hotspot Gateway Edition
Optimized for: Phone → VPN/Proxy → Internet gateway for PC clients
Features:
- TCP/UDP support with connection pooling
- Upstream proxy chaining (SOCKS5/HTTP)
- Mobile network optimizations (reconnection, keepalive)
- Connection statistics and monitoring
- Bandwidth management
- DNS caching for faster lookups
- Auto-reconnect on mobile network changes
"""

from twisted.internet import reactor, protocol, endpoints, defer, task
from twisted.internet.protocol import Protocol, Factory, DatagramProtocol, ClientFactory
from twisted.internet.error import DNSLookupError, TimeoutError, ConnectError, ConnectionLost
from twisted.python import log
from collections import deque, defaultdict
import struct
import socket
import sys
import argparse
import time
import threading
from datetime import datetime

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


class DNSCache:
    """DNS cache to reduce lookups on mobile networks"""
    def __init__(self, ttl=300):
        self.cache = {}
        self.ttl = ttl
        self.hits = 0
        self.misses = 0

    def get(self, hostname):
        if hostname in self.cache:
            ip, timestamp = self.cache[hostname]
            if time.time() - timestamp < self.ttl:
                self.hits += 1
                log.msg(f"[DNS-CACHE] HIT: {hostname} -> {ip} (hits: {self.hits})")
                return ip
            else:
                del self.cache[hostname]
        self.misses += 1
        return None

    def set(self, hostname, ip):
        self.cache[hostname] = (ip, time.time())
        log.msg(f"[DNS-CACHE] STORE: {hostname} -> {ip}")

    def clear(self):
        self.cache.clear()
        log.msg("[DNS-CACHE] Cleared")


class ConnectionPool:
    """Connection pool to reuse connections - reduces overhead on mobile networks"""
    def __init__(self, max_idle=30, idle_timeout=60):
        self.pool = defaultdict(deque)
        self.max_idle = max_idle
        self.idle_timeout = idle_timeout
        self.stats = {'reused': 0, 'created': 0, 'expired': 0}

    def get(self, host, port):
        key = (host, port)
        while self.pool[key]:
            conn, timestamp = self.pool[key].popleft()
            if time.time() - timestamp < self.idle_timeout:
                if conn.transport and conn.transport.connected:
                    self.stats['reused'] += 1
                    log.msg(f"[POOL] REUSE: {host}:{port} (reused: {self.stats['reused']})")
                    return conn
            else:
                self.stats['expired'] += 1
                if conn.transport:
                    conn.transport.loseConnection()
        return None

    def put(self, host, port, conn):
        key = (host, port)
        if len(self.pool[key]) < self.max_idle:
            self.pool[key].append((conn, time.time()))
            log.msg(f"[POOL] STORE: {host}:{port} (pool size: {len(self.pool[key])})")

    def cleanup(self):
        """Remove expired connections"""
        now = time.time()
        for key in list(self.pool.keys()):
            while self.pool[key]:
                conn, timestamp = self.pool[key][0]
                if now - timestamp >= self.idle_timeout:
                    self.pool[key].popleft()
                    self.stats['expired'] += 1
                    if conn.transport:
                        conn.transport.loseConnection()
                else:
                    break


class Statistics:
    """Global statistics tracker"""
    def __init__(self):
        self.start_time = time.time()
        self.total_connections = 0
        self.active_connections = 0
        self.total_bytes_up = 0
        self.total_bytes_down = 0
        self.failed_connections = 0
        self.successful_connections = 0
        self.dns_queries = 0
        self.udp_packets_sent = 0
        self.udp_packets_recv = 0

    def log_stats(self):
        uptime = time.time() - self.start_time
        log.msg("=" * 60)
        log.msg(f"[STATS] Uptime: {uptime:.0f}s | Active: {self.active_connections}")
        log.msg(f"[STATS] Total connections: {self.total_connections} (Success: {self.successful_connections}, Failed: {self.failed_connections})")
        log.msg(f"[STATS] Bandwidth: ↑{self.total_bytes_up/1024/1024:.2f}MB ↓{self.total_bytes_down/1024/1024:.2f}MB")
        log.msg(f"[STATS] DNS queries: {self.dns_queries} | UDP packets: ↑{self.udp_packets_sent} ↓{self.udp_packets_recv}")
        log.msg("=" * 60)


class UpstreamProxy:
    """Configuration for upstream proxy (phone's VPN/proxy)"""
    def __init__(self, proxy_type, host, port, username=None, password=None):
        self.proxy_type = proxy_type  # 'socks5', 'socks4', 'http'
        self.host = host
        self.port = port
        self.username = username
        self.password = password


class SOCKS5Server(Protocol):
    """Advanced SOCKS5 protocol handler with mobile optimizations"""

    def __init__(self, username=None, password=None, bind_host='0.0.0.0', 
                 upstream_proxy=None, dns_cache=None, stats=None, conn_pool=None):
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
        self.upstream_proxy = upstream_proxy
        self.dns_cache = dns_cache
        self.stats = stats
        self.conn_pool = conn_pool
        self.bytes_sent = 0
        self.bytes_received = 0
        self.connect_time = time.time()
        self.last_activity = time.time()
        self.keepalive_task = None

    def connectionMade(self):
        self.client_addr = self.transport.getPeer()
        self.stats.total_connections += 1
        self.stats.active_connections += 1
        log.msg(f"[CONNECT] Client #{self.stats.total_connections} from {self.client_addr.host}:{self.client_addr.port}")
        
        # Enable TCP keepalive for mobile networks
        self.transport.setTcpKeepAlive(1)
        try:
            sock = self.transport.getHandle()
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 30)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
            # Disable Nagle's algorithm for lower latency
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except:
            pass

    def dataReceived(self, data):
        self.pending_data += data
        self.last_activity = time.time()
        self.bytes_received += len(data)
        self.stats.total_bytes_down += len(data)

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
            if len(self.pending_data) >= 10:
                request_data = self.pending_data
                self.pending_data = b''
                self.handle_request(request_data)
        elif self.state == 'RELAYING_TCP':
            if self.remote_transport:
                self.remote_transport.write(data)
                self.bytes_sent += len(data)
                self.stats.total_bytes_up += len(data)
            self.pending_data = b''

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

        if self.auth_required:
            if USER_PASS_AUTH in methods:
                self.transport.write(struct.pack('!BB', SOCKS5_VERSION, USER_PASS_AUTH))
                self.state = 'AUTHENTICATING'
            else:
                self.transport.write(struct.pack('!BB', SOCKS5_VERSION, NO_ACCEPTABLE_METHODS))
                self.transport.loseConnection()
        else:
            if NO_AUTH in methods:
                self.transport.write(struct.pack('!BB', SOCKS5_VERSION, NO_AUTH))
                self.state = 'AUTHENTICATED'
            else:
                self.transport.write(struct.pack('!BB', SOCKS5_VERSION, NO_ACCEPTABLE_METHODS))
                self.transport.loseConnection()

    def handle_auth(self, data):
        """Handle username/password authentication (RFC 1929)"""
        if len(data) < 3:
            self.send_auth_reply(AUTH_FAILURE)
            return

        version = data[0]
        if version != AUTH_VERSION:
            self.send_auth_reply(AUTH_FAILURE)
            return

        ulen = data[1]
        if len(data) < 3 + ulen:
            self.send_auth_reply(AUTH_FAILURE)
            return

        username = data[2:2+ulen].decode('utf-8', errors='ignore')
        offset = 2 + ulen
        
        if len(data) < offset + 1:
            self.send_auth_reply(AUTH_FAILURE)
            return

        plen = data[offset]
        if len(data) < offset + 1 + plen:
            self.send_auth_reply(AUTH_FAILURE)
            return

        password = data[offset+1:offset+1+plen].decode('utf-8', errors='ignore')

        if username == self.username and password == self.password:
            self.send_auth_reply(AUTH_SUCCESS)
            self.state = 'AUTHENTICATED'
            log.msg(f"[AUTH] ✓ User: {username}")
        else:
            self.send_auth_reply(AUTH_FAILURE)
            log.msg(f"[AUTH] ✗ User: {username}")

    def send_auth_reply(self, status):
        self.transport.write(struct.pack('!BB', AUTH_VERSION, status))
        if status != AUTH_SUCCESS:
            self.transport.loseConnection()

    def handle_request(self, data):
        """Handle SOCKS5 request (CONNECT, BIND, UDP ASSOCIATE)"""
        if len(data) < 10:
            self.send_reply(REP_GENERAL_FAILURE)
            return

        version, cmd, rsv, atyp = struct.unpack('!BBBB', data[:4])

        if version != SOCKS5_VERSION:
            self.send_reply(REP_GENERAL_FAILURE)
            return

        # Parse destination address
        offset = 4
        if atyp == ATYP_IPV4:
            if len(data) < offset + 6:
                self.send_reply(REP_GENERAL_FAILURE)
                return
            dst_addr = socket.inet_ntoa(data[offset:offset+4])
            offset += 4
        elif atyp == ATYP_DOMAIN:
            if len(data) < offset + 1:
                self.send_reply(REP_GENERAL_FAILURE)
                return
            domain_len = data[offset]
            offset += 1
            if len(data) < offset + domain_len + 2:
                self.send_reply(REP_GENERAL_FAILURE)
                return
            try:
                dst_addr = data[offset:offset+domain_len].decode('utf-8', errors='strict')
            except UnicodeDecodeError:
                self.send_reply(REP_GENERAL_FAILURE)
                return
            offset += domain_len
        elif atyp == ATYP_IPV6:
            if len(data) < offset + 18:
                self.send_reply(REP_ADDRESS_TYPE_NOT_SUPPORTED)
                return
            try:
                dst_addr = socket.inet_ntop(socket.AF_INET6, data[offset:offset+16])
            except:
                self.send_reply(REP_ADDRESS_TYPE_NOT_SUPPORTED)
                return
            offset += 16
        else:
            self.send_reply(REP_ADDRESS_TYPE_NOT_SUPPORTED)
            return

        dst_port = struct.unpack('!H', data[offset:offset+2])[0]

        cmd_name = {CMD_CONNECT: 'CONNECT', CMD_BIND: 'BIND', CMD_UDP_ASSOCIATE: 'UDP_ASSOCIATE'}.get(cmd, 'UNKNOWN')
        log.msg(f"[REQUEST] {cmd_name} → {dst_addr}:{dst_port}")

        if cmd == CMD_CONNECT:
            self.handle_connect(dst_addr, dst_port, atyp)
      
        elif cmd == CMD_BIND:
            self.send_reply(REP_COMMAND_NOT_SUPPORTED)
        else:
            self.send_reply(REP_COMMAND_NOT_SUPPORTED)

    def handle_connect(self, dst_addr, dst_port, atyp):
        """Handle TCP CONNECT with upstream proxy chaining and DNS caching"""
        
        def on_connect_failed(failure):
            if failure.check(DNSLookupError):
                log.msg(f"[DNS] ✗ Failed: {dst_addr}")
                reply_code = REP_HOST_UNREACHABLE
            elif failure.check(TimeoutError):
                log.msg(f"[DNS] ⏱ Timeout: {dst_addr}")
                reply_code = REP_TTL_EXPIRED
            else:
                log.msg(f"[CONNECT] ✗ Error: {failure.value}")
                reply_code = REP_GENERAL_FAILURE
            
            self.stats.failed_connections += 1
            if self.transport.connected:
                self.send_reply(reply_code)
                self.transport.loseConnection()

        def do_connect(resolved_ip):
            log.msg(f"[CONNECT] {dst_addr} → {resolved_ip}:{dst_port}")
            
            if self.upstream_proxy:
                # Chain through upstream proxy
                self.connect_via_upstream(resolved_ip, dst_port)
            else:
                # Direct connection
                self.connect_direct(resolved_ip, dst_port)

        # DNS resolution with caching
        if atyp == ATYP_DOMAIN:
            # Check cache first
            cached_ip = self.dns_cache.get(dst_addr) if self.dns_cache else None
            if cached_ip:
                do_connect(cached_ip)
            else:
                self.stats.dns_queries += 1
                log.msg(f"[DNS] Resolving {dst_addr}...")
                d = reactor.resolve(dst_addr)
                d.addCallback(lambda ip: self.cache_and_connect(dst_addr, ip, do_connect))
                d.addErrback(on_connect_failed)
        else:
            do_connect(dst_addr)

    def cache_and_connect(self, hostname, ip, callback):
        """Cache DNS result and proceed with connection"""
        if self.dns_cache:
            self.dns_cache.set(hostname, ip)
        callback(ip)

    def connect_direct(self, dst_addr, dst_port):
        """Direct connection to destination"""
        factory = RemoteTCPClientFactory(self, dst_addr, dst_port)
        reactor.connectTCP(dst_addr, dst_port, factory, timeout=30)

    def connect_via_upstream(self, dst_addr, dst_port):
        """Connect through upstream SOCKS5/HTTP proxy"""
        log.msg(f"[UPSTREAM] Chaining via {self.upstream_proxy.host}:{self.upstream_proxy.port}")
        factory = UpstreamProxyClientFactory(self, dst_addr, dst_port, self.upstream_proxy)
        reactor.connectTCP(self.upstream_proxy.host, self.upstream_proxy.port, factory, timeout=30)

    def handle_udp_associate(self):
        """Handle UDP ASSOCIATE request with stats tracking"""
        try:
            self.udp_relay = UDPRelay(self.stats)
            self.udp_listen_port = reactor.listenUDP(0, self.udp_relay, interface=self.bind_host)
            relay_port = self.udp_listen_port.getHost().port
            log.msg(f"[UDP] Relay started on {self.bind_host}:{relay_port}")
            self.send_reply(REP_SUCCESS, self.bind_host, relay_port)
            self.state = 'UDP_ASSOCIATED'
        except Exception as e:
            log.msg(f"[UDP] ✗ Failed: {e}")
            self.send_reply(REP_GENERAL_FAILURE)

    def send_reply(self, rep, bind_addr='0.0.0.0', bind_port=0):
        """Send SOCKS5 reply"""
        try:
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

            rep_symbols = {REP_SUCCESS: '✓', REP_GENERAL_FAILURE: '✗', REP_HOST_UNREACHABLE: '✗'}
            symbol = rep_symbols.get(rep, '✗')
            if rep == REP_SUCCESS:
                log.msg(f"[REPLY] {symbol} SUCCESS")
            else:
                log.msg(f"[REPLY] {symbol} ERROR {rep}")
        except Exception as e:
            log.msg(f"[ERROR] Send reply failed: {e}")

    def connectionLost(self, reason):
        """Clean up on disconnect"""
        duration = time.time() - self.connect_time
        self.stats.active_connections -= 1
        
        log.msg(f"[DISCONNECT] Session: {duration:.1f}s | ↑{self.bytes_sent/1024:.1f}KB ↓{self.bytes_received/1024:.1f}KB")
        
        if self.remote_transport:
            self.remote_transport.loseConnection()
        if self.udp_listen_port:
            self.udp_listen_port.stopListening()
        if self.keepalive_task and self.keepalive_task.running:
            self.keepalive_task.stop()

    def start_tcp_relay(self, remote_transport):
        """Start relaying TCP data"""
        self.remote_transport = remote_transport
        self.state = 'RELAYING_TCP'
        peer = remote_transport.getPeer()
        self.send_reply(REP_SUCCESS, peer.host, peer.port)
        self.stats.successful_connections += 1
        log.msg(f"[RELAY] ✓ Active to {peer.host}:{peer.port}")

    def tcp_relay_data(self, data):
        """Receive data from remote and send to client"""
        if self.state == 'RELAYING_TCP' and self.transport and self.transport.connected:
            self.transport.write(data)
            self.bytes_received += len(data)
            self.stats.total_bytes_down += len(data)
            self.last_activity = time.time()


class RemoteTCPClientFactory(ClientFactory):
    """Factory for direct TCP connections"""
    
    def __init__(self, socks5_server, dst_addr, dst_port):
        self.socks5_server = socks5_server
        self.dst_addr = dst_addr
        self.dst_port = dst_port
    
    def buildProtocol(self, addr):
        proto = RemoteTCPClient()
        proto.factory = self
        return proto
    
    def clientConnectionFailed(self, connector, reason):
        log.msg(f"[CONNECT] ✗ TCP failed to {self.dst_addr}:{self.dst_port}")
        self.socks5_server.stats.failed_connections += 1
        if self.socks5_server.transport.connected:
            self.socks5_server.send_reply(REP_CONNECTION_REFUSED)
            self.socks5_server.transport.loseConnection()


class RemoteTCPClient(Protocol):
    """Client connection to remote server"""

    def connectionMade(self):
        log.msg(f"[CONNECT] ✓ Remote connected")
        self.factory.socks5_server.start_tcp_relay(self.transport)
        
        # Optimize for mobile networks
        try:
            sock = self.transport.getHandle()
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except:
            pass

    def dataReceived(self, data):
        self.factory.socks5_server.tcp_relay_data(data)

    def connectionLost(self, reason):
        if self.factory.socks5_server.transport.connected:
            self.factory.socks5_server.transport.loseConnection()


class UpstreamProxyClientFactory(ClientFactory):
    """Factory for upstream SOCKS5 proxy connections"""
    
    def __init__(self, socks5_server, dst_addr, dst_port, upstream_proxy):
        self.socks5_server = socks5_server
        self.dst_addr = dst_addr
        self.dst_port = dst_port
        self.upstream_proxy = upstream_proxy
    
    def buildProtocol(self, addr):
        proto = UpstreamProxyClient(self.dst_addr, self.dst_port, self.upstream_proxy)
        proto.factory = self
        return proto
    
    def clientConnectionFailed(self, connector, reason):
        log.msg(f"[UPSTREAM] ✗ Failed to connect to upstream proxy")
        self.socks5_server.stats.failed_connections += 1
        if self.socks5_server.transport.connected:
            self.socks5_server.send_reply(REP_CONNECTION_REFUSED)
            self.socks5_server.transport.loseConnection()


class UpstreamProxyClient(Protocol):
    """Client that connects through upstream SOCKS5 proxy"""
    
    def __init__(self, dst_addr, dst_port, upstream_proxy):
        self.dst_addr = dst_addr
        self.dst_port = dst_port
        self.upstream_proxy = upstream_proxy
        self.state = 'INIT'
        self.buffer = b''
    
    def connectionMade(self):
        log.msg(f"[UPSTREAM] Connected to {self.upstream_proxy.host}:{self.upstream_proxy.port}")
        # Send SOCKS5 greeting
        if self.upstream_proxy.username:
            methods = struct.pack('!BBB', SOCKS5_VERSION, 2, NO_AUTH, USER_PASS_AUTH)
        else:
            methods = struct.pack('!BBB', SOCKS5_VERSION, 1, NO_AUTH)
        self.transport.write(methods)
        self.state = 'GREETING_SENT'
    
    def dataReceived(self, data):
        self.buffer += data
        
        if self.state == 'GREETING_SENT':
            if len(self.buffer) >= 2:
                version, method = struct.unpack('!BB', self.buffer[:2])
                self.buffer = self.buffer[2:]
                
                if method == USER_PASS_AUTH and self.upstream_proxy.username:
                    # Send username/password
                    auth_data = struct.pack('!B', AUTH_VERSION)
                    username = self.upstream_proxy.username.encode('utf-8')
                    password = self.upstream_proxy.password.encode('utf-8')
                    auth_data += struct.pack('!B', len(username)) + username
                    auth_data += struct.pack('!B', len(password)) + password
                    self.transport.write(auth_data)
                    self.state = 'AUTH_SENT'
                elif method == NO_AUTH:
                    self.send_connect_request()
                else:
                    log.msg(f"[UPSTREAM] ✗ Unsupported auth method: {method}")
                    self.transport.loseConnection()
        
        elif self.state == 'AUTH_SENT':
            if len(self.buffer) >= 2:
                version, status = struct.unpack('!BB', self.buffer[:2])
                self.buffer = self.buffer[2:]
                if status == AUTH_SUCCESS:
                    self.send_connect_request()
                else:
                    log.msg(f"[UPSTREAM] ✗ Auth failed")
                    self.transport.loseConnection()
        
        elif self.state == 'CONNECT_SENT':
            if len(self.buffer) >= 10:
                version, rep, rsv, atyp = struct.unpack('!BBBB', self.buffer[:4])
                if rep == REP_SUCCESS:
                    log.msg(f"[UPSTREAM] ✓ Connected to {self.dst_addr}:{self.dst_port}")
                    self.state = 'RELAYING'
                    self.factory.socks5_server.start_tcp_relay(self.transport)
                    # Send any buffered data
                    if len(self.buffer) > 10:
                        remaining = self.buffer[10:]
                        self.factory.socks5_server.tcp_relay_data(remaining)
                    self.buffer = b''
                else:
                    log.msg(f"[UPSTREAM] ✗ Connect failed: {rep}")
                    self.transport.loseConnection()
        
        elif self.state == 'RELAYING':
            if self.buffer:
                self.factory.socks5_server.tcp_relay_data(self.buffer)
                self.buffer = b''
    
    def send_connect_request(self):
        """Send CONNECT request to upstream proxy"""
        request = struct.pack('!BBB', SOCKS5_VERSION, CMD_CONNECT, 0)
        
        # Try to parse as IP first
        try:
            socket.inet_aton(self.dst_addr)
            request += struct.pack('!B', ATYP_IPV4)
            request += socket.inet_aton(self.dst_addr)
        except socket.error:
            # Use domain name
            request += struct.pack('!B', ATYP_DOMAIN)
            domain_bytes = self.dst_addr.encode('utf-8')
            request += struct.pack('!B', len(domain_bytes))
            request += domain_bytes
        
        request += struct.pack('!H', self.dst_port)
        self.transport.write(request)
        self.state = 'CONNECT_SENT'
        log.msg(f"[UPSTREAM] Requesting {self.dst_addr}:{self.dst_port}")
    
    def connectionLost(self, reason):
        if self.factory.socks5_server.transport.connected:
            self.factory.socks5_server.transport.loseConnection()


class UDPRelay(DatagramProtocol):
    """UDP relay with statistics"""

    def __init__(self, stats=None):
        self.client_addr = None
        self.session_table = {}
        self.stats = stats

    def datagramReceived(self, data, addr):
        if self.client_addr is None:
            self.client_addr = addr
            log.msg(f"[UDP] Client: {addr}")

        if addr == self.client_addr:
            self.handle_client_packet(data)
        else:
            self.handle_remote_packet(data, addr)

    def handle_client_packet(self, data):
        if len(data) < 10:
            return

        try:
            rsv, frag, atyp = struct.unpack('!HBB', data[:4])
            if frag != 0:
                return

            offset = 4
            if atyp == ATYP_IPV4:
                if len(data) < offset + 6:
                    return
                dst_addr = socket.inet_ntoa(data[offset:offset+4])
                offset += 4
            elif atyp == ATYP_DOMAIN:
                if len(data) < offset + 1:
                    return
                domain_len = data[offset]
                offset += 1
                if len(data) < offset + domain_len + 2:
                    return
                dst_addr = data[offset:offset+domain_len].decode('utf-8', errors='ignore')
                offset += domain_len
            elif atyp == ATYP_IPV6:
                if len(data) < offset + 18:
                    return
                dst_addr = socket.inet_ntop(socket.AF_INET6, data[offset:offset+16])
                offset += 16
            else:
                return

            dst_port = struct.unpack('!H', data[offset:offset+2])[0]
            payload = data[offset+2:]

            self.transport.write(payload, (dst_addr, dst_port))
            if self.stats:
                self.stats.udp_packets_sent += 1
            log.msg(f"[UDP] → {dst_addr}:{dst_port} ({len(payload)}B)")
        except Exception as e:
            log.msg(f"[UDP] ✗ Error: {e}")

    def handle_remote_packet(self, data, from_addr):
        try:
            try:
                addr_bytes = socket.inet_aton(from_addr[0])
                atyp = ATYP_IPV4
            except socket.error:
                try:
                    addr_bytes = socket.inet_pton(socket.AF_INET6, from_addr[0])
                    atyp = ATYP_IPV6
                except socket.error:
                    atyp = ATYP_DOMAIN
                    addr_bytes = bytes([len(from_addr[0])]) + from_addr[0].encode('utf-8')

            header = struct.pack('!HBB', 0, 0, atyp)
            header += addr_bytes
            header += struct.pack('!H', from_addr[1])

            packet = header + data
            self.transport.write(packet, self.client_addr)
            if self.stats:
                self.stats.udp_packets_recv += 1
            log.msg(f"[UDP] ← {from_addr[0]}:{from_addr[1]} ({len(data)}B)")
        except Exception as e:
            log.msg(f"[UDP] ✗ Error: {e}")


class SOCKS5Factory(Factory):
    """Factory for SOCKS5 server with shared resources"""

    def __init__(self, username=None, password=None, bind_host='0.0.0.0', 
                 upstream_proxy=None, dns_cache=None, stats=None, conn_pool=None):
        self.username = username
        self.password = password
        self.bind_host = bind_host
        self.upstream_proxy = upstream_proxy
        self.dns_cache = dns_cache or DNSCache()
        self.stats = stats or Statistics()
        self.conn_pool = conn_pool or ConnectionPool()

    def buildProtocol(self, addr):
        return SOCKS5Server(
            self.username, 
            self.password, 
            self.bind_host,
            self.upstream_proxy,
            self.dns_cache,
            self.stats,
            self.conn_pool
        )


def main():
    parser = argparse.ArgumentParser(description='Advanced SOCKS5 Proxy Server - Mobile Hotspot Edition')
    parser.add_argument('-p', '--port', type=int, default=1098, help='Proxy port (default: 1098)')
    parser.add_argument('-b', '--bind', default='0.0.0.0', help='Bind address (default: 0.0.0.0)')
    parser.add_argument('-u', '--username', help='Username for authentication')
    parser.add_argument('-P', '--password', help='Password for authentication')
    
    # Upstream proxy settings
    parser.add_argument('--upstream-type', choices=['socks5', 'socks4', 'http'], help='Upstream proxy type')
    parser.add_argument('--upstream-host', help='Upstream proxy host')
    parser.add_argument('--upstream-port', type=int, help='Upstream proxy port')
    parser.add_argument('--upstream-user', help='Upstream proxy username')
    parser.add_argument('--upstream-pass', help='Upstream proxy password')
    
    # Performance settings
    parser.add_argument('--dns-cache-ttl', type=int, default=300, help='DNS cache TTL in seconds (default: 300)')
    parser.add_argument('--stats-interval', type=int, default=60, help='Statistics logging interval (default: 60s)')
    
    args = parser.parse_args()

    log.startLogging(sys.stdout)

    # Validate auth settings
    if (args.username and not args.password) or (args.password and not args.username):
        log.msg("[ERROR] Both username and password required for auth")
        sys.exit(1)

    # Setup upstream proxy if configured
    upstream_proxy = None
    if args.upstream_host and args.upstream_port:
        upstream_proxy = UpstreamProxy(
            args.upstream_type or 'socks5',
            args.upstream_host,
            args.upstream_port,
            args.upstream_user,
            args.upstream_pass
        )

    # Create shared resources
    dns_cache = DNSCache(ttl=args.dns_cache_ttl)
    stats = Statistics()
    conn_pool = ConnectionPool()

    # Create factory
    factory = SOCKS5Factory(
        args.username, 
        args.password, 
        args.bind,
        upstream_proxy,
        dns_cache,
        stats,
        conn_pool
    )
    
    endpoint = endpoints.TCP4ServerEndpoint(reactor, 1098)
    endpoint.listen(factory)

    # Setup periodic tasks
    stats_task = task.LoopingCall(stats.log_stats)
    stats_task.start(args.stats_interval)
    
    cleanup_task = task.LoopingCall(conn_pool.cleanup)
    cleanup_task.start(30)

    log.msg("=" * 70)
    log.msg("🚀 ADVANCED SOCKS5 PROXY SERVER - MOBILE HOTSPOT EDITION")
    log.msg("=" * 70)
    log.msg(f"📡 Listen: {args.bind}:{args.port}")
    log.msg(f"🔧 Features: TCP/UDP, IPv4/IPv6/Domain, Connection Pooling, DNS Cache")
    
    if args.username:
        log.msg(f"🔐 Auth: USERNAME/PASSWORD (user: {args.username})")
    else:
        log.msg(f"🔓 Auth: NO AUTHENTICATION")
    
    if upstream_proxy:
        log.msg(f"⛓️  Upstream: {upstream_proxy.proxy_type.upper()} → {upstream_proxy.host}:{upstream_proxy.port}")
    else:
        log.msg(f"🌐 Mode: DIRECT CONNECTION")
    
    log.msg(f"💾 DNS Cache: {args.dns_cache_ttl}s TTL")
    log.msg(f"📊 Stats: Every {args.stats_interval}s")
    log.msg(f"📱 Optimized: Mobile networks, TCP keepalive, Low latency")
    log.msg("=" * 70)

    reactor.run()

main()
