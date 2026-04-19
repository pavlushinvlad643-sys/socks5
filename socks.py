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

    def init(self, username=None, password=None, bind_host='0.0.0.0'):
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
