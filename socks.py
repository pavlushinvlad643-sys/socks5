#!/usr/bin/env python3

import socket
import threading
import struct

BUFFER_SIZE = 4096

def forward(source, destination):
    try:
        while True:
            data = source.recv(BUFFER_SIZE)
            if not data:
                break
            destination.sendall(data)
    except:
        pass
    finally:
        source.close()
        destination.close()


def handle_client(client):

    try:
        # handshake
        data = client.recv(262)
        client.sendall(b"\x05\x00")

        # request
        data = client.recv(4)
        ver, cmd, _, atyp = struct.unpack("!BBBB", data)

        if atyp == 1:  # IPv4
            addr = socket.inet_ntoa(client.recv(4))
        elif atyp == 3:  # domain
            length = client.recv(1)[0]
            addr = client.recv(length).decode()
        else:
            client.close()
            return

        port = struct.unpack('!H', client.recv(2))[0]

        print(f"[CONNECT] {addr}:{port}")

        remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote.connect((addr, port))

        bind_addr = remote.getsockname()

        reply = b"\x05\x00\x00\x01"
        reply += socket.inet_aton(bind_addr[0])
        reply += struct.pack("!H", bind_addr[1])

        client.sendall(reply)

        # FULL DUPLEX (вот это ключ!)
        t1 = threading.Thread(target=forward, args=(client, remote))
        t2 = threading.Thread(target=forward, args=(remote, client))

        t1.start()
        t2.start()

    except Exception as e:
        print("ERROR:", e)
        client.close()


def main():
    host = "0.0.0.0"
    port = 1081  # новый порт

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen(128)

    print(f"[OK] SOCKS5 работает на {host}:{port}")

    while True:
        client, addr = server.accept()
        print(f"[NEW] {addr}")
        threading.Thread(target=handle_client, args=(client,)).start()


if __name__ == "__main__":
    main()
