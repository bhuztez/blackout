#!/usr/bin/env python3

from socket import (
    socket, AF_INET, SOCK_STREAM,
    SOL_SOCKET, SO_REUSEADDR, SOMAXCONN)

from struct import pack, unpack


def main(port):
    peers = ()

    s = socket(AF_INET, SOCK_STREAM)
    s.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    s.bind(('', port))
    s.listen(SOMAXCONN)

    while True:
        conn, addr = s.accept()
        n, = unpack("!H", conn.recv(2))

        new_peers = peers

        for _ in range(n):
            peer = conn.recv(6)
            if peer not in new_peers:
                new_peers += (peer,)

        conn.send(pack("!H", len(peers)))

        for peer in peers:
            conn.send(peer)

        peers = new_peers[:10]


if __name__ == '__main__':
    import sys
    main(int(sys.argv[1]))
