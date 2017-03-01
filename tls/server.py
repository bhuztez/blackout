#!/usr/bin/env python3

from socket import (
    socket, AF_INET, SOCK_STREAM,
    SOL_SOCKET, SO_REUSEADDR, SOMAXCONN)

import ssl

from struct import pack, unpack


def main(port):
    import os.path
    ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    peers = ()

    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_cert_chain(
        certfile=os.path.join(ROOT,"peer.crt"),
        keyfile=os.path.join(ROOT,"peer.key"))
    context.load_verify_locations(
        os.path.join(ROOT,"ca.crt"))

    s = socket(AF_INET, SOCK_STREAM)
    s.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    s.bind(('', port))
    s.listen(SOMAXCONN)

    while True:
        conn, addr = s.accept()
        conn = context.wrap_socket(conn, server_side=True)
        print(conn.recv(5))
        conn.close()


if __name__ == '__main__':
    import sys
    main(int(sys.argv[1]))
