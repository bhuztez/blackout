#!/usr/bin/env python3

from socket import (
    socket, AF_INET, SOCK_STREAM,
    SOL_SOCKET, SO_REUSEADDR, SOMAXCONN)

import ssl

import os.path
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
context.verify_mode = ssl.CERT_REQUIRED
context.load_cert_chain(
    certfile=os.path.join(ROOT,"peer.crt"),
    keyfile=os.path.join(ROOT,"peer.key"))
context.load_verify_locations(
    os.path.join(ROOT,"ca.crt"))

def main(port):
    s = socket(AF_INET, SOCK_STREAM)
    s.connect(("127.0.0.1",port))
    conn = context.wrap_socket(s, server_side=False)
    conn.write(b"hello")
    conn.close()


if __name__ == '__main__':
    import sys
    main(int(sys.argv[1]))
