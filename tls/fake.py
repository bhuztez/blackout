#!/usr/bin/env python3

from asyncio import Transport, get_event_loop, Protocol, Future
from asyncio.sslproto import SSLProtocol
import ssl


class FakeTransport(Transport):

    def __init__(self, protocol):
        super().__init__()
        self._closing = False
        self._peer = protocol

    def is_closing(self):
        return self._closing

    def close(self):
        if self.close:
            return
        self._closing = True

    def pause_reading(self):
        self._peer.pause_writing()

    def resume_reading(self):
        self._peer.resume_writing()

    def write(self, data):
        self._peer.data_received(data)

    def write_eof(self):
        self._peer.eof_received()

    def can_write_eof(self):
        return True

    def abort(self):
        self._peer.connection_lost(None)


class ClientProtocol(Protocol):

    def connection_made(self, transport):
        pass

    def data_received(self, data):
        print(data)


class ServerProtocol(Protocol):

    def connection_made(self, transport):
        transport.write(b"hello")

    def data_received(self, data):
        pass


def create_tls_context():
    import os.path
    ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_cert_chain(
        certfile=os.path.join(ROOT,"peer.crt"),
        keyfile=os.path.join(ROOT,"peer.key"))
    context.load_verify_locations(
        os.path.join(ROOT,"ca.crt"))
    return context


async def make_pair(c, s):
    loop = get_event_loop()

    f = Future()

    pc = SSLProtocol(loop, c, create_tls_context(), f)
    ps = SSLProtocol(loop, s, create_tls_context(), None, server_side=True)

    tc = FakeTransport(ps)
    ts = FakeTransport(pc)

    ps.connection_made(ts)
    pc.connection_made(tc)

    await f



def run_loop():
    loop = get_event_loop()
    try:
        loop.run_until_complete(make_pair(ClientProtocol(), ServerProtocol()))
    finally:
        loop.close()


def main():
    run_loop()

if __name__ == '__main__':
    main()
