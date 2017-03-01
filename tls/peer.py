#!/usr/bin/env python3

from asyncio import Transport, get_event_loop, Protocol, Future, ensure_future
from asyncio.sslproto import SSLProtocol
from struct import unpack
import ssl


class ProxyProtocol(Protocol):

    def __init__(self, name, protocol):
        self.name = name
        self._protocol = protocol

    def switch(self, protocol):
        self._protocol = protocol

    def connection_made(self, transport):
        self._protocol.connection_made(transport)

    def connection_lost(self, exc):
        self._protocol.connection_lost(exc)

    def data_received(self, data):
        self._protocol.data_received(data)

    def eof_received(self):
        self._protocol.eof_received()

    def pause_writing(self):
        self._protocol.pause_writing()

    def resume_writing(self):
        self._protocol.resume_writing()



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


class CaptureClientHello(Transport):

    def __init__(self, waiter):
        self._waiter = waiter

    def write(self, data):
        self._waiter.set_result(data)


class PeerSSLProtocol(Protocol):

    def __init__(self, loop, name):
        self.proxy = ProxyProtocol(name, self)
        self.buffer = b''
        self.length = None

        self.connected = Future()
        self.hello_received = Future()
        ensure_future(self.init_connection(loop))

    async def init_connection(self, loop):
        waiter = Future()

        hello_sent = Future()

        context = create_tls_context()
        trans = CaptureClientHello(hello_sent)
        ssl_proto = SSLProtocol(loop, ClientProtocol(), context, waiter)
        ssl_proto.connection_made(trans)

        out_data = await hello_sent
        my_random = out_data[15:43]

        transport = await self.connected
        transport.write(out_data)

        await self.hello_received
        peer_random = self.buffer[15:43]

        if my_random == peer_random:
            transport.close()
            return

        if my_random > peer_random:
            print("I am server", self.proxy.name, repr(self), transport)

            ssl_proto._waiter = None
            ssl_proto._transport = None

            context = create_tls_context()
            proto = SSLProtocol(loop, ServerProtocol(), context, waiter, server_side=True)

            self.proxy.switch(proto)
            proto.connection_made(transport)
            loop.call_soon(proto.data_received, self.buffer)

        else:
            print("I am client", self.proxy.name, repr(self), transport)

            ssl_proto._transport = transport
            self.proxy.switch(ssl_proto)
            loop.call_soon(ssl_proto.data_received, self.buffer[self.length+5:])

        await waiter


    def connection_made(self, transport):
        self.connected.set_result(transport)

    def data_received(self, data):
        self.buffer = self.buffer + data

        if self.hello_received.done():
            return

        l = len(self.buffer)

        if self.length is None and l >= 5:
            self.length, = unpack("!H", self.buffer[3:5])

        if l >= self.length + 5:
            self.hello_received.set_result(None)


def make_pair():
    loop = get_event_loop()

    pa = PeerSSLProtocol(loop, "A").proxy
    pb = PeerSSLProtocol(loop, "B").proxy

    ta = FakeTransport(pb)
    tb = FakeTransport(pa)

    pa.connection_made(ta)
    pb.connection_made(tb)



def run_loop():
    make_pair()
    loop = get_event_loop()
    try:
        loop.run_forever()
    finally:
        loop.close()


def main():
    run_loop()


if __name__ == '__main__':
    main()
