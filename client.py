#!/usr/bin/env python3

# from errno import EADDRNOTAVAIL

from struct import pack, unpack
from collections import deque, defaultdict
from itertools import count
import os
import os.path

from socket import (
    inet_aton, inet_ntoa,
    socket,
    AF_INET, SOCK_STREAM,
    SOL_SOCKET, SO_REUSEADDR, SO_REUSEPORT,
    SOMAXCONN)

from asyncio import (
    get_event_loop, sleep, ensure_future,
    open_connection, Protocol, Future)


class ObjectRequest:

    def __init__(self, club, conn, sha):
        self.club = club
        self.conn = conn
        self.sha = sha
        self.f = club.tempfile(sha)

    def write(self, data):
        self.f.write(data)

    def finish(self):
        self.f.close()
        self.conn.request = None

        # if sha does not match
        #   self.fail()
        # else

        self.club.finish_object(self.sha, self.conn)

    def fail(self):
        self.f.close()
        self.conn.request = None

        self.club.fail_object(self.sha, self.conn)


class Club:

    def __init__(self, path):
        self.path = path
        self.endpoints = set()

        self.sha_to_conn = defaultdict(lambda: set())
        self.conn_to_sha = defaultdict(lambda: set())

        self.requesting = set()


    def _object_path(self, filename):
        return os.path.join(self.path, 'cur', filename)

    def _temp_path(self, filename):
        return os.path.join(self.path, 'tmp', filename)

    def tempfile(self, sha):
        return open(self._temp_path(sha.hex()), 'xb')

    def open(self, sha):
        try:
            return open(self._object_path(sha.hex()), 'rb')
        except FileNotFoundError:
            return None

    def list_objects(self):
        return os.listdir(os.path.join(self.path, 'cur'))

    def new_object(self, sha, conn):
        if os.path.exists(self._object_path(sha.hex())):
            return

        self.sha_to_conn[sha].add(conn)
        self.conn_to_sha[conn].add(sha)

        if sha in self.requesting:
            return

        if conn.request_object(sha):
            self.requesting.add(sha)


    def finish_object(self, sha, conn):
        os.rename(self._temp_path(sha.hex()), self._object_path(sha.hex()))

        s = self.sha_to_conn.pop(sha)
        self.requesting.remove(sha)

        for c in s:
            objs = self.conn_to_sha[c]
            objs.remove(sha)

            candidates = objs - self.requesting

            if not candidates:
                continue

            choice = next(iter(candidates))

            if c.request_object(choice):
                self.requesting.add(choice)


    def fail_object(self, sha, conn):
        self.conn_to_sha[conn].remove(sha)
        s = self.sha_to_conn[sha]
        s.remove(conn)

        for c in s:
            if conn.request_object(sha):
                return

        self.requesting.remove(sha)


    def connection_lost(self, conn):
        s = self.conn_to_sha.pop(conn, set())
        for sha in s:
            self.sha_to_conn[sha].remove(conn)


class Connection(Protocol):

    def __init__(self, endpoint, addr):
        self.endpoint = endpoint
        self.addr = addr

        self.club = endpoint.club

        self.paused = False
        self.pending_writes = deque()

        self.buffer = b''
        self.state = (2, self._decode_length)

        self.responding = None
        self.to_respond = deque()

        self.request = None


    def pause_writing(self):
        self.paused = True

    def resume_writing(self):
        self.paused = False

        while self.pending_writes and not self.paused:
            self.pending_writes.popleft().set_result(None)

    async def _write(self, data):
        if not self.paused:
            self.transport.write(pack("!H", len(data)) + data)
            return

        future = Future()
        self.pending_writes.append(future)
        await future


    def write_object(self, sha):
        return self._write(b'\x00\x01' + sha)

    def write_peer(self, peer):
        return self._write(b'\x00\x02' + peer)


    async def write_response(self, sha):
        f = self.club.open(sha)

        if f is None:
            await self._write(b'\x00\x06' + b'\x01\x94')
            return

        with f:
            last = f.read(1024)

            while True:
                cur = f.read(1024)
                if len(cur) == 0:
                    await self._write(b'\x00\x05' + last)
                    return

                await self._write(b'\x00\x04' + last)
                last = cur

    async def _do_respond(self, sha):
        await self.write_response(sha)

        if not self.to_respond:
            self.responding = None
        else:
            self.responding = ensure_future(self._do_respond(self.to_respond.popleft()))


    def handle_request(self, sha):
        if self.responding is not None:
            self.to_respond.append(sha)
            return

        self.responding = ensure_future(self._do_respond(sha))


    async def _do_request(self, sha):
        await self._write(b'\x00\x03' + sha)

    def request_object(self, sha):
        if self.request is not None:
            return False

        self.request = ObjectRequest(self.club, self, sha)
        ensure_future(self._do_request(sha))
        return True

    async def _send_object_list(self):
        objects = self.club.list_objects()
        for o in objects:
            await self.write_object(bytes.fromhex(o))

    def connection_made(self, transport):
        self.transport = transport
        ensure_future(self._send_object_list())


    def connection_lost(self, exc):
        if self.request is not None:
            self.request.fail()

        if self.responding is not None:
            self.responding.cancel()

        self.club.connection_lost(self)
        self.endpoint.connections.pop(self.addr)


    def data_received(self, data):
        self.buffer += data

        while len(self.buffer) >= self.state[0]:
            n = self.state[0]
            packet = self.buffer[:n]
            self.buffer = self.buffer[n:]
            self.state = self.state[1](packet)

    def _decode_length(self, data):
        n, = unpack('!H', data)
        return (n, self._decode_body)


    def _decode_body(self, data):
        t, = unpack("!H", data[:2])

        if t == 1:
            sha = data[2:]
            self.club.new_object(sha, self)
        elif t == 2: # peer
            raise NotImplementedError
        elif t == 3:
            self.handle_request(data[2:])
        elif t == 4:
            self.request.write(data)
        elif t == 5:
            self.request.write(data)
            self.request.finish()
        elif t == 6:
            self.request.fail()
        else:
            raise NotImplementedError

        return (2, self._decode_length)


def encode_addr(addr):
    return inet_aton(addr[0]) + pack("!H", addr[1])

def decode_addr(b):
    return (inet_ntoa(b[:4]), unpack("!H", b[4:])[0])


class TcpEndpoint:

    def __init__(self, club, addr, loop=None):
        self.club = club
        self.addr = addr
        self.connections = {}

        if loop is None:
            loop = get_event_loop()
        self.loop = loop

        club.endpoints.add(self)
        ensure_future(self._do_accept())


    def get_address(self):
        return encode_addr(self.addr)


    async def _do_accept(self):
        s = socket(AF_INET, SOCK_STREAM)
        s.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        s.setsockopt(SOL_SOCKET, SO_REUSEPORT, 1)
        s.setblocking(False)
        s.bind(self.addr)
        s.listen(SOMAXCONN)

        while True:
            conn, addr = await self.loop.sock_accept(s)
            addr = encode_addr(addr)

            transport, connection = await self.loop.create_connection(lambda: Connection(self, addr), sock=conn)
            self.connections[addr] = connection


    def connect(self, peer):
        if peer in self.connections:
            return

        return ensure_future(self._do_connect(peer))


    async def _do_connect(self, peer):
        addr = decode_addr(peer)

        s = socket(AF_INET, SOCK_STREAM)
        s.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        s.setsockopt(SOL_SOCKET, SO_REUSEPORT, 1)
        s.setblocking(False)
        s.bind(self.addr)

        try:
            await self.loop.sock_connect(s, addr)
        except OSError:
            return

        transport, connection = await self.loop.create_connection(lambda: Connection(self, addr), sock=s)
        self.connections[addr] = connection



def create_periodic_task(f, delay, interval):
    async def task():
        await sleep(delay)
        while True:
            await f()
            await sleep(interval)

    return ensure_future(task())


class TcpTrackerClient:

    def __init__(self, club, host, port, interval=5, delay=2):
        self.club = club
        self.host = host
        self.port = port
        create_periodic_task(self.announce, delay, interval)

    async def announce(self):
        try:
            reader, writer = await open_connection(self.host, self.port)
        except OSError:
            return

        local_addrs = [e.get_address() for e in self.club.endpoints]

        n = len(self.club.endpoints)
        writer.write(pack("!H", n) + b''.join(local_addrs))

        n = await reader.read(2)
        if len(n) != 2:
            return

        n, = unpack("!H", n)

        for _ in range(n):
            peer = await reader.read(6)

            if len(peer) != 6:
                return

            for endpoint in self.club.endpoints:
                if peer not in local_addrs:
                    endpoint.connect(peer)

        writer.close()


def run_loop():
    loop = get_event_loop()
    try:
        loop.run_forever()
    finally:
        loop.close()

def main(port, path):
    club = Club(path)

    endpoint = TcpEndpoint(club, ("127.0.0.1", port))
    client = TcpTrackerClient(club, "127.0.0.1", 10000)
    run_loop()


if __name__ == '__main__':
    import sys
    main(int(sys.argv[1]), sys.argv[2])
