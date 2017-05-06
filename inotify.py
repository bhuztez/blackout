#!/usr/bin/env python3

from os import fsencode, fsdecode, strerror, fdopen, read
from asyncio import get_event_loop
from termios import FIONREAD
from fcntl import ioctl
from errno import EINTR
import ctypes
from ctypes.util import find_library

libc = ctypes.CDLL(find_library('c'), use_errno=True)

IN_NONBLOCK = 0o0004000
IN_CLOEXEC  = 0o2000000

IN_MOVED_TO = 0x00000080
IN_CREATE   = 0x00000100

inotify_init1 = libc.inotify_init1
inotify_init1.argtypes = [ctypes.c_int]
inotify_init1.restype = ctypes.c_int

inotify_add_watch = libc.inotify_add_watch
inotify_add_watch.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
inotify_add_watch.restype = ctypes.c_int

inotify_rm_watch = libc.inotify_rm_watch
inotify_rm_watch.argtypes = [ctypes.c_int, ctypes.c_int]
inotify_rm_watch.restype = ctypes.c_int

def init(flags):
    while True:
        res = inotify_init1(flags)
        if res >= 0:
            return res

        e = ctypes.get_errno()
        if e != EINTR:
            raise OSError(e, strerror(e))

def add_watch(fd, path, mask):
    path = fsencode(path)

    while True:
        res = inotify_add_watch(fd, path, mask)
        if res >= 0:
            return res

        e = ctypes.get_errno()
        if e != EINTR:
            raise OSError(e, strerror(e))

def rm_watch(fd, wd):
    while True:
        res = inotify_rm_watch(fd, wd)
        if res >= 0:
            return res

        e = ctypes.get_errno()
        if e != EINTR:
            raise OSError(e, strerror(e))


class _Event(ctypes.Structure):
    _fields_ = (
        ('wd', ctypes.c_int),
        ('mask', ctypes.c_uint32),
        ('cookie', ctypes.c_uint32),
        ('len', ctypes.c_uint32))

class Event:

    def __init__(self, wd, mask, cookie, name):
        self.wd = wd
        self.mask = mask
        self.cookie = cookie
        self.name = name


def iter_events(data):
    offset = 0
    size = len(data)
    while offset < size:
        e = _Event.from_buffer_copy(data, offset)
        offset += ctypes.sizeof(_Event)

        yield Event(e.wd, e.mask, e.cookie,
                    fsdecode(ctypes.create_string_buffer(data[offset:offset+e.len], e.len).value))
        offset += e.len


class Monitor:

    def __init__(self, loop=None):
        self.fd = init(IN_NONBLOCK | IN_CLOEXEC)
        self.callbacks = {}

        if loop is None:
            loop = get_event_loop()

        loop.add_reader(self.fd, self.on_inotify)

    def on_inotify(self):
        size = ctypes.c_int()
        ioctl(self.fd, FIONREAD, size)
        for e in iter_events(read(self.fd, size.value)):
            callback = self.callbacks[e.wd]
            callback(e)

    def register(self, path, flags, callback):
        wd = add_watch(self.fd, path, flags)
        self.callbacks[wd] = callback
        return wd

    def unregister(self, wd):
        del self.callbacks[wd]
        rm_watch(self.fd, wd)


def run_loop(loop):
    try:
        loop.run_forever()
    finally:
        loop.close()


def main(path):
    loop = get_event_loop()
    m = Monitor(loop)

    def callback(e):
        print(e.name)

    m.register(path, IN_CREATE | IN_MOVED_TO, callback)
    run_loop(loop)


if __name__ == '__main__':
    import sys
    main(sys.argv[1])
