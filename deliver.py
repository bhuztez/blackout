#!/usr/bin/env python3

import smtplib
import os
from email import message_from_binary_file
from asyncio import get_event_loop

import inotify


def deliver(server, path, name):
    cur_path = os.path.join(path, 'cur', name)
    new_path = os.path.join(path, 'new', name)

    if not os.path.exists(new_path):
        return

    if not os.path.exists(cur_path):
        try:
            os.link(new_path, cur_path)
        except FileExistsError:
            pass

    with open(new_path, 'rb') as f:
        msg = message_from_binary_file(f)

    msg['Message-ID'] = '<%s>'%(name)

    server.sendmail("user", ["user"], msg.as_bytes())
    os.unlink(new_path)


def run_loop(loop):
    try:
        loop.run_forever()
    finally:
        loop.close()


def main(path):
    loop = get_event_loop()
    m = inotify.Monitor(loop)

    server = smtplib.LMTP(os.path.join(path, "dovecot", "lmtp"))
    server.set_debuglevel(1)

    def callback(e):
        deliver(server, path, e.name)

    m.register(os.path.join(path, 'new'), inotify.IN_MOVED_TO, callback)

    for name in os.listdir(os.path.join(path, 'new')):
        deliver(server, path, name)

    run_loop(loop)
    server.quit()

if __name__ == '__main__':
    import sys
    main(os.path.abspath(sys.argv[1]))
