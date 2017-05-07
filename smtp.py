#!/usr/bin/env python3

import asyncore
import smtpd
from email import message_from_bytes
import hashlib
import os

class SMTPServer(smtpd.SMTPServer):

    def __init__(self, port, path):
        super().__init__(('127.0.0.1', port), None, enable_SMTPUTF8=True)
        self.path = path

        os.makedirs(os.path.join(path, 'cur'), exist_ok=True)
        os.makedirs(os.path.join(path, 'new'), exist_ok=True)
        os.makedirs(os.path.join(path, 'tmp'), exist_ok=True)

    def process_message(self, peer, mailfrom, rcpttos, data, **kwargs):
        msg = message_from_bytes(data)
        del msg['Message-ID']
        data = msg.as_bytes()
        name = hashlib.sha256(data).hexdigest()

        path = self.path

        with open(os.path.join(path, 'tmp', name), 'xb') as f:
            f.write(data)

        os.rename(os.path.join(path, 'tmp', name), os.path.join(path, 'new', name))
        os.link(os.path.join(path, 'new', name), os.path.join(path, 'cur', name))


def main(port, path):
    SMTPServer(port, path)

    try:
        asyncore.loop()
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    import sys
    main(int(sys.argv[1]), sys.argv[2])
