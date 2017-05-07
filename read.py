#!/usr/bin/env python3

import poplib
from email import message_from_bytes

def main(port):
    server = poplib.POP3('127.0.0.1', port)
    server.set_debuglevel(1)
    server.user('user')
    server.pass_('secret')

    for i, _ in enumerate(server.list()[1]):
        _, lines, _ = server.retr(i+1)
        print(message_from_bytes(b'\n'.join(lines)))


if __name__ == '__main__':
    import sys
    main(int(sys.argv[1]))
