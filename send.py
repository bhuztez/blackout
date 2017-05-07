#!/usr/bin/env python3

import smtplib
from email.message import EmailMessage
from email.utils import make_msgid, formatdate


def main(port):
    msg = EmailMessage()
    msg.set_content('content')
    msg['Subject'] = 'Subject'
    msg['From'] = 'alice@example.com'
    msg['To'] = 'bob@example.com'
    msg['Message-ID'] = make_msgid()
    msg['Date'] = formatdate(localtime=True)

    server = smtplib.SMTP('127.0.0.1', port)
    server.set_debuglevel(1)
    server.send_message(msg)
    server.quit()


if __name__ == '__main__':
    import sys
    main(int(sys.argv[1]))
