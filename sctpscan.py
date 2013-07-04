#!/usr/bin/env python
# encoding: utf-8

import sys
import sctp
import socket
import binascii
from IPy import IP

import ports

def bind_socket(soc, port):
    while True:
        try:
            soc.bind(('0.0.0.0', port))
        except socket.error, e:
            if port == ports.default_port:
                raise e
            port = ports.default_port
            print e
            continue
        break

def main(iprange):

    for ip in IP(iprange):
        for port in ports.sctp_ports:

            soc = sctp.sctpsocket_tcp(socket.AF_INET)

            if ip.strNormal().split('.')[0] != '127':
                # Enable port mirroring for remote hosts
                try:
                    bind_socket(soc, port)
                except socket.error, e:
                    print e

            try:
                soc.connect((ip.strNormal(), port))
                print 'SCTP Port Open: %s' % port
            except socket.error, e:
                pass
            soc.close()

if __name__ == '__main__':
    if not len(sys.argv) == 2:
        print 'usage %s: IP' % sys.argv[0]
        exit(1)
    main(sys.argv[1])
