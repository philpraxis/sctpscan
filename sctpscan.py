#!/usr/bin/env python
# encoding: utf-8

import sys
import sctp
import socket
import select
import binascii
import resource
from IPy import IP

import ports

def bind_socket(soc, port):
    while True:
        try:
            soc.bind(('0.0.0.0', port))
        except socket.error, e:
            if port == ports.default_port:
                raise e
            print 'Cant bind mirror port %s, use %s instead' % (port, ports.default_port)
            port = ports.default_port
            continue
        break

def main(iprange):

    timeout = 3
    resource.setrlimit(resource.RLIMIT_NOFILE, (4096, 4096))

    for ip in IP(iprange):
        slist = []
        opened = closed = filtered = 0
        print 'Scanning %s' % ip
        for port in ports.sctp_ports:

            soc = sctp.sctpsocket_tcp(socket.AF_INET)

            if ip.strNormal().split('.')[0] != '127':
                # Enable port mirroring for remote hosts
                try:
                    bind_socket(soc, port)
                except socket.error, e:
                    print 'Cant bind default port %s, use kernel attributed source port' % ports.default_port

            # Use non blocking sockets + select to scan in parallel
            soc.settimeout(timeout)
            soc.setblocking(0)
            try:
                soc.connect((ip.strNormal(), port))
            except socket.error, e:
                pass
            slist.append(soc)

        while True:
            rlist, wlist, xlist = select.select([], slist, [], 1)
            if not rlist and not wlist and not xlist:
                break
            for soc in wlist:
                try:
                    # If we can get remote IP/port, then port is opened
                    name = soc.getpeername()
                    print 'SCTP Port Open: %s %s' % soc.getpeername()
                    opened += 1
                except socket.error, e:
                    # If we cant get remote IP/port, then port is closed
                    closed += 1
                    pass
                soc.close()
                slist.remove(soc)

        # Contains filtered ports, or closed ports that were too slow to reply
        for soc in slist:
            filtered += 1
            soc.close()

        print 'Results: %s opened, %s closed, %s filtered' % (opened, closed, filtered)

if __name__ == '__main__':
    if not len(sys.argv) == 2:
        print 'usage %s: IP' % sys.argv[0]
        exit(1)
    main(sys.argv[1])
