#!/usr/bin/env python
# encoding: utf-8

import sctp
import socket
import binascii

import ports

def bind_socket(soc, port):
    while True:
        try:
            soc.bind(('127.0.0.2', port))
        except socket.error, e:
            if port == ports.default_port:
                raise e
            port = ports.default_port
            print e
            continue
        break

for port in ports.sctp_ports:

    # print port
    soc = sctp.sctpsocket_tcp(socket.AF_INET)

    try:
        bind_socket(soc, port)
    except socket.error, e:
        print e

    try:
        soc.connect(('127.0.0.1', port))
        print 'SCTP Port Open: %s' % port
    except socket.error, e:
        pass
    soc.close()
