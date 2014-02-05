#!/usr/bin/env python

default_port = 10000

# a list of often used SCTP ports

sctp_ports = [1,
             7,       # echo
             9,       # discard
             20,      # ftp-data
             21,      # ftp
             22,      # ssh
             80,      # http
             100,
             128,
             179,     # bgp
             260,
             250,
             443,     # https
             1167,    # cisco-ipsla - Cisco IP SLAs Control Protocol
             1812,    # radius
             2097,
             2000,    # Huawei UMG8900 MGW H248 port
             2001,    # Huawei UMG8900 MGW H248 port
             2010,    # Huawei UMG8900 MGW H248 port
             2011,    # Huawei UMG8900 MGW H248 port
             2020,    # Huawei UMG8900 MGW H248 port
             2021,    # Huawei UMG8900 MGW H248 port
             2100,    # Huawei UMG8900 MGW H248 port
             2110,    # Huawei UMG8900 MGW H248 port
             2120,    # Huawei UMG8900 MGW H248 port
             2225,    # rcip-itu -- Resource Connection Initiation Protocol
             2427,    # mgcp-gateway - MGCP and SGCP -- http:#en.wikipedia.org/wiki/Media_Gateway_Control_Protocol
             2477,
             2577,    # Test configuration for Cisco AS5400 products (SCTP/IUQ/Q931)
             2904,    # m2ua -- http:#www.pt.com/tutorials/iptelephony/tutorial_voip_mtp.html , then mtp2, mtp3, sccp  (default for Huawei UMG8900 MGW)
             2905,    # m3ua -- http:#www.ietf.org/rfc/rfc3332.txt - http:#www.hssworld.com/voip/stacks/sigtran/Sigtran_M3UA/overview.htm
             2906,    # m3ua common config port
             2907,    # m3ua -- py sms m3ua default ports
             2908,    # m3ua -- py sms m3ua default ports
             2909,    # m3ua common config port
             2944,    # megaco-h248 - Megaco-H.248 text
             2945,    # h248-binary - Megaco/H.248 binary (default for Huawei UMG8900 MGW)
             3000,    # m3ua common port
             3097,    # ITU-T Q.1902.1/Q.2150.3
             3565,    # m2pa -- http:#rfc.archivesat.com/rfc4166.htm
             3740,    # ayiya -- http:#unfix.org/~jeroen/archive/drafts/draft-massar-v6ops-ayiya-01.txt
             3863,    # RSerPool's ASAP protocol -- http:#tdrwww.iem.uni-due.de/dreibholz/rserpool/
             3864,    # RSerPool's ENRP protocol (asap-sctp/tls) -- http:#tdrwww.iem.uni-due.de/dreibholz/rserpool/
             3868,    # Diameter
             4000,    # m3ua common port
             4739,    # IPFIX (IP Flow Info Export) default port -- http:#tools.ietf.org/wg/ipfix/
             4740,    # IPFIX (IP Flow Info Export) over DTLS default port -- http:#tools.ietf.org/wg/ipfix/
             5000,
             5001,
             5060,    # SIP - Session Initiation Protocol
             5061,    # sip-tls
             5090,    # car - Candidate Access Router Discovery (CARD) -- http:#rfc.net/rfc4066.html
             5091,    # cxtp - Context Transfer Protocol -- http:#rfc.net/rfc4067.html
             5672,    # AMQP
             5675,    # v5ua,  V5UA (V5.2-User Adaptation) Layer -- http:#rfc.archivesat.com/rfc4166.htm
             6000,
             6100,    # Huawei UMG8900 MGW config
             6110,    # Huawei UMG8900 MGW config
             6120,    # Huawei UMG8900 MGW config
             6130,    # Huawei UMG8900 MGW config
             6140,    # Huawei UMG8900 MGW config
             6150,    # Huawei UMG8900 MGW config
             6160,    # Huawei UMG8900 MGW config
             6170,    # Huawei UMG8900 MGW config
             6180,    # Huawei UMG8900 MGW config
             6190,    # Huawei UMG8900 MGW config
             6529,    # Non standard V5 & IUA port -- from port 6005
             6700,    # SCTP based TML (Transport Mapping Layer) for ForCES protocol -- http:#www.ietf.org/id/draft-ietf-forces-sctptml-05.txt
             6701,    # SCTP based TML (Transport Mapping Layer) for ForCES protocol -- http:#www.ietf.org/id/draft-ietf-forces-sctptml-05.txt
             6702,    # SCTP based TML (Transport Mapping Layer) for ForCES protocol -- http:#www.ietf.org/id/draft-ietf-forces-sctptml-05.txt
             6789,    # iua test port for some CISCO default configurations
             6790,    # iua test port for some CISCO default configurations
             7000,    # MTP3 / BICC
             7001,    # Common M3UA port
             7102,    # found in the wild
             7103,    # found in the wild
             7105,    # found in the wild
             7551,    # found in the wild
             7626,    # simco - SImple Middlebox COnfiguration (SIMCO)
             7701,    # found in the wild
             7800,    # found in the wild
             8000,    # found in the wild, MTP3 / BICC
             8001,    # found in the wild
             8471,    # pim-port PIM over Reliable Transport
             8787,    # iua test port for some CISCO default configurations
             9006,    # tunneling?
             9084,    # IBM AURORA Performance Visualizer
             9899,    # sctp-tunneling, actually is usually tcp/udp based but could come from human error
             9911,    # iua test port for some CISCO default configurations
             9900,    # sua (SCCP User Adaptation layer) or iua (ISDN Q.921 User Adaptation -- http:#rfc.archivesat.com/rfc4166.htm)  (default for Huawei UMG8900 MGW)
             9901,    # enrp-sctp - enrp server channel
             9902,     # enrp-sctp-tls - enrp/tls server channel 
             10000,
             10001,
             11146,    # Local port for M3UA, Cisco BTS 10200 Softswitch
             11997,    # wmereceiving - WorldMailExpress 
             11998,    # wmedistribution - WorldMailExpress 
             11999,    # wmereporting - WorldMailExpress 
             12205,    # Local port for SUA, Cisco BTS uses for FSAIN communication is usually 12205,
             12235,    # Local port for SUA, Cisco BTS usage for FSPTC
             13000,    # m3ua -- py sms m3ua default ports
             13001,    # m3ua -- py sms m3ua default ports
             14000,    # m3ua common port, m2pa sometimes too
             14001,    # sua, SUA (SS7 SCCP User Adaptation) Layer -- http:#rfc.archivesat.com/rfc4166.htm , m3ua sometimes too
             20049,    # nfsrdma Network File System (NFS) over RDMA
             29118,    # SGsAP in 3GPP
             29168,    # SBcAP in 3GPP, [TS 29.168][Kymalainen]           2009-08-20
             30000,
             32905,    # m3ua common port
             32931,
             32768,
             36412,    # S1AP
             36422,    # X2AP
             ]
