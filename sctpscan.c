//
// SCTPscan, SCTP protocol scanner, part of SIGTRanalyzer Security Suite, TSTF Research
// (C) Philippe Langlois, Telecom Security Task Force (pl@tstf.net)
// September, 1, 2002 - 2009
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
//
// $Date: 2007-03-06 13:36:10 +0100 (Tue, 06 Mar 2007) $
// $Revision: 83 $
// $Author: phil $
// $Id: sctpscan.c 83 2007-03-06 12:36:10Z phil $

// Compile:
// cc -g sctpscan.c -o sctpscan -I /usr/include/glib-2.0/ -I /usr/lib/glib-2.0/include/ -lglib-2.0
//
// On MacOSX:
// cc -g sctpscan.c -o sctpscan -L/sw/lib/ -I /sw/include/glib-2.0/ -I /sw/lib/glib-2.0/include/ -lglib-2.0
// (it seems that on some Tiger install, the glib2.0 path is not accessible to non-priviledged users, 
// check this in case of problem), or manually add the path to the added libraries, in this case:
//
// Compile Problems:
// Q: I get tons of errors when compiling... unknown reference to .h files
// A: You are missing some files. Maybe you should do something like:
//    this on Debian/Ubuntu: apt-get install libglib2.0-dev libc6-dev
//    this on MacOSX/Darwin: fink install glib2-dev
//    On some bare bone systems, you don't have these packages/files and it's required to compile SCTPscan
//
// Compile Problems:
// Q: I try to run the Dummy SCTP server for testing, and I get: "socket: Socket type not supported"
// A: Your kernel does not support SCTP sockets. 
//    	SCTP sockets are supported by Linux Kernel 2.6 or Solaris 10.
//    For Linux, you may want to try as root something like: modprobe sctp
//    	Then rerun: sctpscan --dummyserver
//    	Note: you only need a SCTP-aware kernel to run dummyserver. 
//    	Scanning is ok with 2.4 linux kernels!
//    For Mac Os X, you may add support for SCTP in Tiger 10.4.8 by downloading:
//	http://sctp.fh-muenster.de/sctp-nke.html
//	Install the software package and run as root:
//	  kextload /System/Library/Extensions/SCTP.kext
//	Then you can run "sctpscan -d" to run the dummy server.
//	Note that "netstat" won't report the use of the SCTP socket, use instead:
//	   lsof -n | grep -i '132?'
//
// In case of questions, requests etc...
// IRC Server:	irc.freenode.net
// Channel:	#tstf

// VERSION HISTORY
//
// v1: added -Frequent or -F to scan for frequently used ports in SCTP
// 
// v2: added select() before writing, 
//     option to display the list of ports.
// 
// v3: ICMP code display in decimal, not hexadecimal
//     SCTP packets display finally working
// 
// v4: personnalized, 
//     removed ref to sctpping
//     password protection
// 
// v5: changed usage location tracking to wave with FPID as dest port: 48888+FPID
// 
// v6:
//     added mode for autoportscan live SCTP hosts
//     added new common ports in Frequent Ports to scan: 7102, 7103, 7105, 7551, 7701, 7800, 8001
//     added a mode for autoportscan when doing frequent portscan during a netscan (hehe... just that, hope you get it)
//     added command line read of the IP to scan with a given scan (-i)
//
// v7: added scan option for class A, B, C, ... scans
//
// v8: add the differentiation between packets for this host to do portscan and residual packets from previous scanned host
//	
// v9: added automatic inferface lookup, can be enhanced
//     add the interface and ip address detection at each start of C-Class scan or start of program
//     added ICMP packet type decoding
//     added SHUTDOWN_ACK type of scan :) like NULL scan of nmap but for SCTP ;-)
//
// v10:
//     fixed the autoportscan bug that took the currently scanned host to portscan
//		instead of portscanning the host that last replied some SCTP packet
//     added put autoportscan on Frequent ports only when doing netscan's: useful to cut down on time
//     added management of ICMP coming from router:
//		Portscanning 193.153.0.252
//		ICMP packet from 193.153.0.245: Host Unreachable (type=3 code=1)
//     added portscanning when we receive an ICMP Port Unreachable
//	        which can show a TCP/IP stack responding with ICMP to SCTP on empty port
//
// v11:
//	now if GLIB is present, you can have multiple hosts to portscan remembered, and never 2 portscan of the same host
//	compact mode reporting shows now an interesting compact output of a scan, useful in portscans
//	added some statistics of duration
//	added some detailed reporting of what's being scanned
//
// v12:
//	SCTPscan now doesn't print INIT/SHUTDOWN_ACK packets it just sent to its local address (bugfix #101)
//	By default, when scanning, we send both INIT and SHUTDOWN_ACK (feat #103)
//	Collaborative reporting of scan results (feat #104)
//	Zombie (-Z) option: disable reporting and collaboration (feat #105)
//	Services listing in Frequent port tables (feat #106)
//	Corrected missing Zombie option (bugfix #107) [revision 32.]
//	Dummy server mode (for testing only) (feat #108) [revision 33.]
//	Execution of external command on new SCTP port (--exec / -E) (feat #109) [revision 34.]
//	Version & revision reporting (feat #110) [revision 48.]
//	Added compile instructions for MacOSX [revision 58.]
//	Added default ports 3863 (RSerPool's ASAP protocol), 3864 (RSerPool's ENRP protocol),
//	   4739 (IPFIX default port) [revision 66.]
//	FreeBSD port (not fully tested, to be confirmed) [revision 66.]
//	using 0.0.0.0 / :: as default address (autodetermination) [revision 67.]
//	Fixed use of 0.0.0.0 [revision 78.]
//	Verified MacOSX support: fully working (scanner and dummy server with SCTP NKE Kernel Extensions), no need for libpcap [revision 78.]
//	Initial version with libpcap prototype. Does not yet decode the SCTP packets with libpcap. (Still needs to be done, anyone?)

//
// BUG:
//	Doesn't see returned packets if the SCTP kernel support is present
//		Need libpcap support to circumvent this.
//	Doesn't scan correctly with -B (both) scan fashion... only SHUTDOWN_ACKs are sent....
//		anyway, this scan method is kind of useless since it doesn't show open ports... 
//		Just mention SCTP presence
//	Bug in received packet statistics: says it received one SCTP packets when it never actually 
//		reveived one, but received an INIT packet sent to itself.
//

// TODO:
//	Add port-mirror, port-mirror-minus-1, port-mirror-plus-1, -M 0<default>,1,2,... : tries to mirror port, or to mirror 1 port above or below, ...
//	Test SCTPlib examples programs
//	Add Connection parameter scanning in TCPbridge
//	Add Abort Cause code in the Abort display message
//	Add display of INIT/Other packets coming toward us we did not expect (any packet)
//	Add information gathering on multiple addresses disclosure in case of multihomed target
//	Add Payload Protocol Identifier adjustment (IUA==1, V5UA==6, )
//	Add SCTP Tunneling protoccol TCP-port syn scanning
//	Add libpcap support for *BSD distribution
//	Server-side hide of reporting IP address if UID owner has set privacy/anon mode
//	Scan-run random ID reporting string
//	Tag ID reporting string
//	server-side UID generation, client side UID storage
//	Add reporting of scanned C-class netblock
//	Add server side validation of already scanned zone.
//	Add public access to the SCTP collaboration platform
// 
//	enhance the setting/auto-setting of scan timeouts & waits / MODE
//	add fuzzy logic control on packet emission delays
//
//	IPv6 support would be very nice. 
//	specify multiple local addresses to test the multi-homing (sctp_bindx()).
//	specify a port range
//	improve fuzzing/fingerprinting (ECN support, supported address types, Add-IP, 
//	  Authentication, PR-SCTP, Stream Reset, maximum number of in and out streams)
//

// Sample Usage:

// Kernel support for SCTP sockets can have adverse effect with our scanning results

// Under Linux 2.6 kernel
// 
// [root@nubuntu] ./sctpscan -s -r 192.168.0 -p 10000
// Netscanning with Crc32 checksumed packet
// 192.168.0.3 SCTP present on port 10000
// SCTP packet received from 192.168.0.4 port 10000 type 1 (Initiation (INIT))
// End of scan: duration=5 seconds packet_sent=254 packet_rcvd=205 (SCTP=2, ICMP=203)
// [root@nubuntu] uname -a
// Linux nubuntu 2.6.17-10-386 #2 Fri Oct 13 18:41:40 UTC 2006 i686 GNU/Linux
// [root@nubuntu] 
//
// If after this scan, we test the dummy server SCTP daemon built in SCTPscan, 
// we'll notice that further scans from this host will have different behaviours.
// 
// [root@nubuntu] ./sctpscan -d
// Trying to bind SCTP port
// Listening on SCTP port 10000
// ^C    
// [root@nubuntu] 
// [root@nubuntu] 
// [root@nubuntu] ./sctpscan -s -r 192.168.0 -p 10000
// Netscanning with Crc32 checksumed packet
// 192.168.0.3 SCTP present on port 10000
// SCTP packet received from 192.168.0.4 port 10000 type 1 (Initiation (INIT))
// SCTP packet received from 192.168.0.4 port 10000 type 6 (Abort (ABORT))
// End of scan: duration=5 seconds packet_sent=254 packet_rcvd=206 (SCTP=3, ICMP=203)
// [root@nubuntu] 
// 

// 
// Under Mac OS X:
// 
// localhost:~/Documents/sctpscan/ root# kextload /System/Library/Extensions/SCTP.kext
// kextload: /System/Library/Extensions/SCTP.kext loaded successfully
// localhost:~/Documents/sctpscan/ root# ./sctpscan -s -r 192.168.0 -p 10000
// Netscanning with Crc32 checksumed packet
// End of scan: duration=9 seconds packet_sent=254 packet_rcvd=3 (SCTP=0, ICMP=3)
// localhost:~/Documents/sctpscan/ root# kextunload /System/Library/Extensions/SCTP.kext
// kextunload: unload kext /System/Library/Extensions/SCTP.kext succeeded
// localhost:~/Documents/sctpscan/ root# ./sctpscan -s -r 192.168.0 -p 10000
// Netscanning with Crc32 checksumed packet
// SCTP packet received from 127.0.0.1 port 10000 type 1 (Initiation (INIT))
// 192.168.0.4 SCTP present on port 10000
// End of scan: duration=9 seconds packet_sent=254 packet_rcvd=5 (SCTP=2, ICMP=3)
// localhost:~/Documents/sctpscan/ root# 
// 
// You saw in this example that loading the SCTP kernel module prevents SCTPscan to receive
// the response packets, and thus is not capable to detect presence of a remote open port.
// 

// strss7 :
// ports: 10000, 10001, 10002
//
// lksctp-2_5_29-0_5_0:
// test/funtest.h ports: 
//	SCTP_TESTPORT_1 1024
//	SCTP_TESTPORT_2 (SCTP_TESTPORT_1+1)
//	SCTP_TESTPORT_FOO (SCTP_TESTPORT_1+0xFF)
//
//  tcpdump -s 1500 -i lo proto 132 -n &");
//  tcpdump -s 1500 -i eth0 proto 132 -n &");
//
//tcpdump -i ppp0 'icmp[0] != 8 and icmp[0] != 0' -n
//tcpdump -i eth0 -s 1500 -n ip proto 132 or icmp -w pcapfile.$$

#ifdef __linux__
#define HAVE_STROPTS_H
#define USE_GLIB_20_H
#define HAVE_LINUX_SOCKIOS_H
#endif

#ifdef __APPLE__
#define USE_GLIB_H
#endif

#ifdef __FreeBSD__
#define USE_GLIB_H
#define HAVE_NETINET_IP_SYSTM_H
#include <osreldate.h>
#if __FreeBSD_version >= 700028
// Uncomment for now, the struct sctphdr in this file is not
// the same as in <netinet/sctp.h>
//  define HAVE_NETINET_SCTP_H
#endif

#endif

#define __USE_BSD	/* use bsd'ish ip header */
#include <sys/types.h>
#include <sys/socket.h>	/* these headers are for a Linux system, but */
#ifdef HAVE_NETINET_IP_COMPAT_H
#include <netinet/ip_compat.h>
#endif
#ifdef HAVE_NETINET_IP_SYSTM_H
#include <netinet/in_systm.h>
#endif

#include <netinet/in.h>	/* the names on other systems are easy to guess.. */
#include <netinet/ip.h>
#define __FAVOR_BSD	/* use bsd'ish tcp header */
#include <netinet/tcp.h>
#include <arpa/inet.h>

#if defined(HAVE_SCTP_H)
#include <sctp.h>
#endif

#if defined(HAVE_NETINET_SCTP_H)
#include <netinet/sctp.h>
#endif

#if defined(HAVE_INET_IP_H)
#include <inet/ip.h>
#endif

#if defined(HAVE_STDIN_H)
#include <stdin.h>
#endif 

#ifdef __linux__
#define __FAVOR_BSD				/* should be __FAVOUR_BSD ;) */
#ifndef _USE_BSD
#define _USE_BSD
#endif
#endif
#include <netinet/ip_icmp.h>	// Problem with Solaris

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__sun__)
#define ICMP_DEST_UNREACH ICMP_UNREACH_HOST
#define ICMP_PORT_UNREACH ICMP_UNREACH_PORT
#endif

#include <unistd.h>
#include <netdb.h>
#include <stdlib.h>
#include <stdio.h>
#ifdef HAVE_STROPTS_H
#include <stropts.h>
#endif 
#include <getopt.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <ctype.h>

#include <net/if.h>
#if defined(HAVE_LINUX_SOCKIOS_H)
#include </usr/include/linux/sockios.h>
#endif
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <signal.h>

#if defined(USE_GLIB_H)
#include <glib.h>
#elif defined(USE_GLIB_20_H)
#include <glib-2.0/glib.h>
#endif

#ifdef HAVE_PCAP
#include <pcap.h>

#define SNAP_LEN 65535
#define PROMISC 1
#define NO_PROMISC 0
#define PCAP_TIMEOUT 100

#endif

#ifndef IPPROTO_RAW
#define IPPROTO_RAW	255
#endif

#ifndef IPPROTO_ICMP
#define IPPROTO_ICMP	1
#endif

#ifndef IPPROTO_SCTP
#define IPPROTO_SCTP	132
#endif

/* 
 * SCTP Checksum functions
 */

/* The following code has been taken from
 * draft-ietf-tsvwg-sctpcsum-03.txt
 * as in lksctp (SCTP reference implementation)
 */

#ifdef linux
#include <linux/types.h>
#endif
     
#define CRC32C_POLY 0x1EDC6F41 
#define CRC32C(c,d) (c=(c>>8)^crc_c[(c^(d))&0xFF]) 
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */ 
/* Copyright 2001, D. Otis.  Use this program, code or tables    */ 
/* extracted from it, as desired without restriction.            */ 
/*                                                               */ 
/* 32 Bit Reflected CRC table generation for SCTP.               */ 
/* To accommodate serial byte data being shifted out least       */ 
/* significant bit first, the table's 32 bit words are reflected */ 
/* which flips both byte and bit MS and LS positions.  The CRC   */ 
/* is calculated MS bits first from the perspective of the serial*/ 
/* stream.  The x^32 term is implied and the x^0 term may also   */ 
/* be shown as +1.  The polynomial code used is 0x1EDC6F41.      */ 
/* Castagnoli93                                                  */ 
/* x^32+x^28+x^27+x^26+x^25+x^23+x^22+x^20+x^19+x^18+x^14+x^13+  */ 
/* x^11+x^10+x^9+x^8+x^6+x^0                                     */ 
/* Guy Castagnoli Stefan Braeuer and Martin Herrman              */ 
/* "Optimization of Cyclic Redundancy-Check Codes                */ 
/* with 24 and 32 Parity Bits",                                  */ 
/* IEEE Transactions on Communications, Vol.41, No.6, June 1993  */ 
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */ 
unsigned long  crc_c[256] = 
  { 
    0x00000000L, 0xF26B8303L, 0xE13B70F7L, 0x1350F3F4L,  
    0xC79A971FL, 0x35F1141CL, 0x26A1E7E8L, 0xD4CA64EBL,  
    0x8AD958CFL, 0x78B2DBCCL, 0x6BE22838L, 0x9989AB3BL,  
    0x4D43CFD0L, 0xBF284CD3L, 0xAC78BF27L, 0x5E133C24L,  
    0x105EC76FL, 0xE235446CL, 0xF165B798L, 0x030E349BL,  
    0xD7C45070L, 0x25AFD373L, 0x36FF2087L, 0xC494A384L,  
    0x9A879FA0L, 0x68EC1CA3L, 0x7BBCEF57L, 0x89D76C54L,  
    0x5D1D08BFL, 0xAF768BBCL, 0xBC267848L, 0x4E4DFB4BL,  
    0x20BD8EDEL, 0xD2D60DDDL, 0xC186FE29L, 0x33ED7D2AL,  
    0xE72719C1L, 0x154C9AC2L, 0x061C6936L, 0xF477EA35L,  
    0xAA64D611L, 0x580F5512L, 0x4B5FA6E6L, 0xB93425E5L,  
    0x6DFE410EL, 0x9F95C20DL, 0x8CC531F9L, 0x7EAEB2FAL,  
    0x30E349B1L, 0xC288CAB2L, 0xD1D83946L, 0x23B3BA45L,  
    0xF779DEAEL, 0x05125DADL, 0x1642AE59L, 0xE4292D5AL,  
    0xBA3A117EL, 0x4851927DL, 0x5B016189L, 0xA96AE28AL,  
    0x7DA08661L, 0x8FCB0562L, 0x9C9BF696L, 0x6EF07595L,  
    0x417B1DBCL, 0xB3109EBFL, 0xA0406D4BL, 0x522BEE48L,  
    0x86E18AA3L, 0x748A09A0L, 0x67DAFA54L, 0x95B17957L,  
    0xCBA24573L, 0x39C9C670L, 0x2A993584L, 0xD8F2B687L,  
    0x0C38D26CL, 0xFE53516FL, 0xED03A29BL, 0x1F682198L,  
    0x5125DAD3L, 0xA34E59D0L, 0xB01EAA24L, 0x42752927L,  
    0x96BF4DCCL, 0x64D4CECFL, 0x77843D3BL, 0x85EFBE38L,  
    0xDBFC821CL, 0x2997011FL, 0x3AC7F2EBL, 0xC8AC71E8L,  
    0x1C661503L, 0xEE0D9600L, 0xFD5D65F4L, 0x0F36E6F7L,  
    0x61C69362L, 0x93AD1061L, 0x80FDE395L, 0x72966096L,  
    0xA65C047DL, 0x5437877EL, 0x4767748AL, 0xB50CF789L,  
    0xEB1FCBADL, 0x197448AEL, 0x0A24BB5AL, 0xF84F3859L,  
    0x2C855CB2L, 0xDEEEDFB1L, 0xCDBE2C45L, 0x3FD5AF46L,  
    0x7198540DL, 0x83F3D70EL, 0x90A324FAL, 0x62C8A7F9L,  
    0xB602C312L, 0x44694011L, 0x5739B3E5L, 0xA55230E6L,  
    0xFB410CC2L, 0x092A8FC1L, 0x1A7A7C35L, 0xE811FF36L,  
    0x3CDB9BDDL, 0xCEB018DEL, 0xDDE0EB2AL, 0x2F8B6829L,  
    0x82F63B78L, 0x709DB87BL, 0x63CD4B8FL, 0x91A6C88CL,  
    0x456CAC67L, 0xB7072F64L, 0xA457DC90L, 0x563C5F93L,  
    0x082F63B7L, 0xFA44E0B4L, 0xE9141340L, 0x1B7F9043L,  
    0xCFB5F4A8L, 0x3DDE77ABL, 0x2E8E845FL, 0xDCE5075CL,  
    0x92A8FC17L, 0x60C37F14L, 0x73938CE0L, 0x81F80FE3L,  
    0x55326B08L, 0xA759E80BL, 0xB4091BFFL, 0x466298FCL,  
    0x1871A4D8L, 0xEA1A27DBL, 0xF94AD42FL, 0x0B21572CL,  
    0xDFEB33C7L, 0x2D80B0C4L, 0x3ED04330L, 0xCCBBC033L,  
    0xA24BB5A6L, 0x502036A5L, 0x4370C551L, 0xB11B4652L,  
    0x65D122B9L, 0x97BAA1BAL, 0x84EA524EL, 0x7681D14DL,  
    0x2892ED69L, 0xDAF96E6AL, 0xC9A99D9EL, 0x3BC21E9DL,  
    0xEF087A76L, 0x1D63F975L, 0x0E330A81L, 0xFC588982L,  
    0xB21572C9L, 0x407EF1CAL, 0x532E023EL, 0xA145813DL,  
    0x758FE5D6L, 0x87E466D5L, 0x94B49521L, 0x66DF1622L,  
    0x38CC2A06L, 0xCAA7A905L, 0xD9F75AF1L, 0x2B9CD9F2L,  
    0xFF56BD19L, 0x0D3D3E1AL, 0x1E6DCDEEL, 0xEC064EEDL,  
    0xC38D26C4L, 0x31E6A5C7L, 0x22B65633L, 0xD0DDD530L,  
    0x0417B1DBL, 0xF67C32D8L, 0xE52CC12CL, 0x1747422FL,  
    0x49547E0BL, 0xBB3FFD08L, 0xA86F0EFCL, 0x5A048DFFL,  
    0x8ECEE914L, 0x7CA56A17L, 0x6FF599E3L, 0x9D9E1AE0L,  
    0xD3D3E1ABL, 0x21B862A8L, 0x32E8915CL, 0xC083125FL,  
    0x144976B4L, 0xE622F5B7L, 0xF5720643L, 0x07198540L,  
    0x590AB964L, 0xAB613A67L, 0xB831C993L, 0x4A5A4A90L,  
    0x9E902E7BL, 0x6CFBAD78L, 0x7FAB5E8CL, 0x8DC0DD8FL,  
    0xE330A81AL, 0x115B2B19L, 0x020BD8EDL, 0xF0605BEEL,  
    0x24AA3F05L, 0xD6C1BC06L, 0xC5914FF2L, 0x37FACCF1L,  
    0x69E9F0D5L, 0x9B8273D6L, 0x88D28022L, 0x7AB90321L,  
    0xAE7367CAL, 0x5C18E4C9L, 0x4F48173DL, 0xBD23943EL,  
    0xF36E6F75L, 0x0105EC76L, 0x12551F82L, 0xE03E9C81L,  
    0x34F4F86AL, 0xC69F7B69L, 0xD5CF889DL, 0x27A40B9EL,  
    0x79B737BAL, 0x8BDCB4B9L, 0x988C474DL, 0x6AE7C44EL,  
    0xBE2DA0A5L, 0x4C4623A6L, 0x5F16D052L, 0xAD7D5351L,  
  }; 

uint32_t 
count_crc(uint8_t *buffer, uint16_t length)
{	
  unsigned int i;
  unsigned long crc32 = ~0L; 
  unsigned long result;
  unsigned char byte0, byte1, byte2, byte3;
     
  /* Calculate the CRC. */
  for (i = 0; i < length ; i++)
    {
      CRC32C(crc32, buffer[i]);
    }
	
  result = ~crc32;

  /*  result  now holds the negated polynomial remainder;
   *  since the table and algorithm is "reflected" [williams95].
   *  That is,  result has the same value as if we mapped the message
   *  to a polyomial, computed the host-bit-order polynomial
   *  remainder, performed final negation, then did an end-for-end
   *  bit-reversal.  
   *  Note that a 32-bit bit-reversal is identical to four inplace
   *  8-bit reversals followed by an end-for-end byteswap.
   *  In other words, the bytes of each bit are in the right order,
   *  but the bytes have been byteswapped.  So we now do an explicit
   *  byteswap.  On a little-endian machine, this byteswap and 
   *  the final ntohl cancel out and could be elided.
   */
  byte0 = result & 0xff;
  byte1 = (result>>8) & 0xff;
  byte2 = (result>>16) & 0xff;
  byte3 = (result>>24) & 0xff;
	
  crc32 = ((byte0 << 24) |
	   (byte1 << 16) |
	   (byte2 << 8)  |
	   byte3);
  return(crc32);

}  /* count_crc() */


// ---------------------------  TOOLS ------------------------------

/* $Id: sctpscan.c 83 2007-03-06 12:36:10Z phil $ */
/*
** Copyright (C) 2001 Fyodor Yarochkin <fygrave@tigerteam.net>,
**                    Ofir Arkin       <ofir@sys-security.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

/* nifty idea stolen from 'skin'.. better than my own roting sockets
 * magic! ;-) */
 

#ifdef SIOCGIFADDR
struct in_addr xp_get_iface_addr(char *iname) {
    struct ifreq ifr;
    int sd;
    struct in_addr retval;
    struct sockaddr_in *sinaddr;

    if (!iname) {
        retval.s_addr = 0xffffffff; /* error */
        return retval;
    }

    if((sd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket");
        exit(1);
    }

    memset((void *)&ifr, 0, sizeof(struct ifreq));

    strncpy(ifr.ifr_name, iname, sizeof(ifr.ifr_name));

    if (ioctl(sd, SIOCGIFADDR,(char *)&ifr) < 0) {
        perror("ioctl(SIOCGIFADDR)");
        close(sd);
        exit(1); /* interface doesn't exist or your kernel is flacky */
    }
    close(sd);
    sinaddr = (struct sockaddr_in *) &ifr.ifr_addr;
    memcpy((void *)&retval, (void *)&(sinaddr->sin_addr.s_addr),
             sizeof(retval));
    return retval;
}
#endif

struct in_addr xp_get_src_addr(struct in_addr dst) {
	struct sockaddr_in src, remote;
	int sockfd;
	socklen_t socklen;

	remote.sin_family = AF_INET;
	remote.sin_port = htons(1234);
	remote.sin_addr.s_addr = dst.s_addr;
	src.sin_addr.s_addr = 0xffffffff;
	if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("xp_get_src_addr():socket");
		return src.sin_addr;
	}
	if ((connect(sockfd, (struct sockaddr *) &remote, sizeof(remote))) < 0) {
		perror("xp_get_src_addr():connect");
		return src.sin_addr;
	}
	socklen = sizeof(src);
	if ((getsockname(sockfd, (struct sockaddr *) &src, &socklen)) < 0) {
		perror("xp_get_src_addr(): getsockname");
		return src.sin_addr;
	}	
	return src.sin_addr;
}

/*
 * ICMP - RFC 792 - http://www.iana.org/assignments/icmp-parameters
 */

static char *unreach[] = {
  "Network Unreachable",
  "Host Unreachable",
  "Protocol Unreachable",
  "Port Unreachable",
  "Fragmentation needed and DF set",
  "Source Route Failed",
  "Destination Network Unknown",
  "Destination Host Unknown",
  "Source Host Isolated",
  "Communication with Destination Network is Administratively Prohibited",
  "Communication with Destination Host is Administratively Prohibited",
  "Destination Network Unreachable for Type of Service",
  "Destination Host Unreachable for Type of Service",
  "Communication Administratively Prohibited      [RFC1812]",
  "Host Precedence Violation                      [RFC1812]",
  "Precedence cutoff in effect                    [RFC1812]" };

static char *exceed[] = {
  "TTL exceeded in transit",
  "Frag ReAsm time exceeded" };

static char *redirect[] = {
  "Redirect for Network",
  "Redirect for Host",
  "Redirect for TOS and Network",
  "Redirect for TOS and Host" };


char *get_icmp_str(int type, int code)
{
  switch (type)
    {
    case 0 : /* icmp echo reply received */
      return("received icmp echo reply");
      break;
      
    case 3 : /* destination unreachable message */
      if (code < sizeof(unreach)/sizeof(char *) ) {
	return(unreach[code]);
      }
      break;
      
    case 4  : /* source quench */
      return("Source Quench");
      break;
      
    case 5  : /* redirect */
      if (code < sizeof(redirect)/sizeof(char *)) return(redirect[code]);
      break;
      
    case 8  : /* icmp echo request */
      return( "PING requested of us");
      break;
      
    case 11 : /* time exceeded message */
      if (code < sizeof(exceed)/sizeof(char *) ) return(exceed[code]);
      break;
      
    case 12 : /* parameter problem message */
      return("IP Parameter problem");
      break;
      
    case 13 : /* timestamp message */
      return("Timestamp message");
      break;
      
    case 14 : /* timestamp reply */
      return("Timestamp reply");
      break;
      
    case 15 : /* info request */
      return("Info requested");
      break;
      
    case 16 : /* info reply */
      return("Info reply");
      break;
    }
  return("UNKNOWN");
}

// ----- RUN TIME DATA

#ifdef __G_LIB_H__
char *get_cmd_line(int argc, char **argv)
{
  gchar *cmd_line = g_strdup(argv[0]);
  gchar *old_str;
  gint	i;

  for (i = 1; i < argc; i++)
    {
      old_str = cmd_line;
      cmd_line = g_strdup_printf("%s %s", cmd_line, argv[i]);
      g_free(old_str);
    }
  return(cmd_line);
}
#endif

// ----- COLLABORATION

#ifdef __G_LIB_H__

/* #include <glib.h> */
/* #include <glib-2.0/glib.h> */

gboolean collab_http_get_file(gchar *url, gchar *hostname, gint port,
                gchar *filename, gchar *proxy_host, gint proxy_port);
gchar *collab_http_get_buffer(gchar *url, gchar *hostname, gint port,
                gchar *proxy_host, gint proxy_port);

#ifdef DEBUG
  #define DEBUG_PRINT(s, i) fprintf(stderr, s, i);
#else
  #define DEBUG_PRINT(s, i) do {} while(0);
#endif

int collab_http_connect(gchar *hostname, gint port)
{
  struct sockaddr_in dest_host;
  struct hostent *host_address;
  int fd;
  
  if ((host_address = gethostbyname(hostname)) == NULL)
    return(-1);
  
  if ((fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1)
    return(-1);
  
  dest_host.sin_family = AF_INET;
  dest_host.sin_addr = *((struct in_addr *)host_address->h_addr);
  dest_host.sin_port = htons(port);
  memset(&(dest_host.sin_zero), '\0', 8);
  
  if (connect(fd, (struct sockaddr *)&dest_host, sizeof(struct sockaddr)) == -1)
    {
      close(fd);
      return(-1);
    }
  
  return(fd);
}

int collab_http_recv(int fd, gchar **buffer)
{
  int n = 0; /* 1: ok, 0: connection terminated, -1: problem */
  gchar thisbuffer[1024]; 
        
  n = recv(fd, thisbuffer, 1023, 0);

  if (n == -1)
    {
      *buffer = NULL;
    }
  else if (n == 0) 
    {
      *buffer = NULL;
    }
  else 
    {
      thisbuffer[n] = '\0';
      *buffer = g_strdup((const gchar *)thisbuffer); 
    }

  return(n);
}
                
gboolean collab_http_get_header(int fd, gchar **buffer)
{
  gchar lastchar = 0, *thisbuffer;
  int l;
  
  while((l = collab_http_recv(fd, &thisbuffer)) > 0)
    {
      gboolean found = FALSE;
      gchar *where;
      gchar *p;
      
      if (lastchar == '\r' && (p = g_strstr_len(thisbuffer, 3, "\n\r\n"))) 
	{
	  where = p + 3;
	  found = TRUE;
	}
      else if ((p = strstr(thisbuffer, "\r\n\r\n"))) 
	{
	  where = p + 4;
	  found = TRUE;
	}
      if (found)
	{
	  *buffer = g_strdup(where);
	}
      else
	lastchar = thisbuffer[l];
      
      g_free(thisbuffer);
      
      if (found) 
	return(TRUE);
    }

  return(FALSE);
}

gboolean collab_http_get(gchar *url, gchar *hostname, gint port, gboolean savefile, gchar **fname_buff, 
                gchar *proxy_host, gint proxy_port)
{
  int fd, error;
  FILE *file = NULL;
  gchar *buffer = NULL;
  gchar *retstr = NULL;
  gchar *request = NULL;
  
  if (port == 0)
    port = 80;
  if (proxy_host)
    fd = collab_http_connect(proxy_host, proxy_port);
  else
    fd = collab_http_connect(hostname, port); /* used to be 80 */
  
  if (fd == -1)
    return(FALSE);
  
  if (proxy_host)
    request = g_strdup_printf("GET http://%s%s HTTP/1.0\r\n\r\n",
			      hostname, url);
  else
    request = g_strdup_printf("GET %s HTTP/1.0\r\n"
			      "Host: %s\r\n\r\n", url, hostname);
  
  if (request == NULL)
    {
      close(fd);
      return(FALSE);
    }
  
  error = send(fd, request, strlen(request), 0);
  g_free(request);
  
  if (error == -1)
    { 
      close(fd);
      return(FALSE);
    }
  
  if (savefile)
    {
      file = fopen(*fname_buff, "w");
      
      if (!file)
	{
	  DEBUG_PRINT("Error opening file %s\n", *fname_buff);
	  close(fd);
	  return(FALSE);
	}
    }
  
  
  if (collab_http_get_header(fd, &buffer) == FALSE)
    {
      close(fd);
      return(FALSE);
    }
  
  if (buffer)
    {
      int l = strlen(buffer);
      
      if (savefile)
	fwrite(buffer, sizeof(char), l, file);
      else
	retstr = g_strdup(buffer);
      
      g_free(buffer);
    }
  
  while((error = collab_http_recv(fd, &buffer)) > 0)
    {
      if (savefile) 
	{
	  int l = strlen(buffer);
	  fwrite(buffer, sizeof(char), l, file);
	}
      else
	{
	  if (retstr) 
	    {
	      gchar *str;
	      str = g_strconcat(retstr, buffer, NULL);
	      g_free(retstr);
	      retstr = str;
	    }
	  else
	    retstr = g_strdup(buffer);
	}
      g_free(buffer);
    }
  
  if (error == -1)
    {
      fclose(file);
      close(fd);
      g_free(retstr);
      return(FALSE);
    }
  
  if (savefile)
    fclose(file);
  else
    *fname_buff = retstr;
  
  close(fd);
  
  return(TRUE);
}

gboolean collab_http_get_file(gchar *url, gchar *hostname, gint port, gchar *filename, 
			      gchar *proxy_host, gint proxy_port)
{
  return(collab_http_get(url, hostname, port, TRUE, &filename, proxy_host, proxy_port));
}

gchar *collab_http_get_buffer(gchar *url, gchar *hostname, gint port, gchar *proxy_host, gint proxy_port)
{
  gchar *buffer = NULL;
  
  collab_http_get(url, hostname, port, FALSE, &buffer, proxy_host, proxy_port);
  
  return(buffer);
}


#endif


// ---------------------------- END OF TOOLS ---------------------------------



// -------------------- DEFINE'S
#define HOST_BUF_LEN 256
#define READBUFSIZE 1024
#define DEFAULT_SRC_PORT 2905
#define DEFAULT_DST_PORT 2905
//XXX Defined for ADSL
//#define SELECT_TIMEOUT 10000    /* 10000 micro second */
#define SELECT_TIMEOUT 100
#define MAXPACKET 4096
#define P 7777		/* used for destination only */

#ifndef min 
#define min(x,y)      ((x)>(y)?(y):(x)) 
#endif 


// -------------------- PROTOCOL DESCRIPTION
// STRUCTURES
struct sctphdr
{
  /*
    The data types/sizes we need to use are: unsigned char - 1 byte (8 bits),
    unsigned short int - 2 bytes (16 bits) and unsigned int - 4 bytes (32 bits)
  */
  unsigned short int	sport;
  unsigned short int	dport;
  unsigned int		veriftag;
  unsigned int		sctp_sum;
  //unsigned char		identifier;	// type
  //unsigned char		flags;
  //unsigned short int	length;
  // chunk follows
};

struct sctphdr_chunk
{
  unsigned short int	sport;
  unsigned short int	dport;
  unsigned int		veriftag;
  unsigned int		sctp_sum;
  unsigned char		identifier;	// type
  unsigned char		flags;
  unsigned short int	length;
  // chunk follows
};

// chunk identifier 
#define SH_DATA 0
#define SH_INIT 1
#define SH_INIT_ACK 2
#define SH_SACK 3
#define SH_HEARTBEAT 4
#define SH_HEARTBEAT_ACK 5
#define SH_ABORT 6
#define SH_SHUTDOWN_ACK 8
#define SH_COOKIE_ECHO 10
#define SH_COOKIE_ACK 11
#define SH_ECNE 12
#define SH_CWR 13
#define SH_SHUTDOWN_COMPLETE 14

struct chunk_generic
{
  unsigned char		identifier;	// type
  unsigned char		flags;
  unsigned short int	length;
};

struct chunk_init
{
  /*
    The data types/sizes we need to use are: unsigned char - 1 byte (8 bits),
    unsigned short int - 2 bytes (16 bits) and unsigned int - 4 bytes (32 bits)
  */
  unsigned char		identifier;	// type
  unsigned char		flags;
  unsigned short int	length;
  unsigned int		inittag;// same as init_tsn but not in same byteorder
  unsigned int		a_rwnd; // Advertised Receiver Window Credit (a_rwnd) 
  unsigned short int		outstreams;
  unsigned short int		instreams;
  unsigned int		init_tsn;	// same as inittag but not in same byteorder
  // Optional/Variable-Length Parameters follows...
};

struct chunk_shutdown_ack
{
  /*
    The data types/sizes we need to use are: unsigned char - 1 byte (8 bits),
    unsigned short int - 2 bytes (16 bits) and unsigned int - 4 bytes (32 bits)
  */
  unsigned char		identifier;	// type
  unsigned char		flags;
  unsigned short int	length;
};

struct vlparam
{
  unsigned short int	type;
  unsigned short int	length;
  // follows payload which length is above
};
#define VLPARAM_IPV4 htons(0x0005)
#define VLPARAM_COOKIE htons(0x0009)
#define VLPARAM_ADDRTYPE htons(0x000C)

struct vlparam_ip
{
  unsigned short int	type; // 0x0005 for ipv4
  unsigned short int	length;
  unsigned int		ipaddr;
};

struct vlparam_cookie
{
  unsigned short int	type; // 0x0009 for cookie preservative
  unsigned short int	length;
  unsigned int		increment;
};

struct vlparam_supported_addrtype
{
  unsigned short int	type;
  unsigned short int	length;
  unsigned short int	addrtype; // 0x0005 for ipv4
};

// -------------------- PROGRAM SPECIFIC

typedef struct addr
{
  uint16_t	port	__attribute__((packed));
  struct in_addr	addr[1]	__attribute__((packed));
} addr_t;

struct app_s
{
  char *hostl;		// local sending IP
  char *hostr;		// target (destination) IP or range
  
  int sctpscan_version;
  int portscan_opt;
  int netscan_opt;
  int autoportscan_opt;
  int linein_opt;
  int fuzz_opt;
  // both_checksum_opt: 
  // 0 : send only the specified checksum
  // 1 : send both new crc32 and old legacy-driven adler32
  int both_checksum_opt;
  int quiet_sendsctp_opt;
  int frequentportscan_opt;		// Frequents Ports portscan
  int in_portscan;			// indicate if you are indeed in a portscan 0=no, 1=yes
  int compact_opt;
  int zombie_opt;			// Does not contribute reports to collaboration platform. No reporting. (feat 105)
  char *exec_on_port_opt;		// Execution of external command on new SCTP port (--exec / -E) (feat 109)
  int tcp_bridge_opt;			// TCP to SCTP bridge
  
  // Runtime Datas
#ifdef __G_LIB_H__
  gchar *cmd_line;
#endif

  // Checksum: 
  // 3 : Adler32
  // 2 : max value
  // 1 : null
  // 0 : CRC32
  int checksum;

  // Listen Retries & Select Timeout
  int select_timeout_sec;
  int select_timeout_usec;
  int listen_retries;

  // Streams information
  int init_outstreams;
  int init_instreams;

  // Last Fuzz infos
  char fuzzcase_name[255];

  // Fuzz Option Convention: 
  // 0 : default normal behaviour
  // 1 : null value
  // 2 : max value (christmas tree packet)
  // 3+: specific cases
  int fuzz_ip_frag;
  int fuzz_sctp_sport;
  int fuzz_sctp_dport;
  int fuzz_veriftag;
  int fuzz_init_flags;
  int fuzz_init_inittag;
  int fuzz_init_arwnd;
  int fuzz_init_outstreams;
  int fuzz_init_instreams;
  int fuzz_init_inittsn;
  int fuzz_cookie_increment;
  //int fuzz_;

  // Raw Send Socket
  int raw_socket;
  // Receive socket
  int rcv_icmp_socket;
  int rcv_sctp_socket;

  // Current dest addr
  u_int32_t cur_dstaddr;

#ifdef HAVE_PCAP
  pcap_t	*rcv_icmp_pcap;
  int		rcv_icmp_pcap_fd;
  pcap_t	*rcv_sctp_pcap;
  int		rcv_sctp_pcap_fd;
#endif

#define PACKET_TYPE_SH_INIT_PLUS_SH_SHUTDOWN_ACK 1000
  int packet_type;
  // Packet type to send:
  // 	 SH_DATA 0
  // 	 SH_INIT 1
  // 	 SH_INIT_ACK 2
  // 	 SH_SACK 3
  // 	 SH_HEARTBEAT 4
  // 	 SH_HEARTBEAT_ACK 5
  // 	 SH_ABORT 6
  // 	 SH_SHUTDOWN_ACK 8
  // 	 SH_COOKIE_ECHO 10
  // 	 SH_COOKIE_ACK 11
  // 	 SH_SHUTDOWN_COMPLETE 14
  // Combined packet types:
  //	 1000 : SH_INIT + SH_SHUTDOWN_ACK

  // Data structure to hold which hosts to scan
#ifndef __G_LIB_H__
  char host_to_portscan[20];
  char host_already_portscan[20]; // host_already_portscan
#else
  GQueue *host_to_portscan;
  GQueue *host_already_portscan;
#endif

  int ctr_packet_sent;
  int ctr_packet_rcvd;
  int ctr_packet_icmp_rcvd;
  int ctr_packet_sctp_rcvd;
};

typedef struct app_s app_t;

// GLOBALS
int sctp_ports[] = { 1,
		     7,		// echo
		     9,		// discard
		     20,	// ftp-data
		     21,	// ftp
		     22,	// ssh
		     80,	// http
		     100,
		     128,
		     179,	// bgp
		     260,
		     250,
		     443,	// https
		     1167,	// cisco-ipsla - Cisco IP SLAs Control Protocol
		     1812,	// radius
		     2097,
		     2000,	// Huawei UMG8900 MGW H248 port
		     2001,	// Huawei UMG8900 MGW H248 port
		     2010,	// Huawei UMG8900 MGW H248 port
		     2011,	// Huawei UMG8900 MGW H248 port
		     2020,	// Huawei UMG8900 MGW H248 port
		     2021,	// Huawei UMG8900 MGW H248 port
		     2100,	// Huawei UMG8900 MGW H248 port
		     2110,	// Huawei UMG8900 MGW H248 port
		     2120,	// Huawei UMG8900 MGW H248 port
		     2225, 	// rcip-itu -- Resource Connection Initiation Protocol
		     2427,	// mgcp-gateway - MGCP and SGCP -- http://en.wikipedia.org/wiki/Media_Gateway_Control_Protocol
		     2477,
		     2577,	// Test configuration for Cisco AS5400 products (SCTP/IUQ/Q931)
		     2904,	// m2ua -- http://www.pt.com/tutorials/iptelephony/tutorial_voip_mtp.html , then mtp2, mtp3, sccp  (default for Huawei UMG8900 MGW)
		     2905,	// m3ua -- http://www.ietf.org/rfc/rfc3332.txt - http://www.hssworld.com/voip/stacks/sigtran/Sigtran_M3UA/overview.htm
		     2906,	// m3ua common config port
		     2907,	// m3ua -- py sms m3ua default ports
		     2908,	// m3ua -- py sms m3ua default ports
		     2909,	// m3ua common config port
		     2944,	// megaco-h248 - Megaco-H.248 text
		     2945,	// h248-binary - Megaco/H.248 binary (default for Huawei UMG8900 MGW)
		     3000,	// m3ua common port
		     3097,	// ITU-T Q.1902.1/Q.2150.3
		     3565,	// m2pa -- http://rfc.archivesat.com/rfc4166.htm
		     3740,	// ayiya -- http://unfix.org/~jeroen/archive/drafts/draft-massar-v6ops-ayiya-01.txt
		     3863,	// RSerPool's ASAP protocol -- http://tdrwww.iem.uni-due.de/dreibholz/rserpool/
		     3864,	// RSerPool's ENRP protocol (asap-sctp/tls) -- http://tdrwww.iem.uni-due.de/dreibholz/rserpool/
		     3868,	// Diameter
		     4000,	// m3ua common port
		     4739,	// IPFIX (IP Flow Info Export) default port -- http://tools.ietf.org/wg/ipfix/
		     4740,	// IPFIX (IP Flow Info Export) over DTLS default port -- http://tools.ietf.org/wg/ipfix/
		     5000,
		     5001,
		     5060,	// SIP - Session Initiation Protocol
		     5061,	// sip-tls
		     5090,	// car - Candidate Access Router Discovery (CARD) -- http://rfc.net/rfc4066.html
		     5091,	// cxtp - Context Transfer Protocol -- http://rfc.net/rfc4067.html
		     5672,	// AMQP
		     5675,	// v5ua,  V5UA (V5.2-User Adaptation) Layer -- http://rfc.archivesat.com/rfc4166.htm
		     6000,
		     6100,	// Huawei UMG8900 MGW config
		     6110,	// Huawei UMG8900 MGW config
		     6120,	// Huawei UMG8900 MGW config
		     6130,	// Huawei UMG8900 MGW config
		     6140,	// Huawei UMG8900 MGW config
		     6150,	// Huawei UMG8900 MGW config
		     6160,	// Huawei UMG8900 MGW config
		     6170,	// Huawei UMG8900 MGW config
		     6180,	// Huawei UMG8900 MGW config
		     6190,	// Huawei UMG8900 MGW config
		     6529,	// Non standard V5 & IUA port -- from port 6005
		     6700,	// SCTP based TML (Transport Mapping Layer) for ForCES protocol -- http://www.ietf.org/id/draft-ietf-forces-sctptml-05.txt
		     6701,	// SCTP based TML (Transport Mapping Layer) for ForCES protocol -- http://www.ietf.org/id/draft-ietf-forces-sctptml-05.txt
		     6702,	// SCTP based TML (Transport Mapping Layer) for ForCES protocol -- http://www.ietf.org/id/draft-ietf-forces-sctptml-05.txt
		     6789,	// iua test port for some CISCO default configurations
		     6790,	// iua test port for some CISCO default configurations
		     7000,	// MTP3 / BICC
		     7001,	// Common M3UA port
		     7102,	// found in the wild
		     7103,	// found in the wild
		     7105,	// found in the wild
		     7551,	// found in the wild
	             7626,	// simco - SImple Middlebox COnfiguration (SIMCO)
		     7701,	// found in the wild
		     7800,	// found in the wild
		     8000,	// found in the wild, MTP3 / BICC
		     8001,	// found in the wild
		     8471,	// pim-port PIM over Reliable Transport
		     8787,	// iua test port for some CISCO default configurations
		     9006,	// tunneling?
		     9084,	// IBM AURORA Performance Visualizer
		     9899,	// sctp-tunneling, actually is usually tcp/udp based but could come from human error
		     9911,	// iua test port for some CISCO default configurations
		     9900,	// sua (SCCP User Adaptation layer) or iua (ISDN Q.921 User Adaptation -- http://rfc.archivesat.com/rfc4166.htm)  (default for Huawei UMG8900 MGW)
		     9901,	// enrp-sctp - enrp server channel
		     9902, 	// enrp-sctp-tls - enrp/tls server channel 
		     10000,
		     10001,
		     11146,	// Local port for M3UA, Cisco BTS 10200 Softswitch
		     11997,	// wmereceiving - WorldMailExpress 
		     11998,	// wmedistribution - WorldMailExpress 
		     11999,	// wmereporting - WorldMailExpress 
		     12205,	// Local port for SUA, Cisco BTS uses for FSAIN communication is usually 12205,
		     12235,	// Local port for SUA, Cisco BTS usage for FSPTC
		     13000,	// m3ua -- py sms m3ua default ports
		     13001,	// m3ua -- py sms m3ua default ports
		     14000,	// m3ua common port, m2pa sometimes too
		     14001,	// sua, SUA (SS7 SCCP User Adaptation) Layer -- http://rfc.archivesat.com/rfc4166.htm , m3ua sometimes too
		     20049,	// nfsrdma Network File System (NFS) over RDMA
		     29118,	// SGsAP in 3GPP
		     29168,	// SBcAP in 3GPP, [TS 29.168][Kymalainen]           2009-08-20
		     30000,
		     32905,	// m3ua common port
		     32931,
		     32768,
		     0}; // Frequently used SCTP Ports

static addr_t loc_addr = { 0, { { INADDR_ANY } } };
static addr_t rem_addr = { 0, { { INADDR_ANY } } };
char *sctp_identifier[15];		// global to be used after fill-up by init_sctp_identifier()
char *sctp_code[15];			// global to be used after fill-up by init_sctp_identifier()
char *payload_protocol_identifier[15];	// global to be used after fill-up by init_sctp_identifier()

void init_sctp_identifier()
{
  // Requires a global variable:
  // char *sctp_identifier[15];

  sctp_identifier[0] = "Payload Data (DATA)";
  sctp_identifier[1] = "Initiation (INIT)";
  sctp_identifier[2] = "Initiation Acknowledgement (INIT ACK)";
  sctp_identifier[3] = "Selective Acknowledgement (SACK)";
  sctp_identifier[4] = "Heartbeat Request (HEARTBEAT)";
  sctp_identifier[5] = "Heartbeat Acknowledgement (HEARTBEAT ACK)";
  sctp_identifier[6] = "Abort (ABORT)";
  sctp_identifier[7] = "Shutdown (SHUTDOWN)";
  sctp_identifier[8] = "Shutdown Acknowledgement (SHUTDOWN ACK)";
  sctp_identifier[9] = "Operation Error (ERROR)";
  sctp_identifier[10] = "State Cookie (COOKIE ECHO)";
  sctp_identifier[11] = "Cookie Acknowledgement (COOKIE ACK)";
  sctp_identifier[12] = "Reserved for Explicit Congestion Notification Echo (ECNE)";
  sctp_identifier[13] = "Reserved for Congestion Window Reduced (CWR)";
  sctp_identifier[14] = "Shutdown Complete (SHUTDOWN COMPLETE)";

  sctp_code[0] = "DATA";
  sctp_code[1] = "INIT";
  sctp_code[2] = "INIT_ACK";
  sctp_code[3] = "SACK";
  sctp_code[4] = "HEARTBEAT";
  sctp_code[5] = "HEARTBEAT_ACK";
  sctp_code[6] = "ABORT";
  sctp_code[7] = "SHUTDOWN";
  sctp_code[8] = "SHUTDOWN_ACK";
  sctp_code[9] = "ERROR";
  sctp_code[10] = "COOKIE_ECHO";
  sctp_code[11] = "COOKIE_ACK";
  sctp_code[12] = "ECNE";
  sctp_code[13] = "CWR";
  sctp_code[14] = "SHUTDOWN_COMPLETE";

  payload_protocol_identifier[0] = "";
  payload_protocol_identifier[1] = "IUA";	// IUA (ISDN Q.921 User Adaptation) Layer
  payload_protocol_identifier[2] = "M2UA";	// M2UA (SS7 MTP2-User Adaptation) Layer
  payload_protocol_identifier[3] = "M3UA";
  payload_protocol_identifier[4] = "SUA";	// SUA (SS7 SCCP User Adaptation) Layer
  payload_protocol_identifier[5] = "M2PA";	// M2PA (SS7 MTP2-User Peer-to-Peer Adaptation)
  payload_protocol_identifier[6] = "V5UA";	// V5UA (V5.2-User Adaptation) Layer
  payload_protocol_identifier[7] = "";
  payload_protocol_identifier[8] = "";
  payload_protocol_identifier[9] = "";
  payload_protocol_identifier[10] = "DUA";	// DUA (DPNSS/DASS User adaptation) Layer
  //  payload_protocol_identifier[] = "";
}
int	fuzzopt = 0;
int	listen_retries;


// ------------------------ ACTVE SCTP PAYLOAD / HIGHER LEVEL CONNECTION

#ifdef IPPROTO_SCTP
// placeholder for the socket-level audit code.
#endif //  IPPROTO_SCTP

// ------------------------ FUNCTIONS
// Dummy server: dummy listening SCTP server. (feat 108) */
int dummyserver(int portl)
{
  int sd, s, len;
  socklen_t addrlen;
  struct sockaddr_in servaddr, clientaddr;
  char buffer[128];
  int listen_port;

  listen_port = portl;
  if ((sd = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP)) == -1)
    {
      perror("socket");
      fprintf(stderr, "Your kernel does not seem to support SCTP sockets.\n");
      fprintf(stderr, "It's supported by Linux Kernel 2.6 or Solaris 10.\n");
      fprintf(stderr, "For Linux, you may want to run as root: modprobe sctp\n");
      exit(EXIT_FAILURE);
    }

  memset((void *)&servaddr, 0, sizeof(servaddr));
  servaddr.sin_family = AF_INET;
  servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
  servaddr.sin_port = htons(listen_port);
  
  printf("Trying to bind SCTP port\n");
  if (bind(sd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0)
    perror("bind");
  
  listen(sd, 10);
  printf("Listening on SCTP port %d\n", listen_port);
  printf("Note that if kernel supports SCTP sockets (such as provided by SCTPlib), even if this listen in raw socket mode, you may receive ABORT to your INIT packets.");
  
  for(;;)
    {
      addrlen = sizeof(clientaddr);
      if ((s = accept(sd, (struct sockaddr *)&clientaddr, &addrlen)) == -1)
	{
	  perror("accept");
	  exit(EXIT_FAILURE);
	}
      printf("Connection received...\n");
      
      write(s, "1234567890", 10);
      while((len = read(s, buffer, sizeof(buffer))) > 0)
	{
	  buffer[len]='\0';
	  printf("Content received: %s\n", buffer);
	  write(s, buffer, len);
	}
      close(s);
    }
}

// ------------------------ TCP Bridge to SCTP sockets ------------------------

#define MAX_PAYLOAD_LENGTH 1024
#define MAX_IP_LEN 256

static int localAssocID = 0;

// --- Notif handlers / callbacks
#ifdef HAVE_SCTP_H
struct SCTPSock {
    int instanceID;
    int assocID;
    SCTP_ulpCallbacks uc;
};

void dataArriveNotif(unsigned int assoc, unsigned short stream, unsigned int len,
                     unsigned short streamSN,unsigned int TSN, unsigned int protoID,
                     unsigned int unordered, void* ulpDataPtr)
{
    unsigned char chunk[MAX_PAYLOAD_LENGTH];
    unsigned int length = MAX_PAYLOAD_LENGTH;
    unsigned short seqno;
    unsigned int tsn;

    // TODO: copy to internal buffer where SCTP_READ could read it
    printf("Data arrived\n");
}


void sendFailureNotif(unsigned int assoc, unsigned char *unsentData,
                      unsigned int dataLength, unsigned int *context, void *dummy)
{
    printf("Send failure\n");
}


void networkStatusChangeNotif(unsigned int assoc, short destAddrIndex,
                              unsigned short newState, void *ulpDataPtr)
{
    printf("Network status change: path %u is now %s\n",
           destAddrIndex, ((newState == SCTP_PATH_OK) ? "ACTIVE" : "INACTIVE"));
}


void *communicationUpNotif(unsigned int assoc, int status, unsigned  int noOfDestinations,
                           unsigned short instreams, unsigned short outstreams,
                           int associationSupportsPRSCTP, void *dummy)
{

    printf("Communication up: %u path(s), %u in-stream(s), %u out-stream(s)\n",
           noOfDestinations, instreams, outstreams);
    //noOfInStreams = instreams;
    //noOfOutStreams = outstreams;
    //assocID = assoc;
    localAssocID = assoc;
    return NULL;

}

void communicationLostNotif(unsigned int assoc, unsigned short status, void *ulpDataPtr)
{
    unsigned char buffer[MAX_PAYLOAD_LENGTH];
    unsigned int bufferLength = sizeof(buffer);
    unsigned short streamID, streamSN;
    unsigned int protoID;
    unsigned int tsn;
    unsigned char flags;
    void* ctx;

    printf("Communication lost (status %u)\n", status);

    /* retrieve data */
    while (sctp_receiveUnsent(assoc, buffer, &bufferLength, &tsn,
                              &streamID, &streamSN, &protoID, &flags, &ctx) >= 0) {
        /* do something with the retrieved data */
        /* after that, reset bufferLength */
        bufferLength = sizeof(buffer);
    }

    while (sctp_receiveUnacked(assoc, buffer, &bufferLength, &tsn,
                                &streamID, &streamSN, &protoID,&flags, &ctx) >= 0) {
        /* do something with the retrieved data */
        /* after that, reset bufferLength */
        bufferLength = sizeof(buffer);
    }


    /* delete the association */
    sctp_deleteAssociation(assoc);
    //noOfInStreams = 0;
    //noOfOutStreams = 0;
    //assocID = 0;
    localAssocID = 0;
}

void communicationErrorNotif(unsigned int assoc, unsigned short status, void *dummy)
{
  printf("Communication error on association %x (status %u)\n", assoc, status);
}

void restartNotif(unsigned int assoc, void *ulpDataPtr)
{
  printf("Association %x restarted\n", assoc);
}

void shutdownCompleteNotif(unsigned int assoc, void *ulpDataPtr)
{
  printf("Shutdown complete on association %x\n", assoc);
  sctp_deleteAssociation(assoc);
  //noOfInStreams = 0;
  //noOfOutStreams = 0;
  //assocID = 0;
  localAssocID = 0;
}

void peerShutdownReceivedNotif(unsigned int assoc, void *ulpDataPtr)
{
  printf("Peer shutdown received on association %x\n", assoc);
  sctp_deleteAssociation(assoc);
  localAssocID = 0;
}
// --- End of handlers

// --- Helper functions
void sctp_assocDefaultsPrint(struct SCTP_Instance_Parameters *params)
{
  int idx;

  idx = 0;
  printf("* read-only (get):   noOfLocalAddresses=%d\n", params->   noOfLocalAddresses);
  for(idx = 0; idx < params->   noOfLocalAddresses; idx++)
    {
      printf("* read-only (get):  localAddressList[%d][]=%s\n", idx, params->localAddressList[idx]);
    }
  printf("* initial round trip timeout: rtoInitial=%d\n", params-> rtoInitial);
  printf("* minimum timeout value: rtoMin=%d\n", params-> rtoMin);
  printf("* maximum timeout value: rtoMax=%d\n", params-> rtoMax);
  printf("* lifetime of a cookie: validCookieLife=%d\n", params-> validCookieLife);
  printf("*  (get/set):   outStreams=%d\n", params->   outStreams);
  printf("*  (get/set):   inStreams=%d\n", params->   inStreams);
  printf("* does the instance by default signal unreliable streams (as a server) no==0, yes==1: supportUnreliableStreams=%d\n", params-> supportUnreliableStreams);
  printf("* does the instance by default signal unreliable streams (as a server) no==0, yes==1: supportADDIP=%d\n", params-> supportADDIP);
  printf("* maximum retransmissions per association: assocMaxRetransmits=%d\n", params-> assocMaxRetransmits);
  printf("* maximum retransmissions per path: pathMaxRetransmits=%d\n", params-> pathMaxRetransmits);
  printf("* maximum initial retransmissions: maxInitRetransmits=%d\n", params-> maxInitRetransmits);
  printf("* from recvcontrol : my receiver window: myRwnd=%d\n", params-> myRwnd);
  printf("* recvcontrol: delay for delayed ACK in msecs: delay=%d\n", params-> delay);
  printf("* per instance: for the IP type of service field.: ipTos=%d\n", params-> ipTos);
  printf("* limit the number of chunks queued in the send queue: maxSendQueue=%d\n", params-> maxSendQueue);
  printf("* currently unused, may limit the number of chunks queued in the receive queue later.  Is this really needed ? The protocol limits the receive queue with window advertisement of arwnd==0 : maxRecvQueue=%d\n", params-> maxRecvQueue);
  printf("* maximum number of associations we want. Is this limit greater than 0, implementation will automatically send ABORTs to incoming INITs, when there are that many associations ! : maxNumberOfAssociations=%d\n", params-> maxNumberOfAssociations);
}


void sctp_assocStatusPrint(struct SCTP_Association_Status *p)
{
  printf("p->state=%d\n", (int)p->state); 
  printf("p->numberOfAddresses=%d\n",(int)p->numberOfAddresses);
  // unsigned char  primaryDestinationAddress[SCTP_MAX_IP_LEN];
  printf("p->primaryDestinationAddress=%s	\n",p->primaryDestinationAddress);
  printf("p->sourcePort=%d\n",p->sourcePort);
  printf("p->destPort=%d\n",p->destPort);
  printf("p->outStreams=%d\n",p->outStreams);
  printf("p->inStreams=%d	\n",p->inStreams);
  printf("p->supportUnreliableStreams=%d	does the assoc support unreliable streams  no==0, yes==1\n",p->supportUnreliableStreams);
  printf("p->supportADDIP=%d		does the assoc support adding/deleting IP addresses no==0, yes==1\n",p->supportADDIP);
  printf("p->primaryAddressIndex=%d\n",p->primaryAddressIndex);
  printf("p->currentReceiverWindowSize=%d\n",p->currentReceiverWindowSize);
  printf("p->outstandingBytes=%d\n",p->outstandingBytes);
  printf("p->noOfChunksInSendQueue=%d\n",p->noOfChunksInSendQueue);
  printf("p->noOfChunksInRetransmissionQueue=%d\n",p->noOfChunksInRetransmissionQueue);
  printf("p->noOfChunksInReceptionQueue=%d\n",p->noOfChunksInReceptionQueue);
  printf("p->rtoInitial=%d		the initial round trip timeout\n",p->rtoInitial);
  printf("p->rtoMin=%d			the minimum RTO timeout\n",p->rtoMin);
  printf("p->rtoMax=%d			the maximum RTO timeout\n",p->rtoMax);
  printf("p->validCookieLife=%d		the lifetime of a cookie\n",p->validCookieLife);
  printf("p->assocMaxRetransmits=%d	maximum retransmissions per association\n",p->assocMaxRetransmits);
  printf("p->pathMaxRetransmits=%d	maximum retransmissions per path\n",p->pathMaxRetransmits);
  printf("p->maxInitRetransmits=%d	maximum initial retransmissions\n",p->maxInitRetransmits);
  printf("p->myRwnd=%d			from recvcontrol : my receiver window\n",p->myRwnd);
  printf("p->delay=%d			recvcontrol: delay for delayed ACK in msecs\n",p->delay);
  printf("p->ipTos=%d			per instance: for the IP type of service field.\n",(unsigned char)p->ipTos);
  printf("p->maxSendQueue=%d		limit the number of chunks queued in the send queue\n",p->maxSendQueue);
  printf("p->maxRecvQueue=%d		currently unused, may limit the number of chunks queued in the receive queue later. Is this really needed ? The protocol limits the receive queue with window advertisement of arwnd==0\n",p->maxRecvQueue);
}

#endif /* HAVE_SCTP_H */

// --- TCP bridge
// 
// Problems when testing client and server on the same host with SCTPlib.
// No problem when testing client and server on two different hosts:
// Linux machine running SCTPlib chargen_server:
// linux13# ./chargen_server -V
// MacOSX10.4-12# ./sctpscan -r 192.168.1.13 -p 19 -t 12346
// 
int TCPtoSCTP(int tcp_port, char *hostl, int portl, unsigned char *hostr, int portr, int inoutstreams)
{
  int tcp_sd, tcp_s, tcp_len;
  socklen_t tcp_addrlen;
  struct sockaddr_in tcp_servaddr, tcp_clientaddr;
  char tcp_buffer[128];
  int tcp_listen_port = 0;

  tcp_listen_port = tcp_port;

  // Listen to TCP port if tcpport != 0
  if (tcp_listen_port != 0)
    {
      if ((tcp_sd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1)
	{
	  perror("socket (could open TCP socket)");
	  exit(EXIT_FAILURE);
	}
      
      memset((void *)&tcp_servaddr, 0, sizeof(tcp_servaddr));
      tcp_servaddr.sin_family = AF_INET;
      tcp_servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
      tcp_servaddr.sin_port = htons(tcp_listen_port);
      
      printf("Trying to bind TCP port\n");
      if (bind(tcp_sd, (struct sockaddr *)&tcp_servaddr, sizeof(tcp_servaddr)) < 0)
	perror("bind (not bind TCP port)");
      
      listen(tcp_sd, 10);
      printf("Listening on TCP port %d\n", tcp_listen_port);
    }

  // Connect to SCTP port
  if (hostr != NULL && portr != 0)
    {
#ifdef HAVE_SCTP_H
      struct SCTPSock *con;
      unsigned char ip_l[1][SCTP_MAX_IP_LEN];
      void *ulpDataPtr = NULL;
      int instreams;
      int outstreams;

      fprintf(stderr,"DEBUG: Connecting SCTP to remote host %s, remote port=%d with SCTPlib.\n", hostr, portr);
      con = malloc(sizeof(struct SCTPSock));
      if (con == NULL) perror("malloc:SCTPsock is NULL!!");
      con->assocID = 0;
      con->instanceID = 0;

      sctp_initLibrary();
      // Register handlers
      con->uc.dataArriveNotif = &dataArriveNotif;
      con->uc.sendFailureNotif = &sendFailureNotif;
      con->uc.networkStatusChangeNotif = &networkStatusChangeNotif;
      con->uc.communicationUpNotif = &communicationUpNotif;
      con->uc.communicationLostNotif = &communicationLostNotif;
      con->uc.communicationErrorNotif = &communicationErrorNotif;
      con->uc.restartNotif = &restartNotif;
      con->uc.shutdownCompleteNotif = &shutdownCompleteNotif;
      con->uc.peerShutdownReceivedNotif = peerShutdownReceivedNotif;

      strncpy((char *)ip_l[0], (const char *)(hostl), SCTP_MAX_IP_LEN - 1);

      instreams = outstreams = inoutstreams;
      con->instanceID = sctp_registerInstance(portl, instreams, outstreams, 
					      1 /* =noOfLocalAddresses */, ip_l, (con->uc));
      if (con->instanceID > 0) {
	printf("SCTP instance initialized (instanceID=%d)\n", con->instanceID);
      } else {
	perror("SCTP initalization failed. maybe you need to run it as root?!\n");
      }
      ulpDataPtr = NULL;

      // Connecting...  Associating...
      con->assocID = sctp_associate(con->instanceID, outstreams, hostr, portr, ulpDataPtr);

      // Manage SCTP events? (XXX tentative)
      while(1)
	{
	  sctp_eventLoop();
	}

      if (con->assocID > 0)
	{
	  SCTP_InstanceParameters params;
	  int assocDefaultsErrorCode;
	  SCTP_AssociationStatus status;
	  int assocStatusErrorCode;

	  printf("We got a SCTP association running! assocID=%d\n", con->assocID);

	  assocDefaultsErrorCode = sctp_getAssocDefaults(con->instanceID, &params);
	  printf("assocDefaultsErrorCode=%d\n",assocDefaultsErrorCode);
	  sctp_assocDefaultsPrint(&params);

	  assocStatusErrorCode = sctp_getAssocStatus(con->assocID, &status);
	  printf("assocStatusErrorCode=%d\n",assocStatusErrorCode);
	  sctp_assocStatusPrint(&status);
	}

#else
      fprintf(stderr,"ERROR: No SCTPlib support\n");
      exit(EXIT_FAILURE);      
#endif /* HAVE_SCTP_H */
    }
  else
    {
      fprintf(stderr,"ERROR: Missing remote host or port to bridge to (remote host at %x, remote port=%d.\n", (unsigned int)hostr, portr);
      exit(EXIT_FAILURE);
    }
  
  // Listen / Accept / Bridge all packets from SCTP to TCP
  for(;;)
    {
      // Accept new TCP client
      tcp_addrlen = sizeof(tcp_clientaddr);
      if ((tcp_s = accept(tcp_sd, (struct sockaddr *)&tcp_clientaddr, &tcp_addrlen)) == -1)
	{
	  perror("accept");
	  exit(EXIT_FAILURE);
	}
      printf("Connection received...\n");
      
      //write(tcp_s, "1234567890", 10); // old code, send SCTP received content.
      // from TCP to SCTP
      while((tcp_len = read(tcp_s, tcp_buffer, sizeof(tcp_buffer))) > 0)
	{
	  //buffer[len]='\0'; // old code
	  printf("Content received: %s\n", tcp_buffer);
	  //write(tcp_s, tcp_buffer, tcp_len); // old code, send 
	}
      close(tcp_s);
    }

  // from SCTP to TCP
  return(0);
}
// --- End of TCP bridge


// ------------------------ FUNCTIONS
unsigned short		/* this function generates header checksums */
csum (unsigned short *buf, int nwords)
{
  unsigned long sum;
  for (sum = 0; nwords > 0; nwords--)
    sum += *buf++;
  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  return(~sum);
}

unsigned int Adler32( unsigned char* buf, 
		      // Buffer address. 
		      // 
		      unsigned int HowManyBytes, 
		      // Size of buffer in bytes. 
		      // 
		      unsigned int adler ) 
// Cumulative Adler32 checksum computed so far. 
// 
// Always use 1 as the initial value. 
{ 
  signed short int HowManyThisPass; 
  unsigned int s1; 
  unsigned int s2; 

  // Separate the check sum into two 16-bit parts and put 
  // them into 32-bit variables. 
  s1 = adler & 0xFFFF; 
  s2 = (adler >> 16) & 0xFFFF; 

  // Until all of the input has been processed. 
  while( HowManyBytes ) 
    { 
      // Calculate how many bytes to process on this pass 
      // so that the 32-bit accumulators don't overflow: 
      // 
      // 65521 is the largest prime smaller than 65536. 
      // 5552 is the largest n such that 
      // 255n (n+1)/2 + (n+1)(65520) <= 2^32-1. 
      // 
      HowManyThisPass = (signed short int) min( HowManyBytes, 5552 ); 

      // Account for the bytes to be processed on this pass. 
      HowManyBytes -= HowManyThisPass; 

      // As long as 16 or more bytes remain to be 
      // processed on this pass. 
      while( HowManyThisPass >= 16 ) 
	{ 
	  // Sum the input bytes in 's1' and sum the 
	  // running 's1' values in 's2'. 
	  s1 += *buf++; s2 += s1; 
	  s1 += *buf++; s2 += s1; 
	  s1 += *buf++; s2 += s1; 
	  s1 += *buf++; s2 += s1; 
	  s1 += *buf++; s2 += s1; 
	  s1 += *buf++; s2 += s1; 
	  s1 += *buf++; s2 += s1; 
	  s1 += *buf++; s2 += s1; 
	  s1 += *buf++; s2 += s1; 
	  s1 += *buf++; s2 += s1; 
	  s1 += *buf++; s2 += s1; 
	  s1 += *buf++; s2 += s1; 
	  s1 += *buf++; s2 += s1; 
	  s1 += *buf++; s2 += s1; 
	  s1 += *buf++; s2 += s1; 
	  s1 += *buf++; s2 += s1; 

	  // Account for the bytes processed. 
	  HowManyThisPass -= 16; 
	} 

      // As long as any bytes remain to be processed. 
      while( HowManyThisPass-- ) 
	{ 
	  // Sum the input bytes in 's1' and sum the 
	  // running 's1' values in 's2'. 
	  s1 += *buf++; s2 += s1; 
	} 

      // Compute the remainder mod 65521 of each 
      // accumulator: 65521 is the largest 
      // prime smaller than 65536. 
      s1 %= 65521L; 
      s2 %= 65521L; 
    } 

  // Merge the two accumulators and return the result. 
  return( (s2 << 16) | s1 ); 
} 

char *get_frequent_ports_str()
{
  static char str[8192];
  int p;
  int i = 0;

  if (sctp_ports != 0 && sctp_ports[i] != 0)
    {
      p = sctp_ports[i];
      sprintf(str, "%d", p);
      i++;
      while ( sctp_ports[i] != 0)
	{
	  p = sctp_ports[i];
	  sprintf(str, "%s, %d", str, p);
	  //printf("Sending for port %d on host %s\n", p, hostr);
	  //      printf("%d\n", sctp_ports[i]);
	  i++;
	}
      return(str);
    }
  else
    return("Empty!!!");
}

char *get_sending_ip(char *tempt_host)
{
  struct in_addr tmp_dst;
  struct in_addr tmp_src;

  tmp_dst.s_addr = inet_addr(tempt_host);
  tmp_src = xp_get_src_addr(tmp_dst);
  return(inet_ntoa(tmp_src));
}

// ----------------- Collaboration

#ifdef __G_LIB_H__
static gchar *_url_encode_char (const gchar chr)
{
  static gchar reserved_chars[] =
    { ';', '/', '?', ':', '@', '&', '=', '+', '$', ',',
    '<', '>', '%', '#', '\t', '\r', '\n', '\v', '\0'
  };
  gchar *encoded_string;
  gint j = 0;

  if (chr == ' ')
    {
      return g_strdup_printf ("+");
    }
  else
    {
      while (reserved_chars[j] != '\0')
        {
          if (reserved_chars[j] == chr)
            {
              encoded_string = g_strdup_printf ("%%%.2X", chr);
              return encoded_string;
            }
          j++;
        }
    }
  if (isprint (chr))
    return g_strdup_printf ("%c", chr);

  encoded_string = g_strdup_printf ("%%%.2X", chr);
  return encoded_string;
}

gchar *url_encode (const gchar * url)
{
  gchar *encoded_str = g_strdup ("");
  gchar *encoded_chr;
  gchar *old_str;
  gint i;

  if (url == NULL)
      return encoded_str; //return the null string

  for (i = 0; i < strlen (url); i++)
    {
      old_str = encoded_str;
      encoded_chr = _url_encode_char (url[i]);
      encoded_str = g_strdup_printf ("%s%s", encoded_str, encoded_chr);
      g_free (encoded_chr);
      g_free (old_str);
    }
  return (encoded_str);
}
#endif

int exec_script(struct app_s *app, char *present_on_ip, int port, char *sctp_code, char *comment)
{
  // Local collaboration: execution of local script
  if (app->exec_on_port_opt)
    {
      char	command[4096];

      sprintf(command, "%s %s %d", app->exec_on_port_opt, present_on_ip, port);
      system(command);
    }
  return(0);
}

int collab_report(struct app_s *app, char *present_on_ip, int port, char *sctp_code, char *comment)
{
  // Remote collaboration
  if (app->zombie_opt)
    {
      // Does not do any reporting - no collaboration. (selfish mode.... hmmm....) (feat #105)
      return(-1);
    }
  else
    {
#ifdef __G_LIB_H__
      gchar	*res_buf = NULL;
      gchar	*hostname;
      gchar	*proxy_host;
      gint	http_port;
      gint	proxy_port = 0;
      gchar	req_string[4096];
      gchar	*cmd_line;		// cmd_line
      struct tm *time_struct;		//client_date;
      time_t t;
      char	version[20];
      //scanned_range;
      http_port = 3000;
      proxy_host = NULL;
      cmd_line = url_encode(app->cmd_line);
      t = time(NULL);
      time_struct = localtime(&t);

      char *revision = "$Revision: 83 $";
      int  rev;

      sscanf(revision, "$Revision: %d", &rev);
      //printf("%d\n", res);
      sprintf(version, "%d.%d", app->sctpscan_version, rev);

      signal(SIGCHLD, SIG_IGN);
      if (fork() != 0)
	{
	  return(0);
	}
      else
	{
#ifdef SIGTSTP /* BSD */
	  setpgrp(0, getpid());
#else /* Sys V */
	  setpgrp();
	  signal(SIGHUP, SIG_IGN);
#endif

	  //printf("collab_report called\n");
	  if (comment == NULL)
	    comment = strdup(" ");
	  sprintf(req_string, "/share/create?sctppresence%%5Breporting_ip%%5D=1.2.3.4&sctppresence%%5Breporting_clientdate%%281i%%29%%5D=%d&sctppresence%%5Breporting_clientdate%%282i%%29%%5D=%d&sctppresence%%5Breporting_clientdate%%283i%%29%%5D=%d&sctppresence%%5Breporting_clientdate%%284i%%29%%5D=%d&sctppresence%%5Breporting_clientdate%%285i%%29%%5D=%d&sctppresence%%5Breporting_uid%%5D=UID&sctppresence%%5Bscanned_range%%5D=%s&sctppresence%%5Bcmd_line%%5D=%s&sctppresence%%5Bpresent_on_ip%%5D=%s&sctppresence%%5Bpresent_on_port%%5D=%d&sctppresence%%5Banswer_sctp_code%%5D=%s&sctppresence%%5Bcomments%%5D=%s&sctppresence%%5Bsctpscan_version%%5D=%s&commit=Create", 1900+time_struct->tm_year, 1+time_struct->tm_mon, time_struct->tm_mday, time_struct->tm_hour, time_struct->tm_min, app->hostr, cmd_line, present_on_ip, port, sctp_code, url_encode(comment), version);
	  //printf("req=%s\n", req_string);
	  hostname = strdup("sctp.tstf.net");
	  res_buf = collab_http_get_buffer(req_string, hostname, http_port, proxy_host, proxy_port);
	  //printf("collab_report()= %s\n\n", res_buf);
	  exit(0);
	}
#else
      printf("WARNING: Compiled without GLIB support, Collaborative reporting doesn't work.");
#endif
      return(0);
    }
}


// ----------------- For Portscan List
// if Glib present: remember all scanned hosts
// if Glib is not present: remember only last scanned host
//	This can pose problem in situation where we have dual homed machines
#define DEBUG_PORTSCAN_LIST 0

#ifdef __G_LIB_H__
gint custom_cmp (gconstpointer a, gconstpointer b)
{
  //printf("Comparing %s[%d] %s[%d]\n", a, strlen(a), b, strlen(b));
  return strcmp(a, b);
}
#endif

int add_to_host_to_portscan(struct app_s *app, char *host)
{
#ifndef __G_LIB_H__
  strcpy(app->host_to_portscan, host);
  return(1);
#else
  if (g_queue_find_custom(app->host_already_portscan, host, custom_cmp))
    {
      return(0);	// Already in host_already_portscan, so don't add to scan
    }
  if (g_queue_find_custom(app->host_to_portscan, host, custom_cmp) == NULL)
    {
      //if (DEBUG_PORTSCAN_LIST) printf("\nDEBUG "__FUNCTION__"(): Adding %s to app->host_to_portscan\n", host);
      g_queue_push_head(app->host_to_portscan, strdup(host));
      assert(app->host_to_portscan->length == g_queue_get_length(app->host_to_portscan));
      //if (DEBUG_PORTSCAN_LIST) printf("DEBUG : Now app->host_to_portscan->length == %d\n", app->host_to_portscan->length);
      return(1);
    }
  else
    {
      //if (DEBUG_PORTSCAN_LIST) printf("\nDEBUG "__FUNCTION__"(): Host %s is already in app->host_to_portscan (length=%d)\n", host, app->host_to_portscan->length);
      return(1);
    }
#endif
}


int add_host_to_already_portscanned(struct app_s *app, char *host)
{
#ifndef __G_LIB_H__
  strcpy(app->host_already_portscan, host);
  return(0);
#else
  if (app->host_already_portscan->length == 0 || g_queue_find_custom(app->host_already_portscan, host, custom_cmp) == NULL)
    {
      //if (DEBUG_PORTSCAN_LIST) printf("\nDEBUG "__FUNCTION__"(): Adding %s to app->host_already_portscan\n", host);
      g_queue_push_head(app->host_already_portscan, strdup(host));
      //if (DEBUG_PORTSCAN_LIST) printf("DEBUG : Now app->host_already_portscan->length == %d\n", app->host_already_portscan->length);
      return(0);
    }
  else
    {
      //printf("WARNING: weird thing happened, try to add host %s to app->host_already_portscan, but it's already there!\n", host);
      return(-1);
    }
#endif
}


static char *get_host_to_portscan(struct app_s *app)
{
  char static static_host[40];
  char *host;
  
#ifndef __G_LIB_H__
  return(app->host_to_portscan);
#else
  //if (DEBUG_PORTSCAN_LIST) dump_gqueue(app->host_to_portscan);
  assert(g_queue_is_empty(app->host_to_portscan) == FALSE);
  //if (DEBUG_PORTSCAN_LIST) printf("\nDEBUG "__FUNCTION__"(): Getting %s from app->host_to_portscan\n", g_queue_peek_head(app->host_to_portscan));
  host = g_queue_pop_tail(app->host_to_portscan);
  //if (DEBUG_PORTSCAN_LIST) { printf("After Tail Pop\n"); dump_gqueue(app->host_to_portscan); }
  strncpy(static_host, host, sizeof(static_host) - 2);
  add_host_to_already_portscanned(app, host);
  //if (DEBUG_PORTSCAN_LIST) printf("DEBUG : Returning %s, Now app->host_to_portscan->length == %d\n", static_host, app->host_to_portscan->length);
  return(static_host);
#endif
}

// Returns: 0 if no more host to portscan
//	    1 if there are some hosts to portscan
int check_more_host_to_portscan(struct app_s *app)
{
#ifndef __G_LIB_H__
  if(!strcmp(app->host_to_portscan, app->host_already_portscan))
    return(0);
  else
    return(1);
#else
  //if (DEBUG_PORTSCAN_LIST) printf("\nDEBUG "__FUNCTION__"(): Are there some more hosts in app->host_to_portscan: %s (length=%d)\n", (g_queue_get_length(app->host_to_portscan) > 0)?"TRUE":"FALSE", g_queue_get_length(app->host_to_portscan));
  assert(app->host_to_portscan->length == g_queue_get_length(app->host_to_portscan));
  //printf("POUET %d\n", g_queue_get_length(app->host_to_portscan));
  if( g_queue_get_length(app->host_to_portscan) > 0 )
    { return(1); }
  else
    { return(0); }
#endif
}

int is_already_portscanned(struct app_s *app, char *host)
{
#ifndef __G_LIB_H__
  if (!strcmp(host, app->host_already_portscan))
    return(1);
  else
    return(0);
#else
  //if (DEBUG_PORTSCAN_LIST) printf("\nDEBUG "__FUNCTION__"(): Is %s already in app->host_already_portscan? %s\n", host, (g_queue_find_custom(app->host_already_portscan, host, custom_cmp) == NULL)?"FALSE":"TRUE");
  if (g_queue_find(app->host_already_portscan, host) == NULL)
    return(0);
  else
    return(1);
#endif
}

#ifdef __G_LIB_H__
static void custom_printf (gpointer a, gpointer b)
{
  printf("DEBUG: Each %s\n", (char *)a);	// XXX tentative cast to avoid -Wall error... TBT
}

void dump_gqueue(GQueue *queue)
{
  printf("EACH start: queue->length=%d\n", queue->length);
  g_queue_foreach(queue, custom_printf, "DEBUG: Each %s\n");
  printf("EACH end\n");
}
#endif

// -----------------

int usage()
{
  fprintf(stderr,"SCTPscan - Copyright (C) 2002 - 2009 Philippe Langlois.\n");
  fprintf(stderr,"SCTPscan comes with ABSOLUTELY NO WARRANTY; for details read the LICENSE or COPYING file.\n");
  fprintf(stderr,"Usage:  sctpscan [options]\n");
  fprintf(stderr,"Options:\n");
  fprintf(stderr,"  -p, --port <port>           (default: 10000)\n");
  fprintf(stderr,"      port specifies the remote port number\n");
  fprintf(stderr,"  -P, --loc_port <port>           (default: 10000)\n");
  fprintf(stderr,"      port specifies the local port number\n");
  fprintf(stderr,"  -l, --loc_host <loc_host>   (default: 127.0.0.1)\n");
  fprintf(stderr,"      loc_host specifies the local (bind) host for the SCTP\n");
  fprintf(stderr,"      stream with optional local port number\n");
  fprintf(stderr,"  -r, --rem_host <rem_host>   (default: 127.0.0.2)\n");
  fprintf(stderr,"      rem_host specifies the remote (sendto) address for the SCTP\n");
  fprintf(stderr,"      stream with optional remote port number\n");

  fprintf(stderr,"  -s  --scan -r aaa[.bbb[.ccc]]\n");
  fprintf(stderr,"      scan all machines within network\n");
  fprintf(stderr,"  -m  --map\n");
  fprintf(stderr,"      map all SCTP ports from 0 to 65535 (portscan)\n");
  fprintf(stderr,"  -F  --Frequent\n");
  fprintf(stderr,"      Portscans the frequently used SCTP ports\n");
  fprintf(stderr,"      Frequent SCTP ports: %s\n", get_frequent_ports_str());
  fprintf(stderr,"  -a  --autoportscan\n");
  fprintf(stderr,"      Portscans automatically any host with SCTP aware TCP/IP stack\n");
  fprintf(stderr,"  -i  --linein\n");
  fprintf(stderr,"      Receive IP to scan from stdin\n");

  fprintf(stderr,"  -f  --fuzz\n");
  fprintf(stderr,"      Fuzz test all the remote protocol stack\n");

  fprintf(stderr,"  -B  --bothpackets\n");
  fprintf(stderr,"      Send packets with INIT chunk for one, and SHUTDOWN_ACK for the other\n");
  
  fprintf(stderr,"  -b  --both_checksum\n");
  fprintf(stderr,"      Send both checksum: new crc32 and old legacy-driven adler32\n");
  fprintf(stderr,"  -C  --crc32\n");
  fprintf(stderr,"      Calculate checksums with the new crc32\n");
  fprintf(stderr,"  -A  --adler32\n");
  fprintf(stderr,"      Calculate checksums with the old adler32\n");
  fprintf(stderr,"  -Z  --zombie\n"); // (feat 105)
  fprintf(stderr,"      Does not collaborate to the SCTP Collaboration platform. No reporting.\n");
  fprintf(stderr,"  -d  --dummyserver\n"); // (feat 108)
  fprintf(stderr,"      Starts a dummy SCTP server on port 10000. You can then try to scan it from another machine.\n");
  fprintf(stderr,"  -E  --exec <script_name>\n"); // (feat 109)
  fprintf(stderr,"      Executes <script_name> each time an open SCTP port is found.\n");
  fprintf(stderr,"      Execution arguments: <script_name> host_ip sctp_port\n");
  fprintf(stderr,"  -t  --tcpbridge <listen TCP port>\n"); // 
  fprintf(stderr,"      Bridges all connection from <listen TCP port> to remote designated SCTP port.\n");
  fprintf(stderr,"  -S  --streams <number of streams>\n"); // 
  fprintf(stderr,"      Tries to establish SCTP association with the specified <number of streams> to remote designated SCTP destination.\n");
  //  fprintf(stderr,"  -R  --randomscan\n");
  //  fprintf(stderr,"      Randomly scan class C networks forever\n");
  fprintf(stderr,"\n");
  fprintf(stderr,"Scan port 9999 on 192.168.1.24\n");
  fprintf(stderr,"./sctpscan -l 192.168.1.2 -r 192.168.1.24 -p 9999\n");
  fprintf(stderr,"\n");
  fprintf(stderr,"Scans for availability of SCTP on 172.17.8.* and portscan any host with SCTP stack\n");
  fprintf(stderr,"./sctpscan -s -l 172.22.1.96 -r 172.17.8\n");
  fprintf(stderr,"\n");
  fprintf(stderr,"Scans frequently used ports on 172.17.8.*\n");
  fprintf(stderr,"./sctpscan -s -F -l 172.22.1.96 -r 172.17.8\n");
  fprintf(stderr,"\n");
  fprintf(stderr,"Scans all class-B network for frequent port\n");
  fprintf(stderr,"./sctpscan -s -F -r 172.22 -l `ifconfig eth0 | grep 'inet addr:' |  cut -d: -f2 | cut -d ' ' -f 1 `\n");
  fprintf(stderr,"\n");
  fprintf(stderr,"Simple verification end to end on the local machine:\n");
  fprintf(stderr,"./sctpscan -d &\n");
  fprintf(stderr,"./sctpscan -s -l 192.168.1.24 -r 192.168.1 -p 10000\n");
  fprintf(stderr,"\n");
  fprintf(stderr,"This tool does NOT work behind most NAT.\n");
  fprintf(stderr,"That means that most of the routers / firewall don't know how to NAT SCTP packets.\n");
  fprintf(stderr,"You _need_ to use this tool from a computer having a public IP address (i.e. non-RFC1918)\n");
  fprintf(stderr,"\n");
  return(0);
}

void compact_progress_print(int identifier)
{
  if (identifier == 6)
    putchar('.');
  else
    printf("%d ", identifier);
  /* printf("SCTP packet received from %s port %d type %s\n", inet_ntoa(iphdr->ip_src), ntohs(r_sctph->sport), get_sctp_id_str(r_sctph->identifier)); */
  fflush(NULL);
}

// Does a select on sending socket before we call sendto()
// in order not to overflow the sending socket.
int  wait_for_send(int s)
{
  fd_set r;
  int retval;
  struct timeval mytimeout;

  //XXX defined for ADSL
  // WOW... seems we never need to wait_for_send
  return(0);
  
  // Reception of packets
  mytimeout.tv_sec = 0;
  mytimeout.tv_usec = 10; 

  FD_ZERO(&r);
  FD_SET(s,&r);

  retval = select((s+1), (fd_set *)0, &r, (fd_set *)0, NULL);
  //printf("plop i=%d retval=%d\n", i, retval);
}

char *get_sctp_id_str(int id)
{
  static char str[1024];

  if (id < 15 && id >= 0)
    sprintf(str, "%d (%s)", id, sctp_identifier[id]);
  else
    sprintf(str, "%d", id);
  return(str);
}

char *get_sctp_code(int id)
{
  static char str[1024];

  if (id < 15 && id >= 0)
    sprintf(str, "%s", sctp_code[id]);
  else
    sprintf(str, "%d", id);
  return(str);
}

#ifdef HAVE_PCAP	// ************************* PCAP SPECIFIC **************************

// *********************** SNAP BUSINESS
//#define _BSD_SOURCE 1

/* Ethernet addresses == 6 bytes */
#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet {
  u_char ether_dhost[ETHER_ADDR_LEN];	/* Destination host address */
  u_char ether_shost[ETHER_ADDR_LEN];	/* Source host address */
  u_short ether_type;			/* Ethernet Frame Type: IP? ARP? RARP? */
};

/* IP header */
struct sniff_ip {
  u_char ip_vhl;		/* version << 4 | header length >> 2 */
  u_char ip_tos;		/* type of service */
  u_short ip_len;		/* total length */
  u_short ip_id;		/* identification */
  u_short ip_off;		/* fragment offset field */
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* dont fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
  u_char ip_ttl;		/* time to live */
  u_char ip_p;			/* protocol */
  u_short ip_sum;		/* checksum */
  struct in_addr ip_src,ip_dst; /* source and dest address */
};

#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

// *********************** PKT_HOLDER BUSINES
struct pkt_holder_s {
  int		got_packet;
  int		got_sctp;
  u_char	*ip_packet;
  int		caplen;
  int		pktlen;
  struct app_s	*app;
};


void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
#define SIZE_ETHERNET 14
  
  const struct sniff_ethernet *ethernet; /* The ethernet header */
  const struct sniff_ip *ip; /* The IP header */
  struct pkt_holder_s *here_pkt_holder;
  int	gp_debug;
  
  u_int size_ip;

  gp_debug = 0;
  if (gp_debug) printf("got_packet() called!\n");	// DEBUG
  here_pkt_holder = (struct pkt_holder_s *)args;
  
  if (header->caplen < header->len)
    printf("got_packet() did not capture the totality of the packet\n");

  ethernet = (struct sniff_ethernet*)(packet);
  ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
  size_ip = IP_HL(ip)*4;
  if (size_ip < 20) {
    printf("   * Invalid IP header length: %u bytes\n", size_ip);
    return;
  }
  if (gp_debug) printf("Packet size=%d\n",size_ip);
  here_pkt_holder->ip_packet = (u_char *)(packet + SIZE_ETHERNET);
  here_pkt_holder->got_packet++;
  if (gp_debug) printf("pkt_holder count=%d\n", here_pkt_holder->got_packet);

  // DEBUG: ANALYSIS/DUMP PACKET
  {
    struct ip *iphdr;
    int iplen;

    iphdr = (struct ip *)here_pkt_holder->ip_packet;
    iplen = iphdr->ip_hl << 2;
    if (gp_debug) printf("Packet Type=%d iplen=%d\n", iphdr->ip_p, iplen);
  }
}

#endif // ************************* PCAP SPECIFIC **************************


// Returns: SCTP identifier of received SCTP reply
int select_wait_generic(int s, struct app_s *app)
{
  int retcode = 0;
  fd_set r;
  int retval;
  struct timeval mytimeout;
  unsigned char recvbuff[MAXPACKET];
  struct ip *iphdr;
  int iplen;

#ifdef HAVE_PCAP
  struct pkt_holder_s	pkt_holder;

  pkt_holder.got_packet = 0;
  pkt_holder.got_sctp = 0;
  pkt_holder.ip_packet = NULL;
  pkt_holder.app = app;
  { // TODO ZZZ PCAP_SUPPORT
    int		pcap_sock;
    pcap_t	*handle;
    int		pcap_max_packet_count;	/* Maximum nbr of packets to be processed by pcap_loop */
    int		swg_debug;

    swg_debug = 0;
    //fprintf(stderr, "ERROR, PCAP not implemented\n"); fflush(NULL); exit(1);
    if (s == app->rcv_sctp_socket)
      {
	pcap_sock = app->rcv_sctp_pcap_fd;
	handle = app->rcv_sctp_pcap;
	if (swg_debug > 10) { printf("select_wait_generic SCTP\n"); fflush(NULL); }
      }
    else
      {
	pcap_sock = app->rcv_icmp_pcap_fd;
	handle = app->rcv_icmp_pcap;
	if (swg_debug > 10) { printf("select_wait_generic ICMP\n"); fflush(NULL); }
      }
    
    //mytimeout.tv_sec = 0;
    //mytimeout.tv_usec = PCAP_TIMEOUT; 
    //FD_ZERO(&r);
    //FD_SET(pcap_sock,&r);

    //if (swg_debug) { printf("select_wait_generic : going into select\n"); fflush(NULL); }
    //retval = select((pcap_sock+1), &r, (fd_set *)0, (fd_set *)0, &mytimeout);
    
    //if (swg_debug) { printf("select_wait_generic : select return something, dispatching with:\n");  fflush(NULL); }
    pcap_max_packet_count = 1;
    pcap_dispatch(handle, pcap_max_packet_count, got_packet, (u_char *)&pkt_holder);
  }
  if (pkt_holder.got_packet)
    {
      retval = 1;
    }
#endif /* END OF PCAP / SELECT CHOICE */

//#else /* USE SELECT */

  // Reception of packets
  mytimeout.tv_sec = app->select_timeout_sec;
  mytimeout.tv_usec = app->select_timeout_usec; 

  //printf("select_wait_generic(): app->listen_retries = %d app->select_timeout_sec=%d app->select_timeout_usec=%d\n", app->listen_retries, app->select_timeout_sec, app->select_timeout_usec);

  FD_ZERO(&r);
  FD_SET(s,&r);

  retval = select((s+1), &r, (fd_set *)0, (fd_set *)0, &mytimeout);
  //printf("plop i=%d retval=%d\n", i, retval);
  //printf("retval=%d on socket=%d\n", retval, s);
  
  if(retval)
    {
      /* We got an answer lets check if its the one we want. */

#ifdef PCAP
      //iphdr = (struct ip *)pkt_holder.ip_packet;
      //#else
#endif /* PCAP */

      if((recvfrom(s,&recvbuff,sizeof(recvbuff),0x0,NULL,NULL)) < 0)
	{
	  perror("Recv");
	  close(s);
	  exit(-1);
	}

      // Stats
      app->ctr_packet_rcvd++;
      
      /* Problem with getting back the address of the host
	 is that not all hosts will answer icmp unreachable
	 directly from thier own host. */
      
      iphdr = (struct ip *)recvbuff;
      iplen = iphdr->ip_hl << 2;
      //printf("Packet Type=%d on socket=%d\n", iphdr->ip_p, s);
      if (iphdr->ip_p == 0x84 ) 
	{
	  struct sctphdr_chunk *r_sctph = (struct sctphdr_chunk *) (recvbuff + iplen);

	  // Stats
	  app->ctr_packet_sctp_rcvd++;
	  
	  retcode = r_sctph->identifier;
	  // GZZ
	  add_to_host_to_portscan(app, inet_ntoa(iphdr->ip_src));  //replaces: strcpy(app->host_to_portscan, inet_ntoa(iphdr->ip_src));
	  if ( r_sctph->identifier == SH_INIT_ACK )
	    {
	      collab_report(app, inet_ntoa(iphdr->ip_src), ntohs(r_sctph->sport), get_sctp_code(r_sctph->identifier), NULL);
	      if (!app->quiet_sendsctp_opt)
		{
		  printf("%s SCTP present on port %d\n", inet_ntoa(iphdr->ip_src), ntohs(r_sctph->sport));
		}
	      exec_script(app, inet_ntoa(iphdr->ip_src), ntohs(r_sctph->sport), get_sctp_code(r_sctph->identifier), NULL);
	    }
	  else
	    {
	      // I think we are looking at packets we just sent (bugfix #101)
	      if ( (r_sctph->identifier == SH_INIT || r_sctph->identifier == SH_SHUTDOWN_ACK) 
		   && !strcmp(app->hostl, inet_ntoa(iphdr->ip_src)))
		return(0);

	      // Don't report these ABORTs in case of portscan except first one (to avoid clutter)
 	      if ( ( r_sctph->identifier == SH_ABORT || r_sctph->identifier == SH_SHUTDOWN_ACK ) &&
		   (app->in_portscan || app->autoportscan_opt || app->frequentportscan_opt) )
 		{
 		  if (ntohs(r_sctph->sport) == 1)  // Only report Aborts on port 1
 		    collab_report(app, inet_ntoa(iphdr->ip_src), ntohs(r_sctph->sport), get_sctp_code(r_sctph->identifier), "ABORTs / SHUTDOWN_ACKs flood prevention: only port 1 will be reported.");
 		} 
 	      else 
 		{ // DO report the all other packets
 		  collab_report(app, inet_ntoa(iphdr->ip_src), ntohs(r_sctph->sport), get_sctp_code(r_sctph->identifier), NULL);
 		}
	      if (!app->quiet_sendsctp_opt )
		{
		  if (app->compact_opt)
		    compact_progress_print(r_sctph->identifier);
		  else
		    printf("SCTP packet received from %s port %d type %s\n", 
			   inet_ntoa(iphdr->ip_src), 
			   ntohs(r_sctph->sport),
			   get_sctp_id_str(r_sctph->identifier));
		} // end of !quiet_sendsctp_opt
	    } // end of processing depending on INIT_ACK or another SCTP packet
	} // end of SCTP packet processing
      if (iphdr->ip_p == 0x1 ) // ICMP packet processing
	{
	  char s_icmp_source[20];
	  char s_embeded_source[20];
	  struct icmp *r_icmph = (struct icmp *) (recvbuff + iplen);
	  //struct ip *embeded_iphdr = (struct ip *) r_icmph->icmp_data;	// used for debug
	  //struct sctphdr *embeded_sctphdr = (struct sctphdr *) (((char *)embeded_iphdr) + 20); // ip header len == 20, used for debug.

	  // Stats
	  app->ctr_packet_icmp_rcvd++;
	  
	  strcpy(s_icmp_source, inet_ntoa(iphdr->ip_src));
	  strcpy(s_embeded_source, inet_ntoa(r_icmph->icmp_ip.ip_dst));
	  	  
	  // process rejects
	  // if we get a HOST/NET unreach from some host and we are currently scanning THIS host, well... drop it :)
	  if (iphdr->ip_src.s_addr == app->cur_dstaddr &&
	      r_icmph->icmp_type == ICMP_DEST_UNREACH &&
	      r_icmph->icmp_code != ICMP_PORT_UNREACH)
	    {
	      //printf("host %s alive but reject packets. ICMP type=%d code=%d\n", inet_ntoa(iphdr->ip_src), r_icmph->icmp_type, r_icmph->icmp_code);
#define RETCODE_HOST_OR_NET_REJECT_SCTP -2
	      return(RETCODE_HOST_OR_NET_REJECT_SCTP);
	    }

	  // process other kind of packets
	  if (!app->quiet_sendsctp_opt)
	    {
	      // if we get a packet that shows a PORT UNREACH, even if we went on to scan some other host, let's scan this
	      // potential successfull host
	      if (r_icmph->icmp_type == ICMP_DEST_UNREACH &&
		  r_icmph->icmp_code == ICMP_PORT_UNREACH)
		{
		  // Port unreachable error.
		  // When the designated transport protocol (e.g., UDP) is unable to demultiplex the datagram
		  // but has no protocol mechanism to inform the sender.
		  //printf("host %s alive and accepts SCTP. Consider a full scan here.\n", inet_ntoa(iphdr->ip_src));
		  if (!app->in_portscan)
		    add_to_host_to_portscan(app, s_embeded_source); // replace: strcpy(app->host_to_portscan, s_embeded_source);
		  retcode = 6;
		  // XXX this is very tentative,
		  // history ;-) (scans) will prove us if hosts that send ICMP_PORT_UNREACH are really SCTP capable
		  // this can have the adverse option of launching full portscan against hosts that generically
		  // report ICMP_PORT_UNREACH on unknown protocol, history will tell us once again
/* 		  printf("ICMP packet from %s: %s (type=%d code=%d) about packet sent to %s:%d\n", */
/* 			 s_icmp_source,  */
/* 			 get_icmp_str(r_icmph->icmp_type, r_icmph->icmp_code), */
/* 			 r_icmph->icmp_type, */
/* 			 r_icmph->icmp_code, */
/* 			 s_embeded_source, */
/* 			 ntohs(embeded_sctphdr->dport)); */
		  //printf("select_wait_generic(): Returning %d\n", retcode);
		  if (!app->in_portscan)
		    return(retcode);
		}
	      else
		{
/* 		  printf("ICMP packet from %s: %s (type=%d code=%d) about packet sent to %s\n", */
/* 			 s_icmp_source,  */
/* 			 get_icmp_str(r_icmph->icmp_type, r_icmph->icmp_code), */
/* 			 r_icmph->icmp_type, */
/* 			 r_icmph->icmp_code, */
/* 			 s_embeded_source); */
		}
	    }
	} // end of ICMP packet processing
    } // end of reception of packet in select

  return(retcode);
}

// This version only uses data in app->{select_timeout , listen_retries}
//
// returns: -1 if no packet was received
// returns: the SCTP packet type number of the last packet received (first chunk)
//
// BUG? it seems the "s" socket is never used.
int select_wait(int s, struct app_s *app)
{
  int retcode;
  int retcode_icmp;
  int i;

  if (getenv("DEBUG")) printf("Entering select_wait()\n");

  assert(app->listen_retries != 0);

#define RETCODE_NO_PACKETS_FROM_HOST -1
  retcode = RETCODE_NO_PACKETS_FROM_HOST;	// returns -1 ONLY IF NO PACKET was ever received during the select_wait()
  for (i = 0; i < app->listen_retries; i++)
    {
      // BUG below? 
      retcode = select_wait_generic(app->rcv_sctp_socket, app);
      retcode_icmp = select_wait_generic(app->rcv_icmp_socket, app);
      if (retcode_icmp == RETCODE_HOST_OR_NET_REJECT_SCTP)
	return(RETCODE_HOST_OR_NET_REJECT_SCTP);
      if (app->autoportscan_opt && retcode_icmp)
	{
	  //printf("retcode_icmp=%d\n", retcode_icmp);
	  return(retcode_icmp);
	}      
    } // stops retrying to get packets

  return(retcode);
}

char *get_sctptype_str(int type)
{
  static char resp[256];

  strcpy(resp, "");
  if (type < 0)
    return("");
  if (type < 15)
    return(sctp_identifier[type]);
  else
    {
      sprintf(resp, "Unknown(%d)", type);
      return(resp);
    }
}

int empty_socket(int s)
{
  struct app_s es_app;

  es_app.select_timeout_usec = 10;
  es_app.select_timeout_sec = 0;
  // XXX Defined for ADSL
  //  es_app.listen_retries = 50;
  es_app.listen_retries = 10;
  es_app.cur_dstaddr = 0;

  select_wait(s, &es_app);

  return(0);
}

int send_sctp_packet(int s, char *hostl, char *hostr, short portl, short portr, struct app_s *app, int packet_type)
{
  int retcode;

  //fd_set r;
  //int retval;
  //struct timeval mytimeout;
  //unsigned char recvbuff[MAXPACKET];
  //struct ip *iphdr;
  //int iplen;

  char datagram[4096];	/* this buffer will contain ip header, sctp header,
			   and payload. we'll point an ip header structure
			   at its beginning, and a sctp header structure after
			   that to write the header values into it */

  char *pptr;	// Packet pointer, to keep adding stuff to the packer
  int psize;	// Packet size

  struct ip *iph = (struct ip *) datagram;

  struct sctphdr *sctph = (struct sctphdr *) (datagram + sizeof (struct ip));

  struct chunk_init *c_init = (struct chunk_init *) ( (char *)sctph + sizeof(struct sctphdr));
  struct chunk_shutdown_ack *c_shutdown_ack = (struct chunk_shutdown_ack *) ( (char *)sctph + sizeof(struct sctphdr));

  int chunk_len;

  struct vlparam_ip *vlip1;
  struct vlparam_ip *vlip2;
  struct vlparam_ip *vlip3;
  struct vlparam_cookie *vlcookie;
  struct vlparam_supported_addrtype *vladdrtype;

  struct sockaddr_in sin;
  /* the sockaddr_in containing the dest. address is used
     in sendto() to determine the datagrams path */

  int i;
  if (hostl == 0)
    {
      // with: struct in_addr xp_get_iface_addr(char *iname);
      //struct in_addr inatemp;
      //inatemp = xp_get_iface_addr("eth0");
      //strcpy(localstr, inet_ntoa(inatemp));
      //hostl = localstr;
      //assert(0);
      hostl = strdup("0.0.0.0");	// If not assigned, tries to use 0.0.0.0 (default) address to send packet
      }
  char **hostlp = &hostl;
  char **hostrp = &hostr;
  struct hostent *haddr;

  if (getenv("DEBUG")) printf("DEBUG: local host %s:%d remote host %s:%d\n", hostl, portl, hostr, portr);

  haddr = gethostbyname(*hostlp);
  if (haddr == NULL)
    {
      printf ("Warning: Cannot set can not get address information for localhost \"%s\"\n", *hostlp);
      exit(1);
    }

  loc_addr.port = htons(portl);
  loc_addr.addr[0].s_addr = *(uint32_t *)(haddr->h_addr);

  haddr = gethostbyname(*hostrp);
  rem_addr.port = htons(portr);
  rem_addr.addr[0].s_addr = *(uint32_t *)(haddr->h_addr);

  sin.sin_family = AF_INET;
  sin.sin_port = htons (P);/* you byte-order >1byte header values to network
			      byte order (not needed on big endian machines) */
  sin.sin_addr.s_addr = rem_addr.addr[0].s_addr;

  memset (datagram, 0, 4096);	/* zero out the buffer */

  if (getenv("DEBUG")) printf("iph=%x, sctph=%x offset between the two=%d\n", (unsigned int)iph, (unsigned int)sctph, (int)sctph - (int)iph); 

  /* we'll now fill in the ip/tcp header values, see above for explanations */
  iph->ip_hl = 5;
  iph->ip_v = 4;
  iph->ip_tos = 0;
  if (getenv("DEBUG")) printf("ip_len=%d\n", iph->ip_len);

  iph->ip_id = (u_short)htonl (54321);	/* the value doesn't matter here */
#define MAX_FUZZ_IP_FRAG 5
  switch ( app->fuzz_ip_frag )
    {
    case 5:
      iph->ip_off = htons(IP_RF); 
      strcpy(app->fuzzcase_name, "Reserved fragment");
      break;
    case 4:
      iph->ip_off = htons(IP_DF); 
      strcpy(app->fuzzcase_name, "Don't fragment");
      break;
    case 3:
      iph->ip_off = htons(IP_MF); 
      strcpy(app->fuzzcase_name, "Multiple fragments");
      break;
    case 2:
      iph->ip_off = htons(0xffff); 
      strcpy(app->fuzzcase_name, "Fragment flag = 0xffff");
      break;
    case 1:
      iph->ip_off = 0; 
      strcpy(app->fuzzcase_name, "Fragment flag = 0");
      break;
    case 0:
    default:
      iph->ip_off = 0; 
      //strcpy(app->fuzzcase_name, "Fragment flag = 0 (default)");
      break;
    }
  iph->ip_ttl = 255;
  iph->ip_p = 0x84;	// SCTP
  iph->ip_sum = 0;		/* set it to 0 before computing the actual checksum later */
  iph->ip_src.s_addr = loc_addr.addr[0].s_addr;
  iph->ip_dst.s_addr = rem_addr.addr[0].s_addr;

  // XXX
  memcpy(datagram + sizeof (struct ip), "AAAAAAAAAAAAAAAA", strlen("AAAAAAAAAAAAAAAA"));

  //sctph->sport = htons(10000);
  //sctph->dport = htons(10001);
#define MAX_FUZZ_SCTP_SPORT 2
  switch ( app->fuzz_sctp_sport ) 
    {
    case 2:
      sctph->sport = htons(0xffff); // FUZZ: ok
      strcpy(app->fuzzcase_name, "Source port = 0xffff");
      break;
    case 1:
      sctph->sport = htons(0); // FUZZ: ok
      strcpy(app->fuzzcase_name, "Source port = 0");
      break;
    case 0:
    default:
      sctph->sport = htons(portl);
      //strcpy(app->fuzzcase_name, "Source port not modified");
      break;
    }

#define MAX_FUZZ_SCTP_DPORT 2
  switch ( app->fuzz_sctp_dport ) 
    {
    case 2:
      sctph->dport = htons(0xffff); // FUZZ: no result
      strcpy(app->fuzzcase_name, "Dest port = 0xffff");
      break;
    case 1:
      sctph->dport = htons(0); // FUZZ: no result
      strcpy(app->fuzzcase_name, "Dest port = 0");
      break;
    case 0:
    default:
      sctph->dport = htons(portr);
      //strcpy(app->fuzzcase_name, "Dest port not modified");
      break;
    }

#define MAX_FUZZ_VERIFTAG 2
  switch ( app->fuzz_veriftag )
    {
    case 2:
      memcpy( &(sctph->veriftag), "\xff\xff\xff\xff", 4);		// FUZZ
      strcpy(app->fuzzcase_name, "Verification tag = 0xffffffff");
      break;
    case 1:
      sctph->veriftag = 0;
      strcpy(app->fuzzcase_name, "Verification tag = 0");
      break;
    case 0:
    default:
      sctph->veriftag = 0;
      //strcpy(app->fuzzcase_name, "Verification tag = 0 (default)");
      break;
    }

  sctph->sctp_sum = 0;

  // ========================== CHUNK START ===================================
  // CHUNK (old sctph structure with identifier, flags and length)
  //sctph->identifier = SH_INIT;
  //sctph->flags = 0;
  //sctph->length = htons( sizeof (payload) + 2 ); // NORMAL
  //sctph->length = htons(58); // OLD
  //sctph->length = 0xffff; //  FUZZ ===> dropped with strsctp-0.8.2
  //sctph->length = 0x0000; // FUZZ ===> works with strsctp-0.8.2, ethereal detects only SCTP, not INIT, malformed
  //sctph->length = htons(1); // FUZZ ===> works with strsctp-0.8.2, ethereal detects SCTP INIT, malformed
  //sctph->length = htons(sizeof (payload) + 1); // FUZZ ===> works with strsctp-0.8.2, ethereal detects SCTP INIT, well formed

  if (packet_type == SH_SHUTDOWN_ACK)
    {
      c_shutdown_ack->identifier = SH_SHUTDOWN_ACK;
      c_shutdown_ack->flags = 0;
      c_shutdown_ack->length = htons( sizeof (struct chunk_shutdown_ack) );	//equiv to: c_init->length = htons( psize + 2 );
      chunk_len = c_shutdown_ack->length;
    }
  
  if (packet_type == SH_INIT)
    {
      c_init->identifier = SH_INIT;

#define MAX_FUZZ_INIT_FLAGS 2
      switch ( app->fuzz_init_flags )
	{
	case 2:
	  c_init->flags = 255; // FUZZ: doesn't seem to have any effect
	  strcpy(app->fuzzcase_name, "init flags = 0xff");
	  break;
	case 1:
	  c_init->flags = 0;
	  strcpy(app->fuzzcase_name, "init flags = 0");
	  break;
	case 0:
	default:
	  c_init->flags = 0;
	  //strcpy(app->fuzzcase_name, "init flags = 0 (default)");
	  break;
	}

#define MAX_FUZZ_INIT_INITTAG 2
      switch ( app->fuzz_init_inittag )
	{
	case 2:
	  c_init->inittag = htonl(0xffffffff); // FUZZ: gets ABORT packet instead of INIT_ACK
	  strcpy(app->fuzzcase_name, "init tag = ff ff ff ff");
	  break;
	case 1:
	  c_init->inittag = htonl(0);
	  strcpy(app->fuzzcase_name, "init tag = 0");
	  break;
	case 0:
	default:
	  c_init->inittag = htonl(0x3ee731b1);
	  //strcpy(app->fuzzcase_name, "init tag with random value (default)");
	  break;
	}

#define MAX_FUZZ_INIT_ARWND 2
      switch ( app->fuzz_init_arwnd )
	{
	case 2:
	  c_init->a_rwnd = htonl(0xffff);
	  strcpy(app->fuzzcase_name, "a_rwnd = ff ff");
	  break;
	case 1:
	  c_init->a_rwnd = htonl(0); // FUZZ: gets reply ok, but with a_rwnd in reply == 32768
	  strcpy(app->fuzzcase_name, "a_rwnd = 0");
	  break;
	case 0:
	default:
	  c_init->a_rwnd = htonl(32768);
	  //strcpy(app->fuzzcase_name, "a_rwnd = 32 768 (default)");
	  break;
	}

#define MAX_FUZZ_INIT_OUTSTREAMS 2
      switch ( app->fuzz_init_outstreams )
	{
	case 2:
	  c_init->outstreams = htons(0xffff);
	  strcpy(app->fuzzcase_name, "outstreams = 65535");
	  break;
	case 1:
	  c_init->outstreams = htons(0);
	  strcpy(app->fuzzcase_name, "outstreams = 0");
	  break;
	case 0:
	default:
	  c_init->outstreams = htons(2);
	  //strcpy(app->fuzzcase_name, "outstreams = 2");
	  break;
	}

#define MAX_FUZZ_INIT_INSTREAMS 2
      switch ( app->fuzz_init_instreams )
	{
	case 2:
	  c_init->instreams = htons(0xffff);
	  strcpy(app->fuzzcase_name, "instreams = 65535");
	  break;
	case 1:
	  c_init->instreams = htons(0);
	  strcpy(app->fuzzcase_name, "instreams = 0");
	  break;
	case 0:
	default:
	  c_init->instreams = htons(2);
	  //strcpy(app->fuzzcase_name, "instreams = 2 (default)");
	  break;
	}

      //c_init->outstreams = htons(0); // FUZZ: ok as long as in == out
      //c_init->instreams = htons(0);
      //c_init->outstreams = htons(0xffff); // FUZZ: ok as long as in == out
      //c_init->instreams = htons(0xffff);

#define MAX_FUZZ_INIT_INITTSN 2
      switch ( app->fuzz_init_inittsn )
	{
	case 2:
	  c_init->init_tsn = htonl(0xffffffff);
	  strcpy(app->fuzzcase_name, "init tsn = ff ff ff ff");
	  break;
	case 1:
	  c_init->init_tsn = 0;
	  strcpy(app->fuzzcase_name, "init tsn = 0");
	  break;
	case 0:
	default:
	  c_init->init_tsn = 0x3ee731b1;
	  //strcpy(app->fuzzcase_name, "init tsn = random (default)");
	  break;
	}
      //c_init->init_tsn = 0x0; // FUZZ: ok, doesn't seem to be used at all

      psize = sizeof (struct chunk_init);
      pptr = (char *) ((char *)c_init + sizeof(struct chunk_init));

      if (0) // NOT MANDATORY
	{
	  //vlip1 = (struct vlparam_ip *) ((char *)c_init + sizeof(struct chunk_init));
	  vlip1 = (struct vlparam_ip *) pptr;
	  vlip1->type = VLPARAM_IPV4;
	  vlip1->length = htons(sizeof(struct vlparam_ip));
	  vlip1->ipaddr = inet_addr ("127.0.0.1");
	  pptr += sizeof(struct vlparam_ip);
	  psize += sizeof(struct vlparam_ip);
	}

      if (0) // NOT MANDATORY
	{
	  //vlip2 = (struct vlparam_ip *) ((char *)vlip1 + sizeof(struct vlparam_ip));
	  vlip2 = (struct vlparam_ip *) pptr;
	  vlip2->type = VLPARAM_IPV4;
	  vlip2->length = htons(sizeof(struct vlparam_ip));
	  vlip2->ipaddr = inet_addr ("127.0.0.1");
	  pptr += sizeof(struct vlparam_ip);
	  psize += sizeof(struct vlparam_ip);
	}

      if (0) // NOT MANDATORY
	{
	  //vlip3 = (struct vlparam_ip *) ((char *)vlip2 + sizeof(struct vlparam_ip));
	  vlip3 = (struct vlparam_ip *) pptr;
	  vlip3->type = VLPARAM_IPV4;
	  vlip3->length = htons(sizeof(struct vlparam_ip));
	  vlip3->ipaddr = inet_addr ("127.0.0.1");
	  pptr += sizeof(struct vlparam_ip);
	  psize += sizeof(struct vlparam_ip);
	}

      if (0)
	for (i = 1; i < 3; i++) // FUZZ: 180 is the maximum number of occurancies to receive INIT_ACK (psize = 1468)
	  {
	    //vlip3 = (struct vlparam_ip *) ((char *)vlip2 + sizeof(struct vlparam_ip));
	    vlip3 = (struct vlparam_ip *) pptr;
	    vlip3->type = VLPARAM_IPV4;
	    vlip3->length = htons(sizeof(struct vlparam_ip));
	    vlip3->ipaddr = inet_addr ("127.0.0.1");
	    pptr += sizeof(struct vlparam_ip);
	    psize += sizeof(struct vlparam_ip);
	  }

      //vlcookie = (struct vlparam_cookie *) ((char *)vlip3 + sizeof(struct vlparam_ip));
      vlcookie = (struct vlparam_cookie *) pptr;
      vlcookie->type = VLPARAM_COOKIE;
      vlcookie->length = htons(sizeof(struct vlparam_cookie));
#define MAX_FUZZ_COOKIE_INCREMENT 3
      switch ( app->fuzz_cookie_increment )
	{
	case 3:
	  vlcookie->increment = htonl(1);
	  strcpy(app->fuzzcase_name, "cookie increment = 1");
	  break;
	case 2:
	  vlcookie->increment = htonl(0xffffffff);
	  strcpy(app->fuzzcase_name, "cookie increment = ff ff ff ff");
	  break;
	case 1:
	  vlcookie->increment = htonl(0);
	  strcpy(app->fuzzcase_name, "cookie increment = 0");
	  break;
	case 0:
	default:
	  vlcookie->increment = htonl(100);
	  //strcpy(app->fuzzcase_name, "cookie increment = 100 (default)");
	  break;
	}
      //vlcookie->increment = htonl(100);
      pptr += sizeof(struct vlparam_cookie);
      psize += sizeof(struct vlparam_cookie);

      //vladdrtype = (struct vlparam_supported_addrtype *) ((char *)vlcookie + sizeof(struct vlparam_cookie));
      vladdrtype = (struct vlparam_supported_addrtype *) pptr;
      vladdrtype->type = VLPARAM_ADDRTYPE;
      vladdrtype->length = htons(sizeof(struct vlparam_supported_addrtype));
      vladdrtype->addrtype = htons(0x0005);
      pptr += sizeof(struct vlparam_supported_addrtype);
      psize += sizeof(struct vlparam_supported_addrtype);

      if (getenv("DEBUG")) printf("sctph->length = %d\n", psize + 2);

      // payload fill in
      //memcpy(datagram + sizeof (struct ip) + sizeof (struct sctphdr), payload, sizeof(payload));

      // fill in length
      //c_init->length = htons( sizeof (struct chunk_init) + sizeof (struct vlparam_ip) + sizeof (struct vlparam_ip) + sizeof (struct vlparam_ip) + sizeof (struct vlparam_cookie) + sizeof (struct vlparam_supported_addrtype) + 2 );
      //printf ("add %d ?= psize %d\n", sizeof (struct chunk_init) + sizeof (struct vlparam_ip) + sizeof (struct vlparam_ip) + sizeof (struct vlparam_ip) + sizeof (struct vlparam_cookie) + sizeof (struct vlparam_supported_addrtype) + 2, psize + 2);
      c_init->length = htons( psize + 2 );
      chunk_len = c_init->length;
    }

  iph->ip_len = sizeof (struct ip) + sizeof (struct sctphdr) + ntohs(chunk_len);

  // Checksum computation: first encapsulated packet, then IP
#define MAX_CHECKSUM 3
  switch ( app->checksum )
    {
    case 3:
      if (getenv("DEBUG")) printf("Sending Adler32 checksumed packet\n");
      sctph->sctp_sum = htonl(Adler32( (unsigned char *) sctph, sizeof (struct sctphdr) + ntohs(c_init->length), 1));
      strcpy(app->fuzzcase_name, "Adler32 checksum");
      break;
    case 2:
      sctph->sctp_sum = htonl(0xffffffff);
      strcpy(app->fuzzcase_name, "0xffffffff checksum");
      break;
    case 1:
      sctph->sctp_sum = htonl(0x0);
      strcpy(app->fuzzcase_name, "null checksum");
      break;
    case 0:
    default:
      if (getenv("DEBUG")) printf("Sending CRC32 checksumed packet\n");
      //sctph->sctp_sum = htonl(crc32_payload((unsigned char *) sctph, sizeof (struct sctphdr) + ntohs(c_init->length) ));
      sctph->sctp_sum = htonl(count_crc((unsigned char *) sctph, sizeof (struct sctphdr) + ntohs(c_init->length) ));
      //strcpy(app->fuzzcase_name, "crc32 checksum (default)");
      break;
    }
  
  iph->ip_sum = csum ((unsigned short *) datagram, iph->ip_len >> 1);

  /* finally, it is very advisable to do a IP_HDRINCL call, to make sure
     that the kernel knows the header is included in the data, and doesn't
     insert its own header into the packet before our data */

  {				/* lets do it the ugly way.. */
    int one = 1;
    const int *val = &one;
    if (setsockopt (s, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
      {
	printf ("Warning: Cannot set HDRINCL! Maybe you're not root, exiting!\n");
	exit(1);
      }
    
  }

  wait_for_send(s);		// Make sure the socket is ready to send packets
  if (sendto (s,		/* our socket */
	      datagram,	/* the buffer containing headers and data */
	      iph->ip_len,	/* total length of our datagram */
	      0,		/* routing flags, normally always 0 */
	      (struct sockaddr *) &sin,	/* socket addr, just like in */
	      sizeof (sin)) < 0)		/* a normal send() */
    perror("sendto"); /* printf ("error\n"); */
  else
    if (getenv("DEBUG")) printf ("Packet sent OK\n");

  // Stats
  app->ctr_packet_sent++;
  
  //app->listen_retries = 3;
  app->select_timeout_sec = 0;
  app->select_timeout_usec = SELECT_TIMEOUT;
  app->cur_dstaddr = iph->ip_dst.s_addr;

  //printf("app->listen_retries = %d, app->select_timeout_sec = %d, app->select_timeout_usec = %d\n", app->listen_retries, app->select_timeout_sec, app->select_timeout_usec);
  retcode = select_wait(s, app);
  //printf("send_sctp_packet(): retcode=%d\n",retcode);
  return(retcode);
}

int send_sctp (int s, char *hostl, char *hostr, short portl, short portr, struct app_s *app)
{
  if (app->packet_type == PACKET_TYPE_SH_INIT_PLUS_SH_SHUTDOWN_ACK)
    {
      int packet_type;
      int retcode;

      packet_type = SH_SHUTDOWN_ACK;
      retcode = send_sctp_packet(s, hostl, hostr, portl, portr, app, packet_type);
      if (retcode == RETCODE_HOST_OR_NET_REJECT_SCTP || retcode)
	return(retcode);

      packet_type = SH_INIT; // XXX Refactor here...
      return(send_sctp_packet(s, hostl, hostr, portl, portr, app, packet_type));
    }
  else
    return(send_sctp_packet(s, hostl, hostr, portl, portr, app, SH_INIT)); // XXX Refactor here...
}

// portscan SCTP ports on a machine
int portscan (int s, char *hostl, char *hostr, short portl, short portr, struct app_s *app)
{
  int p;
  int upper_port_limit = 65535;

  app->in_portscan = 1;
  printf("Portscanning %d ports on %s\n", upper_port_limit, hostr);
  for (p = 0; p <= upper_port_limit; p++)
    {
      //printf("Sending for port %d on host %s\n", p, hostr);
      send_sctp( s, hostl, hostr, portl, p, app);
    }
  app->in_portscan = 0;
  // BUG below? seems to report a different host that the one it started on... weird...
  printf("End of portscan on %s\n",hostr);
  return(0);
}

// portscan Frequent SCTP ports on a machine
int frequent_portscan (int s, char *hostl, char *hostr, short portl, short portr, struct app_s *app)
{
  int p;
  int global_ret;
  int i;

  app->in_portscan = 1;
  i = 0;
  global_ret = 0;
  printf("Portscanning Frequent Ports on %s\n", hostr);
  while ( sctp_ports[i] != 0)
    {
      int ret;

      p = sctp_ports[i];
      //printf("Sending for port %d on host %s\n", p, hostr);
      //      printf("%d\n", sctp_ports[i]);
      ret = send_sctp( s, hostl, hostr, portl, p, app);
      if (ret == RETCODE_HOST_OR_NET_REJECT_SCTP)
	break;
      if (ret > global_ret)
	global_ret = ret;
      usleep(2); // XXX: to 50: ok for fast but polite scan
      i++;
    }
  app->in_portscan = 0;
  printf("End of portscan on %s\n",hostr);
  return(global_ret);
}

int netscan_send (int s, char *hostl, char *tempt_host, short portl, short portr, struct app_s *app)
{
  // BUG below??? we don't restore the previous value...
  app->listen_retries = listen_retries = 1;
  if (app->frequentportscan_opt)
    {
      int res;
      
      res = frequent_portscan(s, hostl, tempt_host, portl, portr, app);
      if (res > 0 && app->autoportscan_opt )
	{
	  char *host;
	  
	  host = get_host_to_portscan(app);
	  portscan(s, hostl, host, portl, portr, app);
	  add_host_to_already_portscanned(app, host);
	}
//#define SCAN_SLEEP_TIME      50000
#define SCAN_SLEEP_TIME      200
      usleep(SCAN_SLEEP_TIME); // when you REMOVE this, it goes SLOWER
      return(0);
    }
  if (app->portscan_opt)
    {
      portscan(s, hostl, tempt_host, portl, portr, app);
    }
  else
    {
      int res;
      res = send_sctp(s, hostl, tempt_host, portl, portr, app);
      //printf("netscan_send(): retcode=%d\n",res);
      
      if (res > 0 && app->autoportscan_opt && !app->in_portscan  && check_more_host_to_portscan(app) )
	{
	  char *host;
	  
	  host = get_host_to_portscan(app);
	  printf("DEBUG: host = get_host_to_portscan(app) = %s\n", host);
	  frequent_portscan(s, hostl, host, portl, portr, app);
	  // GZZZ
	  add_host_to_already_portscanned(app, host);
	  //strcpy(app->host_already_portscan, app->host_to_portscan);
	}
      //scan (s, hostl, tempt_host, portl, 10000);
      //scan (s, hostl, tempt_host, portl, 10001);
    }
  usleep(SCAN_SLEEP_TIME); // when you REMOVE this, it goes SLOWER  
  return(0);
}

// Scan a C-Class network
int netscan (int s, char *hostl, char *hostr, short portl, short portr, struct app_s *app)
{
  char tempt_host[257];
  int i,j,k;
  char *pt;
  time_t time_scanstart;
  time_t time_scanend;
  
  pt=strchr(hostr,'.');
  if (pt==NULL) { /* ANET */
    for (k=0;k<=255;k++) {
      for (j=0; j<=255; j++) {
	int start_packet_sent = app->ctr_packet_sent;
	int start_packet_rcvd = app->ctr_packet_rcvd;
	int start_packet_sctp_rcvd = app->ctr_packet_sctp_rcvd;
	int start_packet_icmp_rcvd = app->ctr_packet_icmp_rcvd;
	
	printf("Scanning network %s.%u.%u.*\n", hostr, k, j);
	time_scanstart = time(NULL);
	for ( i = 1; i < 255; i++ ) {
	  sprintf(tempt_host, "%s.%u.%u.%u", hostr, k, j, i ); 
	  netscan_send(s, hostl, tempt_host, portl, portr, app);
	}
	time_scanend = time(NULL);
	printf("Scan of network %s.%u.%u.* took %d seconds packet_sent=%d packet_rcvd=%d (SCTP=%d, ICMP=%d)\n", hostr, k, j,
	       (int)(time_scanend - time_scanstart), app->ctr_packet_sent - start_packet_sent,
	       app->ctr_packet_rcvd - start_packet_rcvd,
	       app->ctr_packet_sctp_rcvd - start_packet_sctp_rcvd,
	       app->ctr_packet_icmp_rcvd - start_packet_icmp_rcvd);
	// XXX to be tested
	// BUG: Doesn't work, we get interchange of src and dest IP
	//hostl = get_sending_ip(tempt_host);
	//printf("XXX Very tentative, found host %s with get_sending_ip()\n",hostl);
	// end XXX
      }
    }
  } else {
    pt++;
    pt=strchr(pt,'.');
    if (pt==NULL) { /* BNET */
      for (j=0;j<=255;j++) {
	printf("Scanning network %s.%u.*\n", hostr, j);
	time_scanstart = time(NULL);
	int start_packet_sent = app->ctr_packet_sent;
	int start_packet_rcvd = app->ctr_packet_rcvd;
	int start_packet_sctp_rcvd = app->ctr_packet_sctp_rcvd;
	int start_packet_icmp_rcvd = app->ctr_packet_icmp_rcvd;

	for ( i = 1; i < 255; i++ ) {
	  sprintf(tempt_host, "%s.%u.%u", hostr, j, i ); 
	  netscan_send(s, hostl, tempt_host, portl, portr, app);
	}
	time_scanend = time(NULL);
	printf("Scan of network %s.%u.* took %d seconds packet_sent=%d packet_rcvd=%d (SCTP=%d, ICMP=%d)\n", hostr, j,
	       (int)(time_scanend - time_scanstart), app->ctr_packet_sent - start_packet_sent,
	       app->ctr_packet_rcvd - start_packet_rcvd,
	       app->ctr_packet_sctp_rcvd - start_packet_sctp_rcvd,
	       app->ctr_packet_icmp_rcvd - start_packet_icmp_rcvd);
	// XXX to be tested
	//hostl = get_sending_ip(tempt_host);
	//printf("XXX Very tentative, found host %s with get_sending_ip()\n",hostl);
	// end XXX
      }
    } else { /* CNET */
      for ( i = 1; i < 255; i++ ) {
	sprintf(tempt_host, "%s.%u", hostr, i ); 
	netscan_send(s, hostl, tempt_host, portl, portr, app);
      }
    }
  }

  return(0);
}

int fuzz_member (int s, char *hostl, char *hostr, short portl, short portr, struct app_s *app, int *fuzzmember, int max, char *tcase)
{
  int f;
  int saved;			// saved value of the fuzzed member
  int fuzz_state;		// state of the fuzz send_sctp();

  saved = *fuzzmember;
  
  for (f = 0; f <= max; f++)	// we test normal case and the exception conditions (0 to max)
    {
      int count;

      count = 0;
      fuzz_state = -1;
      while (fuzz_state == -1 && count < 2)
	{
	  strcpy(app->fuzzcase_name, "normal");	// if not modified, then it's a normal packet, not fuzzed one
	  *fuzzmember = f;
	  fuzz_state = send_sctp(s, hostl, hostr, portl, portr, app);
	  if (fuzz_state != -1)
	    printf("Fingerprint: %s test case %d (%s) : %d %s\n", tcase, *fuzzmember, app->fuzzcase_name, fuzz_state, get_sctptype_str(fuzz_state));
	  count++;
	}
      if (fuzz_state == -1)
	printf("Fingerprint: %s test case %d (%s) : %d %s\n", tcase, *fuzzmember, app->fuzzcase_name, fuzz_state, get_sctptype_str(fuzz_state));
      empty_socket(s);
    }
  *fuzzmember = saved;
  return(fuzz_state);
}

int fuzzhost (int s, char *hostl, char *hostr, short portl, short portr, struct app_s *app)
{
  int tsec;
  int tusec;
  int tlretries;
  int tquiet_sendsctp;

  // backup the original state of the options
  tsec = app->select_timeout_sec;
  tusec = app->select_timeout_usec;
  tlretries = app->listen_retries = listen_retries;
  tquiet_sendsctp = app->quiet_sendsctp_opt;

  // set fuzzing options
  app->select_timeout_sec = 1;
  app->select_timeout_usec = 10000;
  app->listen_retries = listen_retries = 400;
  app->quiet_sendsctp_opt = 1;

  fuzz_member(s, hostl, hostr, portl, portr, app, &(app->checksum), MAX_CHECKSUM, "checksum");
  fuzz_member(s, hostl, hostr, portl, portr, app, &(app->fuzz_ip_frag), MAX_FUZZ_IP_FRAG, "ip frag");
  fuzz_member(s, hostl, hostr, portl, portr, app, &(app->fuzz_sctp_sport), MAX_FUZZ_SCTP_SPORT, "source port");
  fuzz_member(s, hostl, hostr, portl, portr, app, &(app->fuzz_sctp_dport), MAX_FUZZ_SCTP_DPORT, "dest port");
  fuzz_member(s, hostl, hostr, portl, portr, app, &(app->fuzz_veriftag), MAX_FUZZ_VERIFTAG, "veriftag");
  fuzz_member(s, hostl, hostr, portl, portr, app, &(app->fuzz_init_flags), MAX_FUZZ_INIT_FLAGS, "init flags");
  fuzz_member(s, hostl, hostr, portl, portr, app, &(app->fuzz_init_inittag), MAX_FUZZ_INIT_INITTAG, "inittag");
  fuzz_member(s, hostl, hostr, portl, portr, app, &(app->fuzz_init_arwnd), MAX_FUZZ_INIT_ARWND, "arwnd");
  fuzz_member(s, hostl, hostr, portl, portr, app, &(app->fuzz_init_outstreams), MAX_FUZZ_INIT_OUTSTREAMS, "out streams");
  fuzz_member(s, hostl, hostr, portl, portr, app, &(app->fuzz_init_instreams), MAX_FUZZ_INIT_INSTREAMS, "in streams");
  fuzz_member(s, hostl, hostr, portl, portr, app, &(app->fuzz_init_inittsn), MAX_FUZZ_INIT_INITTSN, "init tsn");
  fuzz_member(s, hostl, hostr, portl, portr, app, &(app->fuzz_cookie_increment), MAX_FUZZ_COOKIE_INCREMENT, "cookie increment");
  //fuzz_member(s, hostl, hostr, portl, portr, app, &(), , "");

  // return the options to their original state
  app->select_timeout_sec = tsec;
  app->select_timeout_usec = tusec;
  app->listen_retries = listen_retries = tlretries;
  app->quiet_sendsctp_opt = tquiet_sendsctp;

  return(0);
}

char *get_checksum_str(int checksum)
{
  switch ( checksum )
    {
    case 0:
      return("Crc32");
      break;
    case 1:
      return("Null");
      break;
    case 2:
      return("0xff-bytes");
      break;
    case 3:
      return("Adler32");
      break;
    default:
      return("Unknown-value-for-checksum--incorrect?");
      break;
    }
  return("Error-in-get_checksum_str");
}

// This is not used for the moment
void test_all()
{
  assert(!strcmp(get_sending_ip("127.0.0.1"), "127.0.0.1"));
  assert(!strcmp(get_sending_ip("127.0.0.2"), "127.0.0.2"));
}

int main(int argc, char **argv)
{
//  test_all();

  time_t time_start;
  time_t time_end;
#ifdef HAVE_PCAP
  char *dev;				/* The device to sniff on */
  char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */

  char errbuf_icmp[PCAP_ERRBUF_SIZE];	/* Error string */
  struct bpf_program fp_icmp;		/* The compiled filter */
  char filter_exp_icmp[] = "icmp";	/* The filter expression */

  char errbuf_sctp[PCAP_ERRBUF_SIZE];	/* Error string */
  struct bpf_program fp_sctp;		/* The compiled filter */
  char filter_exp_sctp[] = "sctp";	/* The filter expression */
#endif /* PCAP vs RAW SOCKETS */
//#else /* RAW SOCKETS */
  //int s = socket (PF_INET, SOCK_RAW, 132);	/* open raw socket for SCTP protocol */
  int s;

  int c;
  char *hostl = 0;
  char *hostr = "127.0.0.1";
  char hostbufl[HOST_BUF_LEN];
  char hostbufr[HOST_BUF_LEN];
  short portl = 10000;
  short portr = 10001;
  //struct hostent *haddr;
  int scanopt = 0;
  int mapopt = 0;
  struct app_s app;

  // APP & FUZZ DEF
  app.portscan_opt = 0;
  app.netscan_opt = 0;
  app.autoportscan_opt = 0;
  app.linein_opt = 0;
  app.fuzz_opt = 0;
  app.both_checksum_opt = 0;
  app.frequentportscan_opt = 0;
  app.quiet_sendsctp_opt = 0;
  app.zombie_opt = 0; // Collaborative reporting by default (feat 105)
  app.exec_on_port_opt = NULL;
  app.tcp_bridge_opt = 0;
  app.init_outstreams = 1;
  app.init_instreams = 1;
  app.sctpscan_version = 12;
  app.select_timeout_usec = SELECT_TIMEOUT;
  app.select_timeout_sec = 0;
  app.listen_retries = listen_retries = 1;
  app.fuzz_ip_frag = 0;
  app.fuzz_sctp_sport = 0;
  app.fuzz_sctp_dport = 0;
  app.fuzz_veriftag = 0;
  app.fuzz_init_flags = 0;
  app.fuzz_init_inittag = 0;
  app.fuzz_init_arwnd = 1500;	// Changed that to respect section 6 of RFC  2960
  app.fuzz_init_outstreams = 0;
  app.fuzz_init_instreams = 0;
  app.fuzz_init_inittsn = 0;
  app.fuzz_cookie_increment = 0;
  app.checksum = 0; // CRC 32
  app.packet_type = SH_INIT; //PACKET_TYPE_SH_INIT_PLUS_SH_SHUTDOWN_ACK; // or SH_INIT, starting at v12, BOTH is Default, feat 103
#ifndef __G_LIB_H__
  strcpy(app.host_already_portscan, "somehost"); // of course when you do strcmp of something null, you get 0!! damn libc
  strcpy(app.host_to_portscan, "somehost"); // of course when you do strcmp of something null, you get 0!! damn libc
#else
  app.host_already_portscan = g_queue_new ();
  app.host_to_portscan = g_queue_new ();
#endif
  app.in_portscan = 0;
  app.compact_opt = 0;
  app.ctr_packet_rcvd = 0;
  app.ctr_packet_sent = 0;
  app.ctr_packet_icmp_rcvd = 0;
  app.ctr_packet_sctp_rcvd = 0;
#ifdef __G_LIB_H__
  app.cmd_line = get_cmd_line(argc, argv);
#endif
  
  init_sctp_identifier();

  if (argc < 2) {usage(); close(s); exit(1);}

  fprintf(stderr,"SCTPscan - Copyright (C) 2002 - 2009 Philippe Langlois.\n");

  time_start = time(NULL);
  while (1) 
    {
      int option_index = 0;
      static struct option long_options[] =
	{
	  {   "loc_host",	    1, 0, 'l' },
	  {   "rem_host",	    1, 0, 'r' },
	  {   "scan",		    0, 0, 's' },
	  {   "help",		    0, 0, 'h' },
	  {   "port",		    1, 0, 'p' },
	  {   "loc_port",	    1, 0, 'P' },
	  {   "map",		    0, 0, 'm' },
	  {   "adler32",	    0, 0, 'A' },
	  {   "crc32",		    0, 0, 'C' },
	  {   "fuzz",		    0, 0, 'f' },
	  {   "both_checksum",	    0, 0, 'b' },
	  {   "Frequent",	    0, 0, 'F' },
	  {   "autoportscan",	    0, 0, 'a' },
	  {   "linein",             0, 0, 'i' },
	  {   "bothpackets",        0, 0, 'B' },
	  {   "compact",            0, 0, 'c' },
	  {   "zombie",		    0, 0, 'Z' },
	  {   "dummyserver",	    0, 0, 'd' },
	  {   "exec",		    1, 0, 'E' },
	  {   "tcpbridge",	    1, 0, 't' },
	  {   "streams",	    1, 0, 'S' }
	};
      c = getopt_long(argc,argv,"l:r:shp:P:mACfbFaiBcZdE:t:S:",long_options,&option_index);
      if ( c == -1 )
	break;
      switch ( c ) 
	{
	case 0:
	  switch ( option_index ) 
	    {
	    case 0: /* loc_host */
	      strncpy(hostbufl,optarg,HOST_BUF_LEN);
	      hostl = hostbufl;
	      app.hostl = hostbufl;
	      break;
	    case 1: /* rem_host */
	      strncpy(hostbufr,optarg,HOST_BUF_LEN);
	      hostr = hostbufr;
	      app.hostr = hostbufr;
	      break;
	    case 2: /* scan == netscan */
	      app.netscan_opt = scanopt = 1;
	      break;
	    case 3: /* help */
	      usage();
	      close(s);
	      exit(0);
	    case 4: /* port */
	      portr = atoi(optarg);
	      break;
	    case 5: /* loc_port */
	      portl = atoi(optarg);
	      break;
	    case 6: /* map == portscan */
	      app.portscan_opt = mapopt = 1;
	      break;
	    case 7: /* Adler 32 */
	      app.checksum = 3;
	      break;
	    case 8: /* CRC 32 */
	      app.checksum = 0;
	      break;
	    case 9: /* fuzz */
	      app.fuzz_opt = 1;
	      break;
	    case 10: /* send both checksum */
	      app.both_checksum_opt = 1;
	      break;
	    case 11:
	      app.frequentportscan_opt = 1;
	      break;
	    case 12:
	      app.autoportscan_opt = 1;
	      break;
	    case 13: /* get IPs to scan from stdin */
	      app.linein_opt = 1;
	      break;
	    case 14: /* Send init AND Shutdown Ack packets */
	      app.packet_type = PACKET_TYPE_SH_INIT_PLUS_SH_SHUTDOWN_ACK;
	      break;
	    case 15: /* Compact output */
	        app.compact_opt = 1;
		break;
	    case 16: /* Zombie option: does not collaborate to the SCTP platform. No reporting. (feat 105) */
	      app.zombie_opt = 1;
	      break;
	    case 17: /* Dummy server option: Add an option to start a dummy listening SCTP server. (feat 108) */
	      dummyserver(portl);
	      break;
	    case 18: /* Execution of external command on new SCTP port discovery (--exec / -E) (feat 109) */
	      app.exec_on_port_opt = strdup(optarg);
	      break;
	    case 19: /* TCP to SCTP bridge (--tcpbridge / -t) */
	      app.tcp_bridge_opt = atoi(optarg);
	      break;
	    case 20: /* Number of SCTP streams */
	      app.tcp_bridge_opt = atoi(optarg);
	      break;
	    default:
	      usage();
	      close(s);
	      exit(1);
	    }
	  break;
	case 'l':
	  strncpy(hostbufl,optarg,HOST_BUF_LEN);
	  hostl = hostbufl;
	  app.hostl = hostbufl;
	  break;
	case 'r':
	  strncpy(hostbufr,optarg,HOST_BUF_LEN);
	  hostr = hostbufr;
	  app.hostr = hostbufr;
	  break;
	case 's':
	  app.netscan_opt = scanopt = 1;
	  break;
	case 'h':
	  usage();
	  close(s);
	  exit(0);
	case 'p':
	  portr = atoi(optarg);
	  break;
	case 'P':
	  portl = atoi(optarg);
	  break;
	case 'm':
	  app.portscan_opt = mapopt = 1;
	  break;
	case 'A': /* Adler 32 */
	  app.checksum = 3;
	  break;
	case 'C': /* CRC 32 */
	  app.checksum = 0;
	  break;
	case 'f': /* fuzz */	  
	  app.fuzz_opt = 1;
	  break;
	case 'b': /* send both checksum */
	  app.both_checksum_opt = 1;
	  break;
	case 'F':
	  app.frequentportscan_opt = 1;
	  break;
	case 'a':
	  app.autoportscan_opt = 1;
	  break;
	case 'i':
	  app.linein_opt = 1;
	  break;
	case 'B':
	  app.packet_type = PACKET_TYPE_SH_INIT_PLUS_SH_SHUTDOWN_ACK;
	  break;
	case 'c':
	  app.compact_opt = 1;
	  break;
	case 'Z': /* Zombie option: does not collaborate to the SCTP platform. No reporting. (feat 105) */
	  app.zombie_opt = 1;
	  break;
	case 'd': /* Dummy server option: Add an option to start a dummy listening SCTP server. (feat 108) */
	  dummyserver(portl);
	  break;
	case 'E': /* Execution of external command on new SCTP port discovery (--exec / -E) (feat 109) */
	  app.exec_on_port_opt = strdup(optarg);
	  break;
	case 't': /* TCP bridge to SCTP (--tcpbridge / -t) */
	  app.tcp_bridge_opt = atoi(optarg);
	  break;
	case 'S': /* Number of SCTP streams */
	  app.init_instreams = app.init_outstreams = atoi(optarg);
	  break;
	default:
	  fprintf(stderr,"ERROR: Unrecognized option '%c'.\n",c);
	  usage();
	  close(s);
	  exit(1);
	}
    }
  if ( optind < argc ) 
    {
      fprintf(stderr, "ERROR: Option syntax: ");
      while ( optind < argc )
	fprintf(stderr, "%s ",argv[optind++]);
      fprintf(stderr,"\n");
      usage();
      close(s);
      exit(1);
    }

  /***************** Reality checks ********************/
  if (hostl == 0)
    {
      app.hostl = hostl = strdup("0.0.0.0");	// If not assigned, tries to use 0.0.0.0 (default) address to send packet
    }


  /***************** TCP Bridge ********************/
  if (app.tcp_bridge_opt)
    {
      TCPtoSCTP(app.tcp_bridge_opt, hostl, portl, (unsigned char *)hostr, portr, app.init_instreams);
      exit(0);
    }


  /******************* Socket init *********************/
#ifdef HAVE_PCAP
  /* PCAP: Define the device */
  //dev = pcap_lookupdev(errbuf);
  dev = pcap_lookupdev(errbuf);
  //dev = "lo0";
  if (dev == NULL)
  {
     fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
     return(2);
  }
  // PCAP: Open ICMP
  app.rcv_icmp_pcap = pcap_open_live(dev, SNAP_LEN, NO_PROMISC, PCAP_TIMEOUT, errbuf_icmp);
  if (app.rcv_icmp_pcap == NULL) {
	fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf_icmp);
	return(2);
  }
  // PCAP: Open SCTP
  app.rcv_sctp_pcap = pcap_open_live(dev, SNAP_LEN, NO_PROMISC, PCAP_TIMEOUT, errbuf_sctp);
  if (app.rcv_sctp_pcap == NULL) {
	fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf_sctp);
	return(2);
  }
  // PCAP: Compile & Apply ICMP
  if (pcap_compile(app.rcv_icmp_pcap, &fp_icmp, filter_exp_icmp, 0, 0) == -1) {
	fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp_icmp, pcap_geterr(app.rcv_icmp_pcap));
	return(2);
  }
  if (pcap_setfilter(app.rcv_icmp_pcap, &fp_icmp) == -1) {
	fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp_icmp, pcap_geterr(app.rcv_icmp_pcap));
	return(2);
  }
  // PCAP: Compile & Apply SCTP
  if (pcap_compile(app.rcv_sctp_pcap, &fp_sctp, filter_exp_sctp, 0, 0) == -1) {
	fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp_sctp, pcap_geterr(app.rcv_sctp_pcap));
	return(2);
  }
  if (pcap_setfilter(app.rcv_sctp_pcap, &fp_sctp) == -1) {
	fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp_sctp, pcap_geterr(app.rcv_sctp_pcap));
	return(2);
  }

  app.rcv_icmp_pcap_fd = pcap_get_selectable_fd(app.rcv_icmp_pcap);
  app.rcv_sctp_pcap_fd = pcap_get_selectable_fd(app.rcv_sctp_pcap);

  // Set Non-blocking mode
  if (pcap_setnonblock(app.rcv_icmp_pcap, 1, errbuf_icmp) < 0)
    fprintf(stderr, "Couldn't set rcv_icmp_pcap as nonblocking: %s\n", errbuf_icmp);
  if (pcap_setnonblock(app.rcv_sctp_pcap, 1, errbuf_sctp) < 0)
    fprintf(stderr, "Couldn't set rcv_sctp_pcap as nonblocking: %s\n", errbuf_sctp);

// ZZZ
//#else  /* PCAP vs RAW SOCKETS */
#endif /* PCAP vs RAW SOCKETS */
  app.rcv_icmp_socket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  app.rcv_sctp_socket = socket(AF_INET, SOCK_RAW, IPPROTO_SCTP);
  //rcv_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  //#endif  /* PCAP vs RAW SOCKETS */
  s = socket (AF_INET, SOCK_RAW, IPPROTO_RAW);	  //IPPROTO_RAW
  app.raw_socket = s;

  do
    {
      if (app.linein_opt)
	{
	  char *s;
	  char linein[READBUFSIZE];

	  s = fgets(linein, READBUFSIZE - 2, stdin);
	  if ( s == NULL || strlen(linein) <= 1)
	    break;
	  linein[strlen(linein) - 1] = '\0';
	  strncpy(hostbufr, linein, HOST_BUF_LEN);
	  hostr = hostbufr;
/* 	  hostrp = &hostr; */
	}

      if (app.frequentportscan_opt && !app.portscan_opt && !app.netscan_opt)
	{
	  app.listen_retries = listen_retries = 1;
      
	  if (app.both_checksum_opt)
	    {
	      printf("Portscanning with CRC32 checksumed packet\n");
	      app.checksum = 0;
	      frequent_portscan(s, hostl, hostr, portl, portr, &app);
	  
	      printf("Portscanning with Adler32 checksumed packet\n");
	      app.checksum = 3;
	      frequent_portscan(s, hostl, hostr, portl, portr, &app);
	    }
	  else
	    {
	      //printf("Portscanning with %s checksumed packet\n", app.checksum ? "Adler32" : "CRC32");
	      printf("Portscanning with %s checksumed packet\n", get_checksum_str(app.checksum));
	      frequent_portscan(s, hostl, hostr, portl, portr, &app);
	    }      
	}

      if (app.fuzz_opt)
	{
	  if (app.both_checksum_opt)
	    {
	      app.checksum = 0;
	      //printf("Fingerprinting with %s checksumed packet\n", app.checksum ? "Adler32" : "CRC32");
	      printf("Fingerprinting with %s checksumed packet\n", get_checksum_str(app.checksum));
	      fuzzhost(s, hostl, hostr, portl, portr, &app);

	      app.checksum = 3;
	      //printf("Fingerprinting with %s checksumed packet\n", app.checksum ? "Adler32" : "CRC32");
	      printf("Fingerprinting with %s checksumed packet\n", get_checksum_str(app.checksum));
	      fuzzhost(s, hostl, hostr, portl, portr, &app);
	    }
	  else
	    {
	      //printf("Fingerprinting with %s checksumed packet\n", app.checksum ? "Adler32" : "CRC32");
	      printf("Fingerprinting with %s checksumed packet\n", get_checksum_str(app.checksum));
	      fuzzhost(s, hostl, hostr, portl, portr, &app);
	    }

	  close(s);
	  exit(0);
	}

      if (scanopt || app.netscan_opt)
	{
	  // Launch of the network scan
	  if (app.both_checksum_opt)
	    {
	      printf("Netscanning with CRC32 checksumed packet\n");
	      app.checksum = 0;
	      netscan(s, hostl, hostr, portl, portr, &app);

	      printf("Netscanning with Adler32 checksumed packet\n");
	      app.checksum = 3;
	      netscan(s, hostl, hostr, portl, portr, &app);
	    }
	  else
	    {
	      //printf("Netscanning with %s checksumed packet\n", app.checksum ? "Adler32" : "CRC32");
	      printf("Netscanning with %s checksumed packet\n", get_checksum_str(app.checksum));
	      netscan(s, hostl, hostr, portl, portr, &app);
	    }

	}
      else
	{
	  if (mapopt || app.portscan_opt)
	    {
	      app.listen_retries = listen_retries = 1;

	      if (app.both_checksum_opt)
		{
		  printf("Portscanning with CRC32 checksumed packet\n");
		  app.checksum = 0;
		  portscan(s, hostl, hostr, portl, portr, &app);

		  printf("Portscanning with Adler32 checksumed packet\n");
		  app.checksum = 3;
		  portscan(s, hostl, hostr, portl, portr, &app);
		}
	      else
		{
		  //printf("Portscanning with %s checksumed packet\n", app.checksum ? "Adler32" : "CRC32");
		  printf("Portscanning with %s checksumed packet\n", get_checksum_str(app.checksum));
		  portscan(s, hostl, hostr, portl, portr, &app);
		}

	    }
	  else
	    {
	      app.listen_retries = listen_retries = 20;

	      if (app.both_checksum_opt)
		{
		  printf("Sending CRC32 checksumed packet\n");
		  app.checksum = 0;
		  send_sctp(s, hostl, hostr, portl, portr, &app);

		  printf("Sending Adler32 checksumed packet\n");
		  app.checksum = 3;
		  send_sctp(s, hostl, hostr, portl, portr, &app);
		}
	      else
		{
		  //printf("Sending %s checksumed packet\n", app.checksum ? "Adler32" : "CRC32");
		  printf("Sending %s checksumed packet\n", get_checksum_str(app.checksum));
		  send_sctp(s, hostl, hostr, portl, portr, &app);
		}
	    }
	}
    }
  while( app.linein_opt);

  // Final wait: we want to get our lost sheep, erm, packets
  // XXX Defined for ADSL
  //app.select_timeout_sec = 1;
  //app.select_timeout_usec = 0;
  //app.listen_retries = listen_retries = 3;
  app.select_timeout_sec = 0;
  app.select_timeout_usec = 10000;
  app.listen_retries = listen_retries = 200;
  app.cur_dstaddr = 0;
  select_wait(s, &app);
  close(s);
  time_end = time(NULL);
  printf("End of scan: duration=%d seconds packet_sent=%d packet_rcvd=%d (SCTP=%d, ICMP=%d)\n", (int)(time_end - time_start),
	 app.ctr_packet_sent, app.ctr_packet_rcvd, app.ctr_packet_sctp_rcvd, app.ctr_packet_icmp_rcvd);

  return 0;
}
