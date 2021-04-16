# SCTPScan.c
This program was originally authored by philpraxis but appears to be no longer supported.
I am forking from here: https://github.com/philpraxis/sctpscan
I am modifying the program to support 64 bit architectures and resolve some annoying bugs.


there is a Blackhat talk that also accompanies this program here:
https://www.blackhat.com/presentations/bh-europe-07/Langlois/Whitepaper/bh-eu-07-langlois-WP.pdf
and a HITB talk here:
https://conference.hitb.org/hitbsecconf2013ams/materials/D1T2%20-%20Philippe%20Langlois%20-%20Hacking%20HLR%20HSS%20and%20MME%20Core%20Network%20Elements.pdf

# Is SCTP still relevant?
SCTP is a support Streamining protocol on Linux. The implementation has some interesting features
and is poorly documented or supported, so there is great potential for bugs to be present. SCTP is used as a transport protocol between cell phone towers
and authentication modules for mobile phones. In Telephony Speak, this is the N1/N2 connection in 5G and the S1-MME interface in 4G/LTE. The layer7 protocol used
is S1AP for LTE and NGAP for 5G. So yes, it's still relevant :).
