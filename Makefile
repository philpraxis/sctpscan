all : sctpscan

sctpscan: sctpscan.c
	cc -g sctpscan.c `pkg-config --cflags --libs glib-2.0`  -o sctpscan

clean:
	rm -f pcap_sctp sctpscan fake-m3ua

tgz:
	tar zcvf sctpscan.tar.gz sctpscan.c LICENSE README COPYING Makefile
