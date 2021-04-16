#!/bin/bash
DEST_PORT=${1:-80}
for I in `cat ip_addr.txt`
do
	echo "scan report for network $I on port $DEST_PORT" > results_$I
	echo -n 'start at ' >> results_$I
	date >> results_$I
	sudo ./sctpscan -l `ifconfig ens3 | grep 'inet ' | sed 's/.*inet \(.*\) netmask.*/\1/'` -s -r $I -p $DEST_PORT >> results_$I
	echo -n 'end at ' >> results_$I
	date >> results_$I
done
