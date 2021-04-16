#!/bin/bash
DEST_PORT=${1:-80}
for I in `cat ip_addr.txt`
do
	result_file="results_${I}_${DEST_PORT}"
	echo "scan report for network $I on port $DEST_PORT" > $result_file
	echo -n 'start at ' >> $result_file
	date >> $result_file
	sudo ./sctpscan -l `ifconfig ens3 | grep 'inet ' | sed 's/.*inet \(.*\) netmask.*/\1/'` -s -r $I -p $DEST_PORT >> $result_file
	echo -n 'end at ' >> $result_file
	date >> $result_file
done
