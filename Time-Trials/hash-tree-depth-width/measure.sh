#!/bin/sh
#et -e

for D in `seq 0 9` ; do
    for B in `seq 1 26` ; do
	SUM=0.0
	for N in `seq 1 3`; do

		#echo "Depth $D Branch $B #$N" 1>&2

		/usr/bin/time --format '%U %S' --output /tmp/cpu \
		../../ldns-zone-digest \
			-v \
			-D $D \
			space \
			space-20180725 \
			2>/dev/null
		CPU=`cat /tmp/cpu | sed -e's/ /+/' | bc -l`
		SUM=`echo $SUM+$CPU | bc -l`
	done
	CPU=`echo $SUM/$N | bc -l`
	printf "%d %d %5.2f\n" $D $B $CPU
    done
    echo ""
done
