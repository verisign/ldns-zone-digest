#!/bin/sh
#et -e

for D in `seq 0 9` ; do
    for B in `seq 1 26` ; do
	BEST=99999999
        for I in `seq 1 3`; do
		#echo "Depth $D Branch $B #$N" 1>&2

		/usr/bin/time --format '%U %S' --output /tmp/cpu \
		../../ldns-zone-digest-incremental \
			-p 2 \
			-c \
			-D $D \
			-W $B \
			space \
			space-20180725 \
			> /tmp/timing
		T=`awk '/^TIMINGS:/ {print $5}' /tmp/timing`
		if expr $T '<' $BEST >/dev/null ; then
			BEST=$T
		fi
	done
	printf "%d %d %5.2f\n" $D $B $BEST
    done
    echo ""
done
