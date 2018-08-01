#!/bin/sh
set -e

ZONE=$1 ; shift
YYYYMMDD=$1 ; shift

if test "$ZONE" = "root" ; then
	OWNER="."
else
	OWNER=$ZONE
fi

for D in `seq 0 9` ; do
    for B in `seq 1 26` ; do

	SUM=0
        for I in `seq 1 3`; do

		cp /dev/null /tmp/updates.txt
		perl mk-updates.pl $OWNER > /tmp/updates.txt

		../../ldns-zone-digest-incremental \
			-t \
			-p 2 \
			-c \
			-D $D \
			-W $B \
			-u /tmp/updates.txt \
			$OWNER \
			../../Zones/$ZONE-$YYYYMMDD \
			> /tmp/timing.$$
		T=`awk '/^TIMINGS:/ {print $9}' /tmp/timing.$$`
		SUM=`echo $SUM + $T | bc -l`
	done
	AVG=`echo $SUM / $I | bc -l`
	printf "%d %d %5.2f\n" $D $B $AVG
    done
    echo ""
    echo ""
done
