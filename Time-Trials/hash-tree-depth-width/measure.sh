#!/bin/sh
#et -e

ZONE=$1 ; shift
YYYYMMDD=$1 ; shift

if test "$ZONE" = "root" ; then
	OWNER="."
else
	OWNER=$ZONE
fi

for D in `seq 0 9` ; do
    for B in `seq 1 26` ; do
	BEST=99999999
        for I in `seq 1 3`; do
		#echo "Depth $D Branch $B #$N" 1>&2

		../../ldns-zone-digest-incremental \
			-t \
			-p 2 \
			-c \
			-D $D \
			-W $B \
			$OWNER \
			../../Zones/$ZONE-$YYYYMMDD \
			> /tmp/timing.$$
		T=`awk '/^TIMINGS:/ {print $5}' /tmp/timing.$$`
		if expr $T '<' $BEST >/dev/null ; then
			BEST=$T
		fi
	done
	printf "%d %d %5.2f\n" $D $B $BEST
    done
    echo ""
    echo ""
done
