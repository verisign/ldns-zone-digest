#!/bin/sh
set -e

MODE=$1 ; shift
ALG=$1 ; shift
YYYYMMDD=$1 ; shift

UDIR=Undigested-$YYYYMMDD
DDIR=Digested-$YYYYMMDD-alg$ALG
mkdir -p $UDIR
mkdir -p $DDIR

LOG=/dev/null
if test "$MODE" = "-c" ; then
	LOG=calculate-alg$ALG.log
elif test "$MODE" = "-v" ; then
	LOG=validate-alg$ALG.log
fi

cp /dev/null ${LOG}_

for ZF in /zfa/Zones/*/2018/*-${YYYYMMDD}.gz ; do
	ZN=`basename $ZF | sed -e "s/-${YYYYMMDD}.gz//"`
	echo "$ZN..."
	test "$ZN" = "com" && continue
	if test -s $UDIR/$ZN ; then
		echo "$UDIR/$ZN already exists"
	else
		gzip -dc $ZF > $UDIR/$ZN
	fi
	NR=`wc -l < $UDIR/$ZN`
	NRSET=`cat $UDIR/$ZN | awk '{print $1,$4}' | sort | uniq -i | wc -l`
	rm -f /tmp/cpu
	if test "$MODE" = "-c" ; then
		../../ldns-zone-digest \
			-t \
			-p $ALG \
			-c \
			-o $DDIR/$ZN \
			$ZN \
			$UDIR/$ZN \
		> /tmp/timing.$$
		T=`awk '/^TIMINGS:/ {print $5}' /tmp/timing.$$`
	elif test "$MODE" = "-v" ; then
		../../ldns-zone-digest \
			-v \
			$ZN \
			$DDIR/$ZN \
		> /tmp/timing.$$
		T=`awk '/^TIMINGS:/ {print $7}' /tmp/timing.$$`
	fi
	printf "%s %d %d %5.2f\n" $ZN $NR $NRSET $T >> ${LOG}_
done

sort -n -k 2 < ${LOG}_ > ${LOG}
rm -f ${LOG}_

rm -v /tmp/timing.$$
