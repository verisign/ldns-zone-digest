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
	rm -f /tmp/cpu
	if test "$MODE" = "-c" ; then
		/usr/bin/time --format '%U %S' --output /tmp/cpu \
		../ldns-zone-digest -p $ALG -c $ZN \
		< $UDIR/$ZN \
		> $DDIR/$ZN \
		2>/dev/null
	elif test "$MODE" = "-v" ; then
		/usr/bin/time --format '%U %S' --output /tmp/cpu \
		../ldns-zone-digest -v $ZN \
		< $DDIR/$ZN
	fi
	CPU=`cat /tmp/cpu`
	echo "$ZN $NR $CPU" >> ${LOG}_
done

sort -n -k 2 < ${LOG}_ > ${LOG}
rm -f ${LOG}_
