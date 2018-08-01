YYYYMMDD=20180725
ZONE=earth
PWD=$(shell pwd)
NAME=$(shell basename ${PWD})

all: \
 ${ZONE}/${NAME}-${ZONE}.png \
 ${ZONE}/${NAME}-${ZONE}-2d.png

${ZONE}/${NAME}-${ZONE}.png: ${ZONE}/${NAME}-${ZONE}.dat plotcmd
	cat -s ${ZONE}/${NAME}-${ZONE}.dat \
	| perl normalize-dat.pl \
	| gnuplot -e "ZONE='${ZONE}'" plotcmd > $@_
	mv $@_ $@

${ZONE}/${NAME}-${ZONE}-2d.png: ${ZONE}/${NAME}-${ZONE}.dat plotcmd2d
	gnuplot \
		-e "ZONE='${ZONE}'" \
		-e "DATAFILE='${ZONE}/${NAME}-${ZONE}.dat'" \
		plotcmd2d \
		> $@_
	mv $@_ $@

${ZONE}/${NAME}-${ZONE}.dat:
	mkdir -p ${ZONE}
	sh measure.sh ${ZONE} ${YYYYMMDD} | tee $@_
	mv $@_ $@

allzones:
	for f in `ls -l ../../Zones/ | grep -v '^total' | sort -n -k 5 | awk '{print $$NF}' | sed -e 's/-${YYYYMMDD}//'` ; do \
		echo "${MAKE} ZONE=$$f" ; \
		${MAKE} ZONE=$$f ; \
	done
