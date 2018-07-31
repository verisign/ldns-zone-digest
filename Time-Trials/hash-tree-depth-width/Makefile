YYYYMMDD=20180725
ZONE=earth
PWD=$(shell pwd)
NAME=$(shell basename ${PWD})

${ZONE}/${NAME}-${ZONE}.png: ${ZONE}/${NAME}-${ZONE}.dat plotcmd
	cat ${ZONE}/${NAME}-${ZONE}.dat \
	| perl normalize-dat.pl \
	| gnuplot -e "ZONE='${ZONE}'" plotcmd > $@_
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
