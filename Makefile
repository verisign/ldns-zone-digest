PROG=ldns-zone-hash

${PROG}: ${PROG}.o
	${CC} -g -o $@ ${PROG}.o ${LDFLAGS}

${PROG}.o: ${PROG}.c
	${CC} -g -c -o $@ ${PROG}.c ${CPPFLAGS}
