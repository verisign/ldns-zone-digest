PROG=ldns-zone-hash

${PROG}: ${PROG}.o
	${CC} -o $@ ${PROG}.o ${LDFLAGS}

${PROG}.o: ${PROG}.c
	${CC} -c -o $@ ${PROG}.c ${CPPFLAGS}
