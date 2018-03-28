PROG=ldns-zone-digest


CPPFLAGS=-Wall
LDFLAGS=-lldns -lcrypto

all: ${PROG}

${PROG}: ${PROG}.o
	${CC} -g -o $@ ${PROG}.o ${LDFLAGS}

${PROG}.o: ${PROG}.c
	${CC} -g -c -o $@ ${PROG}.c ${CPPFLAGS}

clean:
	rm -fv ${PROG}.o
	rm -fv ${PROG}
