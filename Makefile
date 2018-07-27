PROG=ldns-zone-digest


CPPFLAGS=-Wall
LDFLAGS=-lldns -lcrypto

all: ${PROG} ${PROG}-incremental

${PROG}: ${PROG}.o
	${CC} -g -o $@ ${PROG}.o ${LDFLAGS}

${PROG}.o: ${PROG}.c
	${CC} -DZONEMD_INCREMENTAL=0 -g -c -o $@ ${PROG}.c ${CPPFLAGS}

${PROG}-incremental: ${PROG}-incremental.o
	${CC} -g -o $@ ${PROG}-incremental.o ${LDFLAGS}

${PROG}-incremental.o: ${PROG}.c
	${CC} -DZONEMD_INCREMENTAL=1 -g -c -o $@ ${PROG}.c ${CPPFLAGS}

clean:
	rm -fv ${PROG}.o
	rm -fv ${PROG}
	rm -fv ${PROG}-incremental.o
	rm -fv ${PROG}-incremental
