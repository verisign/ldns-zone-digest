PROG=ldns-zone-digest


OBJS=simple.o merkle.o
CPPFLAGS=-Wall -g
LDFLAGS=-lldns -lcrypto


all: ${PROG} # ${PROG}-incremental

${PROG}: ${PROG}.o ${OBJS}
	${CC} -g -o $@ ${PROG}.o ${OBJS} ${LDFLAGS}

${PROG}.o: ${PROG}.c
	${CC} ${CPPFLAGS} -c -o $@ ${PROG}.c

#${PROG}-incremental: ${PROG}-incremental.o ${OBJS}
#	${CC} -g -o $@ ${PROG}-incremental.o ${OBJS} ${LDFLAGS}
#
#${PROG}-incremental.o: ${PROG}.c
#	${CC} ${CPPFLAGS} -DZONEMD_INCREMENTAL=1 -c -o $@ ${PROG}.c

clean:
	rm -fv ${OBJS}
	rm -fv ${PROG}.o
	rm -fv ${PROG}
#	rm -fv ${PROG}-incremental.o
#	rm -fv ${PROG}-incremental
