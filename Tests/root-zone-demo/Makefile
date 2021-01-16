READZONE=ldns-read-zone
ZONEHASH=../../ldns-zone-digest

all: root.zone.hashed
	${ZONEHASH} -v . root.zone.hashed 

root.zone.hashed: root.zone.signed
	${ZONEHASH} -c -z Keys/K.+008+17913.private -g -o $@__ . root.zone.signed
	${READZONE} $@__ > $@_
	mv $@_ $@
	rm -fv $@__

root.zone.signed: root.zone.placeholder
	ldns-signzone -f $@__ root.zone.placeholder Keys/K.+008+21544 Keys/K.+008+17913
	${READZONE} $@__ > $@_
	mv $@_ $@
	rm -fv $@__

root.zone.placeholder: root.zone.unsigned
	${ZONEHASH} -p 1:1 -g -o $@__ . root.zone.unsigned
	${READZONE} $@__ > $@_
	mv $@_ $@
	rm -fv $@__

root.zone.unsigned:
	dig @d.root-servers.net . AXFR > $@_
	ldns-read-zone -s $@_ \
	| awk '$$4 != "DNSKEY"' \
	> $@
	rm -fv $@_

clean:
	rm -fv root.zone.*
