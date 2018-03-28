READZONE=ldns-read-zone
ZONEHASH=../../ldns-zone-digest

all: root.zone.hashed
	${ZONEHASH} -v . root.zone.hashed 

root.zone.hashed: root.zone.signed
	${ZONEHASH} -c -z Keys/K.+008+17913.private . root.zone.signed > $@_
	${READZONE} $@_ > $@
	rm -fv $@_

root.zone.signed: root.zone.placeholder
	ldns-signzone -f $@_ root.zone.placeholder Keys/K.+008+21544 Keys/K.+008+17913
	${READZONE} $@_ > $@
	rm -fv $@_

root.zone.placeholder: root.zone.unsigned
	${ZONEHASH} -p 2 . root.zone.unsigned > $@_
	${READZONE} $@_ > $@
	rm -fv $@_

root.zone.unsigned:
	dig @d.root-servers.net . AXFR > $@_
	ldns-read-zone -s $@_ \
	| awk '$$4 != "DNSKEY"' \
	> $@
	rm -fv $@_

clean:
	rm -fv root.zone.*
