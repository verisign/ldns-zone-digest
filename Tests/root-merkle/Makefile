READZONE=ldns-read-zone
ZONEHASH=../../ldns-zone-digest

all: root.zone.hashed
	${ZONEHASH} -s 240 -v . root.zone.hashed 

root.zone.hashed: root.zone.signed
	${ZONEHASH} -s 240 -c -z Keys/K.+008+17913.private -o $@_ . root.zone.signed
	${READZONE} $@_ > $@
	rm -fv $@_

root.zone.signed: root.zone.placeholder
	/usr/local/bin/ldns-signzone -f $@_ root.zone.placeholder Keys/K.+008+21544 Keys/K.+008+17913
	${READZONE} $@_ > $@
	rm -fv $@_

root.zone.placeholder: root.zone.unsigned
	${ZONEHASH} -p 240:1 -o $@_ . root.zone.unsigned
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
