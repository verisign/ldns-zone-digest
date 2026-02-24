example.zone.del: example.zone.add
	../../ldns-zone-digest -c -u del.dat -o example.zone.del example example.zone.add

example.zone.add: example.zone
	../../ldns-zone-digest -c -u add.dat -o example.zone.add example example.zone

example.zone:

clean:
	rm -f example.zone.add
	rm -f example.zone.del
