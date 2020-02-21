check-digest:
	../../ldns-zone-digest -p 1:1 -c -u update.dat -o example.zone.updated example example.zone
	../../ldns-zone-digest -v example example.zone.updated

check-zone:
	named-checkzone -i none example example.zone || ldns-read-zone example.zone >/dev/null
