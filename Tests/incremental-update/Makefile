all:
	named-checkzone -i none example example.zone || ldns-read-zone example.zone >/dev/null
	../../ldns-zone-digest-incremental -p 2 -c -u update.dat -o example.zone.updated example example.zone
	../../ldns-zone-digest-incremental -v example example.zone.updated
