check-digest:
	../../ldns-zone-digest -v example example.zone

check-zone:
	named-checkzone -i none example example.zone || ldns-read-zone example.zone >/dev/null
