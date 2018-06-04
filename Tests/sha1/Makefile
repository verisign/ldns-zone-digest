all:
	named-checkzone -i none example example.zone || ldns-read-zone example.zone >/dev/null
	../../ldns-zone-digest -v example example.zone
