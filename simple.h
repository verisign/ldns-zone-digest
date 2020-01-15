zonemd * zonemd_simple_new(uint8_t type, uint8_t parameter);

ldns_rr_list * zonemd_simple_get_rr_list(const zonemd *zmd, const ldns_rr * rr_unused);

ldns_rr_list * zonemd_simple_get_full_rr_list(const zonemd *zmd);

void zonemd_simple_calc_digest(const zonemd *zmd, unsigned char *buf);

void zonemd_simple_free(zonemd *zmd);
