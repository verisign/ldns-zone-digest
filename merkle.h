
zonemd * zonemd_merkle_new(uint8_t scheme);

ldns_rr_list *zonemd_merkle_get_rr_list(const zonemd *zmd, const ldns_rr * rr);

ldns_rr_list *zonemd_merkle_get_full_rr_list(const zonemd *zmd);

void zonemd_merkle_calc_digest(const zonemd *zmd, const EVP_MD * md, unsigned char *buf);

void zonemd_merkle_free(zonemd *zmd);
