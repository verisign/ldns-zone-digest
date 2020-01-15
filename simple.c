#include <unistd.h>
#include <stdlib.h>
#include <err.h>
#include <ldns/ldns.h>

#include "ldns-zone-digest.h"
#include "simple.h"


zonemd *
zonemd_simple_new(uint8_t type, uint8_t parameter)
{
	const char *md_name;
	zonemd *zmd;

	if (type == 1) {
		md_name = "sha384";
	} else {
		return 0;
	}

	zmd = calloc(1, sizeof(*zmd));
	assert(zmd);
	zmd->type = type;
	zmd->parameter = parameter;
	zmd->md = EVP_get_digestbyname(md_name);
	if (zmd->md == 0)
		errx(1, "%s(%d): Unknown message digest '%s'", __FILE__, __LINE__, md_name);
	zmd->data = ldns_rr_list_new();
	assert(zmd->data);
	return zmd;
}

/*
 * Return the ldns_rr_list where arg RR belongs.
 * 
 * In the case of the simple data structure, there is just one list.
 */
ldns_rr_list *
zonemd_simple_get_rr_list(const zonemd *zmd, const ldns_rr * rr_unused)
{
	return zmd->data;
}

/*
 * Return an ldns_rr_list with ALL RRs in the zone.
 * 
 * In the case of the simple data structure, there is already just one list.
 */
ldns_rr_list *
zonemd_simple_get_full_rr_list(const zonemd *zmd)
{
	return zmd->data;
}

/*
 * zonemd_calc_digest()
 *
 * Calculate a digest over the zone.
 */
void
zonemd_simple_calc_digest(const zonemd *zmd, unsigned char *buf)
{
	EVP_MD_CTX *ctx;
	ctx = EVP_MD_CTX_create();
	assert(ctx);
	if (!EVP_DigestInit(ctx, zmd->md))
		errx(1, "%s(%d): Digest init failed", __FILE__, __LINE__);
	zonemd_rrlist_digest(zmd->data, ctx);
	if (!EVP_DigestFinal_ex(ctx, buf, 0))
		errx(1, "%s(%d): Digest final failed", __FILE__, __LINE__);
	EVP_MD_CTX_destroy(ctx);
}

/*
 * Free data associated with the data structure
 */
void
zonemd_simple_free(zonemd *zmd)
{
	assert(zmd->data);
	ldns_rr_list_deep_free(zmd->data);
	memset(zmd, 0, sizeof(*zmd));
	free(zmd);
}
