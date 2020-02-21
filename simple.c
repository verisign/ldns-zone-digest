#include <unistd.h>
#include <stdlib.h>
#include <err.h>
#include <ldns/ldns.h>

#include "ldns-zone-digest.h"
#include "simple.h"


scheme *
scheme_simple_new(uint8_t opt_scheme)
{
	scheme *s;
	assert(1 == opt_scheme);
	s = calloc(1, sizeof(*s));
	assert(s);
	s->scheme = opt_scheme;
	s->leaf = scheme_simple_get_leaf_rr_list;
	s->calc = scheme_simple_calc_digest;
	s->iter = scheme_simple_iterate;
	s->free = scheme_simple_free;
	s->data = ldns_rr_list_new();
	assert(s->data);
	return s;
}

/*
 * Return the ldns_rr_list where arg RR belongs.
 * 
 * In the case of the simple data structure, there is just one list.
 */
ldns_rr_list *
scheme_simple_get_leaf_rr_list(const scheme *s, const ldns_rr * rr_unused)
{
	return s->data;
}

/*
 * Iterate over ALL RRs in the zone.
 */
void
scheme_simple_iterate(const scheme *s, const scheme_iterate_cb cb, const void *cb_data)
{
	unsigned int i;
	ldns_rr_list *rrlist = s->data;
	ldns_rr_list_sort(rrlist);
	for (i = 0; i < ldns_rr_list_rr_count(rrlist); i++) {
		cb(ldns_rr_list_rr(rrlist, i), cb_data);
	}
}

/*
 * scheme_calc_digest()
 *
 * Calculate a digest over the zone.
 */
void
scheme_simple_calc_digest(const scheme *s, const EVP_MD * md, unsigned char *buf)
{
	EVP_MD_CTX *ctx;
	ctx = EVP_MD_CTX_create();
	assert(ctx);
	if (!EVP_DigestInit(ctx, md))
		errx(1, "%s(%d): Digest init failed", __FILE__, __LINE__);
	zonemd_rrlist_digest(s->data, ctx);
	if (!EVP_DigestFinal_ex(ctx, buf, 0))
		errx(1, "%s(%d): Digest final failed", __FILE__, __LINE__);
	EVP_MD_CTX_destroy(ctx);
}

/*
 * Free data associated with the data structure
 */
void
scheme_simple_free(scheme *s)
{
	assert(s->data);
	ldns_rr_list_deep_free(s->data);
	memset(s, 0, sizeof(*s));
	free(s);
}
