#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <err.h>
#include <ldns/ldns.h>
#include <assert.h>
#include <getopt.h>

typedef int (digest_init_t) (void *);
typedef int (digest_update_t) (void *, const void *, size_t);
typedef int (digest_final_t) (unsigned char *, void *);

const ldns_rr_type LDNS_RR_TYPE_ZONEMD = 65317;
const char *RRNAME = "ZONEMD";
static ldns_rdf *origin = 0;

ldns_rr *
zonemd_pack(ldns_rdf * owner, uint32_t ttl, uint32_t serial, uint8_t digest_type, void *digest, size_t digest_sz)
{
	char *buf;
	buf = calloc(1, 4 + 1 + digest_sz);
	memcpy(&buf[0], &serial, 4);
	memcpy(&buf[4], &digest_type, 1);
	memcpy(&buf[5], digest, digest_sz);
	ldns_rdf *rdf = ldns_rdf_new_frm_data(LDNS_RDF_TYPE_UNKNOWN, 4 + 1 + digest_sz, buf);
	ldns_rr *rr = ldns_rr_new();
	assert(rdf);
	assert(rr);
	ldns_rr_set_owner(rr, ldns_rdf_clone(owner));
	ldns_rr_set_ttl(rr, ttl);
	ldns_rr_set_type(rr, LDNS_RR_TYPE_ZONEMD);
	ldns_rr_push_rdf(rr, rdf);
	free(buf);
	return rr;
}

ldns_rr *
zonemd_find(ldns_zone *zone, uint32_t *ret_serial, uint8_t *ret_digest_type, void *ret_digest, size_t digest_sz)
{
	ldns_rr *ret = 0;
	ldns_rr_list *rrlist;
	unsigned int i;
	rrlist = ldns_zone_rrs(zone);
	for (i = 0; i < ldns_rr_list_rr_count(rrlist); i++) {
		ldns_rr *rr = 0;
		ldns_rdf *rdf;
		unsigned char *buf;
		size_t rdlen;
		rr = ldns_rr_list_rr(rrlist, i);
		if (ldns_rr_get_type(rr) != LDNS_RR_TYPE_ZONEMD)
			continue;
		rdf = ldns_rr_rdf(rr, 0);
		assert(rdf);
		rdlen = ldns_rdf_size(rdf);
		if (rdlen < 5)
			errx(1, "%s(%d): %s RR rdlen (%d) too short", __FILE__, __LINE__, RRNAME, (int) rdlen);
		buf = ldns_rdf_data(rdf);
		assert(buf);
		if (ret_serial)
			memcpy(ret_serial, &buf[0], 4);
		rdlen -= 4;
		if (ret_digest_type)
			memcpy(ret_digest_type, &buf[4], 1);
		rdlen -= 1;
		if (ret_digest)
			memcpy(ret_digest, &buf[5], digest_sz < rdlen ? digest_sz : rdlen);
		ret = rr;
		break;
	}
	return ret;
}

void
zonemd_update_digest(ldns_rr * rr, uint8_t digest_type, unsigned char *digest_buf, unsigned int digest_len)
{
	uint8_t rr_digest_type = 0;
	ldns_rdf *rdf = 0;
	unsigned char *buf = 0;

	rdf = ldns_rr_pop_rdf(rr);
	assert(rdf);
	buf = ldns_rdf_data(rdf);
	assert(buf);

	memcpy(&rr_digest_type, &buf[4], 1);
	if (rr_digest_type != digest_type)
		errx(1, "%s(%d): zonemd_update_digest mismatched digest type.  Found %u but wanted %u.", __FILE__, __LINE__, rr_digest_type, digest_type);

	memcpy(&buf[5], digest_buf, digest_len);
	ldns_rr_push_rdf(rr, rdf);
}

void
zonemd_print(FILE * fp, ldns_rr * rr)
{
	ldns_rr_print(fp, rr);
}

ldns_zone *
zonemd_read_zone(const char *origin_str, FILE * fp, uint32_t ttl, ldns_rr_class class)
{
	ldns_zone *zone = 0;
	ldns_status status;

	fprintf(stderr, "Loading Zone...");
	origin = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_DNAME, origin_str);
	assert(origin);
	status = ldns_zone_new_frm_fp(&zone, fp, origin, ttl, class);
	if (status != LDNS_STATUS_OK)
		errx(1, "%s(%d): ldns_zone_new_frm_fp: %s", __FILE__, __LINE__, ldns_get_errorstr_by_id(status));
	if (!ldns_zone_soa(zone))
		errx(1, "%s(%d): No SOA record in zone", __FILE__, __LINE__);
	/*
	 * ldns_zone_new_frm_fp() doesn't put the SOA into the rr
	 * list, but if we add it here it sticks around.
	 */
	ldns_rr_list_push_rr(ldns_zone_rrs(zone), ldns_rr_clone(ldns_zone_soa(zone)));
	fprintf(stderr, "%s\n", ldns_get_errorstr_by_id(status));
	fprintf(stderr, "%zu records\n", ldns_rr_list_rr_count(ldns_zone_rrs(zone)));
	return zone;
}

ldns_rr_type
my_typecovered(ldns_rr *rrsig)
{
	ldns_rdf *rdf = ldns_rr_rrsig_typecovered(rrsig);
	assert(rdf);
	return ldns_rdf2native_int16(rdf);
}

/*
 * Filter out RRs of type 'type' from the input.  If 'type' is RRISG then
 * only signatures of type 'covered' are filtered.
 */
ldns_rr_list *
zonemd_filter_rr_list(ldns_rr_list *input, ldns_rr_type type, ldns_rr_type covered)
{
	unsigned int i;
	ldns_rr_list *output = 0;
	ldns_rr_list *tbd = 0;

	output = ldns_rr_list_new();
	tbd = ldns_rr_list_new();
	assert(output);
	assert(tbd);

	for (i = 0; i < ldns_rr_list_rr_count(input); i++) {
		ldns_rr *rr = ldns_rr_list_rr(input, i);
		if (ldns_rr_get_type(rr) != type) {
			ldns_rr_list_push_rr(output, rr);
		} else if (type == LDNS_RR_TYPE_RRSIG && my_typecovered(rr) != covered) {
			ldns_rr_list_push_rr(output, rr);
		} else {
			ldns_rr_list_push_rr(tbd, rr);
		}
	}
	ldns_rr_list_deep_free(tbd);

	return output;
}

void
zonemd_add_placeholder(ldns_zone * zone, uint8_t digest_type, unsigned int digest_len)
{
	unsigned char *digest_buf = 0;
	ldns_rr_list *rrlist = 0;
	ldns_rr *soa = 0;
	ldns_rdf *soa_serial_rdf = 0;
	uint32_t soa_serial;
	ldns_rr *zonemd = 0;

	fprintf(stderr, "Remove existing ZONEMD...");
	rrlist = zonemd_filter_rr_list(ldns_zone_rrs(zone), LDNS_RR_TYPE_ZONEMD, 0);

	soa = ldns_zone_soa(zone);
	soa_serial_rdf = ldns_rr_rdf(soa, 2);
	soa_serial = ldns_rdf2native_int32(soa_serial_rdf);

	digest_buf = calloc(1, digest_len);
	assert(digest_buf);
	zonemd = zonemd_pack(ldns_rr_owner(soa), ldns_rr_ttl(soa), soa_serial, digest_type, digest_buf, digest_len);
	free(digest_buf);
	ldns_rr_list_push_rr(rrlist, zonemd);

	ldns_rr_list_free(ldns_zone_rrs(zone));
	ldns_zone_set_rrs(zone, rrlist);
	fprintf(stderr, "Done\n");
}

void
zonemd_calc_digest(ldns_zone * zone, digest_init_t *init, digest_update_t *update, digest_final_t *final, void *ctx, unsigned char *buf, unsigned int len)
{
	ldns_rr_list *rrlist = 0;
	ldns_status status;
	unsigned int i;

	fprintf(stderr, "Sorting Zone...");
	/*
	 * thankfully ldns_zone_sort() already sorts by RRtype for same owner name
	 */
	ldns_zone_sort(zone);
	rrlist = ldns_zone_rrs(zone);
	fprintf(stderr, "%s\n", "Done");
	assert(rrlist);

	if (!init(ctx))
		errx(1, "%s(%d): Digest init failed", __FILE__, __LINE__);

	fprintf(stderr, "Calculating Digest...");
	for (i = 0; i < ldns_rr_list_rr_count(rrlist); i++) {
		uint8_t *buf;
		size_t sz;
		ldns_rr *rr = ldns_rr_list_rr(rrlist, i);
		if (ldns_rr_get_type(rr) == LDNS_RR_TYPE_RRSIG)
			if (my_typecovered(rr) == LDNS_RR_TYPE_ZONEMD)
				continue;
		status = ldns_rr2wire(&buf, rr, LDNS_SECTION_ANSWER, &sz);
		if (status != LDNS_STATUS_OK)
			errx(1, "%s(%d): ldns_rr2wire() failed", __FILE__, __LINE__);
		if (!update(ctx, buf, sz))
			errx(1, "%s(%d): Digest update failed", __FILE__, __LINE__);
		free(buf);
	}
	if (!final(buf, ctx))
		errx(1, "%s(%d): Digest final failed", __FILE__, __LINE__);
	fprintf(stderr, "%s\n", "Done");

	for (i = 0; i < len; i++) {
		fprintf(stderr, "%02x", buf[i]);
	}
	fprintf(stderr, "\n");
}

void
zonemd_resign(ldns_rr * rr, const char *zsk_fname, ldns_zone *zone)
{
	FILE *fp = 0;
	ldns_key *zsk = 0;
	ldns_key_list *keys = 0;
	ldns_status status;
	ldns_rr_list *rrset = 0;
	ldns_rr_list *rrsig = 0;
	ldns_rr_list *rrlist = 0;

	fp = fopen(zsk_fname, "r");
	if (fp == 0)
		err(1, "%s(%d): %s", __FILE__, __LINE__, zsk_fname);
	status = ldns_key_new_frm_fp(&zsk, fp);
	if (status != LDNS_STATUS_OK)
		errx(1, "%s(%d): ldns_key_new_frm_fp: %s", __FILE__, __LINE__, ldns_get_errorstr_by_id(status));
	ldns_key_set_pubkey_owner(zsk, origin);
	keys = ldns_key_list_new();
	assert(keys);
	ldns_key_list_push_key(keys, zsk);

	rrset = ldns_rr_list_new();
	assert(rrset);
	ldns_rr_list_push_rr(rrset, rr);
	rrsig = ldns_sign_public(rrset, keys);
	if (rrsig == 0)
		errx(1, "%s(%d): ldns_sign_public() failed", __FILE__, __LINE__);

	rrlist = zonemd_filter_rr_list(ldns_zone_rrs(zone), LDNS_RR_TYPE_RRSIG, LDNS_RR_TYPE_ZONEMD);
	assert(rrlist);
	ldns_rr_list_push_rr_list(rrlist, rrsig);
	ldns_rr_list_free(ldns_zone_rrs(zone));
	ldns_zone_set_rrs(zone, rrlist);
	ldns_key_list_free(keys);
	ldns_rr_list_free(rrsig);
	ldns_rr_list_free(rrset);
}

void
zonemd_write_zone(ldns_zone * zone, FILE * fp)
{
	ldns_rr_list *rrlist = ldns_zone_rrs(zone);
	unsigned int i;

	assert(rrlist);
	for (i = 0; i < ldns_rr_list_rr_count(rrlist); i++) {
		ldns_rr *rr = ldns_rr_list_rr(rrlist, i);
		if (rr)
			ldns_rr_print(fp, rr);
	}
}

void
usage(const char *p)
{
	fprintf(stderr, "usage: %s [options] origin [zonefile]\n", p);
	fprintf(stderr, "\t-c\t\tcalculate the zone digest\n");
	fprintf(stderr, "\t-p\t\tinsert placeholder record\n");
	fprintf(stderr, "\t-v\t\tverify the zone digest\n");
	fprintf(stderr, "\t-d type\t\tdigest type (sha1, sha256, sha384)\n");
	exit(2);
}

int
main(int argc, char *argv[])
{
	ldns_zone *theZone = 0;
	int ch;
	FILE *input = stdin;
	const char *progname = 0;
	char *origin_str = 0;
	const char *digest = "sha256";
	char *zsk_fname = 0;
	int placeholder = 0;
	int calculate = 0;
	int verify = 0;
	uint8_t digest_type = 0;
	digest_init_t *digest_init = 0;
	digest_update_t *digest_update = 0;
	digest_final_t *digest_final = 0;
	void *digest_ctx;
	unsigned char *digest_buf = 0;
	unsigned int digest_len = 0;

	progname = strrchr(argv[0], '/');
	if (0 == progname)
		progname = argv[0];

	while ((ch = getopt(argc, argv, "cpvd:z:")) != -1) {
		switch (ch) {
		case 'c':
			calculate = 1;
			break;
		case 'p':
			placeholder = 1;
			break;
		case 'v':
			verify = 1;
			break;
		case 'd':
			digest = strdup(optarg);
			break;
		case 'z':
			zsk_fname = strdup(optarg);
			break;
		default:
			usage(progname);
		}
	}
	argc -= optind;
	argv += optind;
	if (argc < 1 || argc > 2)
		usage(progname);
	origin_str = strdup(argv[0]);
	if (argc == 2) {
		input = fopen(argv[1], "r");
		if (0 == input)
			err(1, "%s(%d): %s", __FILE__, __LINE__, argv[1]);
	}

	if (0 == strcasecmp(digest, "sha1")) {
		digest_type = 1;
		digest_init = (digest_init_t *) SHA1_Init;
		digest_update = (digest_update_t *) SHA1_Update;
		digest_final = (digest_final_t *) SHA1_Final;
		digest_ctx = calloc(1, sizeof(SHA_CTX));
		digest_len = SHA_DIGEST_LENGTH;
		digest_buf = calloc(1, digest_len);
	} else if (0 == strcasecmp(digest, "sha256")) {
		digest_type = 2;
		digest_init = (digest_init_t *) SHA256_Init;
		digest_update = (digest_update_t *) SHA256_Update;
		digest_final = (digest_final_t *) SHA256_Final;
		digest_ctx = calloc(1, sizeof(SHA256_CTX));
		digest_len = SHA256_DIGEST_LENGTH;
		digest_buf = calloc(1, digest_len);
	} else if (0 == strcasecmp(digest, "sha384")) {
		digest_type = 4;
		digest_init = (digest_init_t *) SHA384_Init;
		digest_update = (digest_update_t *) SHA384_Update;
		digest_final = (digest_final_t *) SHA384_Final;
		digest_ctx = calloc(1, sizeof(SHA512_CTX));
		digest_len = SHA384_DIGEST_LENGTH;
		digest_buf = calloc(1, digest_len);
	} else {
		errx(1, "%s(%d): Unsupported digest type '%s'", __FILE__, __LINE__, digest);
	}

	theZone = zonemd_read_zone(origin_str, input, 0, LDNS_RR_CLASS_IN);
	if (placeholder)
		zonemd_add_placeholder(theZone, digest_type, digest_len);
	if (calculate) {
		uint8_t found_digest_type;
		ldns_rr *zonemd_rr = zonemd_find(theZone, 0, &found_digest_type, 0, 0);
		if (!zonemd_rr)
			errx(1, "%s(%d): No %s record found in zone.  Use -p to add one.", __FILE__, __LINE__, RRNAME);
		zonemd_calc_digest(theZone, digest_init, digest_update, digest_final, digest_ctx, digest_buf, digest_len);
		if (zonemd_rr)
			zonemd_update_digest(zonemd_rr, digest_type, digest_buf, digest_len);
		if (zonemd_rr && zsk_fname)
			zonemd_resign(zonemd_rr, zsk_fname, theZone);
	}
	if (verify) {
	}
	zonemd_write_zone(theZone, stdout);

	if (digest_ctx)
		free(digest_ctx);
	if (digest_buf)
		free(digest_buf);
	if (zsk_fname)
		free(zsk_fname);
	if (origin_str)
		free(origin_str);
	ldns_zone_deep_free(theZone);

	return 0;
}
