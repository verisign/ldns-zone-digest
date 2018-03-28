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
	return rr;
}

ldns_rr *
zonemd_find(ldns_zone *zone, uint8_t that_digest_type)
{
	ldns_rr *ret = 0;
	ldns_rr_list *rrlist;
	unsigned int i;
	rrlist = ldns_zone_rrs(zone);
	for (i = 0; i < ldns_rr_list_rr_count(rrlist); i++) {
		ldns_rr *rr = 0;
		ldns_rdf *rdf;
		uint8_t this_digest_type;
		unsigned char *buf;
		rr = ldns_rr_list_rr(rrlist, i);
		if (ldns_rr_get_type(rr) != LDNS_RR_TYPE_ZONEMD)
			continue;
		rdf = ldns_rr_rdf(rr, 0);
		assert(rdf);
		if (ldns_rdf_size(rdf) < 5)
			continue;
		buf = ldns_rdf_data(rdf);
		assert(buf);
		memcpy(&this_digest_type, &buf[4], 1);
		if (this_digest_type != that_digest_type)
			continue;
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
		errx(1, "zonemd_update_digest mismatched digest type.  Found %u but wanted %u.", rr_digest_type, digest_type);

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
	ldns_rdf *origin = 0;
	ldns_status status;

	fprintf(stderr, "Loading Zone...");
	origin = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_DNAME, origin_str);
	assert(origin);
	status = ldns_zone_new_frm_fp(&zone, fp, origin, ttl, class);
	if (status != LDNS_STATUS_OK)
		errx(1, "ldns_zone_new_frm_fp: %s", ldns_get_errorstr_by_id(status));
	if (!ldns_zone_soa(zone))
		errx(1, "No SOA record in zone");
	/* ldns_zone_rrs() doesn't give us the SOA, we add it here */
	ldns_rr_list_push_rr(ldns_zone_rrs(zone), ldns_zone_soa(zone));
	fprintf(stderr, "%s\n", ldns_get_errorstr_by_id(status));
	fprintf(stderr, "%zu records\n", ldns_rr_list_rr_count(ldns_zone_rrs(zone)));
	return zone;
}

void
zonemd_add_placeholder(ldns_zone * zone, uint8_t digest_type, unsigned int digest_len)
{
	unsigned int i;
	unsigned char *digest_buf = 0;
	ldns_rr_list *input_rrlist = 0;
	ldns_rr_list *output_rrlist = 0;
	ldns_rr_list *tbd_rrlist = 0;
	ldns_rr *soa = 0;
	ldns_rdf *soa_serial_rdf = 0;
	uint32_t soa_serial;
	ldns_rr *zonemd = 0;

	fprintf(stderr, "Remove existing ZONEMD...");
	input_rrlist = ldns_zone_rrs(zone);
	output_rrlist = ldns_rr_list_new();
	tbd_rrlist = ldns_rr_list_new();

	for (i = 0; i < ldns_rr_list_rr_count(input_rrlist); i++) {
		ldns_rr *rr = ldns_rr_list_rr(input_rrlist, i);
		if (ldns_rr_get_type(rr) == LDNS_RR_TYPE_ZONEMD) {
			ldns_rr_list_push_rr(tbd_rrlist, rr);
		} else {
			ldns_rr_list_push_rr(output_rrlist, rr);
		}
	}
	ldns_rr_list_deep_free(tbd_rrlist);

	soa = ldns_zone_soa(zone);
	soa_serial_rdf = ldns_rr_rdf(soa, 2);
	soa_serial = ldns_rdf2native_int32(soa_serial_rdf);

	digest_buf = calloc(1, digest_len);
	assert(digest_buf);
	zonemd = zonemd_pack(ldns_rr_owner(soa), ldns_rr_ttl(soa), soa_serial, digest_type, digest_buf, digest_len);
	free(digest_buf);
	ldns_rr_list_push_rr(output_rrlist, zonemd);

	ldns_zone_set_rrs(zone, output_rrlist);
	fprintf(stderr, "Done\n");
}

void
zonemd_calc_digest(ldns_zone * zone, digest_init_t *init, digest_update_t *update, digest_final_t *final, void *ctx, unsigned char *buf, unsigned int len)
{
	ldns_rr_list *rrlist = 0;
	ldns_status status;
	unsigned int i;

	fprintf(stderr, "Sorting Zone...");
	ldns_zone_sort(zone);
	rrlist = ldns_zone_rrs(zone);
	fprintf(stderr, "%s\n", "Done");
	assert(rrlist);

	if (!init(ctx))
		errx(1, "Digest init failed");

	fprintf(stderr, "Calculating Digest...");
	for (i = 0; i < ldns_rr_list_rr_count(rrlist); i++) {
		uint8_t *buf;
		size_t sz;
		ldns_rr *rr = ldns_rr_list_rr(rrlist, i);
		if (ldns_rr_get_type(rr) == LDNS_RR_TYPE_RRSIG) {
			ldns_rdf *rdf;
			ldns_rr_type covered;
			rdf = ldns_rr_rrsig_typecovered(rr);
			assert(rdf);
			covered = ldns_rdf2native_int16(rdf);
			if (covered == LDNS_RR_TYPE_ZONEMD)
				continue;
		}
		status = ldns_rr2wire(&buf, rr, LDNS_SECTION_ANSWER, &sz);
		if (status != LDNS_STATUS_OK)
			errx(1, "ldns_rr2wire() failed");
		if (!update(ctx, buf, sz))
			errx(1, "Digest update failed");
		free(buf);
	}
	if (!final(buf, ctx))
		errx(1, "Digest final failed");
	fprintf(stderr, "%s\n", "Done");

	for (i = 0; i < len; i++) {
		fprintf(stderr, "%02x", buf[i]);
	}
	fprintf(stderr, "\n");
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
	const char *origin_str = 0;
	const char *digest = "sha256";
	const char *zsk_fname = 0;
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
			err(1, "%s", argv[1]);
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
		errx(1, "Unsupported digest type '%s'", digest);
	}

	theZone = zonemd_read_zone(origin_str, input, 0, LDNS_RR_CLASS_IN);
	if (placeholder)
		zonemd_add_placeholder(theZone, digest_type, digest_len);
	if (calculate) {
		ldns_rr *zonemd_rr = zonemd_find(theZone, digest_type);
		if (!zonemd_rr)
			errx(1, "No %s record found in zone.  Use -p to add one.", RRNAME);
		zonemd_calc_digest(theZone, digest_init, digest_update, digest_final, digest_ctx, digest_buf, digest_len);
		if (zonemd_rr) {
			zonemd_update_digest(zonemd_rr, digest_type, digest_buf, digest_len);
			//zonemd_resign()
		}
	}
	if (verify) {
	}
	zonemd_write_zone(theZone, stdout);

	return 0;
}
