#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <err.h>
#include <ldns/ldns.h>
#include <assert.h>

const char *Origin_str = ".";
const uint32_t TTL = 86400;
const ldns_rr_class Class = LDNS_RR_CLASS_IN;
const ldns_rr_type LDNS_RR_TYPE_ZONEMD = 65317;

ldns_rr *
zonemd_pack(ldns_rdf *owner, uint32_t serial, uint8_t digest_type, void *digest, size_t digest_sz)
{
	char *buf;
	buf = calloc(1, 4+1+digest_sz);
	memcpy(&buf[0], &serial, 4);
	memcpy(&buf[4], &digest_type, 1);
	memcpy(&buf[5], digest, digest_sz);
	ldns_rdf *rdf = ldns_rdf_new_frm_data(LDNS_RDF_TYPE_UNKNOWN, 4+1+digest_sz, buf);
	ldns_rr *rr = ldns_rr_new();
	assert(rdf);
	assert(rr);
        ldns_rr_set_owner(rr, ldns_rdf_clone(owner));
        ldns_rr_set_ttl(rr, TTL);
        ldns_rr_set_type(rr, LDNS_RR_TYPE_ZONEMD);
	ldns_rr_push_rdf(rr, rdf);
	return rr;
}

void
zonemd_print(FILE *fp, ldns_rr *rr)
{
	ldns_rr_print(fp, rr);
}

int
main(int argc, char *argv[])
{
	ldns_rdf *origin;
	ldns_zone *theZone = 0;
	ldns_rr_list *input_rrlist = 0;
	ldns_rr_list *output_rrlist = 0;
	size_t rrcount = 0;
	unsigned int i;
	ldns_status status;
	SHA256_CTX sha256;
        unsigned char sha256_md[SHA256_DIGEST_LENGTH];

	fprintf(stderr, "Loading Zone...");
	origin = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_DNAME, Origin_str);
	if (!origin)
		errx(1, "ldns_rdf_new_frm_str() failed");
	status = ldns_zone_new_frm_fp (&theZone, stdin, origin, TTL, Class);
	fprintf(stderr, "%s\n", ldns_get_errorstr_by_id(status));
	if (status != LDNS_STATUS_OK)
		errx(1, "ldns_zone_new_frm_fp: %s", ldns_get_errorstr_by_id(status));

	fprintf(stderr, "Sorting Zone...");
	ldns_zone_sort(theZone);
	input_rrlist = ldns_zone_rrs(theZone);
	fprintf(stderr, "%s\n", "Done");

	fprintf(stderr, "Remove existing ZONEMD...");
	output_rrlist = ldns_rr_list_new();
	rrcount = ldns_rr_list_rr_count(input_rrlist);
	for (i = 0; i<rrcount; i++) {
		ldns_rr *rr = ldns_rr_list_rr(input_rrlist, i);
		if (ldns_rr_get_type(rr) == LDNS_RR_TYPE_ZONEMD)
			continue;
		ldns_rr_list_push_rr(output_rrlist, rr);
	}
	fprintf(stderr, "Done\n");

	if (!SHA256_Init(&sha256))
        	errx(1, "SHA256_Init failed");

	fprintf(stderr, "Calculating Digest...");
	rrcount = ldns_rr_list_rr_count(output_rrlist);
	for (i = 0; i<rrcount; i++) {
		uint8_t *buf;
		size_t sz;
		ldns_rr *rr = ldns_rr_list_rr(output_rrlist, i);
		status = ldns_rr2wire (&buf, rr, LDNS_SECTION_ANSWER, &sz);
		if (status != LDNS_STATUS_OK)
			errx(1, "ldns_rr2wire() failed");
		if (!SHA256_Update(&sha256, buf, sz))
			errx(1, "SHA256_Update() failed");
		free(buf);
	}
	if (!SHA256_Final(sha256_md, &sha256))
        	errx(1, "SHA256_Final() failed");
	fprintf(stderr, "%s\n", "Done");

	for (i = 0; i < SHA256_DIGEST_LENGTH; i++) {
		fprintf(stderr, "%02x", sha256_md[i]);
	}
	fprintf(stderr, "\n");

	rrcount = ldns_rr_list_rr_count(output_rrlist);
	for (i = 0; i<rrcount; i++) {
		ldns_rr *rr = ldns_rr_list_rr(output_rrlist, i);
		ldns_rr_print(stdout, rr);
	}

	ldns_rr *zonemd = zonemd_pack(origin, 12345, 2, sha256_md, SHA256_DIGEST_LENGTH);
	zonemd_print(stdout, zonemd);

	return 0;
}
