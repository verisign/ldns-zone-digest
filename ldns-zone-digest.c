/*
 * ldns-zone-digest
 *
 * ldns-zone-digest is a proof-of-concept implementation of
 * draft-wessels-dns-zone-digest, utilizing the ldns library.  That
 * Internet Draft describes how to compute, sign, and validate a
 * message digest covering a DNS zone File.
 *
 * Copyright (c) 2018, Verisign, Inc.
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 * * Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 * 
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 * 
 * * Neither the name of the copyright holder nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

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
static int xor_mode = 0;

void zonemd_print_digest(FILE *, const char *, const unsigned char *, unsigned int, const char *);

/*
 * zonemd_pack()
 *
 * This function creates and returns an ldns_rr for the ZONEMD record.
 */
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

/*
 * zonemd_find()
 *
 * This function searches through an ldns_zone and returns the first ZONEMD record found.
 * It "unpacks" the found RR into the ret_ paramaters.
 */
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

/*
 * zonemd_update_digest() 
 *
 * Updates the digest part of a placeholder ZONEMD record.
 */
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

/*
 * zonemd_print()
 *
 * Convenience function to print a ZONEMD record.  Currently it prints in the
 * RFC3597 unknown RR format.
 */
void
zonemd_print(FILE * fp, ldns_rr * rr)
{
	ldns_rr_print(fp, rr);
}

/*
 * zonemd_read_zone()
 *
 * Read a zone file from disk, with a little extra processing.
 *
 * The ldns library functions don't add the SOA record to its the ldns_zone
 * ldns_rr_list of records.  The SOA is maintained separately.  However, this program
 * is simplified if the list returned by ldns_zone_rrs() does include the SOA record,
 * so we add it here.
 */
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
	fprintf(stderr, "%zu records\n", ldns_rr_list_rr_count(ldns_zone_rrs(zone)));
	return zone;
}

/*
 * my_typecovered()
 *
 * Convenience function to return the typecovered attribute of an RRSIG.
 */
ldns_rr_type
my_typecovered(ldns_rr *rrsig)
{
	ldns_rdf *rdf = ldns_rr_rrsig_typecovered(rrsig);
	assert(rdf);
	return ldns_rdf2native_int16(rdf);
}

/*
 * zonemd_filter_rr_list()
 *
 * Filter out RRs of type 'type' from the input.  If 'type' is RRISG then
 * signatures of type 'covered' are filtered.
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

/*
 * zonemd_add_placeholder()
 *
 * Creates a placeholder ZONEMD record and adds it to 'zone'.  If 'zone' already
 * has a ZONEMD record, it is removed and discarded.
 */
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

/*
 * zonemd_calc_digest_xor()
 *
 * Calculates a digest over the zone using the "XOR technique."  Here there is a digest
 * calculation for each RRset and the final digest is an XOR of all the per-rrset digests.
 * This supports incremental updates of the digest.  Deletions can be xor'd out and additions
 * xor'd in.
 */
void
zonemd_calc_digest_xor(ldns_zone * zone, digest_init_t *init, digest_update_t *update, digest_final_t *final, void *ctx, unsigned char *buf, unsigned int len)
{
	ldns_rr_list *rrlist = 0;
	ldns_status status;
	unsigned int i;
	int ctx_state = 0;
	unsigned char *xor_buf = 0;
	ldns_rr_type xor_last_type = 0;
	ldns_rdf *xor_last_owner = 0;
	unsigned int k;

	xor_buf = calloc(1, len);
	assert(xor_buf);

	fprintf(stderr, "Sorting Zone...");
	/*
	 * thankfully ldns_zone_sort() already sorts by RRtype for same owner name
	 */
	ldns_zone_sort(zone);
	rrlist = ldns_zone_rrs(zone);
	fprintf(stderr, "%s\n", "Done");
	assert(rrlist);

	fprintf(stderr, "Calculating Digest...");
	for (i = 0; i < ldns_rr_list_rr_count(rrlist); i++) {
		uint8_t *wire_buf;
		size_t sz;
		ldns_rr *rr = ldns_rr_list_rr(rrlist, i);
		if (ldns_rr_get_type(rr) == LDNS_RR_TYPE_RRSIG)
			if (my_typecovered(rr) == LDNS_RR_TYPE_ZONEMD)
				continue;
		if (ctx_state == 1) {
			if (ldns_rdf_compare(xor_last_owner, ldns_rr_owner(rr)) || xor_last_type != ldns_rr_get_type(rr)) {
				if (!final(xor_buf, ctx))
					errx(1, "%s(%d): Digest final failed", __FILE__, __LINE__);
				ctx_state = 0;
				for (k = 0; k < len; k++)
					buf[k] ^= xor_buf[k];
			}
		}
		if (ctx_state == 0) {
			if (!init(ctx))
				errx(1, "%s(%d): Digest init failed", __FILE__, __LINE__);
			ctx_state = 1;
		}
		status = ldns_rr2wire(&wire_buf, rr, LDNS_SECTION_ANSWER, &sz);
		if (status != LDNS_STATUS_OK)
			errx(1, "%s(%d): ldns_rr2wire() failed", __FILE__, __LINE__);
		if (!update(ctx, wire_buf, sz))
			errx(1, "%s(%d): Digest update failed", __FILE__, __LINE__);
		free(wire_buf);
		xor_last_owner = ldns_rr_owner(rr);
		xor_last_type = ldns_rr_get_type(rr);
	}
	if (!final(xor_buf, ctx))
		errx(1, "%s(%d): Digest final failed", __FILE__, __LINE__);
	for (k = 0; k < len; k++)
		buf[k] ^= xor_buf[k];
	fprintf(stderr, "%s\n", "Done");
}

/*
 * zonemd_calc_digest()
 *
 * Calculate a digest over the zone.
 */
void
zonemd_calc_digest(ldns_zone * zone, digest_init_t *init, digest_update_t *update, digest_final_t *final, void *ctx, unsigned char *buf, unsigned int len)
{
	ldns_rr_list *rrlist = 0;
	ldns_status status;
	unsigned int i;

	if (xor_mode) {
		zonemd_calc_digest_xor(zone, init, update, final, ctx, buf, len);
		return;
	}

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
		uint8_t *wire_buf;
		size_t sz;
		ldns_rr *rr = ldns_rr_list_rr(rrlist, i);
		if (ldns_rr_get_type(rr) == LDNS_RR_TYPE_RRSIG)
			if (my_typecovered(rr) == LDNS_RR_TYPE_ZONEMD)
				continue;
		status = ldns_rr2wire(&wire_buf, rr, LDNS_SECTION_ANSWER, &sz);
		if (status != LDNS_STATUS_OK)
			errx(1, "%s(%d): ldns_rr2wire() failed", __FILE__, __LINE__);
		if (!update(ctx, wire_buf, sz))
			errx(1, "%s(%d): Digest update failed", __FILE__, __LINE__);
		free(wire_buf);
	}
	if (!final(buf, ctx))
		errx(1, "%s(%d): Digest final failed", __FILE__, __LINE__);
	fprintf(stderr, "%s\n", "Done");
}

/*
 * zonemd_resign()
 *
 * Calculate an RRSIG for the ZONEMD record ('rr' parameter).  Requires access to the private
 * zone signing key.
 */
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

/*
 * zonemd_write_zone()
 *
 * Prints all records in 'zone' to 'fp'
 */
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

/*
 * zonemd_print_digest()
 *
 * Prints a digest value in hex representation for debugging.
 */
void
zonemd_print_digest(FILE *fp, const char *preamble, const unsigned char *buf, unsigned int len, const char *postamble)
{
	unsigned int i;
	if (preamble)
		fputs(preamble, fp);
	for (i = 0; i < len; i++) {
		fprintf(fp, "%02x", buf[i]);
	}
	if (postamble)
		fputs(postamble, fp);
}

typedef struct {
	uint8_t type;
	digest_init_t *init;
	digest_update_t *update;
	digest_final_t *final;
	void *ctx;
	unsigned char *buf;
	unsigned int len;
} digester;

/*
 * zonemd_digester()
 *
 * Sets the function pointers and parameters for chosen digest algorithm.
 * The OpenSSL library probably can do this just as easily.
 */
digester *
zonemd_digester(uint8_t type)
{
	static digester D;
	memset(&D, 0, sizeof(D));
	if (type == 1) {
		D.type = 1;
		D.init = (digest_init_t *) SHA1_Init;
		D.update = (digest_update_t *) SHA1_Update;
		D.final = (digest_final_t *) SHA1_Final;
		D.ctx = calloc(1, sizeof(SHA_CTX));
		D.len = SHA_DIGEST_LENGTH;
		D.buf = calloc(1, D.len);
	} else if (type == 2) {
		D.type = 2;
		D.init = (digest_init_t *) SHA256_Init;
		D.update = (digest_update_t *) SHA256_Update;
		D.final = (digest_final_t *) SHA256_Final;
		D.ctx = calloc(1, sizeof(SHA256_CTX));
		D.len = SHA256_DIGEST_LENGTH;
		D.buf = calloc(1, D.len);
	} else if (type == 4) {
		D.type = 4;
		D.init = (digest_init_t *) SHA384_Init;
		D.update = (digest_update_t *) SHA384_Update;
		D.final = (digest_final_t *) SHA384_Final;
		D.ctx = calloc(1, sizeof(SHA512_CTX));
		D.len = SHA384_DIGEST_LENGTH;
		D.buf = calloc(1, D.len);
	} else {
		errx(1, "%s(%d): Unsupported digest type %u", __FILE__, __LINE__, type);
	}
	return &D;
}

/*
 * zonemd_digester_free()
 *
 * Free digester resources
 */
void
zonemd_digester_free(digester *d)
{
	if (d && d->ctx)
		free(d->ctx);
	if (d && d->buf)
		free(d->buf);
}

void
usage(const char *p)
{
	fprintf(stderr, "usage: %s [options] origin [zonefile]\n", p);
	fprintf(stderr, "\t-c\t\tcalculate the zone digest\n");
	fprintf(stderr, "\t-p type\t\tinsert placeholder record of type (1, 2, 4)\n");
	fprintf(stderr, "\t-v\t\tverify the zone digest\n");
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
	char *zsk_fname = 0;
	int placeholder = 0;
	int calculate = 0;
	int verify = 0;
	int rc = 0;

	progname = strrchr(argv[0], '/');
	if (0 == progname)
		progname = argv[0];

	while ((ch = getopt(argc, argv, "cp:vz:X")) != -1) {
		switch (ch) {
		case 'c':
			calculate = 1;
			break;
		case 'p':
			placeholder = strtoul(optarg, 0, 10);
			break;
		case 'v':
			verify = 1;
			break;
		case 'z':
			zsk_fname = strdup(optarg);
			break;
		case 'X':
			xor_mode = 1;
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

	theZone = zonemd_read_zone(origin_str, input, 0, LDNS_RR_CLASS_IN);
	if (placeholder) {
		digester *d = zonemd_digester(placeholder);
		zonemd_add_placeholder(theZone, d->type, d->len);
		zonemd_digester_free(d);
	}
	if (calculate) {
		uint8_t found_digest_type;
		digester *d = 0;
		ldns_rr *zonemd_rr = zonemd_find(theZone, 0, &found_digest_type, 0, 0);
		if (!zonemd_rr)
			errx(1, "%s(%d): No %s record found in zone.  Use -p to add one.", __FILE__, __LINE__, RRNAME);
		d = zonemd_digester(found_digest_type);
		zonemd_calc_digest(theZone, d->init, d->update, d->final, d->ctx, d->buf, d->len);
		zonemd_update_digest(zonemd_rr, d->type, d->buf, d->len);
		if (zsk_fname)
			zonemd_resign(zonemd_rr, zsk_fname, theZone);
		zonemd_digester_free(d);
	}
	if (verify) {
		uint8_t found_digest_type;
		unsigned char found_digest_buf[512];
		digester *d = 0;
		ldns_rr *zonemd_rr = zonemd_find(theZone, 0, &found_digest_type, found_digest_buf, sizeof(found_digest_buf));
		if (!zonemd_rr)
			errx(1, "%s(%d): No %s record found in zone, cannot verify.", __FILE__, __LINE__, RRNAME);
		d = zonemd_digester(found_digest_type);
		assert(d->len <= sizeof(found_digest_buf));
		/* NOTE d->type is zeroed by zonemd_digester() */
		zonemd_update_digest(zonemd_rr, d->type, d->buf, d->len);
		zonemd_calc_digest(theZone, d->init, d->update, d->final, d->ctx, d->buf, d->len);
		if (memcmp(found_digest_buf, d->buf, d->len) != 0) {
			fprintf(stderr, "Found and calculated digests do NOT match.\n");
			zonemd_print_digest(stderr, "Found     : ", found_digest_buf, d->len, "\n");
			zonemd_print_digest(stderr, "Calculated: ", d->buf, d->len, "\n");
			rc |= 1;
		} else {
			fprintf(stderr, "Found and calculated digests do MATCH.\n");
		}
		zonemd_digester_free(d);
	}
	if (placeholder || calculate)
		zonemd_write_zone(theZone, stdout);

	if (zsk_fname)
		free(zsk_fname);
	if (origin_str)
		free(origin_str);
	ldns_zone_deep_free(theZone);

	return rc;
}
