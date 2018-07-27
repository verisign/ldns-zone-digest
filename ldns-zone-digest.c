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
#include <openssl/evp.h>

const ldns_rr_type LDNS_RR_TYPE_ZONEMD = 65317;
const char *RRNAME = "ZONEMD";
static ldns_rdf *origin = 0;

#if ZONEMD_INCREMENTAL
typedef struct _md_tree {
	unsigned int depth;
	unsigned int branch;    // only for debugging?
	ldns_rr_list *rrlist;
	struct _md_tree *parent;
	struct _md_tree **kids;
	unsigned char digest[EVP_MAX_MD_SIZE];
	bool dirty;
} md_tree;

md_tree * md_tree_get_leaf_by_name(md_tree *node, const char *name);
bool md_tree_add_rr(md_tree *root, ldns_rr *rr); 
void md_tree_del_rr(md_tree *root, ldns_rr *rr); 
void md_tree_calc_digest(md_tree *node, const EVP_MD *md, unsigned char *buf);

md_tree *theTree = 0;
unsigned int md_max_depth = 0;
unsigned int md_max_width = 13;
#endif

#if DEBUG
#define fdebugf(...) fprintf(__VA_ARGS__)
#else
#define fdebugf(...) (void)0
#endif

void zonemd_print_digest(FILE *, const char *, const unsigned char *, unsigned int, const char *);

/*
 * zonemd_rr_pack()
 *
 * This function creates and returns an ldns_rr for the ZONEMD record.
 */
ldns_rr *
zonemd_rr_pack(ldns_rdf * owner, uint32_t ttl, uint32_t serial, uint8_t digest_type, void *digest, size_t digest_sz)
{
	char *buf;
	buf = calloc(1, 4 + 1 + digest_sz);
	ldns_write_uint32(&buf[0], serial);
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
 * zonemd_rr_find()
 *
 * This function searches through an ldns_zone and returns the first ZONEMD record found.
 * It "unpacks" the found RR into the ret_ paramaters.
 */
ldns_rr *
zonemd_rr_find(ldns_zone *zone, uint32_t *ret_serial, uint8_t *ret_digest_type, void *ret_digest, size_t digest_sz)
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
			*ret_serial = ldns_read_uint32(&buf[0]);
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
 * zonemd_rr_update_digest() 
 *
 * Updates the digest part of a placeholder ZONEMD record.
 */
void
zonemd_rr_update_digest(ldns_rr * rr, uint8_t digest_type, unsigned char *digest_buf, unsigned int digest_len)
{
	uint8_t rr_digest_type = 0;
	ldns_rdf *rdf = 0;
	unsigned char *buf = 0;

	rdf = ldns_rr_pop_rdf(rr);
	assert(rdf);
	buf = ldns_rdf_data(rdf);
	assert(buf);

	if (ldns_rdf_size(rdf) != 4 + 1 + digest_len)
		errx(1, "%s(%d): zonemd_rr_update_digest expected rdata size %u but got %zu\n",
			__FILE__, __LINE__,
			4 + 1 + digest_len,
			ldns_rdf_size(rdf));

	memcpy(&rr_digest_type, &buf[4], 1);
	if (rr_digest_type != digest_type)
		errx(1, "%s(%d): zonemd_rr_update_digest mismatched digest type.  Found %u but wanted %u.", __FILE__, __LINE__, rr_digest_type, digest_type);

	if (digest_buf)
		memcpy(&buf[5], digest_buf, digest_len);
	else
		memset(&buf[5], 0, digest_len);
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
	ldns_rr_list *oldlist;
	ldns_rr_list *newlist;
	ldns_rr_list *tbflist;
	unsigned int i;

	fprintf(stderr, "Loading Zone...");
	origin = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_DNAME, origin_str);
	assert(origin);
	status = ldns_zone_new_frm_fp(&zone, fp, origin, ttl, class);
	if (status != LDNS_STATUS_OK)
		errx(1, "%s(%d): ldns_zone_new_frm_fp: %s", __FILE__, __LINE__, ldns_get_errorstr_by_id(status));
	if (!ldns_zone_soa(zone))
		errx(1, "%s(%d): No SOA record in zone", __FILE__, __LINE__);
	/*
	 * Remove any out-of-zone data
	 */
	oldlist = ldns_zone_rrs(zone);
	newlist = ldns_rr_list_new();
	tbflist = ldns_rr_list_new();
	for (i = 0; i < ldns_rr_list_rr_count(oldlist); i++) {
		ldns_rr *rr = ldns_rr_list_rr(oldlist, i);
		if (ldns_dname_compare(ldns_rr_owner(rr), origin) == 0) {
			/* same owner */
			(void) 0;
		} else if (ldns_dname_is_subdomain(ldns_rr_owner(rr), origin)) {
			/* subdomain */
			(void) 0;
		} else {
			/* out-of-zone */
			char *s = ldns_rdf2str(ldns_rr_owner(rr));
			warnx("Ignoring out-of-zone data for '%s'", s);
			free(s);
			ldns_rr_list_push_rr(tbflist, rr);
			continue;
		}
		ldns_rr_list_push_rr(newlist, rr);
#if ZONEMD_INCREMENTAL
		md_tree_add_rr(theTree, rr);
#endif
	}
	/*
	 * ldns_zone_new_frm_fp() doesn't put the SOA into the rr
	 * list, but if we add it here it sticks around.
	 */
	ldns_rr *soa = ldns_rr_clone(ldns_zone_soa(zone));
	ldns_rr_list_push_rr(newlist, soa);
#if ZONEMD_INCREMENTAL
	md_tree_add_rr(theTree, soa);
#endif

	fprintf(stderr, "%zu records\n", ldns_rr_list_rr_count(newlist));
	ldns_zone_set_rrs(zone, newlist);
	ldns_rr_list_deep_free(tbflist);
	ldns_rr_list_free(oldlist);
	return zone;
}

#if ZONEMD_INCREMENTAL
/*
 * zonemd_zone_update()
 *
 * Process incremental updates to zone data.  Input file has lines that start with 'add' or
 * 'del' followed by an RR in presentation format:
 *
 * del example. IN A 1.2.3.4
 * add example. IN A 2.3.4.5
 *
 */
void
zonemd_zone_update(const char *update_file, ldns_zone *zone)
{
	ldns_status status;
	char file_buf[4096];
	unsigned int n_add = 0;
	unsigned int n_del = 0;
	unsigned int line = 0;
	FILE *fp;

	fp = fopen(update_file, "r");
	if (!fp)
		err(1, "%s(%d): %s", __FILE__, __LINE__, update_file);

	fprintf(stderr, "Updating Zone...");
	while (fgets(file_buf, sizeof(file_buf), fp)) {
		line++;
		char *cmd = 0;
		char *rr_str = 0;
		ldns_rr *rr = 0;
		cmd = strtok(file_buf, " \t");
		if (cmd == 0) {
			warnx("%s(%d): zonemd_zone_update: %s line %u unparseable input", __FILE__, __LINE__, update_file, line);
			continue;
		}
		rr_str = strtok(0, "\r\n");
		if (rr_str == 0) {
			warnx("%s(%d): zonemd_zone_update: %s line %u unparseable input", __FILE__, __LINE__, update_file, line);
			continue;
		}
		status = ldns_rr_new_frm_str(&rr, rr_str, 0, origin, 0);
		if (status != LDNS_STATUS_OK)
			errx(1, "%s(%d): ldns_rr_new_frm_str: %s", __FILE__, __LINE__, ldns_get_errorstr_by_id(status));
		if (0 == strcmp(cmd, "add")) {
			ldns_rr_list_push_rr(ldns_zone_rrs(zone), rr);
			md_tree_add_rr(theTree, rr);
			n_add++;
		} else if (0 == strcmp(cmd, "del")) {
			n_del++;
		} else {
			warnx("%s(%d): zonemd_zone_update: %s line %u expected 'add' or 'del'", __FILE__, __LINE__, update_file, line);
			continue;
		}
	}
	fclose(fp);
	fprintf(stderr, "%u additions, %u deletions\n", n_add, n_del);
}
#endif

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
 * zonemd_remove_rr()
 *
 * Remove RRs of type 'type' from the zone.  If 'type' is RRISG then
 * signatures of type 'covered' are removed.
 */
void
zonemd_remove_rr(ldns_zone *zone, ldns_rr_type type, ldns_rr_type covered)
{
	unsigned int i;
	ldns_rr_list *old = ldns_zone_rrs(zone);
	ldns_rr_list *new = 0;
	ldns_rr_list *tbd = 0;

	new = ldns_rr_list_new();
	tbd = ldns_rr_list_new();
	assert(new);
	assert(tbd);

	for (i = 0; i < ldns_rr_list_rr_count(old); i++) {
		ldns_rr *rr = ldns_rr_list_rr(old, i);
		if (ldns_rr_get_type(rr) != type) {
			ldns_rr_list_push_rr(new, rr);
		} else if (type == LDNS_RR_TYPE_RRSIG && my_typecovered(rr) != covered) {
			ldns_rr_list_push_rr(new, rr);
		} else {
			ldns_rr_list_push_rr(tbd, rr);
#if ZONEMD_INCREMENTAL
			md_tree_del_rr(theTree, rr);
#endif
		}
	}
	ldns_rr_list_free(old);
	ldns_zone_set_rrs(zone, new);
	ldns_rr_list_deep_free(tbd);
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
	ldns_rr *soa = 0;
	ldns_rdf *soa_serial_rdf = 0;
	uint32_t soa_serial;
	ldns_rr *zonemd = 0;

	fprintf(stderr, "Remove existing ZONEMD...\n");
	zonemd_remove_rr(zone, LDNS_RR_TYPE_ZONEMD, 0);

	soa = ldns_zone_soa(zone);
	soa_serial_rdf = ldns_rr_rdf(soa, 2);
	soa_serial = ldns_rdf2native_int32(soa_serial_rdf);

	digest_buf = calloc(1, digest_len);
	assert(digest_buf);
	zonemd = zonemd_rr_pack(ldns_rr_owner(soa), ldns_rr_ttl(soa), soa_serial, digest_type, digest_buf, digest_len);
	free(digest_buf);

	fprintf(stderr, "Add placeholder ZONEMD...\n");
	ldns_rr_list_push_rr(ldns_zone_rrs(zone), zonemd);
#if ZONEMD_INCREMENTAL
	md_tree_add_rr(theTree, zonemd);
#endif

}

/*
 * zonemd_calc_digest()
 *
 * Calculate a digest over the zone.
 */
void
zonemd_calc_digest(ldns_zone * zone, const EVP_MD *md, unsigned char *buf)
{
	ldns_rr_list *rrlist = 0;
	ldns_status status;
	unsigned int i;
	EVP_MD_CTX *ctx;

	fprintf(stderr, "Sorting Zone...");
	/*
	 * thankfully ldns_zone_sort() already sorts by RRtype for same owner name
	 */
	ldns_zone_sort(zone);
	rrlist = ldns_zone_rrs(zone);
	fprintf(stderr, "%s\n", "Done");
	assert(rrlist);

	ctx = EVP_MD_CTX_create();
	assert(ctx);
	if (!EVP_DigestInit(ctx, md))
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
		if (!EVP_DigestUpdate(ctx, wire_buf, sz))
			errx(1, "%s(%d): Digest update failed", __FILE__, __LINE__);
		free(wire_buf);
	}
	if (!EVP_DigestFinal(ctx, buf, 0))
		errx(1, "%s(%d): Digest final failed", __FILE__, __LINE__);
	EVP_MD_CTX_destroy(ctx);
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

	zonemd_remove_rr(zone, LDNS_RR_TYPE_RRSIG, LDNS_RR_TYPE_ZONEMD);
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

/*
 * zonemd_digester()
 *
 * wrapper around EVP_get_digestbyname() and so we can reference by number
 */
const EVP_MD *
zonemd_digester(uint8_t type)
{
	const char *name = 0;
	const EVP_MD *md = 0;
	OpenSSL_add_all_digests();
	if (type == 1) {
		name = "sha1";
	} else if (type == 2) {
		name = "sha256";
	} else if (type == 4) {
		name = "sha384";
	} else {
		errx(1, "%s(%d): Unsupported digest type %u", __FILE__, __LINE__, type);
	}
	md = EVP_get_digestbyname(name);
	if (md == 0)
		errx(1, "%s(%d): Unknown message digest '%s'", __FILE__, __LINE__, name);
	return md;
}

void
usage(const char *p)
{
	fprintf(stderr, "usage: %s [options] origin [zonefile]\n", p);
	fprintf(stderr, "\t-c\t\tcalculate the zone digest\n");
	fprintf(stderr, "\t-o file\t\twrite zone to output file\n");
#if ZONEMD_INCREMENTAL
	fprintf(stderr, "\t-u file\t\tfile containing RR updates\n");
#endif
	fprintf(stderr, "\t-p type\t\tinsert placeholder record of type (1, 2, 4)\n");
	fprintf(stderr, "\t-v\t\tverify the zone digest\n");
	fprintf(stderr, "\t-z\t\tZSK file name\n");
#if ZONEMD_INCREMENTAL
	fprintf(stderr, "\t-D\t\tDepth of hash tree\n");
	fprintf(stderr, "\t-W\t\tWidth of hash tree\n");
#endif
	exit(2);
}

double
elapsed_msec(struct timeval *a, struct timeval *b)
{
	double dt = 1000.0 * b->tv_sec - 1000.0 *  a->tv_sec;
	dt += (double) b->tv_usec / 1000.0 - (double) a->tv_usec / 1000.0;
	return dt;
}

void
do_calculate(ldns_zone *zone, const char *zsk_fname)
{
	uint8_t found_digest_type;
	const EVP_MD *md = 0;
	unsigned char *md_buf = 0;
	unsigned int md_len = 0;
	ldns_rr *zonemd_rr = zonemd_rr_find(zone, 0, &found_digest_type, 0, 0);
	if (!zonemd_rr)
		errx(1, "%s(%d): No %s record found in zone.  Use -p to add one.", __FILE__, __LINE__, RRNAME);
	md = zonemd_digester(found_digest_type);
	md_len = EVP_MD_size(md);
#if ZONEMD_INCREMENTAL
	md_buf = theTree->digest;
	md_tree_calc_digest(theTree, md, md_buf);
#else
	md_buf = calloc(1, md_len);
	assert(md_buf);
	zonemd_calc_digest(zone, md, md_buf);
#endif
	zonemd_rr_update_digest(zonemd_rr, found_digest_type, md_buf, md_len);
	if (zsk_fname)
		zonemd_resign(zonemd_rr, zsk_fname, zone);
}

int
do_verify(ldns_zone *zone)
{
	int rc = 0;
	uint8_t found_digest_type;
	unsigned char found_digest_buf[EVP_MAX_MD_SIZE];
	uint32_t found_serial = 0;
	ldns_rr *soa = 0;
	ldns_rdf *soa_serial_rdf = 0;
	uint32_t soa_serial = 0;
	const EVP_MD *md = 0;
	unsigned char *md_buf = 0;
	unsigned int md_len = 0;
	ldns_rr *zonemd_rr = zonemd_rr_find(zone, &found_serial, &found_digest_type, found_digest_buf, sizeof(found_digest_buf));
	if (!zonemd_rr)
		errx(1, "%s(%d): No %s record found in zone, cannot verify.", __FILE__, __LINE__, RRNAME);
	soa = ldns_zone_soa(zone);
	if (!soa)
		errx(1, "%s(%d): No SOA record found in zone, cannot verify.", __FILE__, __LINE__);
	soa_serial_rdf = ldns_rr_rdf(soa, 2);
	soa_serial = ldns_rdf2native_int32(soa_serial_rdf);
	if (found_serial != soa_serial) {
		fprintf(stderr, "%s(%d): SOA serial (%u) does not match ZONEMD serial (%u)\n", __FILE__, __LINE__, soa_serial, found_serial);
		rc |= 1;
	}
	md = zonemd_digester(found_digest_type);
	assert(EVP_MD_size(md) <= sizeof(found_digest_buf));
	md_len = EVP_MD_size(md);
	zonemd_rr_update_digest(zonemd_rr, found_digest_type, 0, md_len);	/* zero digest part */
#if ZONEMD_INCREMENTAL
	md_buf = theTree->digest;
	md_tree_calc_digest(theTree, md, md_buf);
#else
	md_buf = calloc(1, md_len);
	assert(md_buf);
	zonemd_calc_digest(zone, md, md_buf);
#endif
	if (memcmp(found_digest_buf, md_buf, md_len) != 0) {
		fprintf(stderr, "Found and calculated digests do NOT match.\n");
		zonemd_print_digest(stderr, "Found     : ", found_digest_buf, md_len, "\n");
		zonemd_print_digest(stderr, "Calculated: ", md_buf, md_len, "\n");
		rc |= 1;
	} else {
		fprintf(stderr, "Found and calculated digests do MATCH.\n");
	}
#if !ZONEMD_INCREMENTAL
	free(md_buf);
#endif
	return rc;
}

int
main(int argc, char *argv[])
{
	ldns_zone *theZone = 0;
	int ch;
	FILE *input = stdin;
	const char *progname = 0;
	const char *output_file = 0;
	const char *update_file = 0;
	char *origin_str = 0;
	char *zsk_fname = 0;
	int placeholder = 0;
	int calculate = 0;
	int verify = 0;
	int rc = 0;
	struct timeval t0, t1, t2, t3, t4;

	progname = strrchr(argv[0], '/');
	if (0 == progname)
		progname = argv[0];

	while ((ch = getopt(argc, argv, "co:p:u:vz:B:D:")) != -1) {
		switch (ch) {
		case 'c':
			calculate = 1;
			break;
		case 'o':
			output_file = strdup(optarg);
			break;
		case 'p':
			placeholder = strtoul(optarg, 0, 10);
			break;
		case 'u':
			update_file = strdup(optarg);
			break;
		case 'v':
			verify = 1;
			break;
		case 'z':
			zsk_fname = strdup(optarg);
			break;
#if ZONEMD_INCREMENTAL
		case 'D':
			md_max_depth = strtoul(optarg, 0, 10);
			break;
		case 'W':
			md_max_width = strtoul(optarg, 0, 10);
			break;
#endif
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

	gettimeofday(&t0, 0);

#if ZONEMD_INCREMENTAL
	theTree = calloc(1, sizeof(*theTree));
	assert(theTree);
#endif

	theZone = zonemd_read_zone(origin_str, input, 0, LDNS_RR_CLASS_IN);
	if (placeholder) {
		const EVP_MD *md = zonemd_digester(placeholder);
		zonemd_add_placeholder(theZone, placeholder, EVP_MD_size(md));
	}
	gettimeofday(&t1, 0);
	if (calculate)
		do_calculate(theZone, zsk_fname);
	gettimeofday(&t2, 0);
	if (verify)
		rc |= do_verify(theZone);
	gettimeofday(&t3, 0);
#if ZONEMD_INCREMENTAL
	if (update_file) {
		zonemd_zone_update(update_file, theZone);
		if (calculate)
			do_calculate(theZone, zsk_fname);
	}
#endif
	gettimeofday(&t4, 0);
	if (output_file && (placeholder || calculate)) {
		FILE *fp = fopen(output_file, "w");
		if (!fp)
			err(1, "%s(%d): %s", __FILE__, __LINE__, output_file);
		zonemd_write_zone(theZone, fp);
		fclose(fp);
	}

	if (zsk_fname)
		free(zsk_fname);
	if (origin_str)
		free(origin_str);
	ldns_zone_deep_free(theZone);

	printf("TIMINGS: load %7.2lf calculate %7.2lf verify %7.2lf update %7.2lf\n",
		elapsed_msec(&t0, &t1),
		elapsed_msec(&t1, &t2),
		elapsed_msec(&t2, &t3),
		elapsed_msec(&t3, &t4));

	return rc;
}


#if ZONEMD_INCREMENTAL

unsigned int
md_tree_branch_by_name(unsigned int depth, const char *name)
{
	unsigned int len;
	unsigned int pos;
	unsigned int branch;
	len = strlen(name);
	if (len == 0)
		return 0;
	pos = depth % len;
	branch = *(name+pos) % md_max_width;
	fdebugf(stderr, "%s(%d): md_tree_branch_by_name '%s' depth %u pos %u branch %u\n", __FILE__,__LINE__,name, depth, pos, branch);
	return branch;
}

md_tree *
md_tree_get_leaf_by_name(md_tree *node, const char *name)
{
	node->dirty = true;
	if (md_max_depth > node->depth) {
		unsigned int branch = md_tree_branch_by_name(node->depth, name);
		if (node->kids == 0) {
			node->kids = calloc(md_max_width, sizeof(*node->kids));
			assert(node->kids);
		}
		if (node->kids[branch] == 0) {
			node->kids[branch] = calloc(1, sizeof(**node->kids));
			assert(node->kids[branch]);
			node->kids[branch]->depth = node->depth+1;
			node->kids[branch]->branch = branch;
			node->kids[branch]->parent = node;
		}
		return md_tree_get_leaf_by_name(node->kids[branch], name);
	}
	fdebugf(stderr, "%s(%d): md_tree_get_leaf depth %u branch %u\n", __FILE__,__LINE__,node->depth, node->branch);
	return node;
}

md_tree *
md_tree_get_leaf_by_owner(md_tree *node, const ldns_rdf *owner)
{
	md_tree *leaf;
	char *name = ldns_rdf2str(owner);
	assert(name);
	leaf = md_tree_get_leaf_by_name(node, name);
	assert(leaf->kids == 0);	/* leaf nodes don't have kids */
	free(name);
	return leaf;
}

bool
md_tree_add_rr(md_tree *root, ldns_rr *rr)
{
	md_tree *node = md_tree_get_leaf_by_owner(root, ldns_rr_owner(rr));
	if (node->rrlist == 0) {
		node->rrlist = ldns_rr_list_new();
		assert(node->rrlist);
	}
	fdebugf(stderr, "%s(%d): md_tree_add_rr depth %u branch %u\n", __FILE__,__LINE__,node->depth, node->branch);
	return ldns_rr_list_push_rr(node->rrlist, rr);
}

void
md_tree_del_rr(md_tree *root, ldns_rr *del_rr)
{
	unsigned int i;
	md_tree *node = md_tree_get_leaf_by_owner(root, ldns_rr_owner(del_rr));
	assert(node->rrlist);
	fdebugf(stderr, "%s(%d): md_tree_del_rr: at depth %u on branch %u\n", __FILE__,__LINE__,node->depth, node->branch);
	ldns_rr_list *new = ldns_rr_list_new();
	ldns_rr_list *old = node->rrlist;
	
	assert(new);
	for (i = 0; i < ldns_rr_list_rr_count(old); i++) {
		ldns_rr *rr = ldns_rr_list_rr(old, i);
		if (del_rr == rr) {
			fdebugf(stderr, "%s(%d): md_tree_del_rr: removed RR\n", __FILE__, __LINE__);
			continue;
		}
		ldns_rr_list_push_rr(new, rr);
	}
	ldns_rr_list_free(old);
	node->rrlist = new;
}

void
md_tree_calc_digest(md_tree *node, const EVP_MD *md, unsigned char *buf)
{
	EVP_MD_CTX *ctx;
	fdebugf(stderr, "%s(%d): md_tree_calc_digest depth %u branch %u\n", __FILE__,__LINE__,node->depth, node->branch);
	if (!node->dirty)
		return;
	ctx = EVP_MD_CTX_create();
	assert(ctx);
	if (!EVP_DigestInit(ctx, md))
		errx(1, "%s(%d): Digest init failed", __FILE__, __LINE__);
	if (md_max_depth > node->depth) {
		unsigned int branch;
		assert(node->kids);
		for (branch = 0; branch < md_max_width; branch++) {
			if (node->kids[branch] == 0)
				continue;
			md_tree_calc_digest(node->kids[branch], md, (unsigned char *) node->digest);
			if (!EVP_DigestUpdate(ctx, node->digest, EVP_MD_size(md)))
				errx(1, "%s(%d): Digest update failed", __FILE__, __LINE__);
		}
	} else {
		unsigned int i;
		assert(node->rrlist);
		ldns_rr_list_sort(node->rrlist);
		for (i = 0; i < ldns_rr_list_rr_count(node->rrlist); i++) {
			uint8_t *wire_buf;
			size_t sz;
			ldns_status status;
			ldns_rr *rr = ldns_rr_list_rr(node->rrlist, i);
			fdebugf(stderr, "%s(%d): md_tree_calc_digest RR#%u: %s", __FILE__,__LINE__, i, ldns_rr2str(rr));
			if (ldns_rr_get_type(rr) == LDNS_RR_TYPE_RRSIG)
				if (my_typecovered(rr) == LDNS_RR_TYPE_ZONEMD)
					continue;
			status = ldns_rr2wire(&wire_buf, rr, LDNS_SECTION_ANSWER, &sz);
			if (status != LDNS_STATUS_OK)
				errx(1, "%s(%d): ldns_rr2wire() failed", __FILE__, __LINE__);
			if (!EVP_DigestUpdate(ctx, wire_buf, sz))
				errx(1, "%s(%d): Digest update failed", __FILE__, __LINE__);
			free(wire_buf);
		}
	}
	if (!EVP_DigestFinal_ex(ctx, buf, 0))
		errx(1, "%s(%d): Digest final failed", __FILE__, __LINE__);
	EVP_MD_CTX_destroy(ctx);
	node->dirty = false;
}

#endif
