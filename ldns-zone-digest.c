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
#include <sys/time.h>
#include <sys/resource.h>

#include "ldns-zone-digest.h"
#include "simple.h"
#include "merkle.h"

int quiet = 0;

static ldns_rr_type ZONEMD_RR_TYPE = 63;
static int ldns_knows_about_zonemd = 0;
const char *RRNAME = "ZONEMD";
static ldns_rdf *origin = 0;
ldns_rr *the_soa = 0;
uint32_t the_soa_serial = 0;
ldns_output_format_storage ldns_rr_output_fmt_storage;
ldns_output_format *ldns_rr_output_fmt = 0;
scheme *the_scheme = 0;

#define MAX_ZONEMD_COUNT 10
typedef struct  {
	uint8_t scheme;
	uint8_t hashalg;
} placeholder;

unsigned int
uimin(unsigned int a, unsigned int b)
{
	if (a < b)
		return a;
	return b;
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
 * zonemd_rr_create()
 *
 * This function creates and returns an empty ZONEMD record.
 */
ldns_rr *
zonemd_rr_create(ldns_rdf * owner, uint32_t ttl)
{
	ldns_rr *rr = ldns_rr_new();
	assert(rr);
	ldns_rr_set_owner(rr, ldns_rdf_clone(owner));
	ldns_rr_set_ttl(rr, ttl);
	ldns_rr_set_type(rr, ZONEMD_RR_TYPE);
	return rr;
}

/*
 * zonemd_rr_pack()
 *
 * This function packs ZONEMD rdata into an existing RR.
 */
void
zonemd_rr_pack(ldns_rr *rr, uint32_t serial, uint8_t scheme, uint8_t hashalg, void *digest, size_t digest_sz)
{
	while (ldns_rr_rd_count(rr) > 0) {
		ldns_rdf *rdf = ldns_rr_pop_rdf (rr);
		ldns_rdf_deep_free(rdf);
	}
	if (ldns_knows_about_zonemd) {
		char *tbuf = 0;
		if (digest == 0)
			digest = tbuf = calloc(1, digest_sz);
		ldns_rdf *rdf_serial = ldns_native2rdf_int32(LDNS_RDF_TYPE_INT32, serial);
		ldns_rdf *rdf_scheme = ldns_native2rdf_int8(LDNS_RDF_TYPE_INT8, scheme);
		ldns_rdf *rdf_hashalg = ldns_native2rdf_int8(LDNS_RDF_TYPE_INT8, hashalg);
		ldns_rdf *rdf_digest = ldns_rdf_new_frm_data(LDNS_RDF_TYPE_HEX, digest_sz, digest);
		assert(rdf_serial);
		assert(rdf_scheme);
		assert(rdf_hashalg);
		assert(rdf_digest);
		ldns_rr_push_rdf(rr, rdf_serial);
		ldns_rr_push_rdf(rr, rdf_scheme);
		ldns_rr_push_rdf(rr, rdf_hashalg);
		ldns_rr_push_rdf(rr, rdf_digest);
		if (tbuf)
			free(tbuf);
	} else {
		char *buf;
		buf = calloc(1, 4 + 1 + 1 + digest_sz);
		ldns_write_uint32(&buf[0], serial);
		memcpy(&buf[4], &scheme, 1);
		memcpy(&buf[5], &hashalg, 1);
		if (digest && digest_sz)
			memcpy(&buf[6], digest, digest_sz);
		ldns_rdf *rdf = ldns_rdf_new_frm_data(LDNS_RDF_TYPE_UNKNOWN, 4 + 1 + 1 + digest_sz, buf);
		assert(rdf);
		ldns_rr_push_rdf(rr, rdf);
		free(buf);
	}
}

/*
 * zonemd_rr_find()
 *
 * This function searches through the zone data and returns a list of ZONEMD records found.
 */
ldns_rr_list *
zonemd_rr_find(void)
{
	ldns_rr_list *ret = 0;
	const ldns_rr_list *rrlist;
	unsigned int i;
	ret = ldns_rr_list_new();
	assert(ret);
	rrlist = the_scheme->leaf(the_scheme, the_soa);
	assert(rrlist);
	for (i = 0; i < ldns_rr_list_rr_count(rrlist); i++) {
		ldns_rr *rr = 0;
		rr = ldns_rr_list_rr(rrlist, i);
		if (ldns_rr_get_type(rr) != ZONEMD_RR_TYPE)
			continue;
		if (ldns_dname_compare(ldns_rr_owner(rr), origin) != 0)
			continue;
		ldns_rr_list_push_rr(ret, rr);
	}
	return ret;
}

/*
 * zonemd_rr_unpack()
 *
 * This function unpacks ZONEMD fields into the ret_ paramaters.
 */
void
zonemd_rr_unpack(ldns_rr *rr, uint32_t *ret_serial, uint8_t *ret_scheme, uint8_t *ret_hashalg, void *ret_digest, unsigned int *ret_digest_sz)
{
	ldns_rdf *rdf = 0;
	if (ldns_knows_about_zonemd) {
		rdf = ldns_rr_rdf(rr, 0);
		assert(rdf);
		if (LDNS_RDF_TYPE_INT32 != ldns_rdf_get_type(rdf))
			errx(1, "%s(%d): %s RDF #1 expected type %u, but got type %u", __FILE__, __LINE__, RRNAME, LDNS_RDF_TYPE_INT32, ldns_rdf_get_type(rdf));
		if (ret_serial)
			*ret_serial = ldns_rdf2native_int32(rdf);
		rdf = ldns_rr_rdf(rr, 1);
		assert(rdf);
		if (LDNS_RDF_TYPE_INT8 != ldns_rdf_get_type(rdf))
			errx(1, "%s(%d): %s RDF #2 expected type %u, but got type %u", __FILE__, __LINE__, RRNAME, LDNS_RDF_TYPE_INT8, ldns_rdf_get_type(rdf));
		if (ret_scheme)
			*ret_scheme = ldns_rdf2native_int8(rdf);
		rdf = ldns_rr_rdf(rr, 2);
		assert(rdf);
		if (LDNS_RDF_TYPE_INT8 != ldns_rdf_get_type(rdf))
			errx(1, "%s(%d): %s RDF #3 expected type %u, but got type %u", __FILE__, __LINE__, RRNAME, LDNS_RDF_TYPE_INT8, ldns_rdf_get_type(rdf));
		if (ret_hashalg)
			*ret_hashalg = ldns_rdf2native_int8(rdf);
		rdf = ldns_rr_rdf(rr, 3);
		assert(rdf);
		if (LDNS_RDF_TYPE_HEX != ldns_rdf_get_type(rdf))
			errx(1, "%s(%d): %s RDF #4 expected type %u, but got type %u", __FILE__, __LINE__, RRNAME, LDNS_RDF_TYPE_HEX, ldns_rdf_get_type(rdf));
		if (ret_digest) {
			memset(ret_digest, 0, *ret_digest_sz);
			assert(ret_digest_sz);
			*ret_digest_sz = uimin(*ret_digest_sz, ldns_rdf_size(rdf));
			memcpy(ret_digest, ldns_rdf_data(rdf), *ret_digest_sz);
		}
	} else {
		unsigned char *buf;
		size_t rdlen;
		rdf = ldns_rr_rdf(rr, 0);
		assert(rdf);
		rdlen = ldns_rdf_size(rdf);
		if (rdlen < 6)
			errx(1, "%s(%d): %s RR rdlen (%d) too short", __FILE__, __LINE__, RRNAME, (int) rdlen);
		buf = ldns_rdf_data(rdf);
		assert(buf);
		if (ret_serial)
			*ret_serial = ldns_read_uint32(&buf[0]);
		rdlen -= 4;
		if (ret_scheme)
			memcpy(ret_scheme, &buf[4], 1);
		rdlen -= 1;
		if (ret_hashalg)
			memcpy(ret_hashalg, &buf[5], 1);
		rdlen -= 1;
		if (ret_digest) {
			assert(ret_digest_sz);
			*ret_digest_sz = uimin(*ret_digest_sz, rdlen);
			memcpy(ret_digest, &buf[6], *ret_digest_sz);
		}
	}
}

/*
 * zonemd_rr_update_digest()
 *
 * Updates the digest part of a placeholder ZONEMD record.  If the new_digest_buf pointer is NULL, the
 * digest value is set to all zeroes.
 */
void
zonemd_rr_update_digest(ldns_rr * rr, uint32_t serial, unsigned char *new_digest_buf, unsigned int new_digest_len)
{
	uint8_t scheme;
	uint8_t hashalg;
        unsigned int old_digest_sz = EVP_MAX_MD_SIZE;
	unsigned char old_digest_buf[EVP_MAX_MD_SIZE];
	zonemd_rr_unpack(rr, 0, &scheme, &hashalg, old_digest_buf, &old_digest_sz);
	zonemd_rr_pack(rr, serial, scheme, hashalg, new_digest_buf, new_digest_len);
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
 * zonemd_add_rr()
 *
 * Add an RR to the zone data.
 */
void
zonemd_add_rr(ldns_rr *rr)
{
	ldns_rr_list *rrlist;
	rrlist = the_scheme->leaf(the_scheme, rr);
	assert(rrlist);
	ldns_rr_list_push_rr(rrlist, rr);
}

/*
 * zonemd_remove_rr()
 *
 * Remove RRs of type 'type' from the zone apex.  If 'type' is RRISG then
 * signatures of type 'covered' are removed.
 */
void
zonemd_remove_rr(ldns_rr_type type, ldns_rr_type covered)
{
	unsigned int i;
	ldns_rr_list *rrlist = 0;
	ldns_rr_list *tbd = 0;

	tbd = ldns_rr_list_new();
	assert(tbd);

	rrlist = the_scheme->leaf(the_scheme, the_soa);
	assert(rrlist);
	for (i = 0; i < ldns_rr_list_rr_count(rrlist); i++) {
		ldns_rr *rr = ldns_rr_list_rr(rrlist, i);
		if (ldns_dname_compare(ldns_rr_owner(rr), origin) != 0) {
			(void) 0;
		} else if (ldns_rr_get_type(rr) != type) {
			(void) 0;
		} else if (type == LDNS_RR_TYPE_RRSIG && my_typecovered(rr) != covered) {
			(void) 0;
		} else {
			/*
			 * swap the last RR in the list with the current RR to be removed
			 */
			ldns_rr *last = ldns_rr_list_pop_rr(rrlist);
			assert(last);
			ldns_rr_list_push_rr(tbd, rr);
			if (last != rr) {
				ldns_rr *t = ldns_rr_list_set_rr(rrlist, last, i);
				assert(t == rr);
				i--;
			}
		}
	}

	ldns_rr_list_deep_free(tbd);
}

/*
 * honemd_digester()
 *
 * wrapper around EVP_get_digestbyname() and so we can reference by number
 */
const EVP_MD *
zonemd_digester(uint8_t hashalg, const char *file, const int line, bool warn_unsupported)
{
	const char *name = 0;
	const EVP_MD *md = 0;
	if (hashalg == 1) {
		name = "sha384";
	} else if (hashalg == 2) {
		name = "sha512";
	} else {
		if (warn_unsupported)
			warnx("%s(%d): Unsupported hash algorithm %u", file, line, hashalg);
		return 0;
	}
	md = EVP_get_digestbyname(name);
	if (md == 0)
		errx(1, "%s(%d): Unknown message hash algorithm '%s'", file, line, name);
	return md;
}

/*
 *
 * zonemd_rrlist_digest()
 *
 * Loops over an rrlist and calls the digest update function on each RR.
 */
void
zonemd_rrlist_digest(ldns_rr_list *rrlist, EVP_MD_CTX *ctx)
{
	unsigned int i;
	ldns_status status;
	ldns_rr *prev = 0;
	/*
	 * thankfully ldns_rr_list_sort() already sorts by RRtype for same owner name
	 */
	ldns_rr_list_sort(rrlist);
	for (i = 0; i < ldns_rr_list_rr_count(rrlist); i++) {
		uint8_t *wire_buf;
		size_t sz;
		ldns_rr *rr = ldns_rr_list_rr(rrlist, i);
		ldns_rr *rr_copy = 0;
		if (prev && ldns_rr_compare(rr, prev) == 0) {
			char *s = ldns_rr2str(rr);
			assert(s);
			warnx("%s(%d): Ignoring duplicate RR: %s", __FILE__, __LINE__, s);
			free(s);
			continue;
		}
		prev = rr;
		/*
		 * Don't include RRSIG over ZONEMD in the digest
		 */
		if (ldns_rr_get_type(rr) == LDNS_RR_TYPE_RRSIG)
			if (my_typecovered(rr) == ZONEMD_RR_TYPE)
				continue;
		/*
		 * Don't include ZONEMD RRs at apex
		 */
		if (ldns_rr_get_type(rr) == LDNS_RR_TYPE_ZONEMD)
			if (ldns_dname_compare(ldns_rr_owner(rr), origin) == 0)
				continue;
#if 0
		/*
		 * For ZONEMD RRs at apex, create a copy with digest zeroized
		 */
		if (ldns_rr_get_type(rr) == LDNS_RR_TYPE_ZONEMD && ldns_dname_compare(ldns_rr_owner(rr), origin) == 0) {
			uint8_t scheme = 0;
			uint8_t hashalg = 0;
			unsigned char digest[EVP_MAX_MD_SIZE];
			unsigned int digest_len = EVP_MAX_MD_SIZE;
			uint32_t serial = 0;
			const EVP_MD *md = 0;
			rr_copy = ldns_rr_clone(rr);
			zonemd_rr_unpack(rr_copy, &serial, &scheme, &hashalg, digest, &digest_len);
			md = zonemd_digester(hashalg, __FILE__, __LINE__, 0);
			if (md != 0) {
				assert(EVP_MD_size(md) <= (int) sizeof(digest));
				digest_len = EVP_MD_size(md);
			}
			zonemd_rr_update_digest(rr_copy, 0, digest_len);	/* zero digest part */
			rr = rr_copy;
		}
#endif
#if DEBUG
		char *s = ldns_rr2str(rr);
		fdebugf(stderr, "%s(%d): zonemd_rrlist_digest RR#%u: %s", __FILE__, __LINE__, i, s);
		free(s);
#endif
		ldns_rr2canonical(rr);
		status = ldns_rr2wire(&wire_buf, rr, LDNS_SECTION_ANSWER, &sz);
		if (status != LDNS_STATUS_OK)
			errx(1, "%s(%d): ldns_rr2wire() failed", __FILE__, __LINE__);
		if (!EVP_DigestUpdate(ctx, wire_buf, sz))
			errx(1, "%s(%d): Digest update failed", __FILE__, __LINE__);
		free(wire_buf);
		if (rr_copy != 0)
			ldns_rr_free(rr_copy);
	}
}

/*
 * zonemd_resign()
 *
 * Calculate an RRSIG for the ZONEMD RRset ('rrset' parameter).  Requires access to the private
 * zone signing key.
 */
void
zonemd_resign(ldns_rr_list * rrset, const char *zsk_fname)
{
	FILE *fp = 0;
	ldns_key *zsk = 0;
	ldns_key_list *keys = 0;
	ldns_status status;
	ldns_rr_list *rrsig = 0;
	unsigned int i;

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

	fprintf(stderr, "signing %d RRs with %d keys\n", ldns_rr_list_rr_count(rrset), ldns_key_list_key_count(keys));
	rrsig = ldns_sign_public(rrset, keys);
	if (rrsig == 0)
		errx(1, "%s(%d): ldns_sign_public() failed", __FILE__, __LINE__);

	zonemd_remove_rr(LDNS_RR_TYPE_RRSIG, ZONEMD_RR_TYPE);
	for (i = 0; i < ldns_rr_list_rr_count(rrsig); i++)
		zonemd_add_rr(ldns_rr_list_rr(rrsig, i));
	ldns_key_list_free(keys);
	ldns_rr_list_free(rrsig);
}

void
zonemd_write_zone_cb(const ldns_rr *rr, const void *cb_data)
{
	FILE *fp = (void *) cb_data;
	if (rr)
		ldns_rr_print_fmt(fp, ldns_rr_output_fmt, rr);
}

/*
 * zonemd_write_zone()
 *
 * Prints all zone records to output_file
 */
void
zonemd_write_zone(const char *output_file)
{
	FILE *fp = fopen(output_file, "w");
	if (!fp)
		err(1, "%s(%d): %s", __FILE__, __LINE__, output_file);
	the_scheme->iter(the_scheme, zonemd_write_zone_cb, fp);
	fclose(fp);
}

void
usage(const char *p)
{
	fprintf(stderr, "usage: %s [options] origin [zonefile]\n", p);
	fprintf(stderr, "\t-c\t\tcalculate the zone digest\n");
	fprintf(stderr, "\t-g\t\tprint ZONEMD in RFC 3597 generic format\n");
	fprintf(stderr, "\t-o file\t\twrite zone to output file\n");
	fprintf(stderr, "\t-u file\t\tfile containing RR updates\n");
	fprintf(stderr, "\t-p s,h\t\tinsert placeholder record of scheme s and hashalg h\n");
	fprintf(stderr, "\t-v\t\tverify the zone digest\n");
	fprintf(stderr, "\t-z file\t\tZSK file name\n");
	fprintf(stderr, "\t-q\t\tquiet mode, show errors only\n");
	exit(2);
}

void
my_getrusage(struct timeval *ret)
{
	struct rusage ru;
	memset(&ru, 0, sizeof(ru));
	getrusage(RUSAGE_SELF, &ru);
	timeradd(&ru.ru_utime, &ru.ru_stime, ret);
}

double
elapsed_msec(struct timeval *a, struct timeval *b)
{
	double dt = 1000.0 * b->tv_sec - 1000.0 *  a->tv_sec;
	dt += (double) b->tv_usec / 1000.0 - (double) a->tv_usec / 1000.0;
	return dt;
}

/*
 * zonemd_add_placeholders()
 *
 * Creates a placeholder ZONEMD record and adds it to 'zone'.  If 'zone' already
 * has a ZONEMD record, it is removed and discarded.
 */
void
zonemd_add_placeholders(placeholder placeholders[], unsigned int count)
{
	unsigned int i;

	if (!quiet)
		fprintf(stderr, "Remove existing ZONEMD RRset\n");
	zonemd_remove_rr(ZONEMD_RR_TYPE, 0);

	for (i = 0; i < count; i++) {
		const EVP_MD *md = 0;
		unsigned int digest_len = 0;
		unsigned char *digest_buf = 0;
		ldns_rr *zonemd = 0;
		unsigned int j;
		bool is_dupe = 0;

		for (j = 0; j < i; j++)
			if (placeholders[i].scheme == placeholders[j].scheme)
				if (placeholders[i].hashalg == placeholders[j].hashalg)
					is_dupe |= 1;

		if (is_dupe) {
			fprintf(stderr, "Ignoring duplicate digest scheme %u and type %u\n",
				placeholders[i].scheme, placeholders[i].hashalg);
			continue;
		}

		md = zonemd_digester(placeholders[i].hashalg, __FILE__, __LINE__, 1);
		assert(md);
		digest_len = EVP_MD_size(md);
		assert(digest_len);
		digest_buf = calloc(1, digest_len);
		assert(digest_buf);
		zonemd = zonemd_rr_create(ldns_rr_owner(the_soa), ldns_rr_ttl(the_soa));
		zonemd_rr_pack(zonemd, the_soa_serial, placeholders[i].scheme, placeholders[i].hashalg, digest_buf, digest_len);
		free(digest_buf);
		if (!quiet)
			fprintf(stderr, "Add placeholder ZONEMD with scheme %u and hash algorithm %u\n",
				placeholders[i].scheme,
				placeholders[i].hashalg);
		zonemd_add_rr(zonemd);
	}
}

/*
 * zonemd_read_zone()
 *
 * Read a zone file from disk, with a little extra processing.
 *
 */
void
zonemd_read_zone(const char *origin_str, FILE * fp, uint32_t ttl, ldns_rr_class class)
{
	ldns_zone *zone;
	ldns_status status;
	ldns_rr_list *oldlist;
	ldns_rr_list *tbflist;
	ldns_rdf *soa_serial_rdf = 0;
	unsigned int i;
	unsigned int count = 0;

	if (!quiet)
		fprintf(stderr, "Loading Zone...");
	origin = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_DNAME, origin_str);
	assert(origin);
	status = ldns_zone_new_frm_fp(&zone, fp, origin, ttl, class);
	if (status != LDNS_STATUS_OK)
		errx(1, "%s(%d): ldns_zone_new_frm_fp: %s", __FILE__, __LINE__, ldns_get_errorstr_by_id(status));
	if (!ldns_zone_soa(zone))
		errx(1, "%s(%d): No SOA record in zone", __FILE__, __LINE__);
	the_soa = ldns_rr_clone(ldns_zone_soa(zone));
	zonemd_add_rr(the_soa);
	soa_serial_rdf = ldns_rr_rdf(the_soa, 2);
	the_soa_serial = ldns_rdf2native_int32(soa_serial_rdf);
	count++;
	/*
	 * Remove any out-of-zone data
	 */
	oldlist = ldns_zone_rrs(zone);
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
			assert(s);
			warnx("%s(%d): Ignoring out-of-zone data for '%s'", __FILE__, __LINE__, s);
			free(s);
			ldns_rr_list_push_rr(tbflist, rr);
			continue;
		}
		zonemd_add_rr(rr);
		count++;
	}

	if (!quiet)
		fprintf(stderr, "%u records\n", count);
	ldns_rr_list_deep_free(tbflist);
	ldns_rr_list_free(oldlist);
	ldns_zone_set_rrs(zone, 0);
	ldns_zone_deep_free(zone);
}

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
zonemd_zone_update(const char *update_file)
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

	if (!quiet)
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
			zonemd_add_rr(rr);
			n_add++;
		} else if (0 == strcmp(cmd, "del")) {
			n_del++;
		} else {
			warnx("%s(%d): zonemd_zone_update: %s line %u expected 'add' or 'del'", __FILE__, __LINE__, update_file, line);
			continue;
		}
	}
	fclose(fp);
	if (!quiet)
		fprintf(stderr, "%u additions, %u deletions\n", n_add, n_del);
}

bool
supported_scheme(uint8_t scheme, const char *file, const int line, bool is_fatal)
{
	const char *msg = "bug";
	switch(scheme) {
	case 0:
		msg = "%s(%d): Scheme %u is RESERVED and must not be used";
		break;
	case 1:
	case 240:
		if (the_scheme->scheme == scheme)
			return 1;
		msg = "%s(%d): No in-memory data for scheme %u";
		break;
	default:
		msg = "%s(%d): Unsupported scheme %u";
		break;
	}
	if (is_fatal)
		errx(1, msg, file, line, scheme);
	else
		warnx(msg, file, line, scheme);
	return 0;
}

void
do_calculate(const char *zsk_fname)
{
	ldns_rr_list *zonemd_rr_list = zonemd_rr_find();
	unsigned int i;
	if (!zonemd_rr_list || 0 == ldns_rr_list_rr_count(zonemd_rr_list))
		errx(1, "%s(%d): No %s record found at zone apex.  Use -p to add one.", __FILE__, __LINE__, RRNAME);
	for (i = 0; i < ldns_rr_list_rr_count(zonemd_rr_list); i++) {
		uint8_t found_scheme = 0;
		uint8_t found_hashalg = 0;
		unsigned char *md_buf = 0;
		unsigned int md_len = 0;
		const EVP_MD *md = 0;
		ldns_rr *zonemd_rr = ldns_rr_list_rr(zonemd_rr_list, i);
		zonemd_rr_unpack(zonemd_rr, 0, &found_scheme, &found_hashalg, 0, 0);
		if (!supported_scheme(found_scheme, __FILE__, __LINE__, 0))
			continue;
		md = zonemd_digester(found_hashalg, __FILE__, __LINE__, 1);
		if (0 == md)
			continue;
		md_len = EVP_MD_size(md);
		md_buf = calloc(1, md_len);
		assert(md_buf);
		the_scheme->calc(the_scheme, md, md_buf);
		zonemd_rr_update_digest(zonemd_rr, the_soa_serial, md_buf, md_len);
		free(md_buf);
	}
	if (zsk_fname)
		zonemd_resign(zonemd_rr_list, zsk_fname);
	ldns_rr_list_free(zonemd_rr_list);
}

int
do_verify(void)
{
	int rc = 1;
	ldns_rr_list *zonemd_rr_list = zonemd_rr_find();
	unsigned int i;
	if (!zonemd_rr_list)
		errx(1, "%s(%d): No %s record found at zone apex, cannot verify.", __FILE__, __LINE__, RRNAME);
	for (i = 0; i < ldns_rr_list_rr_count(zonemd_rr_list); i++) {
		uint8_t found_scheme;
		uint8_t found_hashalg;
		unsigned char found_digest_buf[EVP_MAX_MD_SIZE];
		unsigned int found_digest_len = EVP_MAX_MD_SIZE;
		uint32_t found_serial = 0;
		const EVP_MD *md = 0;
		unsigned char *md_buf = 0;
		unsigned int md_len = 0;
		ldns_rr *zonemd_rr = ldns_rr_list_rr(zonemd_rr_list, i);
		zonemd_rr_unpack(zonemd_rr, &found_serial, &found_scheme, &found_hashalg, found_digest_buf, &found_digest_len);
		if (found_digest_len < 12) {
			fprintf(stderr, "Ignoring digest of size %u, smaller than the minimum length 12\n", found_digest_len);
			continue;
		}
		if (found_serial != the_soa_serial) {
			fprintf(stderr, "%s(%d): SOA serial (%u) does not match ZONEMD serial (%u)\n", __FILE__, __LINE__, the_soa_serial, found_serial);
			continue;
		}
		if (!supported_scheme(found_scheme, __FILE__, __LINE__, 0))
			continue;
		md = zonemd_digester(found_hashalg, __FILE__, __LINE__, 1);
		if (md == 0) {
			fprintf(stderr, "Unable to verify unsupported hash algorithm %u\n", found_hashalg);
			continue;
		}
		if (found_digest_len != EVP_MD_size(md)) {
			fprintf(stderr, "Ignoring digest of size %u, expected size %d for alg %u\n", found_digest_len, EVP_MD_size(md), found_hashalg);
			continue;
		}
		assert(EVP_MD_size(md) <= (int) sizeof(found_digest_buf));
		md_len = EVP_MD_size(md);
		md_buf = calloc(1, md_len);
		assert(md_buf);
		the_scheme->calc(the_scheme, md, md_buf);
		if (memcmp(found_digest_buf, md_buf, md_len) != 0) {
			fprintf(stderr, "Found and calculated digests for scheme:hashalg %u:%u do NOT match.\n", found_scheme, found_hashalg);
			zonemd_print_digest(stderr, "Found     : ", found_digest_buf, md_len, "\n");
			zonemd_print_digest(stderr, "Calculated: ", md_buf, md_len, "\n");
		} else {
			if (!quiet)
				fprintf(stderr, "Found and calculated digests for scheme:hashalg %u:%u do MATCH.\n", found_scheme, found_hashalg);
			rc = 0;
		}
		free(md_buf);
	}
	ldns_rr_list_free(zonemd_rr_list);
	return rc;
}

void
probe_ldns(const char *origin_str)
{
	ldns_rr *rr = 0;
	ldns_rdf *origin = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_DNAME, origin_str);
	ldns_status status = ldns_rr_new_frm_str (&rr, "test 300 IN ZONEMD 123456789 2 0 deadbeef", 0, origin, 0);
	fdebugf(stderr, "%s(%d): probe_ldns: %s\n", __FILE__, __LINE__, ldns_get_errorstr_by_id(status));
	if (LDNS_STATUS_OK == status) {
		ldns_knows_about_zonemd = 1;
		ZONEMD_RR_TYPE = ldns_rr_get_type(rr);
	}
	ldns_rdf_deep_free(origin);
	if (rr)
		ldns_rr_free(rr);
}

int
main(int argc, char *argv[])
{
	int ch;
	FILE *input = stdin;
	char *progname = 0;
	char *output_file = 0;
	char *update_file = 0;
	char *origin_str = 0;
	char *zsk_fname = 0;
	uint8_t opt_scheme = 1;
	placeholder placeholders[MAX_ZONEMD_COUNT];
	unsigned int placeholder_cnt = 0;
	int calculate = 0;
	int verify = 0;
	int print_timings = 0;
	int rc = 0;
	struct timeval t0, t1, t2, t3, t4;

	progname = strrchr(argv[0], '/');
	if (0 == progname)
		progname = argv[0];
	memset(placeholders, 0, sizeof(placeholders));

	OpenSSL_add_all_digests();

	ldns_rr_output_fmt = ldns_output_format_init(&ldns_rr_output_fmt_storage);

	while ((ch = getopt(argc, argv, "cgo:p:qs:tu:vz:")) != -1) {
		switch (ch) {
		case 'c':
			calculate = 1;
			break;
		case 'g':
			ldns_output_format_set_type(ldns_rr_output_fmt, ZONEMD_RR_TYPE);
			break;
		case 'o':
			output_file = strdup(optarg);
			break;
		case 'p':
			if (placeholder_cnt < MAX_ZONEMD_COUNT) {
				char *p;
				p = strtok(optarg, ",.:/-+");
				if (0 == p) {
					warnx("%s(%d): bad -p arg", __FILE__, __LINE__);
					usage(progname);
				}
				placeholders[placeholder_cnt].scheme = (uint8_t) strtoul(p, 0, 10);
				p = strtok(0, "");
				if (0 == p) {
					warnx("%s(%d): bad -p arg", __FILE__, __LINE__);
					usage(progname);
				}
				placeholders[placeholder_cnt].hashalg = (uint8_t) strtoul(p, 0, 10);
				placeholder_cnt++;
			}
			break;
		case 'q':
			quiet = 1;
			break;
		case 's':
			opt_scheme = (uint8_t) strtoul(optarg, 0, 10);
			break;
		case 't':
			print_timings = 1;
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

	probe_ldns(origin_str);

	my_getrusage(&t0);



	switch (opt_scheme) {
	case 1:
		the_scheme = scheme_simple_new(opt_scheme);
		break;
	case 240:
		the_scheme = scheme_merkle_new(opt_scheme);
		break;
	default:
		errx(1, "%s(%d): Unsupported scheme %u", __FILE__, __LINE__, opt_scheme);
		break;
	}
	zonemd_read_zone(origin_str, input, 0, LDNS_RR_CLASS_IN);
        fclose(input);
        input = 0;

	if (placeholder_cnt)
		zonemd_add_placeholders(placeholders, placeholder_cnt);
	my_getrusage(&t1);
	if (calculate)
		do_calculate(zsk_fname);
	my_getrusage(&t2);
	if (verify)
		rc |= do_verify();
	my_getrusage(&t3);
	if (update_file) {
		zonemd_zone_update(update_file);
		if (calculate)
			do_calculate(zsk_fname);
	}
	my_getrusage(&t4);
	if (output_file && (placeholder_cnt || calculate)) {
		zonemd_write_zone(output_file);
	}

	if (zsk_fname)
		free(zsk_fname);
	if (origin_str)
		free(origin_str);
	if (output_file)
		free(output_file);
	if (update_file)
		free(update_file);
	the_scheme->free(the_scheme);

	if (print_timings)
		printf("TIMINGS: load %7.2lf calculate %7.2lf verify %7.2lf update %7.2lf\n",
			elapsed_msec(&t0, &t1),
			elapsed_msec(&t1, &t2),
			elapsed_msec(&t2, &t3),
			elapsed_msec(&t3, &t4));

	return rc;
}
