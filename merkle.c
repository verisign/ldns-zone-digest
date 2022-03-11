#include <unistd.h>
#include <stdlib.h>
#include <err.h>
#include <ldns/ldns.h>

#include "ldns-zone-digest.h"
#include "merkle.h"

typedef struct _merkle_tree
{
	unsigned int depth;
	char branch_str[128];
	ldns_rr_list *rrlist;
	struct _merkle_tree *parent;	// not used currently
	struct _merkle_tree **kids;
	unsigned char digest[EVP_MAX_MD_SIZE];
	bool dirty;
} merkle_tree;

unsigned int merkle_tree_max_width = 13;
unsigned int merkle_tree_max_depth = 7;

#if ZONEMD_SAVE_LEAF_COUNTS
FILE *save_leaf_counts = 0;
#endif




/* ============================================================================== */

/*
 * merkle_tree_branch_by_name()
 *
 * Return branch index for a given name and depth
 */
static unsigned int
merkle_tree_branch_by_name(unsigned int depth, const char *name)
{
	unsigned int len;
	unsigned int pos;
	unsigned int branch;
	len = strlen(name);
	if (len == 0)
		return 0;
	pos = depth % len;
	branch = *(name + pos) % merkle_tree_max_width;
	//fdebugf(stderr, "%s(%d): merkle_tree_branch_by_name '%s' depth %u pos %u branch %u\n", __FILE__, __LINE__, name,
	//	depth, pos, branch);
	return branch;
}

/*
 * merkle_tree_get_leaf_by_name()
 *
 * Return the leaf node corresponding to the given name
 */
static merkle_tree *
merkle_tree_get_leaf_by_name_sub(const scheme *s, merkle_tree * node, const char *name)
{
	node->dirty = true;
	if (merkle_tree_max_depth > node->depth) {
		unsigned int branch = merkle_tree_branch_by_name(node->depth, name);
		if (node->kids == 0) {
			node->kids = calloc(merkle_tree_max_width, sizeof(*node->kids));
			assert(node->kids);
		}
		if (node->kids[branch] == 0) {
			node->kids[branch] = calloc(1, sizeof(**node->kids));
			assert(node->kids[branch]);
			node->kids[branch]->depth = node->depth + 1;
			node->kids[branch]->parent = node;
			if (node->depth == 0) {
				snprintf(node->kids[branch]->branch_str, sizeof(node->kids[branch]->branch_str), "%u", branch);
			} else {
				char *t = node->branch_str;
				snprintf(node->kids[branch]->branch_str, sizeof(node->kids[branch]->branch_str), "%s %u", t, branch);
			}
		}
		return merkle_tree_get_leaf_by_name_sub(s, node->kids[branch], name);
	}
	fdebugf(stderr, "%s(%d): merkle_tree_get_leaf '%s' is at %s\n", __FILE__, __LINE__, name, node->branch_str);
	return node;
}

/*
 * iterate and callback sub
 *
 */
static void
merkle_tree_iterate_sub(const scheme *s, merkle_tree * node, const scheme_iterate_cb cb, const void *cb_data)
{
	unsigned int i;
	if (node == 0)
		return;
	if (merkle_tree_max_depth > node->depth && node->kids) {
		unsigned int branch;
		for (branch = 0; branch < merkle_tree_max_width; branch++)
			merkle_tree_iterate_sub(s, node->kids[branch], cb, cb_data);
		return;
	}
	for (i = 0; i < ldns_rr_list_rr_count(node->rrlist); i++)
		cb(ldns_rr_list_rr(node->rrlist, i), cb_data);
#if ZONEMD_SAVE_LEAF_COUNTS
	if (save_leaf_counts) {
		fprintf(save_leaf_counts, "%zd\n", ldns_rr_list_rr_count(node->rrlist));
	}
#endif
}

/*
 * merkle_tree_free_sub()
 *
 * Walk all branches of the tree and free the data.
 */
static void
merkle_tree_free_sub(scheme *s, merkle_tree * node)
{
	if (node == 0)
		return;
	if (merkle_tree_max_depth > node->depth && node->kids) {
		unsigned int branch;
		for (branch = 0; branch < merkle_tree_max_width; branch++) {
			merkle_tree_free_sub(s, node->kids[branch]);
			free(node->kids[branch]);
		}
		free(node->kids);
	} else {
		assert(node->rrlist);
		ldns_rr_list_deep_free(node->rrlist);
	}
}

/* ============================================================================== */

scheme *
scheme_merkle_new(uint8_t opt_scheme)
{
	scheme *s;
	assert(240 == opt_scheme);
	fdebugf(stderr, "Creating Merkle Tree of scheme %u\n", opt_scheme);
	s = calloc(1, sizeof(*s));
	assert(s);
	s->scheme = opt_scheme;
	s->leaf = scheme_merkle_get_leaf_rr_list;
	s->calc = scheme_merkle_calc_digest;
	s->iter = scheme_merkle_iterate;
	s->free = scheme_merkle_free;
	s->data = calloc(1, sizeof(merkle_tree));
	assert(s->data);
#if ZONEMD_SAVE_LEAF_COUNTS
	save_leaf_counts = fopen("leaf-counts.dat", "w");
#endif
	return s;
}

/*
 */
ldns_rr_list *
scheme_merkle_get_leaf_rr_list(const scheme *s, const ldns_rr * rr)
{
	const ldns_rdf *owner;
	char *name;
	merkle_tree *leaf;
	owner = ldns_rr_owner(rr);
	assert(owner);
	name = ldns_rdf2str(owner);
	assert(name);
	leaf = merkle_tree_get_leaf_by_name_sub(s, s->data, name);
	assert(leaf);
	assert(leaf->kids == 0);	/* leaf nodes don't have kids */
	free(name);
	if (leaf->rrlist == 0) {
		leaf->rrlist = ldns_rr_list_new();
		assert(leaf->rrlist);
	}
	return leaf->rrlist;
}

/*
 * Iterate over ALL RRs in the zone.
 */
void
scheme_merkle_iterate(const scheme *s, const scheme_iterate_cb cb, const void *cb_data)
{
	merkle_tree_iterate_sub(s, s->data, cb, cb_data);
}

static void
scheme_merkle_calc_digest_sub(const scheme *s, merkle_tree *node, const EVP_MD * md, unsigned char *buf, const char *nonce)
{
	EVP_MD_CTX *ctx;
	//fdebugf(stderr, "%s(%d): scheme_calc_digest depth %u branch %u\n", __FILE__, __LINE__, node->depth,
	//	node->branch);
	fdebugf(stderr, "%s(%d): scheme_calc_digest at %s\n", __FILE__, __LINE__, node->branch_str);
	if (!node->dirty)
		return;
	ctx = EVP_MD_CTX_create();
	assert(ctx);
	if (!EVP_DigestInit(ctx, md))
		errx(1, "%s(%d): Digest init failed", __FILE__, __LINE__);
        if (nonce)
                if (!EVP_DigestUpdate(ctx, nonce, strlen(nonce)))
                        errx(1, "%s(%d): Digest update failed", __FILE__, __LINE__);
	if (merkle_tree_max_depth > node->depth) {
		unsigned int branch;
		assert(node->kids);
		for (branch = 0; branch < merkle_tree_max_width; branch++) {
			if (node->kids[branch] == 0)
				continue;
			scheme_merkle_calc_digest_sub(s, node->kids[branch], md, (unsigned char *) node->digest, 0);
			if (!EVP_DigestUpdate(ctx, node->digest, EVP_MD_size(md)))
				errx(1, "%s(%d): Digest update failed", __FILE__, __LINE__);
		}
	} else {
		assert(node->rrlist);
		ldns_rr_list_sort(node->rrlist);
		zonemd_rrlist_digest(node->rrlist, ctx);
	}
	if (!EVP_DigestFinal_ex(ctx, buf, 0))
		errx(1, "%s(%d): Digest final failed", __FILE__, __LINE__);
	EVP_MD_CTX_destroy(ctx);
	node->dirty = false;
}

void
scheme_merkle_calc_digest(const scheme *s, const EVP_MD * md, unsigned char *buf, const char *nonce)
{
	scheme_merkle_calc_digest_sub(s, s->data, md, buf, nonce);
}

void
scheme_merkle_free(scheme *s)
{
	assert(s->data);
	merkle_tree_free_sub(s, s->data);
	free(s->data);
	free(s);
#if ZONEMD_SAVE_LEAF_COUNTS
	fclose(save_leaf_counts);
	save_leaf_counts = 0;
#endif
}
