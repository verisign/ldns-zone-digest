#include <unistd.h>
#include <stdlib.h>
#include <err.h>
#include <ldns/ldns.h>

#include "ldns-zone-digest.h"
#include "merkle.h"

typedef struct _zonemd_tree
{
	unsigned int depth;
	char branch_str[128];
	ldns_rr_list *rrlist;
	struct _zonemd_tree *parent;	// not used currently
	struct _zonemd_tree **kids;
	unsigned char digest[EVP_MAX_MD_SIZE];
	bool dirty;
} zonemd_tree;

unsigned int merkle_tree_max_width = 13;
unsigned int merkle_tree_max_depth = 7;

#if ZONEMD_SAVE_LEAF_COUNTS
FILE *save_leaf_counts = 0;
#endif




/* ============================================================================== */

/*
 * zonemd_tree_branch_by_name()
 *
 * Return branch index for a given name and depth
 */
static unsigned int
zonemd_tree_branch_by_name(unsigned int depth, const char *name)
{
	unsigned int len;
	unsigned int pos;
	unsigned int branch;
	len = strlen(name);
	if (len == 0)
		return 0;
	pos = depth % len;
	branch = *(name + pos) % merkle_tree_max_width;
	//fdebugf(stderr, "%s(%d): zonemd_tree_branch_by_name '%s' depth %u pos %u branch %u\n", __FILE__, __LINE__, name,
	//	depth, pos, branch);
	return branch;
}

/*
 * zonemd_tree_get_leaf_by_name()
 *
 * Return the leaf node corresponding to the given name
 */
static zonemd_tree *
zonemd_tree_get_leaf_by_name_sub(const zonemd *zmd, zonemd_tree * node, const char *name)
{
	node->dirty = true;
	if (merkle_tree_max_depth > node->depth) {
		unsigned int branch = zonemd_tree_branch_by_name(node->depth, name);
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
		return zonemd_tree_get_leaf_by_name_sub(zmd, node->kids[branch], name);
	}
	fdebugf(stderr, "%s(%d): zonemd_tree_get_leaf '%s' is at %s\n", __FILE__, __LINE__, name, node->branch_str);
	return node;
}

/*
 * zonemd_tree_full_rrlist()
 *
 * Walk all branches of the tree and buld a full rrlist.  The rrlist is
 * allocated by the caller.
 */
static void
zonemd_tree_full_rrlist_sub(const zonemd *zmd, zonemd_tree * node, ldns_rr_list * rrlist)
{
	if (node == 0)
		return;
	if (merkle_tree_max_depth > node->depth && node->kids) {
		unsigned int branch;
		for (branch = 0; branch < merkle_tree_max_width; branch++)
			zonemd_tree_full_rrlist_sub(zmd, node->kids[branch], rrlist);
		return;
	}
	ldns_rr_list_push_rr_list(rrlist, node->rrlist);
#if ZONEMD_SAVE_LEAF_COUNTS
	if (save_leaf_counts) {
		fprintf(save_leaf_counts, "%zd\n", ldns_rr_list_rr_count(node->rrlist));
	}
#endif
}

/*
 * zonemd_tree_free_sub()
 *
 * Walk all branches of the tree and free the data.
 */
static void
zonemd_tree_free_sub(zonemd *zmd, zonemd_tree * node)
{
	if (node == 0)
		return;
	if (merkle_tree_max_depth > node->depth && node->kids) {
		unsigned int branch;
		for (branch = 0; branch < merkle_tree_max_width; branch++) {
			zonemd_tree_free_sub(zmd, node->kids[branch]);
			free(node->kids[branch]);
		}
		free(node->kids);
	} else {
		assert(node->rrlist);
		ldns_rr_list_deep_free(node->rrlist);
	}
}

/* ============================================================================== */

zonemd *
zonemd_merkle_new(uint8_t scheme)
{
        zonemd *zmd;
	fdebugf(stderr, "Creating Merkle Tree of scheme %u\n", scheme);

        zmd = calloc(1, sizeof(*zmd));
        assert(zmd);
        zmd->scheme = scheme;
        zmd->data = calloc(1, sizeof(zonemd_tree));
        assert(zmd->data);
#if ZONEMD_SAVE_LEAF_COUNTS
	save_leaf_counts = fopen("leaf-counts.dat", "w");
#endif
        return zmd;
}

/*
 */
ldns_rr_list *
zonemd_merkle_get_rr_list(const zonemd *zmd, const ldns_rr * rr)
{
	const ldns_rdf *owner;
	char *name;
	zonemd_tree *leaf;
	owner = ldns_rr_owner(rr);
	assert(owner);
	name = ldns_rdf2str(owner);
	assert(name);
	leaf = zonemd_tree_get_leaf_by_name_sub(zmd, zmd->data, name);
	assert(leaf);
	assert(leaf->kids == 0);	/* leaf nodes don't have kids */
	free(name);
	if (leaf->rrlist == 0) {
		leaf->rrlist = ldns_rr_list_new();
		assert(leaf->rrlist);
	}
	return leaf->rrlist;
}

ldns_rr_list *
zonemd_merkle_get_full_rr_list(const zonemd *zmd)
{
	ldns_rr_list *rrlist;
	rrlist = ldns_rr_list_new();
	assert(rrlist);
	zonemd_tree_full_rrlist_sub(zmd, zmd->data, rrlist);
	return rrlist;
}

static void
zonemd_merkle_calc_digest_sub(const zonemd *zmd, zonemd_tree *node, const EVP_MD * md, unsigned char *buf)
{
	EVP_MD_CTX *ctx;
	//fdebugf(stderr, "%s(%d): zonemd_calc_digest depth %u branch %u\n", __FILE__, __LINE__, node->depth,
	//	node->branch);
	fdebugf(stderr, "%s(%d): zonemd_calc_digest at %s\n", __FILE__, __LINE__, node->branch_str);
	if (!node->dirty)
		return;
	ctx = EVP_MD_CTX_create();
	assert(ctx);
	if (!EVP_DigestInit(ctx, md))
		errx(1, "%s(%d): Digest init failed", __FILE__, __LINE__);
	if (merkle_tree_max_depth > node->depth) {
		unsigned int branch;
		assert(node->kids);
		for (branch = 0; branch < merkle_tree_max_width; branch++) {
			if (node->kids[branch] == 0)
				continue;
			zonemd_merkle_calc_digest_sub(zmd, node->kids[branch], md, (unsigned char *) node->digest);
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
zonemd_merkle_calc_digest(const zonemd *zmd, const EVP_MD * md, unsigned char *buf)
{
	zonemd_merkle_calc_digest_sub(zmd, zmd->data, md, buf);
}

void
zonemd_merkle_free(zonemd *zmd)
{
	assert(zmd->data);
	zonemd_tree_free_sub(zmd, zmd->data);
	free(zmd->data);
	free(zmd);
#if ZONEMD_SAVE_LEAF_COUNTS
	fclose(save_leaf_counts);
	save_leaf_counts = 0;
#endif
}
