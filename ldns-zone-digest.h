#include <openssl/evp.h>

#if DEBUG
#define fdebugf(...) fprintf(__VA_ARGS__)
#else
#define fdebugf(...) (void)0
#endif


void zonemd_rrlist_digest(ldns_rr_list *rrlist, EVP_MD_CTX *ctx);
void zonemd_print_digest(FILE *fp, const char *preamble, const unsigned char *buf, unsigned int len, const char *postamble);

typedef struct _scheme scheme;

typedef void (*scheme_iterate_cb)(const ldns_rr *, const void *scheme_iterate_data);

typedef scheme *(scheme_new)(uint8_t);
typedef ldns_rr_list *(scheme_get_leaf_rr_list)(const struct _scheme *, const ldns_rr *for_rr);
typedef void (scheme_calc_digest)(const struct _scheme *, const EVP_MD * md, unsigned char *buf);
typedef void (scheme_iterate)(const struct _scheme *, scheme_iterate_cb, const void *scheme_iterate_data);
typedef void (scheme_free)(struct _scheme *);

struct _scheme {
	uint8_t scheme;
	scheme_get_leaf_rr_list *leaf;
	scheme_calc_digest *calc;
	scheme_iterate *iter;
	scheme_free *free;
	void *data;
};

extern char *opt_nonce;
