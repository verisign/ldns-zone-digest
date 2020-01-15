#include <openssl/evp.h>

#if DEBUG
#define fdebugf(...) fprintf(__VA_ARGS__)
#else
#define fdebugf(...) (void)0
#endif


void zonemd_rrlist_digest(ldns_rr_list *rrlist, EVP_MD_CTX *ctx);
void zonemd_print_digest(FILE *fp, const char *preamble, const unsigned char *buf, unsigned int len, const char *postamble);


typedef struct _zonemd {
	uint8_t type;
	uint8_t parameter;
	const EVP_MD * md;
	void *data;
} zonemd;
