#ifndef NOSTR_HMAC_SHA256_H
#define NOSTR_HMAC_SHA256_H

#include <stddef.h>
#include "sha256.h"

typedef struct {
    SHA256_CTX inner;
    unsigned char okeypad[64];
} NostrHmacCtx;

void nostr_hmac_sha256_init(NostrHmacCtx *ctx, const unsigned char *key,
    size_t keylen);
void nostr_hmac_sha256_update(NostrHmacCtx *ctx, const unsigned char *data,
    size_t len);
void nostr_hmac_sha256_final(NostrHmacCtx *ctx, unsigned char out[32]);

/* one-shot */
void nostr_hmac_sha256(const unsigned char *key, size_t keylen,
    const unsigned char *msg, size_t msglen, unsigned char out[32]);

/* HKDF-SHA256 expand step (RFC 5869); okmlen <= 255*32 */
void nostr_hkdf_expand_sha256(const unsigned char prk[32],
    const unsigned char *info, size_t infolen,
    unsigned char *okm, size_t okmlen);

#endif
