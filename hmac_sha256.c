/* HMAC-SHA256 (RFC 2104) and HKDF-SHA256 expand (RFC 5869) over the
 * vendored B-Con sha256.  This file is in the public domain (see
 * UNLICENSE). */

#include "hmac_sha256.h"

#include <string.h>

void
nostr_hmac_sha256_init(NostrHmacCtx *ctx, const unsigned char *key,
    size_t keylen)
{
    unsigned char kb[64];
    size_t i;

    memset(kb, 0, sizeof(kb));
    if (keylen > 64) {
	SHA256_CTX h;
	sha256_init(&h);
	sha256_update(&h, key, keylen);
	sha256_final(&h, kb);
    } else {
	memcpy(kb, key, keylen);
    }
    for (i = 0; i < 64; i++) {
	ctx->okeypad[i] = (unsigned char)(kb[i] ^ 0x5c);
	kb[i] ^= 0x36;
    }
    sha256_init(&ctx->inner);
    sha256_update(&ctx->inner, kb, 64);
    memset(kb, 0, sizeof(kb));
}

void
nostr_hmac_sha256_update(NostrHmacCtx *ctx, const unsigned char *data,
    size_t len)
{
    sha256_update(&ctx->inner, data, len);
}

void
nostr_hmac_sha256_final(NostrHmacCtx *ctx, unsigned char out[32])
{
    unsigned char ih[32];
    SHA256_CTX h;

    sha256_final(&ctx->inner, ih);
    sha256_init(&h);
    sha256_update(&h, ctx->okeypad, 64);
    sha256_update(&h, ih, 32);
    sha256_final(&h, out);
    memset(ih, 0, sizeof(ih));
    memset(ctx, 0, sizeof(*ctx));
}

void
nostr_hmac_sha256(const unsigned char *key, size_t keylen,
    const unsigned char *msg, size_t msglen, unsigned char out[32])
{
    NostrHmacCtx ctx;

    nostr_hmac_sha256_init(&ctx, key, keylen);
    nostr_hmac_sha256_update(&ctx, msg, msglen);
    nostr_hmac_sha256_final(&ctx, out);
}

void
nostr_hkdf_expand_sha256(const unsigned char prk[32],
    const unsigned char *info, size_t infolen,
    unsigned char *okm, size_t okmlen)
{
    unsigned char t[32];
    unsigned char counter = 0;
    size_t tlen = 0;

    while (okmlen > 0) {
	NostrHmacCtx ctx;
	size_t n;

	counter++;
	nostr_hmac_sha256_init(&ctx, prk, 32);
	nostr_hmac_sha256_update(&ctx, t, tlen);
	nostr_hmac_sha256_update(&ctx, info, infolen);
	nostr_hmac_sha256_update(&ctx, &counter, 1);
	nostr_hmac_sha256_final(&ctx, t);
	tlen = 32;
	n = okmlen < 32 ? okmlen : 32;
	memcpy(okm, t, n);
	okm += n;
	okmlen -= n;
    }
    memset(t, 0, sizeof(t));
}
