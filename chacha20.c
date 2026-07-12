/* IETF ChaCha20 stream cipher, straight from RFC 8439.
 * This file is in the public domain (see UNLICENSE). */

#include "chacha20.h"

#include <string.h>

#define ROTL32(v, n) (((v) << (n)) | ((v) >> (32 - (n))))

#define QR(a, b, c, d) do { \
	a += b; d ^= a; d = ROTL32(d, 16); \
	c += d; b ^= c; b = ROTL32(b, 12); \
	a += b; d ^= a; d = ROTL32(d, 8);  \
	c += d; b ^= c; b = ROTL32(b, 7);  \
    } while (0)

static uint32_t
Le32(const unsigned char *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8)
	| ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void
Block(const uint32_t st[16], unsigned char out[64])
{
    uint32_t x[16];
    int i;

    memcpy(x, st, sizeof(x));
    for (i = 0; i < 10; i++) {
	QR(x[0], x[4], x[8],  x[12]);
	QR(x[1], x[5], x[9],  x[13]);
	QR(x[2], x[6], x[10], x[14]);
	QR(x[3], x[7], x[11], x[15]);
	QR(x[0], x[5], x[10], x[15]);
	QR(x[1], x[6], x[11], x[12]);
	QR(x[2], x[7], x[8],  x[13]);
	QR(x[3], x[4], x[9],  x[14]);
    }
    for (i = 0; i < 16; i++) {
	uint32_t v = x[i] + st[i];
	out[4*i]   = (unsigned char)v;
	out[4*i+1] = (unsigned char)(v >> 8);
	out[4*i+2] = (unsigned char)(v >> 16);
	out[4*i+3] = (unsigned char)(v >> 24);
    }
}

void
nostr_chacha20_ietf_xor(const unsigned char key[32],
    const unsigned char nonce[12], uint32_t counter,
    const unsigned char *in, unsigned char *out, size_t len)
{
    uint32_t st[16];
    unsigned char ks[64];
    size_t i, n;

    st[0] = 0x61707865; st[1] = 0x3320646e;
    st[2] = 0x79622d32; st[3] = 0x6b206574;
    for (i = 0; i < 8; i++) {
	st[4+i] = Le32(key + 4*i);
    }
    st[12] = counter;
    st[13] = Le32(nonce);
    st[14] = Le32(nonce + 4);
    st[15] = Le32(nonce + 8);

    while (len > 0) {
	Block(st, ks);
	st[12]++;
	n = len < 64 ? len : 64;
	for (i = 0; i < n; i++) {
	    out[i] = (unsigned char)(in[i] ^ ks[i]);
	}
	in += n;
	out += n;
	len -= n;
    }
    memset(ks, 0, sizeof(ks));
    memset(st, 0, sizeof(st));
}
