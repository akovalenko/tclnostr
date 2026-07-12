/* NIP-44 v2 payload encryption: secp256k1 ECDH -> HKDF conversation
 * key, per-message keys, padded ChaCha20 + HMAC-SHA256 (with the nonce
 * as AAD), base64 payload.  Follows the spec pseudocode; the official
 * vector suite runs in tests/.
 * This file is in the public domain (see UNLICENSE). */

#include "nip44.h"

#include <stdlib.h>
#include <string.h>

#include <secp256k1_ecdh.h>

#include "base64.h"
#include "chacha20.h"
#include "hmac_sha256.h"

/* x-only ECDH: hand back the shared point's x coordinate unhashed */
static int
CopyX(unsigned char *output, const unsigned char *x32,
    const unsigned char *y32, void *data)
{
    (void)y32; (void)data;
    memcpy(output, x32, 32);
    return 1;
}

const char *
nostr_nip44_convkey(const secp256k1_context *ctx,
    const unsigned char sec32[32], const unsigned char pub32[32],
    unsigned char convkey32[32])
{
    secp256k1_pubkey pk;
    unsigned char comp[33], shared[32];

    if (!secp256k1_ec_seckey_verify(ctx, sec32)) {
	return "invalid secret key";
    }
    comp[0] = 2;
    memcpy(comp + 1, pub32, 32);
    if (!secp256k1_ec_pubkey_parse(ctx, &pk, comp, sizeof(comp))) {
	return "invalid public key";
    }
    if (!secp256k1_ecdh(ctx, shared, &pk, sec32, CopyX, NULL)) {
	return "ECDH failed";
    }
    nostr_hmac_sha256((const unsigned char *)"nip44-v2", 8, shared, 32,
	convkey32);
    memset(shared, 0, sizeof(shared));
    return NULL;
}

/* spec calc_padded_len: chunked power-of-two padding, minimum 32 */
static size_t
PaddedLen(size_t n)
{
    size_t np, chunk;

    if (n <= 32) return 32;
    for (np = 32; np < n; np <<= 1) {}
    chunk = (np <= 256) ? 32 : np / 8;
    return chunk * ((n - 1) / chunk + 1);
}

size_t
nostr_nip44_payload_len(size_t plainlen)
{
    /* version + nonce + BE16 length prefix + padded + mac, in base64 */
    return NOSTR_BASE64_LEN(1 + 32 + 2 + PaddedLen(plainlen) + 32);
}

typedef struct {
    unsigned char enc[32];
    unsigned char nonce[12];
    unsigned char auth[32];
} MessageKeys;

static void
GetMessageKeys(const unsigned char convkey32[32],
    const unsigned char nonce32[32], MessageKeys *mk)
{
    nostr_hkdf_expand_sha256(convkey32, nonce32, 32, (unsigned char *)mk,
	sizeof(*mk));
}

static void
MacWithAad(const unsigned char auth[32], const unsigned char aad32[32],
    const unsigned char *msg, size_t msglen, unsigned char out[32])
{
    NostrHmacCtx ctx;

    nostr_hmac_sha256_init(&ctx, auth, 32);
    nostr_hmac_sha256_update(&ctx, aad32, 32);
    nostr_hmac_sha256_update(&ctx, msg, msglen);
    nostr_hmac_sha256_final(&ctx, out);
}

const char *
nostr_nip44_encrypt(const unsigned char convkey32[32],
    const unsigned char nonce32[32], const unsigned char *plain,
    size_t plainlen, char *payloadOut)
{
    MessageKeys mk;
    unsigned char *bin, *ct;
    size_t padded, ctlen, binlen;

    if (plainlen < NOSTR_NIP44_MIN_PLAIN
	    || plainlen > NOSTR_NIP44_MAX_PLAIN) {
	return "plaintext must be 1 to 65535 bytes";
    }
    padded = PaddedLen(plainlen);
    ctlen = 2 + padded;
    binlen = 1 + 32 + ctlen + 32;
    bin = (unsigned char *)malloc(binlen);
    if (bin == NULL) {
	return "out of memory";
    }
    bin[0] = 2;
    memcpy(bin + 1, nonce32, 32);
    ct = bin + 33;
    ct[0] = (unsigned char)(plainlen >> 8);
    ct[1] = (unsigned char)plainlen;
    memcpy(ct + 2, plain, plainlen);
    memset(ct + 2 + plainlen, 0, padded - plainlen);

    GetMessageKeys(convkey32, nonce32, &mk);
    nostr_chacha20_ietf_xor(mk.enc, mk.nonce, 0, ct, ct, ctlen);
    MacWithAad(mk.auth, nonce32, ct, ctlen, bin + 33 + ctlen);
    memset(&mk, 0, sizeof(mk));

    nostr_base64_encode(bin, binlen, payloadOut);
    memset(bin, 0, binlen);
    free(bin);
    return NULL;
}

const char *
nostr_nip44_decrypt(const unsigned char convkey32[32],
    const char *payload, size_t payloadlen, unsigned char *plainOut,
    size_t *plainlenOut)
{
    MessageKeys mk;
    unsigned char *bin, mac[32], diff;
    size_t binlen = 0, ctlen, plen, i;
    const char *err = NULL;

    if (payloadlen > 0 && payload[0] == '#') {
	return "unsupported encryption version";
    }
    /* spec bounds: 132..87472 base64 chars, 99..65603 decoded bytes */
    if (payloadlen < 132 || payloadlen > 87472) {
	return "invalid payload length";
    }
    bin = (unsigned char *)malloc(3 * (payloadlen / 4));
    if (bin == NULL) {
	return "out of memory";
    }
    if (!nostr_base64_decode(payload, payloadlen, bin, &binlen)) {
	err = "invalid base64";
	goto out;
    }
    if (binlen < 99 || binlen > 65603) {
	err = "invalid payload length";
	goto out;
    }
    if (bin[0] != 2) {
	err = "unsupported encryption version";
	goto out;
    }
    ctlen = binlen - 65;
    GetMessageKeys(convkey32, bin + 1, &mk);
    MacWithAad(mk.auth, bin + 1, bin + 33, ctlen, mac);
    diff = 0;
    for (i = 0; i < 32; i++) {
	diff |= (unsigned char)(mac[i] ^ bin[33 + ctlen + i]);
    }
    if (diff != 0) {
	err = "invalid MAC";
	goto out;
    }
    nostr_chacha20_ietf_xor(mk.enc, mk.nonce, 0, bin + 33, plainOut, ctlen);
    plen = ((size_t)plainOut[0] << 8) | plainOut[1];
    if (plen < NOSTR_NIP44_MIN_PLAIN || 2 + PaddedLen(plen) != ctlen) {
	memset(plainOut, 0, ctlen);
	err = "invalid padding";
	goto out;
    }
    memmove(plainOut, plainOut + 2, plen);
    memset(plainOut + plen, 0, ctlen - plen);
    *plainlenOut = plen;
out:
    memset(&mk, 0, sizeof(mk));
    memset(mac, 0, sizeof(mac));
    free(bin);
    return err;
}
