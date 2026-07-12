#ifndef NOSTR_NIP44_H
#define NOSTR_NIP44_H

#include <stddef.h>
#include <secp256k1.h>

/* NIP-44 v2 payload encryption.  All functions return NULL on success
 * or a static error message. */

#define NOSTR_NIP44_MIN_PLAIN 1
#define NOSTR_NIP44_MAX_PLAIN 65535

/* conversation key: ECDH(sec, pub) x-only -> HKDF-extract "nip44-v2" */
const char *nostr_nip44_convkey(const secp256k1_context *ctx,
    const unsigned char sec32[32], const unsigned char pub32[32],
    unsigned char convkey32[32]);

/* base64 chars (excl. NUL) of the payload for a given plaintext size */
size_t nostr_nip44_payload_len(size_t plainlen);

/* payloadOut must hold nostr_nip44_payload_len(plainlen)+1 bytes */
const char *nostr_nip44_encrypt(const unsigned char convkey32[32],
    const unsigned char nonce32[32], const unsigned char *plain,
    size_t plainlen, char *payloadOut);

/* plainOut must hold at least payloadlen bytes (decoded is smaller);
 * *plainlenOut receives the plaintext length */
const char *nostr_nip44_decrypt(const unsigned char convkey32[32],
    const char *payload, size_t payloadlen, unsigned char *plainOut,
    size_t *plainlenOut);

#endif
