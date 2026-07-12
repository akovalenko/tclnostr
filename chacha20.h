#ifndef NOSTR_CHACHA20_H
#define NOSTR_CHACHA20_H

#include <stddef.h>
#include <stdint.h>

/* IETF ChaCha20 (RFC 8439): 32-byte key, 12-byte nonce, 32-bit block
 * counter.  XORs the keystream over in -> out (encrypts and decrypts);
 * in and out may be the same buffer. */
void nostr_chacha20_ietf_xor(const unsigned char key[32],
    const unsigned char nonce[12], uint32_t counter,
    const unsigned char *in, unsigned char *out, size_t len);

#endif
