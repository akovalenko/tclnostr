#ifndef NOSTR_BASE64_H
#define NOSTR_BASE64_H

#include <stddef.h>

/* chars written (excl. NUL) for n input bytes: 4*ceil(n/3) */
#define NOSTR_BASE64_LEN(n) ((((n) + 2) / 3) * 4)

/* standard alphabet, padded; out must hold NOSTR_BASE64_LEN(n)+1 */
void nostr_base64_encode(const unsigned char *in, size_t n, char *out);

/* Strict decode: standard alphabet only, correct '=' padding, no
 * whitespace.  out must hold 3*(inlen/4).  Returns 1 and sets *outlen
 * on success, 0 on malformed input. */
int nostr_base64_decode(const char *in, size_t inlen, unsigned char *out,
    size_t *outlen);

#endif
