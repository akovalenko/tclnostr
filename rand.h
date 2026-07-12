/* Platform CSPRNG: fills buf with len random bytes, returns 1 on success. */

#ifndef NOSTR_RAND_H
#define NOSTR_RAND_H 1

#include <stddef.h>

int nostr_fill_random(unsigned char *buf, size_t len);

#endif /* NOSTR_RAND_H */
