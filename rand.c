/* Platform CSPRNG for key generation, context randomization and the
 * BIP-340 aux_rand.  Windows: BCryptGenRandom (system-preferred RNG,
 * needs -lbcrypt).  Linux: getrandom(2).  Other unix: /dev/urandom. */

#include "rand.h"

#ifdef _WIN32

#include <windows.h>
#include <bcrypt.h>

int nostr_fill_random(unsigned char *buf, size_t len)
{
    NTSTATUS st = BCryptGenRandom(NULL, buf, (ULONG)len,
	BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return st == 0;
}

#elif defined(__linux__)

#include <errno.h>
#include <sys/random.h>

int nostr_fill_random(unsigned char *buf, size_t len)
{
    size_t off = 0;
    while (off < len) {
	ssize_t n = getrandom(buf + off, len - off, 0);
	if (n < 0) {
	    if (errno == EINTR) continue;
	    return 0;
	}
	off += (size_t)n;
    }
    return 1;
}

#else

#include <stdio.h>

int nostr_fill_random(unsigned char *buf, size_t len)
{
    FILE *f = fopen("/dev/urandom", "rb");
    size_t got;
    if (f == NULL) return 0;
    got = fread(buf, 1, len, f);
    fclose(f);
    return got == len;
}

#endif
