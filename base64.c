/* Strict base64 codec (RFC 4648, standard alphabet).
 * This file is in the public domain (see UNLICENSE). */

#include "base64.h"

static const char b64dig[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

void
nostr_base64_encode(const unsigned char *in, size_t n, char *out)
{
    while (n >= 3) {
	unsigned int v = ((unsigned int)in[0] << 16)
	    | ((unsigned int)in[1] << 8) | in[2];
	*out++ = b64dig[v >> 18];
	*out++ = b64dig[(v >> 12) & 63];
	*out++ = b64dig[(v >> 6) & 63];
	*out++ = b64dig[v & 63];
	in += 3;
	n -= 3;
    }
    if (n > 0) {
	unsigned int v = (unsigned int)in[0] << 16;
	if (n == 2) v |= (unsigned int)in[1] << 8;
	*out++ = b64dig[v >> 18];
	*out++ = b64dig[(v >> 12) & 63];
	*out++ = (n == 2) ? b64dig[(v >> 6) & 63] : '=';
	*out++ = '=';
    }
    *out = '\0';
}

static int
B64Val(char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

int
nostr_base64_decode(const char *in, size_t inlen, unsigned char *out,
    size_t *outlen)
{
    size_t i, n = 0;
    int pad = 0;

    if (inlen == 0 || inlen % 4 != 0) return 0;
    if (in[inlen-1] == '=') {
	pad++;
	if (in[inlen-2] == '=') pad++;
    }
    for (i = 0; i < inlen; i += 4) {
	int a = B64Val(in[i]), b = B64Val(in[i+1]);
	int c, d;
	unsigned int v;
	int last = (i + 4 == inlen);
	c = (last && pad >= 2) ? 0 : B64Val(in[i+2]);
	d = (last && pad >= 1) ? 0 : B64Val(in[i+3]);
	if (a < 0 || b < 0 || c < 0 || d < 0) return 0;
	v = ((unsigned int)a << 18) | ((unsigned int)b << 12)
	    | ((unsigned int)c << 6) | (unsigned int)d;
	out[n++] = (unsigned char)(v >> 16);
	if (!last || pad < 2) out[n++] = (unsigned char)(v >> 8);
	if (!last || pad < 1) out[n++] = (unsigned char)v;
    }
    /* canonical padding: the bits dropped by '=' must be zero */
    if (pad == 1 && (B64Val(in[inlen-2]) & 3) != 0) return 0;
    if (pad == 2 && (B64Val(in[inlen-3]) & 15) != 0) return 0;
    *outlen = n;
    return 1;
}
