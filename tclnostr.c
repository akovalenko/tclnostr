/* tclnostr — Nostr (NIP-01) signer/verifier for Tcl 9.
 *
 * The package covers the frozen, fiddly parts in C: canonical NIP-01
 * event serialization (the byte format the event id is the sha256 of),
 * BIP-340 Schnorr signing/verification via libsecp256k1, NIP-19
 * npub/nsec bech32 codec, and a strict parser for the fixed event-JSON
 * schema.  It emits and parses only that schema; general JSON (API
 * responses etc.) is the script layer's business.
 *
 * Two sign entry points mirror nak: build an event from fields, or
 * take an (unsigned, possibly partial) event JSON, fill the missing
 * fields, canonicalize and sign.  Verification is self-contained.
 *
 * This file is in the public domain (see UNLICENSE); the vendored
 * files under vendor/ keep their own licenses.
 */

#include <tcl.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <inttypes.h>

#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>

#include "sha256.h"
#include "bech32.h"
#include "rand.h"

#define NOSTR_VERSION "0.1"

typedef struct {
    secp256k1_context *ctx;	/* one per interp, randomized at creation */
    Tcl_Encoding utf8;		/* internal <-> strict UTF-8 bytes */
} NostrState;

/* ------------------------------------------------------------------ hex -- */

static const char hexdig[] = "0123456789abcdef";

static void
HexEncode(const unsigned char *in, size_t n, char *out)
{
    size_t i;
    for (i = 0; i < n; i++) {
	out[2*i] = hexdig[in[i] >> 4];
	out[2*i+1] = hexdig[in[i] & 0xf];
    }
    out[2*n] = '\0';
}

static int
HexVal(char c, int requireLower)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (!requireLower && c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int
HexDecode(const char *s, size_t hexlen, unsigned char *out, int requireLower)
{
    size_t i;
    for (i = 0; i < hexlen; i += 2) {
	int hi = HexVal(s[i], requireLower);
	int lo = HexVal(s[i+1], requireLower);
	if (hi < 0 || lo < 0) return 0;
	out[i/2] = (unsigned char)((hi << 4) | lo);
    }
    return 1;
}

/* Is obj a string of exactly hexlen lowercase hex digits? */
static int
IsLowerHexObj(Tcl_Obj *obj, Tcl_Size hexlen)
{
    Tcl_Size len, i;
    const char *s = Tcl_GetStringFromObj(obj, &len);
    if (len != hexlen) return 0;
    for (i = 0; i < len; i++) {
	if (HexVal(s[i], 1) < 0) return 0;
    }
    return 1;
}

/* -------------------------------------------------------- NIP-19 bech32 -- */

static int
Bech32Encode32(const char *hrp, const unsigned char in32[32], char out[128])
{
    uint8_t data5[64];
    size_t d5len = 0;
    bech32_convert_bits(data5, &d5len, 5, in32, 32, 8, 1);
    return bech32_encode(out, hrp, data5, d5len, BECH32_ENCODING_BECH32);
}

static int
Bech32Decode32(const char *in, char hrpOut[8], unsigned char out32[32])
{
    uint8_t data5[84], bytes[64];
    char hrp[84];
    size_t d5len = 0, blen = 0;
    if (strlen(in) > 90) return 0;
    if (bech32_decode(hrp, data5, &d5len, in) != BECH32_ENCODING_BECH32) {
	return 0;
    }
    if (strlen(hrp) > 7) return 0;
    if (!bech32_convert_bits(bytes, &blen, 8, data5, d5len, 5, 0)) return 0;
    if (blen != 32) return 0;
    memcpy(out32, bytes, 32);
    memset(bytes, 0, sizeof(bytes));	/* may hold an nsec payload */
    strcpy(hrpOut, hrp);
    return 1;
}

/* ------------------------------------------------------------ key input -- */

static int
GetSecKey(Tcl_Interp *interp, Tcl_Obj *obj, unsigned char sec32[32])
{
    Tcl_Size len;
    const char *s = Tcl_GetStringFromObj(obj, &len);
    char hrp[8];
    if (len == 64 && HexDecode(s, 64, sec32, 0)) {
	return TCL_OK;
    }
    if (Bech32Decode32(s, hrp, sec32) && strcmp(hrp, "nsec") == 0) {
	return TCL_OK;
    }
    memset(sec32, 0, 32);
    Tcl_SetObjResult(interp, Tcl_NewStringObj(
	"secret key must be nsec1... or 64 hex digits", -1));
    return TCL_ERROR;
}

/* Accepts npub1... or 64 hex digits; fills lowercase pkhex[65]. */
static int
GetPubkeyHex(Tcl_Interp *interp, Tcl_Obj *obj, char pkhex[65])
{
    Tcl_Size len;
    const char *s = Tcl_GetStringFromObj(obj, &len);
    unsigned char pk32[32];
    char hrp[8];
    if (len == 64 && HexDecode(s, 64, pk32, 0)) {
	HexEncode(pk32, 32, pkhex);
	return TCL_OK;
    }
    if (Bech32Decode32(s, hrp, pk32) && strcmp(hrp, "npub") == 0) {
	HexEncode(pk32, 32, pkhex);
	return TCL_OK;
    }
    Tcl_SetObjResult(interp, Tcl_NewStringObj(
	"public key must be npub1... or 64 hex digits", -1));
    return TCL_ERROR;
}

/* ------------------------------------------------- JSON string emitters -- */

/* Append the string bytes JSON-escaped.  canonical=1 is the NIP-01 hash
 * serialization: exactly 7 characters are escaped, every other byte —
 * including other control bytes and raw UTF-8 — goes through verbatim.
 * canonical=0 emits valid JSON: same 7 plus \u00XX for remaining
 * control bytes. */
static void
AppendEscaped(Tcl_DString *out, const char *bytes, Tcl_Size n, int canonical)
{
    Tcl_Size i;
    for (i = 0; i < n; i++) {
	unsigned char c = (unsigned char)bytes[i];
	switch (c) {
	case '\n': Tcl_DStringAppend(out, "\\n", 2); break;
	case '"':  Tcl_DStringAppend(out, "\\\"", 2); break;
	case '\\': Tcl_DStringAppend(out, "\\\\", 2); break;
	case '\r': Tcl_DStringAppend(out, "\\r", 2); break;
	case '\t': Tcl_DStringAppend(out, "\\t", 2); break;
	case '\b': Tcl_DStringAppend(out, "\\b", 2); break;
	case '\f': Tcl_DStringAppend(out, "\\f", 2); break;
	default:
	    if (!canonical && c < 0x20) {
		char u[8];
		snprintf(u, sizeof(u), "\\u%04x", c);
		Tcl_DStringAppend(out, u, 6);
	    } else {
		Tcl_DStringAppend(out, bytes + i, 1);
	    }
	}
    }
}

static void
AppendJsonStringObj(NostrState *st, Tcl_DString *out, Tcl_Obj *obj,
    int canonical)
{
    Tcl_DString ext;
    Tcl_Size len;
    const char *s = Tcl_GetStringFromObj(obj, &len);
    Tcl_UtfToExternalDString(st->utf8, s, len, &ext);
    Tcl_DStringAppend(out, "\"", 1);
    AppendEscaped(out, Tcl_DStringValue(&ext), Tcl_DStringLength(&ext),
	canonical);
    Tcl_DStringAppend(out, "\"", 1);
    Tcl_DStringFree(&ext);
}

/* tags: Tcl list of lists of strings -> JSON array of arrays of strings */
static int
AppendTags(Tcl_Interp *interp, NostrState *st, Tcl_DString *out,
    Tcl_Obj *tags, int canonical)
{
    Tcl_Size ntags, nel, i, j;
    Tcl_Obj **tagv, **elv;
    if (Tcl_ListObjGetElements(interp, tags, &ntags, &tagv) != TCL_OK) {
	return TCL_ERROR;
    }
    Tcl_DStringAppend(out, "[", 1);
    for (i = 0; i < ntags; i++) {
	if (i) Tcl_DStringAppend(out, ",", 1);
	if (Tcl_ListObjGetElements(interp, tagv[i], &nel, &elv) != TCL_OK) {
	    return TCL_ERROR;
	}
	Tcl_DStringAppend(out, "[", 1);
	for (j = 0; j < nel; j++) {
	    if (j) Tcl_DStringAppend(out, ",", 1);
	    AppendJsonStringObj(st, out, elv[j], canonical);
	}
	Tcl_DStringAppend(out, "]", 1);
    }
    Tcl_DStringAppend(out, "]", 1);
    return TCL_OK;
}

/* --------------------------------------------- canonical form, event id -- */

/* sha256 of the NIP-01 serialization
 * [0,"<pubkey>",<created_at>,<kind>,<tags>,"<content>"] */
static int
ComputeEventId(Tcl_Interp *interp, NostrState *st, const char pkhex[65],
    uint64_t createdAt, int kind, Tcl_Obj *tags, Tcl_Obj *content,
    unsigned char id32[32])
{
    Tcl_DString ser;
    char num[32];
    SHA256_CTX h;

    Tcl_DStringInit(&ser);
    Tcl_DStringAppend(&ser, "[0,\"", 4);
    Tcl_DStringAppend(&ser, pkhex, 64);
    Tcl_DStringAppend(&ser, "\",", 2);
    snprintf(num, sizeof(num), "%" PRIu64 ",", createdAt);
    Tcl_DStringAppend(&ser, num, -1);
    snprintf(num, sizeof(num), "%d,", kind);
    Tcl_DStringAppend(&ser, num, -1);
    if (AppendTags(interp, st, &ser, tags, 1) != TCL_OK) {
	Tcl_DStringFree(&ser);
	return TCL_ERROR;
    }
    Tcl_DStringAppend(&ser, ",", 1);
    AppendJsonStringObj(st, &ser, content, 1);
    Tcl_DStringAppend(&ser, "]", 1);

    sha256_init(&h);
    sha256_update(&h, (const BYTE *)Tcl_DStringValue(&ser),
	(size_t)Tcl_DStringLength(&ser));
    sha256_final(&h, id32);
    Tcl_DStringFree(&ser);
    return TCL_OK;
}

/* ------------------------------------------------- event JSON emission -- */

static int
EmitEvent(Tcl_Interp *interp, NostrState *st, const char idhex[65],
    const char pkhex[65], uint64_t createdAt, int kind, Tcl_Obj *tags,
    Tcl_Obj *content, const char sighex[129], Tcl_Obj **resultOut)
{
    Tcl_DString out, utf;
    char num[32];

    Tcl_DStringInit(&out);
    Tcl_DStringAppend(&out, "{\"id\":\"", -1);
    Tcl_DStringAppend(&out, idhex, 64);
    Tcl_DStringAppend(&out, "\",\"pubkey\":\"", -1);
    Tcl_DStringAppend(&out, pkhex, 64);
    Tcl_DStringAppend(&out, "\",\"created_at\":", -1);
    snprintf(num, sizeof(num), "%" PRIu64, createdAt);
    Tcl_DStringAppend(&out, num, -1);
    Tcl_DStringAppend(&out, ",\"kind\":", -1);
    snprintf(num, sizeof(num), "%d", kind);
    Tcl_DStringAppend(&out, num, -1);
    Tcl_DStringAppend(&out, ",\"tags\":", -1);
    if (AppendTags(interp, st, &out, tags, 0) != TCL_OK) {
	Tcl_DStringFree(&out);
	return TCL_ERROR;
    }
    Tcl_DStringAppend(&out, ",\"content\":", -1);
    AppendJsonStringObj(st, &out, content, 0);
    Tcl_DStringAppend(&out, ",\"sig\":\"", -1);
    Tcl_DStringAppend(&out, sighex, 128);
    Tcl_DStringAppend(&out, "\"}", 2);

    Tcl_ExternalToUtfDString(st->utf8, Tcl_DStringValue(&out),
	Tcl_DStringLength(&out), &utf);
    *resultOut = Tcl_NewStringObj(Tcl_DStringValue(&utf),
	Tcl_DStringLength(&utf));
    Tcl_DStringFree(&utf);
    Tcl_DStringFree(&out);
    return TCL_OK;
}

/* --------------------------------------------------- event JSON parser -- */

/* Strict parser for the fixed NIP-01 event schema.  Unknown or duplicate
 * fields are errors (an unknown field would not enter the id, i.e. it
 * would ride along unsigned).  Operates on strict UTF-8 bytes. */

typedef struct {
    Tcl_Interp *interp;
    NostrState *st;
    const unsigned char *p, *end;
} JsonParser;

typedef struct {
    Tcl_Obj *id, *pubkey, *sig;	/* as given; validated by the consumer */
    Tcl_Obj *tags;		/* list of lists of strings */
    Tcl_Obj *content;
    uint64_t created_at;
    int hasCreated;
    int kind;
    int hasKind;
} ParsedEvent;

static void
FreeParsedEvent(ParsedEvent *ev)
{
    if (ev->id) Tcl_DecrRefCount(ev->id);
    if (ev->pubkey) Tcl_DecrRefCount(ev->pubkey);
    if (ev->sig) Tcl_DecrRefCount(ev->sig);
    if (ev->tags) Tcl_DecrRefCount(ev->tags);
    if (ev->content) Tcl_DecrRefCount(ev->content);
    memset(ev, 0, sizeof(*ev));
}

static void
JpError(JsonParser *jp, const char *msg)
{
    Tcl_SetObjResult(jp->interp,
	Tcl_ObjPrintf("invalid event JSON: %s", msg));
}

static void
JpSkipWs(JsonParser *jp)
{
    while (jp->p < jp->end && (*jp->p == ' ' || *jp->p == '\t'
	    || *jp->p == '\n' || *jp->p == '\r')) {
	jp->p++;
    }
}

static int
JpHex4(JsonParser *jp, unsigned int *out)
{
    unsigned int v = 0;
    int i;
    if (jp->end - jp->p < 4) return 0;
    for (i = 0; i < 4; i++) {
	int d = HexVal((char)jp->p[i], 0);
	if (d < 0) return 0;
	v = (v << 4) | (unsigned int)d;
    }
    jp->p += 4;
    *out = v;
    return 1;
}

static void
AppendUtf8(Tcl_DString *ds, unsigned int cp)
{
    char b[4];
    if (cp < 0x80) {
	b[0] = (char)cp;
	Tcl_DStringAppend(ds, b, 1);
    } else if (cp < 0x800) {
	b[0] = (char)(0xC0 | (cp >> 6));
	b[1] = (char)(0x80 | (cp & 0x3F));
	Tcl_DStringAppend(ds, b, 2);
    } else if (cp < 0x10000) {
	b[0] = (char)(0xE0 | (cp >> 12));
	b[1] = (char)(0x80 | ((cp >> 6) & 0x3F));
	b[2] = (char)(0x80 | (cp & 0x3F));
	Tcl_DStringAppend(ds, b, 3);
    } else {
	b[0] = (char)(0xF0 | (cp >> 18));
	b[1] = (char)(0x80 | ((cp >> 12) & 0x3F));
	b[2] = (char)(0x80 | ((cp >> 6) & 0x3F));
	b[3] = (char)(0x80 | (cp & 0x3F));
	Tcl_DStringAppend(ds, b, 4);
    }
}

/* Returns a fresh Tcl_Obj (refcount 0) or NULL with an error message. */
static Tcl_Obj *
JpParseString(JsonParser *jp)
{
    Tcl_DString raw, utf;
    Tcl_Obj *res;

    if (jp->p >= jp->end || *jp->p != '"') {
	JpError(jp, "expected string");
	return NULL;
    }
    jp->p++;
    Tcl_DStringInit(&raw);
    for (;;) {
	unsigned char c;
	if (jp->p >= jp->end) {
	    Tcl_DStringFree(&raw);
	    JpError(jp, "unterminated string");
	    return NULL;
	}
	c = *jp->p;
	if (c == '"') {
	    jp->p++;
	    break;
	}
	if (c == '\\') {
	    unsigned char e;
	    jp->p++;
	    if (jp->p >= jp->end) {
		Tcl_DStringFree(&raw);
		JpError(jp, "unterminated escape");
		return NULL;
	    }
	    e = *jp->p++;
	    switch (e) {
	    case '"':  Tcl_DStringAppend(&raw, "\"", 1); break;
	    case '\\': Tcl_DStringAppend(&raw, "\\", 1); break;
	    case '/':  Tcl_DStringAppend(&raw, "/", 1); break;
	    case 'b':  Tcl_DStringAppend(&raw, "\b", 1); break;
	    case 'f':  Tcl_DStringAppend(&raw, "\f", 1); break;
	    case 'n':  Tcl_DStringAppend(&raw, "\n", 1); break;
	    case 'r':  Tcl_DStringAppend(&raw, "\r", 1); break;
	    case 't':  Tcl_DStringAppend(&raw, "\t", 1); break;
	    case 'u': {
		unsigned int cp, lo;
		if (!JpHex4(jp, &cp)) {
		    Tcl_DStringFree(&raw);
		    JpError(jp, "bad \\u escape");
		    return NULL;
		}
		if (cp >= 0xD800 && cp <= 0xDBFF) {
		    if (jp->end - jp->p < 2 || jp->p[0] != '\\'
			    || jp->p[1] != 'u') {
			Tcl_DStringFree(&raw);
			JpError(jp, "lone high surrogate");
			return NULL;
		    }
		    jp->p += 2;
		    if (!JpHex4(jp, &lo) || lo < 0xDC00 || lo > 0xDFFF) {
			Tcl_DStringFree(&raw);
			JpError(jp, "bad low surrogate");
			return NULL;
		    }
		    cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
		} else if (cp >= 0xDC00 && cp <= 0xDFFF) {
		    Tcl_DStringFree(&raw);
		    JpError(jp, "lone low surrogate");
		    return NULL;
		}
		AppendUtf8(&raw, cp);
		break;
	    }
	    default:
		Tcl_DStringFree(&raw);
		JpError(jp, "bad escape character");
		return NULL;
	    }
	} else if (c < 0x20) {
	    Tcl_DStringFree(&raw);
	    JpError(jp, "raw control character in string");
	    return NULL;
	} else if (c < 0x80) {
	    Tcl_DStringAppend(&raw, (const char *)jp->p, 1);
	    jp->p++;
	} else {
	    /* validate the UTF-8 sequence, pass its bytes through */
	    int n = (c >= 0xF0) ? 4 : (c >= 0xE0) ? 3 : (c >= 0xC0) ? 2 : 0;
	    unsigned int cp = 0;
	    int k;
	    if (n == 0 || c > 0xF4 || jp->end - jp->p < n) {
		Tcl_DStringFree(&raw);
		JpError(jp, "invalid UTF-8");
		return NULL;
	    }
	    cp = c & (unsigned char)(0xFF >> (n + 1));
	    for (k = 1; k < n; k++) {
		if ((jp->p[k] & 0xC0) != 0x80) {
		    Tcl_DStringFree(&raw);
		    JpError(jp, "invalid UTF-8");
		    return NULL;
		}
		cp = (cp << 6) | (jp->p[k] & 0x3F);
	    }
	    if ((n == 2 && cp < 0x80) || (n == 3 && cp < 0x800)
		    || (n == 4 && (cp < 0x10000 || cp > 0x10FFFF))
		    || (cp >= 0xD800 && cp <= 0xDFFF)) {
		Tcl_DStringFree(&raw);
		JpError(jp, "invalid UTF-8");
		return NULL;
	    }
	    Tcl_DStringAppend(&raw, (const char *)jp->p, n);
	    jp->p += n;
	}
    }
    Tcl_ExternalToUtfDString(jp->st->utf8, Tcl_DStringValue(&raw),
	Tcl_DStringLength(&raw), &utf);
    res = Tcl_NewStringObj(Tcl_DStringValue(&utf), Tcl_DStringLength(&utf));
    Tcl_DStringFree(&utf);
    Tcl_DStringFree(&raw);
    return res;
}

static int
JpParseUInt(JsonParser *jp, uint64_t *out)
{
    uint64_t v = 0;
    int nd = 0;
    if (jp->p < jp->end && *jp->p == '-') {
	JpError(jp, "negative number");
	return 0;
    }
    if (jp->p >= jp->end || *jp->p < '0' || *jp->p > '9') {
	JpError(jp, "expected number");
	return 0;
    }
    if (*jp->p == '0' && jp->p + 1 < jp->end
	    && jp->p[1] >= '0' && jp->p[1] <= '9') {
	JpError(jp, "leading zero in number");
	return 0;
    }
    while (jp->p < jp->end && *jp->p >= '0' && *jp->p <= '9') {
	if (++nd > 19) {
	    JpError(jp, "number too large");
	    return 0;
	}
	v = v * 10 + (uint64_t)(*jp->p - '0');
	jp->p++;
    }
    if (jp->p < jp->end && (*jp->p == '.' || *jp->p == 'e' || *jp->p == 'E'
	    || *jp->p == '+')) {
	JpError(jp, "expected integer");
	return 0;
    }
    *out = v;
    return 1;
}

/* Returns a fresh list-of-lists Tcl_Obj (refcount 0) or NULL. */
static Tcl_Obj *
JpParseTags(JsonParser *jp)
{
    Tcl_Obj *tags;

    if (jp->p >= jp->end || *jp->p != '[') {
	JpError(jp, "tags must be an array");
	return NULL;
    }
    jp->p++;
    tags = Tcl_NewListObj(0, NULL);
    Tcl_IncrRefCount(tags);
    JpSkipWs(jp);
    if (jp->p < jp->end && *jp->p == ']') {
	jp->p++;
	goto done;
    }
    for (;;) {
	Tcl_Obj *tag;
	JpSkipWs(jp);
	if (jp->p >= jp->end || *jp->p != '[') {
	    JpError(jp, "tag must be an array of strings");
	    goto fail;
	}
	jp->p++;
	tag = Tcl_NewListObj(0, NULL);
	Tcl_ListObjAppendElement(NULL, tags, tag);
	JpSkipWs(jp);
	if (jp->p < jp->end && *jp->p == ']') {
	    jp->p++;
	} else {
	    for (;;) {
		Tcl_Obj *el;
		JpSkipWs(jp);
		el = JpParseString(jp);
		if (el == NULL) goto fail;
		Tcl_ListObjAppendElement(NULL, tag, el);
		JpSkipWs(jp);
		if (jp->p < jp->end && *jp->p == ',') {
		    jp->p++;
		    continue;
		}
		if (jp->p < jp->end && *jp->p == ']') {
		    jp->p++;
		    break;
		}
		JpError(jp, "expected , or ] in tag");
		goto fail;
	    }
	}
	JpSkipWs(jp);
	if (jp->p < jp->end && *jp->p == ',') {
	    jp->p++;
	    continue;
	}
	if (jp->p < jp->end && *jp->p == ']') {
	    jp->p++;
	    break;
	}
	JpError(jp, "expected , or ] in tags");
	goto fail;
    }
done:
    /* hand back refcount-0 object */
    tags->refCount--;
    return tags;
fail:
    Tcl_DecrRefCount(tags);
    return NULL;
}

static int
ParseEvent(Tcl_Interp *interp, NostrState *st, Tcl_Obj *jsonObj,
    ParsedEvent *ev)
{
    Tcl_DString ext;
    Tcl_Size len;
    const char *src;
    JsonParser jpBuf, *jp = &jpBuf;
    int result = TCL_ERROR;

    memset(ev, 0, sizeof(*ev));
    src = Tcl_GetStringFromObj(jsonObj, &len);
    Tcl_UtfToExternalDString(st->utf8, src, len, &ext);
    jp->interp = interp;
    jp->st = st;
    jp->p = (const unsigned char *)Tcl_DStringValue(&ext);
    jp->end = jp->p + Tcl_DStringLength(&ext);

    JpSkipWs(jp);
    if (jp->p >= jp->end || *jp->p != '{') {
	JpError(jp, "expected object");
	goto out;
    }
    jp->p++;
    JpSkipWs(jp);
    if (jp->p < jp->end && *jp->p == '}') {
	jp->p++;
	goto tail;
    }
    for (;;) {
	Tcl_Obj *key, *val;
	const char *k;
	JpSkipWs(jp);
	key = JpParseString(jp);
	if (key == NULL) goto out;
	Tcl_IncrRefCount(key);
	k = Tcl_GetString(key);
	JpSkipWs(jp);
	if (jp->p >= jp->end || *jp->p != ':') {
	    Tcl_DecrRefCount(key);
	    JpError(jp, "expected :");
	    goto out;
	}
	jp->p++;
	JpSkipWs(jp);

	if (strcmp(k, "id") == 0 || strcmp(k, "pubkey") == 0
		|| strcmp(k, "sig") == 0 || strcmp(k, "content") == 0) {
	    Tcl_Obj **slot =
		(k[0] == 'i') ? &ev->id :
		(k[0] == 'p') ? &ev->pubkey :
		(k[0] == 's') ? &ev->sig : &ev->content;
	    if (*slot != NULL) {
		Tcl_DecrRefCount(key);
		JpError(jp, "duplicate field");
		goto out;
	    }
	    val = JpParseString(jp);
	    if (val == NULL) {
		Tcl_DecrRefCount(key);
		goto out;
	    }
	    Tcl_IncrRefCount(val);
	    *slot = val;
	} else if (strcmp(k, "created_at") == 0) {
	    uint64_t v;
	    if (ev->hasCreated) {
		Tcl_DecrRefCount(key);
		JpError(jp, "duplicate field");
		goto out;
	    }
	    if (!JpParseUInt(jp, &v)) {
		Tcl_DecrRefCount(key);
		goto out;
	    }
	    if (v > (uint64_t)INT64_MAX) {
		Tcl_DecrRefCount(key);
		JpError(jp, "created_at out of range");
		goto out;
	    }
	    ev->created_at = v;
	    ev->hasCreated = 1;
	} else if (strcmp(k, "kind") == 0) {
	    uint64_t v;
	    if (ev->hasKind) {
		Tcl_DecrRefCount(key);
		JpError(jp, "duplicate field");
		goto out;
	    }
	    if (!JpParseUInt(jp, &v)) {
		Tcl_DecrRefCount(key);
		goto out;
	    }
	    if (v > 65535) {
		Tcl_DecrRefCount(key);
		JpError(jp, "kind out of range");
		goto out;
	    }
	    ev->kind = (int)v;
	    ev->hasKind = 1;
	} else if (strcmp(k, "tags") == 0) {
	    if (ev->tags != NULL) {
		Tcl_DecrRefCount(key);
		JpError(jp, "duplicate field");
		goto out;
	    }
	    val = JpParseTags(jp);
	    if (val == NULL) {
		Tcl_DecrRefCount(key);
		goto out;
	    }
	    Tcl_IncrRefCount(val);
	    ev->tags = val;
	} else {
	    Tcl_SetObjResult(interp, Tcl_ObjPrintf(
		"invalid event JSON: unknown field \"%s\"", k));
	    Tcl_DecrRefCount(key);
	    goto out;
	}
	Tcl_DecrRefCount(key);
	JpSkipWs(jp);
	if (jp->p < jp->end && *jp->p == ',') {
	    jp->p++;
	    continue;
	}
	if (jp->p < jp->end && *jp->p == '}') {
	    jp->p++;
	    break;
	}
	JpError(jp, "expected , or }");
	goto out;
    }
tail:
    JpSkipWs(jp);
    if (jp->p != jp->end) {
	JpError(jp, "trailing data after event");
	goto out;
    }
    result = TCL_OK;
out:
    Tcl_DStringFree(&ext);
    if (result != TCL_OK) {
	FreeParsedEvent(ev);
    }
    return result;
}

/* -------------------------------------------------------------- signing -- */

static int
SignEvent(Tcl_Interp *interp, NostrState *st, const unsigned char sec32[32],
    uint64_t createdAt, int kind, Tcl_Obj *tags, Tcl_Obj *content,
    const char *expectPkHex, Tcl_Obj **resultOut)
{
    secp256k1_keypair kp;
    secp256k1_xonly_pubkey xpk;
    unsigned char pk32[32], id32[32], sig64[64], aux[32];
    char pkhex[65], idhex[65], sighex[129];
    int rc = TCL_ERROR;

    if (!secp256k1_keypair_create(st->ctx, &kp, sec32)) {
	Tcl_SetObjResult(interp, Tcl_NewStringObj("invalid secret key", -1));
	return TCL_ERROR;
    }
    secp256k1_keypair_xonly_pub(st->ctx, &xpk, NULL, &kp);
    secp256k1_xonly_pubkey_serialize(st->ctx, pk32, &xpk);
    HexEncode(pk32, 32, pkhex);
    if (expectPkHex != NULL && strcmp(expectPkHex, pkhex) != 0) {
	Tcl_SetObjResult(interp, Tcl_NewStringObj(
	    "event pubkey does not match the signing key", -1));
	goto out;
    }
    if (ComputeEventId(interp, st, pkhex, createdAt, kind, tags, content,
	    id32) != TCL_OK) {
	goto out;
    }
    if (!nostr_fill_random(aux, 32)) {
	Tcl_SetObjResult(interp, Tcl_NewStringObj("no entropy source", -1));
	goto out;
    }
    if (!secp256k1_schnorrsig_sign32(st->ctx, sig64, id32, &kp, aux)) {
	Tcl_SetObjResult(interp, Tcl_NewStringObj("signing failed", -1));
	goto out;
    }
    HexEncode(id32, 32, idhex);
    HexEncode(sig64, 64, sighex);
    rc = EmitEvent(interp, st, idhex, pkhex, createdAt, kind, tags, content,
	sighex, resultOut);
out:
    memset(&kp, 0, sizeof(kp));
    memset(aux, 0, sizeof(aux));
    return rc;
}

/* ------------------------------------------------------------- commands -- */

/* Shared option parsing for sign and id: fills the event fields from
 * either -json or the builder options.  On success the caller owns one
 * reference to *tagsOut and *contentOut and must free evOut if
 * *haveEvOut. */
static int
CollectEventArgs(Tcl_Interp *interp, NostrState *st, Tcl_Obj *jsonObj,
    Tcl_Obj *kindObj, Tcl_Obj *contentObj, Tcl_Obj *tagsObj,
    Tcl_Obj *createdObj, ParsedEvent *evOut, int *haveEvOut,
    uint64_t *createdOut, int *kindOut, Tcl_Obj **tagsOut,
    Tcl_Obj **contentOut)
{
    int kind = 1;
    uint64_t created;
    Tcl_Obj *tags = NULL, *content = NULL;

    *haveEvOut = 0;
    if (jsonObj != NULL) {
	if (kindObj || contentObj || tagsObj || createdObj) {
	    Tcl_SetObjResult(interp, Tcl_NewStringObj(
		"-json cannot be combined with -kind/-content/-tags/-created-at",
		-1));
	    return TCL_ERROR;
	}
	if (ParseEvent(interp, st, jsonObj, evOut) != TCL_OK) {
	    return TCL_ERROR;
	}
	*haveEvOut = 1;
	if (evOut->hasKind) kind = evOut->kind;
	created = evOut->hasCreated ? evOut->created_at
				    : (uint64_t)time(NULL);
	tags = evOut->tags;
	content = evOut->content;
    } else {
	if (kindObj != NULL) {
	    int k;
	    if (Tcl_GetIntFromObj(interp, kindObj, &k) != TCL_OK) {
		return TCL_ERROR;
	    }
	    if (k < 0 || k > 65535) {
		Tcl_SetObjResult(interp,
		    Tcl_NewStringObj("kind out of range", -1));
		return TCL_ERROR;
	    }
	    kind = k;
	}
	if (createdObj != NULL) {
	    Tcl_WideInt w;
	    if (Tcl_GetWideIntFromObj(interp, createdObj, &w) != TCL_OK) {
		return TCL_ERROR;
	    }
	    if (w < 0) {
		Tcl_SetObjResult(interp,
		    Tcl_NewStringObj("-created-at must be >= 0", -1));
		return TCL_ERROR;
	    }
	    created = (uint64_t)w;
	} else {
	    created = (uint64_t)time(NULL);
	}
	tags = tagsObj;
	content = contentObj;
    }
    if (tags == NULL) tags = Tcl_NewListObj(0, NULL);
    if (content == NULL) content = Tcl_NewStringObj("", 0);
    Tcl_IncrRefCount(tags);
    Tcl_IncrRefCount(content);
    *createdOut = created;
    *kindOut = kind;
    *tagsOut = tags;
    *contentOut = content;
    return TCL_OK;
}

static int
SignObjCmd(void *cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[])
{
    NostrState *st = (NostrState *)cd;
    Tcl_Obj *secObj = NULL, *jsonObj = NULL, *kindObj = NULL;
    Tcl_Obj *contentObj = NULL, *tagsObj = NULL, *createdObj = NULL;
    Tcl_Obj *tags, *content, *res = NULL;
    ParsedEvent ev;
    int i, haveEv, kind, rc;
    uint64_t created;
    unsigned char sec32[32];
    char expectPk[65];
    const char *expectPkPtr = NULL;

    if (objc < 3 || (objc % 2) != 1) {
	Tcl_WrongNumArgs(interp, 1, objv, "-sec key ?-json event? "
	    "?-kind n? ?-content text? ?-tags list? ?-created-at time?");
	return TCL_ERROR;
    }
    for (i = 1; i + 1 < objc; i += 2) {
	const char *opt = Tcl_GetString(objv[i]);
	if (strcmp(opt, "-sec") == 0) secObj = objv[i+1];
	else if (strcmp(opt, "-json") == 0) jsonObj = objv[i+1];
	else if (strcmp(opt, "-kind") == 0) kindObj = objv[i+1];
	else if (strcmp(opt, "-content") == 0) contentObj = objv[i+1];
	else if (strcmp(opt, "-tags") == 0) tagsObj = objv[i+1];
	else if (strcmp(opt, "-created-at") == 0) createdObj = objv[i+1];
	else {
	    Tcl_SetObjResult(interp, Tcl_ObjPrintf(
		"bad option \"%s\": must be -sec, -json, -kind, -content, "
		"-tags or -created-at", opt));
	    return TCL_ERROR;
	}
    }
    if (secObj == NULL) {
	Tcl_SetObjResult(interp, Tcl_NewStringObj("-sec is required", -1));
	return TCL_ERROR;
    }
    if (CollectEventArgs(interp, st, jsonObj, kindObj, contentObj, tagsObj,
	    createdObj, &ev, &haveEv, &created, &kind, &tags,
	    &content) != TCL_OK) {
	return TCL_ERROR;
    }
    if (haveEv && ev.pubkey != NULL) {
	if (!IsLowerHexObj(ev.pubkey, 64)) {
	    Tcl_SetObjResult(interp, Tcl_NewStringObj(
		"invalid pubkey in event", -1));
	    rc = TCL_ERROR;
	    goto out;
	}
	memcpy(expectPk, Tcl_GetString(ev.pubkey), 64);
	expectPk[64] = '\0';
	expectPkPtr = expectPk;
    }
    if (GetSecKey(interp, secObj, sec32) != TCL_OK) {
	rc = TCL_ERROR;
	goto out;
    }
    rc = SignEvent(interp, st, sec32, created, kind, tags, content,
	expectPkPtr, &res);
    memset(sec32, 0, sizeof(sec32));
    if (rc == TCL_OK) {
	Tcl_SetObjResult(interp, res);
    }
out:
    Tcl_DecrRefCount(tags);
    Tcl_DecrRefCount(content);
    if (haveEv) FreeParsedEvent(&ev);
    return rc;
}

static int
IdObjCmd(void *cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[])
{
    NostrState *st = (NostrState *)cd;
    Tcl_Obj *pubObj = NULL, *jsonObj = NULL, *kindObj = NULL;
    Tcl_Obj *contentObj = NULL, *tagsObj = NULL, *createdObj = NULL;
    Tcl_Obj *tags, *content;
    ParsedEvent ev;
    int i, haveEv, kind, rc = TCL_ERROR;
    uint64_t created;
    unsigned char id32[32];
    char pkhex[65], idhex[65];

    if (objc < 3 || (objc % 2) != 1) {
	Tcl_WrongNumArgs(interp, 1, objv, "?-pubkey key? ?-json event? "
	    "?-kind n? ?-content text? ?-tags list? ?-created-at time?");
	return TCL_ERROR;
    }
    for (i = 1; i + 1 < objc; i += 2) {
	const char *opt = Tcl_GetString(objv[i]);
	if (strcmp(opt, "-pubkey") == 0) pubObj = objv[i+1];
	else if (strcmp(opt, "-json") == 0) jsonObj = objv[i+1];
	else if (strcmp(opt, "-kind") == 0) kindObj = objv[i+1];
	else if (strcmp(opt, "-content") == 0) contentObj = objv[i+1];
	else if (strcmp(opt, "-tags") == 0) tagsObj = objv[i+1];
	else if (strcmp(opt, "-created-at") == 0) createdObj = objv[i+1];
	else {
	    Tcl_SetObjResult(interp, Tcl_ObjPrintf(
		"bad option \"%s\": must be -pubkey, -json, -kind, "
		"-content, -tags or -created-at", opt));
	    return TCL_ERROR;
	}
    }
    if (CollectEventArgs(interp, st, jsonObj, kindObj, contentObj, tagsObj,
	    createdObj, &ev, &haveEv, &created, &kind, &tags,
	    &content) != TCL_OK) {
	return TCL_ERROR;
    }
    if (pubObj != NULL) {
	if (GetPubkeyHex(interp, pubObj, pkhex) != TCL_OK) {
	    goto out;
	}
	if (haveEv && ev.pubkey != NULL
		&& strcmp(Tcl_GetString(ev.pubkey), pkhex) != 0) {
	    Tcl_SetObjResult(interp, Tcl_NewStringObj(
		"event pubkey does not match -pubkey", -1));
	    goto out;
	}
    } else if (haveEv && ev.pubkey != NULL) {
	if (!IsLowerHexObj(ev.pubkey, 64)) {
	    Tcl_SetObjResult(interp, Tcl_NewStringObj(
		"invalid pubkey in event", -1));
	    goto out;
	}
	memcpy(pkhex, Tcl_GetString(ev.pubkey), 64);
	pkhex[64] = '\0';
    } else {
	Tcl_SetObjResult(interp, Tcl_NewStringObj(
	    "no public key: pass -pubkey or an event with one", -1));
	goto out;
    }
    if (ComputeEventId(interp, st, pkhex, created, kind, tags, content,
	    id32) != TCL_OK) {
	goto out;
    }
    HexEncode(id32, 32, idhex);
    Tcl_SetObjResult(interp, Tcl_NewStringObj(idhex, 64));
    rc = TCL_OK;
out:
    Tcl_DecrRefCount(tags);
    Tcl_DecrRefCount(content);
    if (haveEv) FreeParsedEvent(&ev);
    return rc;
}

static int
VerifyObjCmd(void *cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[])
{
    NostrState *st = (NostrState *)cd;
    ParsedEvent ev;
    unsigned char id32[32], want32[32], sig64[64], pk32[32];
    int ok = 0;

    if (objc != 2) {
	Tcl_WrongNumArgs(interp, 1, objv, "eventJson");
	return TCL_ERROR;
    }
    if (ParseEvent(interp, st, objv[1], &ev) != TCL_OK) {
	return TCL_ERROR;
    }
    if (ev.id == NULL || ev.pubkey == NULL || ev.sig == NULL
	    || ev.content == NULL || ev.tags == NULL
	    || !ev.hasKind || !ev.hasCreated) {
	Tcl_SetObjResult(interp, Tcl_NewStringObj(
	    "incomplete event: id, pubkey, created_at, kind, tags, "
	    "content and sig are all required", -1));
	FreeParsedEvent(&ev);
	return TCL_ERROR;
    }
    if (!IsLowerHexObj(ev.id, 64) || !IsLowerHexObj(ev.pubkey, 64)
	    || !IsLowerHexObj(ev.sig, 128)) {
	Tcl_SetObjResult(interp, Tcl_NewStringObj(
	    "id, pubkey and sig must be lowercase hex of 64/64/128 digits",
	    -1));
	FreeParsedEvent(&ev);
	return TCL_ERROR;
    }
    HexDecode(Tcl_GetString(ev.id), 64, id32, 1);
    HexDecode(Tcl_GetString(ev.pubkey), 64, pk32, 1);
    HexDecode(Tcl_GetString(ev.sig), 128, sig64, 1);
    if (ComputeEventId(interp, st, Tcl_GetString(ev.pubkey), ev.created_at,
	    ev.kind, ev.tags, ev.content, want32) != TCL_OK) {
	FreeParsedEvent(&ev);
	return TCL_ERROR;
    }
    if (memcmp(id32, want32, 32) == 0) {
	secp256k1_xonly_pubkey xpk;
	ok = secp256k1_xonly_pubkey_parse(st->ctx, &xpk, pk32)
	    && secp256k1_schnorrsig_verify(st->ctx, sig64, id32, 32, &xpk);
    }
    FreeParsedEvent(&ev);
    Tcl_SetObjResult(interp, Tcl_NewBooleanObj(ok));
    return TCL_OK;
}

static int
KeygenObjCmd(void *cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[])
{
    NostrState *st = (NostrState *)cd;
    secp256k1_keypair kp;
    unsigned char sec[32];
    char out[128];

    if (objc != 1) {
	Tcl_WrongNumArgs(interp, 1, objv, NULL);
	return TCL_ERROR;
    }
    do {
	if (!nostr_fill_random(sec, 32)) {
	    Tcl_SetObjResult(interp,
		Tcl_NewStringObj("no entropy source", -1));
	    return TCL_ERROR;
	}
    } while (!secp256k1_keypair_create(st->ctx, &kp, sec));
    memset(&kp, 0, sizeof(kp));
    Bech32Encode32("nsec", sec, out);
    memset(sec, 0, sizeof(sec));
    Tcl_SetObjResult(interp, Tcl_NewStringObj(out, -1));
    memset(out, 0, sizeof(out));
    return TCL_OK;
}

static int
PubkeyObjCmd(void *cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[])
{
    NostrState *st = (NostrState *)cd;
    secp256k1_keypair kp;
    secp256k1_xonly_pubkey xpk;
    unsigned char sec32[32], pk32[32];
    Tcl_Obj *keyObj;
    int asHex = 0;
    char out[128];

    if (objc == 3 && strcmp(Tcl_GetString(objv[1]), "-hex") == 0) {
	asHex = 1;
	keyObj = objv[2];
    } else if (objc == 2) {
	keyObj = objv[1];
    } else {
	Tcl_WrongNumArgs(interp, 1, objv, "?-hex? seckey");
	return TCL_ERROR;
    }
    if (GetSecKey(interp, keyObj, sec32) != TCL_OK) {
	return TCL_ERROR;
    }
    if (!secp256k1_keypair_create(st->ctx, &kp, sec32)) {
	memset(sec32, 0, sizeof(sec32));
	Tcl_SetObjResult(interp, Tcl_NewStringObj("invalid secret key", -1));
	return TCL_ERROR;
    }
    memset(sec32, 0, sizeof(sec32));
    secp256k1_keypair_xonly_pub(st->ctx, &xpk, NULL, &kp);
    memset(&kp, 0, sizeof(kp));
    secp256k1_xonly_pubkey_serialize(st->ctx, pk32, &xpk);
    if (asHex) {
	HexEncode(pk32, 32, out);
    } else {
	Bech32Encode32("npub", pk32, out);
    }
    Tcl_SetObjResult(interp, Tcl_NewStringObj(out, -1));
    return TCL_OK;
}

static int
EncodeObjCmd(void *cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[])
{
    unsigned char b32[32];
    Tcl_Size len;
    const char *type, *hex;
    char out[128];
    (void)cd;

    if (objc != 3) {
	Tcl_WrongNumArgs(interp, 1, objv, "npub|nsec|note hex");
	return TCL_ERROR;
    }
    type = Tcl_GetString(objv[1]);
    if (strcmp(type, "npub") != 0 && strcmp(type, "nsec") != 0
	    && strcmp(type, "note") != 0) {
	Tcl_SetObjResult(interp, Tcl_ObjPrintf(
	    "bad type \"%s\": must be npub, nsec or note", type));
	return TCL_ERROR;
    }
    hex = Tcl_GetStringFromObj(objv[2], &len);
    if (len != 64 || !HexDecode(hex, 64, b32, 0)) {
	Tcl_SetObjResult(interp,
	    Tcl_NewStringObj("expected 64 hex digits", -1));
	return TCL_ERROR;
    }
    Bech32Encode32(type, b32, out);
    memset(b32, 0, sizeof(b32));
    Tcl_SetObjResult(interp, Tcl_NewStringObj(out, -1));
    memset(out, 0, sizeof(out));
    return TCL_OK;
}

static int
DecodeObjCmd(void *cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[])
{
    unsigned char b32[32];
    char hrp[8], hex[65];
    Tcl_Obj *dict;
    (void)cd;

    if (objc != 2) {
	Tcl_WrongNumArgs(interp, 1, objv, "bech32String");
	return TCL_ERROR;
    }
    if (!Bech32Decode32(Tcl_GetString(objv[1]), hrp, b32)
	    || (strcmp(hrp, "npub") != 0 && strcmp(hrp, "nsec") != 0
		&& strcmp(hrp, "note") != 0)) {
	Tcl_SetObjResult(interp, Tcl_NewStringObj(
	    "expected a bech32 npub/nsec/note string", -1));
	return TCL_ERROR;
    }
    HexEncode(b32, 32, hex);
    memset(b32, 0, sizeof(b32));
    dict = Tcl_NewDictObj();
    Tcl_DictObjPut(NULL, dict, Tcl_NewStringObj("type", -1),
	Tcl_NewStringObj(hrp, -1));
    Tcl_DictObjPut(NULL, dict, Tcl_NewStringObj("hex", -1),
	Tcl_NewStringObj(hex, 64));
    memset(hex, 0, sizeof(hex));
    Tcl_SetObjResult(interp, dict);
    return TCL_OK;
}

/* ----------------------------------------------------------------- init -- */

static void
NostrDeleteState(void *cd, Tcl_Interp *interp)
{
    NostrState *st = (NostrState *)cd;
    (void)interp;
    if (st->ctx) secp256k1_context_destroy(st->ctx);
    if (st->utf8) Tcl_FreeEncoding(st->utf8);
    ckfree(st);
}

DLLEXPORT int
Nostr_Init(Tcl_Interp *interp)
{
    NostrState *st;
    unsigned char seed[32];

    if (Tcl_InitStubs(interp, "9.0", 0) == NULL) {
	return TCL_ERROR;
    }
    st = (NostrState *)ckalloc(sizeof(NostrState));
    memset(st, 0, sizeof(*st));
    st->utf8 = Tcl_GetEncoding(interp, "utf-8");
    if (st->utf8 == NULL) {
	ckfree(st);
	return TCL_ERROR;
    }
    st->ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    if (st->ctx == NULL || !nostr_fill_random(seed, 32)
	    || !secp256k1_context_randomize(st->ctx, seed)) {
	Tcl_SetObjResult(interp, Tcl_NewStringObj(
	    "cannot initialize randomized secp256k1 context", -1));
	NostrDeleteState(st, interp);
	return TCL_ERROR;
    }
    memset(seed, 0, sizeof(seed));
    Tcl_SetAssocData(interp, "tclnostr", NostrDeleteState, st);

    if (Tcl_EvalEx(interp, "namespace eval ::nostr {}", -1, 0) != TCL_OK) {
	return TCL_ERROR;
    }
    Tcl_CreateObjCommand(interp, "::nostr::sign", SignObjCmd, st, NULL);
    Tcl_CreateObjCommand(interp, "::nostr::verify", VerifyObjCmd, st, NULL);
    Tcl_CreateObjCommand(interp, "::nostr::id", IdObjCmd, st, NULL);
    Tcl_CreateObjCommand(interp, "::nostr::keygen", KeygenObjCmd, st, NULL);
    Tcl_CreateObjCommand(interp, "::nostr::pubkey", PubkeyObjCmd, st, NULL);
    Tcl_CreateObjCommand(interp, "::nostr::encode", EncodeObjCmd, st, NULL);
    Tcl_CreateObjCommand(interp, "::nostr::decode", DecodeObjCmd, st, NULL);

    return Tcl_PkgProvide(interp, "nostr", NOSTR_VERSION);
}
