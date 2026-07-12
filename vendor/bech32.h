/* Copyright (c) 2017, 2021 Pieter Wuille
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

/* Bech32 codec extracted from the reference implementation
 * (github.com/sipa/bech32, ref/c/segwit_addr.[ch]); the segwit address
 * layer is dropped, convert_bits is exported. NIP-19 uses plain bech32
 * (BIP-173), not bech32m. */

#ifndef BECH32_H
#define BECH32_H 1

#include <stdint.h>
#include <stdlib.h>

typedef enum {
    BECH32_ENCODING_NONE,
    BECH32_ENCODING_BECH32,
    BECH32_ENCODING_BECH32M
} bech32_encoding;

/** Encode a Bech32 or Bech32m string
 *
 *  Out: output:   Pointer to a buffer of size strlen(hrp) + data_len + 8 that
 *                 will be updated to contain the null-terminated Bech32 string.
 *  In: hrp :      Pointer to the null-terminated human readable part.
 *      data :     Pointer to an array of 5-bit values.
 *      data_len:  Length of the data array.
 *      enc:       Which encoding to use (BECH32_ENCODING_BECH32{,M}).
 *  Returns 1 if successful.
 */
int bech32_encode(
    char *output,
    const char *hrp,
    const uint8_t *data,
    size_t data_len,
    bech32_encoding enc
);

/** Decode a Bech32 or Bech32m string
 *
 *  Out: hrp :     Pointer to a buffer of size strlen(input) - 6. Will be
 *                 updated to contain the null-terminated human readable part.
 *       data:     Pointer to a buffer of size strlen(input) - 8 that will
 *                 hold the encoded 5-bit data values.
 *       data_len: Pointer to a size_t that will be updated to be the number
 *                 of entries in data.
 *  In: input:     Pointer to a null-terminated Bech32 string.
 *  Returns BECH32_ENCODING_BECH32{,M} to indicate decoding was successful
 *  with the specified encoding standard. BECH32_ENCODING_NONE is returned if
 *  decoding failed.
 */
bech32_encoding bech32_decode(
    char *hrp,
    uint8_t *data,
    size_t *data_len,
    const char *input
);

/** Repack a byte sequence between bit widths (e.g. 8 <-> 5 for bech32).
 *  Returns 1 if successful.
 */
int bech32_convert_bits(
    uint8_t *out,
    size_t *outlen,
    int outbits,
    const uint8_t *in,
    size_t inlen,
    int inbits,
    int pad
);

#endif /* BECH32_H */
