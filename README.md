# tclnostr

Nostr signer/verifier for Tcl 9: a C extension (package `nostr`) that
covers the frozen, fiddly parts of the protocol in C — canonical
[NIP-01](https://github.com/nostr-protocol/nips/blob/master/01.md)
event serialization, BIP-340 Schnorr signatures via
[libsecp256k1](https://github.com/bitcoin-core/secp256k1),
[NIP-19](https://github.com/nostr-protocol/nips/blob/master/19.md)
npub/nsec bech32 keys, and a strict parser for the fixed event-JSON
schema. General-purpose JSON handling stays in script land, where it
belongs.

The primary use case is signing [NIP-98](https://github.com/nostr-protocol/nips/blob/master/98.md)
HTTP auth events from Tcl without shelling out to external tools, but
the surface is generic NIP-01.

## API

```tcl
package require nostr

# build an event from fields and sign it -> complete event JSON
nostr::sign -sec $key -kind 27235 -content "" \
    -tags {{u https://api.example/api/v1/vm} {method GET}}

# or: normalize-and-sign an (unsigned, possibly partial) event JSON;
# missing created_at/kind/tags/content are defaulted, id/pubkey/sig
# recomputed (a present pubkey must match the signing key)
nostr::sign -sec $key -json {{"kind":1,"content":"hello"}}

nostr::verify $eventJson       ;# 1/0: id recomputed + BIP-340 verified
nostr::id -pubkey $pk ?...?    ;# canonical event id without signing

nostr::keygen                  ;# fresh key -> nsec1...
nostr::pubkey ?-hex? $key      ;# npub (or hex) for a secret key
nostr::encode npub|nsec|note $hex
nostr::decode $bech32          ;# -> dict: type npub|nsec|note, hex ...
```

Keys are accepted as `nsec1...`/`npub1...` or 64 hex digits. Defaults
mirror nak: kind 1, empty content, empty tags, `created_at` = now.
`-json` input is strict: unknown or duplicate event fields, floats,
lone surrogates, invalid UTF-8 and raw control characters are errors —
an unknown field would not enter the id, i.e. it would ride along
unsigned. Structural problems raise Tcl errors; a well-formed event
that merely fails the crypto makes `verify` return 0.

## Building

```sh
git clone --recurse-submodules <this repo>   # libsecp256k1 is a submodule
./configure                    # or: --with-tcl=/path/to/lib (tclConfig.sh)
make                           # -> libnostr.a + libnostr.so
make test                      # tcltest suite; NAK=/path/to/nak adds
                               # live cross-checks against nak
```

Cross for win64 (static lib only):

```sh
./configure --host=x86_64-w64-mingw32 --with-tcl=/path/to/win64/lib
make libnostr.a
```

`configure` is a small hand-rolled shell script, not autotools — it
accepts (and mostly ignores) the TEA-style flags a driver like
whalebuild passes, sources `tclConfig.sh` and writes `config.mk`.
libsecp256k1 is deliberately built **without its build system**: the
library is effectively one translation unit plus two precomputed-table
files, compiled straight from the submodule with
`-DENABLE_MODULE_SCHNORRSIG -DENABLE_MODULE_EXTRAKEYS` (that is how
rust-secp256k1 vendors it too; on Windows consumers additionally need
`-DSECP256K1_STATIC`, which configure sets for mingw hosts).

For static embedding (tclkit-style builds): link `libnostr.a` and
register `Nostr_Init` via `Tcl_StaticLibrary`; the package needs no
script files.

## Vendored code

- `deps/secp256k1` — git submodule, pinned to a release tag (MIT).
- `vendor/bech32.[ch]` — bech32 codec from the reference
  implementation, github.com/sipa/bech32 (MIT), segwit layer dropped.
- `vendor/sha256.[ch]` — Brad Conte's public-domain SHA-256
  (github.com/B-Con/crypto-algorithms).

Everything else is public domain, see UNLICENSE.

## Notes

- The NIP-01 hash serialization escapes exactly seven characters
  (`\n \" \\ \r \t \b \f`); every other byte, including other control
  bytes and raw UTF-8, passes through verbatim. The *emitted* event
  JSON is valid JSON (remaining control bytes as `\u00XX`) — the two
  formats parse back to the same strings.
- One randomized `secp256k1_context` per interp; signing uses fresh
  `aux_rand` from the OS CSPRNG (getrandom / BCryptGenRandom /
  /dev/urandom), so signatures are not deterministic — ids are.
- Tcl 9 only (stubs-enabled, `Tcl_Size`).
