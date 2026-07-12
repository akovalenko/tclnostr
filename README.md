# tclnostr

Nostr signer/verifier for Tcl 9: a C extension (package `nostr`) that
covers the frozen, fiddly parts of the protocol in C — canonical
[NIP-01](https://github.com/nostr-protocol/nips/blob/master/01.md)
event serialization, BIP-340 Schnorr signatures via
[libsecp256k1](https://github.com/bitcoin-core/secp256k1),
[NIP-19](https://github.com/nostr-protocol/nips/blob/master/19.md)
npub/nsec bech32 keys, a strict parser for the fixed event-JSON schema,
[NIP-44](https://github.com/nostr-protocol/nips/blob/master/44.md) v2
payload encryption with [NIP-59](https://github.com/nostr-protocol/nips/blob/master/59.md)
gift wrap (the crypto for [NIP-17](https://github.com/nostr-protocol/nips/blob/master/17.md)
private messages), and a splitter for relay frames. General-purpose
JSON handling stays in script land, where it belongs.

The original use case is signing [NIP-98](https://github.com/nostr-protocol/nips/blob/master/98.md)
HTTP auth events from Tcl without shelling out to external tools; with
the NIP-44/59 layer the same package also sends and receives encrypted
direct messages over a WebSocket relay connection driven from script.

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

### Encrypted direct messages (NIP-44 / NIP-17)

```tcl
# NIP-44 v2 payload encryption (ChaCha20 + HMAC over an ECDH key)
nostr::nip44 convkey -sec $key -pub $peer      ;# -> 32-byte hex conv key
nostr::nip44 encrypt -sec $key -pub $peer $text        ;# -> base64 payload
nostr::nip44 decrypt -sec $key -pub $peer $payload     ;# -> plaintext
# a cached -convkey may stand in for -sec/-pub on any of the three

# NIP-59 gift wrap: build an unsigned rumor, wrap it for a recipient,
# and open one you received (the chain — wrap sig, seal sig, and
# seal-author == rumor-author — is verified inside unwrap)
set rumor [nostr::event -pubkey $mypub -kind 14 -content "hi" \
    -tags {{p <recipient-hex>}}]        ;# unsigned: id set, no sig
set wrap  [nostr::wrap -sec $key -to $peer $rumor]     ;# kind-1059 event
nostr::unwrap -sec $key $wrap           ;# -> dict: from <hex>, rumor <json>
```

`nostr::event` mirrors `nostr::sign`/`nostr::id` but emits an *unsigned*
event — a NIP-59 rumor. `nostr::wrap` seals the rumor (kind 13, signed
by the sender) inside a gift wrap (kind 1059, signed by a one-shot
ephemeral key), both timestamps randomized up to two days into the past
per NIP-59. `nostr::unwrap` reverses it and refuses a wrap whose sealed
author does not match the rumor author, so a valid wrap cannot
impersonate a third party.

### Relay frames

```tcl
nostr::frame $line   ;# split one relay message (a JSON array) to a list
```

Strings are decoded, `true`/`false`/`null` become `1`/`0`/`{}`, numbers
pass through as text, and nested objects/arrays are handed back as raw
JSON slices — so an `["EVENT",$sub,{…}]` frame yields the exact event
bytes to feed straight into `nostr::verify` or `nostr::unwrap`. The
outbound direction is trivial script-side: a signed event is already
canonical JSON, so an `EVENT`/`REQ` envelope is plain string assembly.

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

`chacha20`, `hmac_sha256` (with an HKDF-expand step) and `base64` are
small self-contained implementations from their RFCs (8439 / 2104 /
5869 / 4648), written for this package. The NIP-44 v2 layer follows the
spec pseudocode and is checked against the official
[paulmillr/nip44](https://github.com/paulmillr/nip44) vector suite (see
`tests/vectors2tcl.py`, which regenerates `tests/nip44-vectors.tcl`).
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
