# tclnostr test suite.  Run:  make test   (or tclsh9.0 tests/all.tcl)
# Set NAK=/path/to/nak to enable the live cross-checks against nak.

package require tcltest 2.5
namespace import tcltest::*

set root [file dirname [file dirname [file normalize [info script]]]]
load [file join $root libnostr[info sharedlibextension]] Nostr

# Reference key: BIP-340 test vector 0 (secret key 3).
set SEC 0000000000000000000000000000000000000000000000000000000000000003
set PK  f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9

# Golden signed event: produced by nak with --sec $SEC --ts 1700000000.
set GOLDEN {{"kind":1,"id":"693fe0c19b0498f428adfe65182bfe135d34dd9efc39905887d5c5efa528d044","pubkey":"f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9","created_at":1700000000,"tags":[],"content":"hello tclnostr","sig":"30a6bcca9a2f1342d47a9949317e22a0c34e01fd94d38b7bc34d93030e7839412592ff31cb1980e092ff7162e3f6d80a8d0ee25e586893fa99c8d33ee88b892b"}}
set GOLDENID 693fe0c19b0498f428adfe65182bfe135d34dd9efc39905887d5c5efa528d044

proc evfield {ev name} {
    if {![regexp "\"$name\":\"(\[0-9a-f\]+)\"" $ev -> v]} {
	error "no $name in $ev"
    }
    return $v
}

set nak ""
if {[info exists env(NAK)] && $env(NAK) ne ""} {
    set nak $env(NAK)
} else {
    set nak [lindex [auto_execok nak] 0]
}
testConstraint nak [expr {$nak ne ""}]

# ------------------------------------------------------------- NIP-19 ----

test nip19-npub-decode {spec vector} {
    nostr::decode npub10elfcs4fr0l0r8af98jlmgdh9c8tcxjvz9qkw038js35mp4dma8qzvjptg
} {type npub hex 7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e}

test nip19-nsec-decode {spec vector} {
    nostr::decode nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5
} {type nsec hex 67dea2ed018072d675f5415ecfaed7d2597555e202d85b3d65ea4e58d2d92ffa}

test nip19-npub-encode {spec vector} {
    nostr::encode npub 7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e
} npub10elfcs4fr0l0r8af98jlmgdh9c8tcxjvz9qkw038js35mp4dma8qzvjptg

test nip19-nsec-encode {spec vector} {
    nostr::encode nsec 67dea2ed018072d675f5415ecfaed7d2597555e202d85b3d65ea4e58d2d92ffa
} nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5

test nip19-case-insensitive-hex {encode accepts uppercase hex} {
    nostr::encode npub 7E7E9C42A91BFEF19FA929E5FDA1B72E0EBC1A4C1141673E2794234D86ADDF4E
} npub10elfcs4fr0l0r8af98jlmgdh9c8tcxjvz9qkw038js35mp4dma8qzvjptg

test nip19-reject-bech32m {checksum variant matters} {
    catch {nostr::decode npub10elfcs4fr0l0r8af98jlmgdh9c8tcxjvz9qkw038js35mp4dma8qzvjptq} msg
    set msg
} {expected a bech32 npub/nsec/note string}

# --------------------------------------------------------------- keys ----

test pubkey-hex {BIP-340 vector 0} {
    nostr::pubkey -hex $SEC
} $PK

test pubkey-npub-roundtrip {} {
    nostr::decode [nostr::pubkey $SEC]
} [list type npub hex $PK]

test pubkey-from-nsec {} {
    nostr::pubkey -hex [nostr::encode nsec $SEC]
} $PK

test keygen-shape {} {
    set k [nostr::keygen]
    list [string range $k 0 4] [string length $k] \
	[dict get [nostr::decode $k] type]
} {nsec1 63 nsec}

test seckey-bad {} {
    catch {nostr::pubkey zzz} msg
    set msg
} {secret key must be nsec1... or 64 hex digits}

# ----------------------------------------------------------- id, sign ----

test id-golden {canonical id matches nak} {
    nostr::id -pubkey $PK -kind 1 -content "hello tclnostr" -created-at 1700000000
} $GOLDENID

test sign-golden-id {builder path} {
    evfield [nostr::sign -sec $SEC -kind 1 -content "hello tclnostr" \
	-created-at 1700000000] id
} $GOLDENID

test sign-json-golden-id {normalize&sign path} {
    evfield [nostr::sign -sec $SEC -json \
	{{"kind":1,"content":"hello tclnostr","created_at":1700000000}}] id
} $GOLDENID

test sign-verify-roundtrip {} {
    nostr::verify [nostr::sign -sec $SEC -kind 1 -content "hi" \
	-created-at 1700000000]
} 1

test sign-defaults {kind 1, empty content, now} {
    set ev [nostr::sign -sec $SEC]
    list [regexp {"kind":1,} $ev] [regexp {"content":"",} $ev] \
	[nostr::verify $ev]
} {1 1 1}

test sign-nsec-input {} {
    evfield [nostr::sign -sec [nostr::encode nsec $SEC] -kind 1 \
	-content "hello tclnostr" -created-at 1700000000] id
} $GOLDENID

test sign-tags-builder-vs-json {} {
    set a [nostr::sign -sec $SEC -kind 27235 -created-at 1700000000 \
	-tags {{u https://api.example/api/v1/vm} {method GET}}]
    set b [nostr::sign -sec $SEC -json {{"kind":27235,"created_at":1700000000,"tags":[["u","https://api.example/api/v1/vm"],["method","GET"]]}}]
    list [expr {[evfield $a id] eq [evfield $b id]}] [nostr::verify $a]
} {1 1}

test resign-own-output {full event JSON re-signs to same id} {
    set ev [nostr::sign -sec $SEC -kind 1 -content "loop" -created-at 1700000000]
    expr {[evfield [nostr::sign -sec $SEC -json $ev] id] eq [evfield $ev id]}
} 1

test sign-pubkey-mismatch {} {
    catch {nostr::sign -sec $SEC -json \
	{{"kind":1,"pubkey":"7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e"}}} msg
    set msg
} {event pubkey does not match the signing key}

# ------------------------------------------------------------- verify ----

test verify-golden {nak-signed event verifies} {
    nostr::verify $GOLDEN
} 1

test verify-tampered-content {} {
    nostr::verify [string map {"hello tclnostr" "hello tclnostr!"} $GOLDEN]
} 0

test verify-tampered-sig {sig prefix flipped; id still matches} {
    nostr::verify [string map {30a6bcca 40a6bcca} $GOLDEN]
} 0

test verify-incomplete {} {
    catch {nostr::verify {{"kind":1,"content":"x"}}} msg
    set msg
} {incomplete event: id, pubkey, created_at, kind, tags, content and sig are all required}

# ---------------------------------------------------- escaping, unicode ----

test escape-roundtrip {7 escaped chars + unicode survive sign/verify} {
    set c "a\"b\\c\nd\te\rf\bg\ffтест😀"
    set ev [nostr::sign -sec $SEC -kind 1 -content $c -created-at 1700000000]
    nostr::verify $ev
} 1

test escape-u-equivalence {A is A} {
    expr {[evfield [nostr::sign -sec $SEC -json \
	    {{"kind":1,"content":"A","created_at":1700000000}}] id]
	eq [evfield [nostr::sign -sec $SEC -kind 1 -content A \
	    -created-at 1700000000] id]}
} 1

test escape-surrogate-pair {😀 is the emoji} {
    expr {[evfield [nostr::sign -sec $SEC -json \
	    {{"kind":1,"content":"😀","created_at":1700000000}}] id]
	eq [evfield [nostr::sign -sec $SEC -kind 1 -content 😀 \
	    -created-at 1700000000] id]}
} 1

test escape-json-newline {json \n equals builder newline} {
    expr {[evfield [nostr::sign -sec $SEC -json \
	    {{"kind":1,"content":"a\nb","created_at":1700000000}}] id]
	eq [evfield [nostr::sign -sec $SEC -kind 1 -content "a\nb" \
	    -created-at 1700000000] id]}
} 1

# ------------------------------------------------------- parser errors ----

test parse-unknown-field {} {
    catch {nostr::sign -sec $SEC -json {{"kind":1,"foo":2}}} msg
    set msg
} {invalid event JSON: unknown field "foo"}

test parse-duplicate-field {} {
    catch {nostr::sign -sec $SEC -json {{"kind":1,"kind":2}}} msg
    set msg
} {invalid event JSON: duplicate field}

test parse-trailing-data {} {
    catch {nostr::sign -sec $SEC -json {{"kind":1} x}} msg
    set msg
} {invalid event JSON: trailing data after event}

test parse-kind-range {} {
    catch {nostr::sign -sec $SEC -json {{"kind":65536}}} msg
    set msg
} {invalid event JSON: kind out of range}

test parse-lone-surrogate {} {
    catch {nostr::sign -sec $SEC -json {{"kind":1,"content":"\ud800"}}} msg
    set msg
} {invalid event JSON: lone high surrogate}

test parse-raw-control {} {
    catch {nostr::verify "{\"kind\":1,\"content\":\"a\x01b\"}"} msg
    set msg
} {invalid event JSON: raw control character in string}

test parse-float-created {} {
    catch {nostr::sign -sec $SEC -json {{"kind":1,"created_at":17.5}}} msg
    set msg
} {invalid event JSON: expected integer}

test builder-kind-range {} {
    catch {nostr::sign -sec $SEC -kind 65536} msg
    set msg
} {kind out of range}

test json-excludes-builder {} {
    catch {nostr::sign -sec $SEC -json {{"kind":1}} -content x} msg
    set msg
} {-json cannot be combined with -kind/-content/-tags/-created-at}

# ------------------------------------------------------ nak cross-check ----

test nak-id-parity {same canonical id for tags + unicode content} nak {
    set ts 1700000000
    set c "спам\"и\\мясо\nномер два 😀"
    set out [exec $nak -q event --sec $SEC -k 30023 -c $c --ts $ts \
	-t d=check -t "sometag=one;two" 2> /dev/null]
    set mine [nostr::sign -sec $SEC -kind 30023 -content $c -created-at $ts \
	-tags {{d check} {sometag one two}}]
    expr {[evfield $out id] eq [evfield $mine id]}
} 1

test nak-verifies-ours {exit 0 = valid} nak {
    set ev [nostr::sign -sec $SEC -kind 1 -content "verify me" \
	-created-at 1700000000]
    catch {exec $nak -q verify << $ev 2> /dev/null}
} 0

test nak-rejects-tampered {sanity of the check above} nak {
    set ev [string map {30a6bcca 40a6bcca} $GOLDEN]
    catch {exec $nak -q verify << $ev 2> /dev/null}
} 1

test we-verify-naks {fresh nak event with tags} nak {
    nostr::verify [exec $nak -q event --sec $SEC -k 27235 -c "" \
	-t u=https://api.example/x -t method=GET 2> /dev/null]
} 1

cleanupTests
