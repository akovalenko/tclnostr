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

# ------------------------------------------------------ NIP-44 vectors ----

source [file join [file dirname [info script]] nip44-vectors.tcl]

proc unhex {h} {
    encoding convertfrom utf-8 [binary decode hex $h]
}

testConstraint sha256sum [expr {[auto_execok sha256sum] ne ""}]
proc sha256bytes {bytes} {
    set path [file join [tcltest::temporaryDirectory] nip44-long.bin]
    set f [open $path wb]
    puts -nonewline $f $bytes
    close $f
    set h [lindex [exec sha256sum $path] 0]
    file delete $path
    return $h
}

# Second key for two-party tests: BIP-340 vector secret key 5.
set SEC2 0000000000000000000000000000000000000000000000000000000000000005
set PK2 [nostr::pubkey -hex $SEC2]

test nip44-vectors-convkey {official conversation-key vectors} {
    set bad {}
    foreach v $NIP44_CONVKEY_VALID {
	lassign $v sec1 pub2 ck
	if {[nostr::nip44 convkey -sec $sec1 -pub $pub2] ne $ck} {
	    lappend bad $ck
	}
    }
    set bad
} {}

test nip44-vectors-padded-len {payload length reflects calc_padded_len} {
    set ck [lindex [lindex $NIP44_ENCDEC 0] 2]
    set nonce [lindex [lindex $NIP44_ENCDEC 0] 3]
    set bad {}
    foreach v $NIP44_PADDED {
	lassign $v len padded
	if {$len > 65535} continue	;# beyond encryptable range (pure calc)
	# base64 of version(1) + nonce(32) + lenprefix(2) + padded + mac(32)
	set want [expr {(((1 + 32 + 2 + $padded + 32) + 2) / 3) * 4}]
	set p [nostr::nip44 encrypt -convkey $ck -nonce $nonce \
	    [string repeat a $len]]
	if {[string length $p] != $want} {
	    lappend bad "$len:[string length $p]:$want"
	}
    }
    set bad
} {}

test nip44-vectors-encrypt-decrypt {official payload vectors} {
    set bad {}
    foreach v $NIP44_ENCDEC {
	lassign $v sec1 sec2 ck nonce pthex payload
	set pt [unhex $pthex]
	if {[nostr::nip44 convkey -sec $sec1 \
		-pub [nostr::pubkey -hex $sec2]] ne $ck} {
	    lappend bad "ck:$nonce"
	    continue
	}
	if {[nostr::nip44 encrypt -convkey $ck -nonce $nonce $pt] \
		ne $payload} {
	    lappend bad "enc:$nonce"
	}
	if {[nostr::nip44 decrypt -sec $sec2 \
		-pub [nostr::pubkey -hex $sec1] $payload] ne $pt} {
	    lappend bad "dec:$nonce"
	}
    }
    set bad
} {}

test nip44-vectors-long-messages {long-message vectors, hashes only} sha256sum {
    set bad {}
    foreach v $NIP44_LONG {
	lassign $v ck nonce pathex repeat ptsha paysha
	set pt [string repeat [unhex $pathex] $repeat]
	if {[sha256bytes [encoding convertto utf-8 $pt]] ne $ptsha} {
	    lappend bad "pt:$nonce"
	    continue
	}
	set p [nostr::nip44 encrypt -convkey $ck -nonce $nonce $pt]
	if {[sha256bytes $p] ne $paysha} {
	    lappend bad "pay:$nonce"
	}
	if {[nostr::nip44 decrypt -convkey $ck $p] ne $pt} {
	    lappend bad "dec:$nonce"
	}
    }
    set bad
} {}

test nip44-vectors-invalid-lengths {encrypt rejects out-of-range sizes} {
    set ck [lindex [lindex $NIP44_ENCDEC 0] 2]
    set bad {}
    foreach len $NIP44_INVALID_LEN {
	if {![catch {nostr::nip44 encrypt -convkey $ck \
		[string repeat a $len]}]} {
	    lappend bad $len
	}
    }
    set bad
} {}

test nip44-vectors-invalid-convkey {bad keys are rejected} {
    set bad {}
    foreach v $NIP44_INVALID_CONVKEY {
	lassign $v sec1 pub2 notehex
	if {![catch {nostr::nip44 convkey -sec $sec1 -pub $pub2}]} {
	    lappend bad [unhex $notehex]
	}
    }
    set bad
} {}

test nip44-vectors-invalid-decrypt {bad payloads are rejected} {
    set bad {}
    foreach v $NIP44_INVALID_DECRYPT {
	lassign $v ck payload notehex
	if {![catch {nostr::nip44 decrypt -convkey $ck $payload}]} {
	    lappend bad [unhex $notehex]
	}
    }
    set bad
} {}

# -------------------------------------------------------- nip44 command ----

test nip44-convkey-symmetric {ECDH is symmetric} {
    expr {[nostr::nip44 convkey -sec $SEC -pub $PK2]
	eq [nostr::nip44 convkey -sec $SEC2 -pub $PK]}
} 1

test nip44-roundtrip-unicode {} {
    set pt "привет, nip44 🎁"
    nostr::nip44 decrypt -sec $SEC2 -pub $PK \
	[nostr::nip44 encrypt -sec $SEC -pub $PK2 $pt]
} "привет, nip44 🎁"

test nip44-convkey-equals-secpub {cached convkey is the same path} {
    set ck [nostr::nip44 convkey -sec $SEC -pub $PK2]
    set p [nostr::nip44 encrypt -convkey $ck "hello"]
    nostr::nip44 decrypt -sec $SEC2 -pub $PK $p
} hello

test nip44-wrong-key-fails {} {
    set p [nostr::nip44 encrypt -sec $SEC -pub $PK2 "hello"]
    catch {nostr::nip44 decrypt -sec $SEC -pub $PK2 \
	[string map {A B B A} $p]}
} 1

# --------------------------------------------------------- rumor, wrap ----

test event-unsigned {id matches nostr::id, no sig member} {
    set r [nostr::event -pubkey $PK -kind 14 -content "hi" \
	-created-at 1700000000]
    list [expr {[evfield $r id] eq [nostr::id -pubkey $PK -kind 14 \
	-content "hi" -created-at 1700000000]}] [regexp {"sig"} $r] \
	[expr {[nostr::sign -sec $SEC -json $r] ne ""}]
} {1 0 1}

test event-rejects-signed {} {
    catch {nostr::event -json [nostr::sign -sec $SEC -kind 1]} msg
    set msg
} {event already has a sig: a rumor must be unsigned}

test wrap-unwrap-roundtrip {} {
    set rumor [nostr::event -pubkey $PK -kind 14 -content "секрет" \
	-tags [list [list p $PK2]]]
    set wrap [nostr::wrap -sec $SEC -to $PK2 $rumor]
    set got [nostr::unwrap -sec $SEC2 $wrap]
    list [expr {[dict get $got from] eq $PK}] \
	[expr {[dict get $got rumor] eq $rumor}] \
	[regexp {"kind":1059,} $wrap]
} {1 1 1}

test wrap-self-copy {sender's own wrapped copy} {
    set rumor [nostr::event -pubkey $PK -kind 14 -content "self"]
    expr {[dict get [nostr::unwrap -sec $SEC \
	[nostr::wrap -sec $SEC -to $PK $rumor]] rumor] eq $rumor}
} 1

test wrap-backdated {NIP-59 timestamps land in the two-day window} {
    set rumor [nostr::event -pubkey $PK -kind 14 -content "t"]
    set wrap [nostr::wrap -sec $SEC -to $PK2 $rumor]
    regexp {"created_at":(\d+)} $wrap -> ts
    set now [clock seconds]
    expr {$ts <= $now + 5 && $ts >= $now - 172811}
} 1

test wrap-rejects-signed-rumor {} {
    catch {nostr::wrap -sec $SEC -to $PK2 [nostr::sign -sec $SEC -kind 14]} msg
    set msg
} {rumor must be unsigned (it has a sig)}

test wrap-rejects-foreign-rumor {} {
    set rumor [nostr::event -pubkey $PK2 -kind 14 -content "x"]
    catch {nostr::wrap -sec $SEC -to $PK2 $rumor} msg
    set msg
} {rumor pubkey does not match the signing key}

test unwrap-wrong-recipient {} {
    set rumor [nostr::event -pubkey $PK -kind 14 -content "x"]
    set wrap [nostr::wrap -sec $SEC -to $PK2 $rumor]
    catch {nostr::unwrap -sec $SEC \
	    0000000000000000000000000000000000000000000000000000000000000007 \
	    $wrap}
} 1

test unwrap-tampered-wrap {} {
    set rumor [nostr::event -pubkey $PK -kind 14 -content "x"]
    set wrap [nostr::wrap -sec $SEC -to $PK2 $rumor]
    catch {nostr::unwrap -sec $SEC2 \
	[string map {{"kind":1059,} {"kind":1058,}} $wrap]} msg
    set msg
} {gift wrap does not verify}

test unwrap-impersonation {seal author != rumor pubkey is rejected} {
    # attacker (key 7) seals a rumor that claims to be from $PK
    set attacker 0000000000000000000000000000000000000000000000000000000000000007
    set rumor [nostr::event -pubkey $PK -kind 14 -content "fake"]
    set seal [nostr::sign -sec $attacker -kind 13 \
	-content [nostr::nip44 encrypt -sec $attacker -pub $PK2 $rumor]]
    set eph [nostr::keygen]
    set wrap [nostr::sign -sec $eph -kind 1059 -tags [list [list p $PK2]] \
	-content [nostr::nip44 encrypt -sec $eph -pub $PK2 $seal]]
    catch {nostr::unwrap -sec $SEC2 $wrap} msg
    set msg
} {rumor pubkey does not match the seal}

test unwrap-signed-rumor-rejected {} {
    set signed [nostr::sign -sec $SEC -kind 14 -content "signed!"]
    set seal [nostr::sign -sec $SEC -kind 13 \
	-content [nostr::nip44 encrypt -sec $SEC -pub $PK2 $signed]]
    set eph [nostr::keygen]
    set wrap [nostr::sign -sec $eph -kind 1059 -tags [list [list p $PK2]] \
	-content [nostr::nip44 encrypt -sec $eph -pub $PK2 $seal]]
    catch {nostr::unwrap -sec $SEC2 $wrap} msg
    set msg
} {rumor is signed (must be unsigned)}

# -------------------------------------------------------- relay frames ----

test frame-ok {} {
    nostr::frame {["OK","abcd",true,"duplicate: already have it"]}
} {OK abcd 1 {duplicate: already have it}}

test frame-eose-notice {} {
    list [nostr::frame {["EOSE","sub1"]}] \
	[nostr::frame {["NOTICE","slow down"]}] \
	[nostr::frame {["X",null,false,-3.5e2]}]
} {{EOSE sub1} {NOTICE {slow down}} {X {} 0 -3.5e2}}

test frame-event-raw-slice {sliced event JSON still verifies} {
    set ev [nostr::sign -sec $SEC -kind 1 -content "via frame" \
	-created-at 1700000000]
    set f [nostr::frame "\[\"EVENT\",\"s1\",$ev\]"]
    list [lindex $f 0] [lindex $f 1] [expr {[lindex $f 2] eq $ev}] \
	[nostr::verify [lindex $f 2]]
} {EVENT s1 1 1}

test frame-nested-structures {brackets/braces inside strings don't confuse} {
    nostr::frame {["REQ","s",{"a":["[","]"],"b":{"c":2}}]}
} {REQ s {{"a":["[","]"],"b":{"c":2}}}}

test frame-not-array {} {
    catch {nostr::frame {{"kind":1}}} msg
    set msg
} {invalid frame JSON: a relay frame is a JSON array}

test frame-trailing-data {} {
    catch {nostr::frame {["EOSE","s"] x}} msg
    set msg
} {invalid frame JSON: trailing data after frame}

# ------------------------------------------------ nak nip44 cross-check ----

test nak-decrypts-ours {} nak {
    exec $nak decrypt --sec $SEC2 -p $PK \
	[nostr::nip44 encrypt -sec $SEC -pub $PK2 "спам и мясо ⚡"] \
	2> /dev/null
} "спам и мясо ⚡"

test nak-we-decrypt {} nak {
    set p [exec $nak encrypt --sec $SEC -p $PK2 "обратно ⚡" 2> /dev/null]
    nostr::nip44 decrypt -sec $SEC2 -pub $PK $p
} "обратно ⚡"

cleanupTests
