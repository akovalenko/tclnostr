# End-to-end relay/DM test, driven against a loopback relay (nak serve).
# Not part of `make test`: it needs tcllib (websocket, json) and a
# running relay, so tests/run-relay-e2e.sh boots the relay and runs
# this under a tclsh that can see the freshly-built libnostr and the
# tcllib modules.  Env: RELAY_URL, LIBNOSTR, TCLLIB_MODULES.

if {[info exists env(TCLLIB_MODULES)]} {
    foreach d [split $env(TCLLIB_MODULES) :] { lappend auto_path $d }
}
load $env(LIBNOSTR) Nostr
source [file join [file dirname [info script]] .. relay.tcl]

set URL $env(RELAY_URL)
set fails 0
proc check {name got want} {
    global fails
    if {$got eq $want} {
	puts "ok   - $name"
    } else {
	puts "FAIL - $name\n       got:  $got\n       want: $want"
	incr fails
    }
}

# BIP-340 vector keys 3 (alice) and 5 (bob).
set ALICE 0000000000000000000000000000000000000000000000000000000000000003
set BOB   0000000000000000000000000000000000000000000000000000000000000005
set APUB [nostr::pubkey -hex $ALICE]
set BPUB [nostr::pubkey -hex $BOB]

# 1. publish a plain note and read it back through a subscription.
set note [nostr::sign -sec $ALICE -kind 1 -content "e2e note ⚡"]
set noteid [nostr::id -pubkey $APUB -kind 1 -content "e2e note ⚡" \
    -created-at [lindex [regexp -inline {"created_at":(\d+)} $note] 1]]
set c [nostr::relay::connect $URL]
lassign [nostr::relay::publish $c $note] accepted okmsg
check "publish accepted" $accepted 1
nostr::relay::subscribe $c s1 [dict create ids [list $noteid]]
set back [nostr::relay::collect $c]
check "subscription returns the note" [llength $back] 1
check "returned event verifies" [nostr::verify [lindex $back 0]] 1
# a relay may re-order JSON fields; the id (and signature) is the
# invariant, not the byte layout.
check "returned event has the same id" \
    [regexp -inline {"id":"([0-9a-f]{64})"} [lindex $back 0]] \
    [list "\"id\":\"$noteid\"" $noteid]
nostr::relay::close $c

# 2. NIP-17 DM: alice -> bob, bob fetches and unwraps.
set res [nostr::dm::send -sec $ALICE -to $BPUB -relays [list $URL] \
    "привет, боб 🎁"]
check "dm published to relay" \
    [lindex [dict get [dict get $res results] $URL] 0] 1

set got [nostr::dm::fetch -sec $BOB -relays [list $URL]]
check "bob receives exactly one dm" [llength $got] 1

# a tight -since must still find the wrap: NIP-59 backdates the wrap up
# to two days, and fetch widens the filter to compensate.
set sincegot [nostr::dm::fetch -sec $BOB -relays [list $URL] \
    -since [clock seconds]]
check "fetch -since still finds the backdated wrap" [llength $sincegot] 1
set m [lindex $got 0]
check "dm sender is alice" [dict get $m from] $APUB
set rumor [dict get $m rumor]
check "dm content decrypts" \
    [regexp {"content":"привет, боб 🎁"} $rumor] 1
check "dm rumor is kind 14" [regexp {"kind":14,} $rumor] 1
check "dm rumor is unsigned" [regexp {"sig"} $rumor] 0

# 3. self-copy: alice can read her own outbound thread.
set mine [nostr::dm::fetch -sec $ALICE -relays [list $URL]]
check "alice sees her self-copy" [llength $mine] 1
check "self-copy content matches" \
    [regexp {"content":"привет, боб 🎁"} [dict get [lindex $mine 0] rumor]] 1

# 4. a wrap addressed to bob is opaque to a third party (key 7).
set stranger 0000000000000000000000000000000000000000000000000000000000000007
set none [nostr::dm::fetch -sec $stranger -relays [list $URL]]
check "stranger reads nothing (wraps p-tagged elsewhere)" [llength $none] 0

# 5. NIP-42 AUTH: an auth-required relay challenges on connect; the
#    client auto-answers and publish/fetch succeed after the retry.
if {[info exists env(AUTH_URL)]} {
    set au $env(AUTH_URL)
    set res [nostr::dm::send -sec $ALICE -to $BPUB -relays [list $au] \
	-selfcopy 0 "через auth-релей 🔐"]
    check "auth-relay publish accepted after AUTH" \
	[lindex [dict get [dict get $res results] $au] 0] 1
    set got [nostr::dm::fetch -sec $BOB -relays [list $au]]
    check "auth-relay fetch returns the dm" [llength $got] 1
    if {[llength $got] == 1} {
	check "auth-relay dm content" \
	    [regexp {"content":"через auth-релей 🔐"} \
		[dict get [lindex $got 0] rumor]] 1
    }
}

# 6. watch: a persistent subscription delivers both the stored backlog
#    and live post-EOSE events through -onevent, without closing.
proc waitn {var n {ms 5000}} {
    upvar #0 $var v
    for {set i 0} {$i * 100 < $ms && [llength $v] < $n} {incr i} {
	after 100 {set ::tick 1}; vwait ::tick
    }
    return [llength $v]
}
set pub [nostr::relay::connect $URL]
lassign [nostr::relay::publish $pub \
    [nostr::sign -sec $BOB -kind 1 -content "watch: backlog"]] acc msg
check "watch backlog note accepted" $acc 1
set ::seen {}
set w [nostr::relay::connect $URL]
nostr::relay::watch $w w1 [dict create kinds [list 1] authors [list $BPUB]] \
    -onevent {lappend ::seen}
check "watch delivers the stored backlog" [waitn ::seen 1] 1
nostr::relay::publish $pub [nostr::sign -sec $BOB -kind 1 -content "watch: live"]
check "watch delivers the live post-EOSE event" [waitn ::seen 2] 2
check "live event content" \
    [regexp {"content":"watch: live"} [lindex $::seen 1]] 1
check "watched events verify" \
    [expr {[nostr::verify [lindex $::seen 0]]
	   && [nostr::verify [lindex $::seen 1]]}] 1
nostr::relay::close $w
nostr::relay::close $pub

# 7. watch through an auth relay: the REQ is retried automatically
#    after the NIP-42 handshake, and the wrap published in 5 arrives.
if {[info exists env(AUTH_URL)]} {
    set ::aseen {}
    set aw [nostr::relay::connect $env(AUTH_URL) -sec $BOB]
    nostr::relay::watch $aw w2 [dict create kinds [list 1059] #p [list $BPUB]] \
	-onevent {lappend ::aseen}
    check "auth-relay watch sees the stored wrap" [waitn ::aseen 1 10000] 1
    nostr::relay::close $aw
}

puts ""
if {$fails == 0} {
    puts "relay e2e: ALL PASS"
    exit 0
} else {
    puts "relay e2e: $fails FAILED"
    exit 1
}
