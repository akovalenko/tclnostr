# relay.tcl -- a small Nostr relay client and NIP-17 direct-message
# layer on top of the `nostr` C package.  Transport is tcllib
# websocket over http; the fixed-schema crypto and parsing live in C
# (nostr::sign / verify / wrap / unwrap / frame), so this file is only
# envelopes, subscriptions and an event loop.
#
# For a wss:// relay the caller must register an https socket factory
# with the http package first (nostr::relay::tls is a ready one that
# layers tls over an optional proxy); a ws:// relay needs nothing.
#
# This file is in the public domain (see UNLICENSE).

package require Tcl 9
package require nostr
package require websocket
package require json

namespace eval nostr::relay {
    variable conn;			# token -> state array, flattened
    variable counter 0
    namespace export connect publish subscribe collect close
}

# Register an https factory so wss:// works: tls over a plain (or, with
# -socketcmd, proxied) channel.  Idempotent-ish; call once at startup.
proc nostr::relay::tls {args} {
    package require tls
    set factory [list ::nostr::relay::TlsSocket {*}$args]
    ::http::register https 443 $factory
}
proc nostr::relay::TlsSocket {args} {
    # trailing args after our options are: host port
    set sockcmd ::socket
    set opts {}
    while {[llength $args] > 2} {
	set a [lindex $args 0]
	if {$a eq "-socketcmd"} {
	    set sockcmd [lindex $args 1]
	    set args [lrange $args 2 end]
	} else {
	    lappend opts $a
	    set args [lrange $args 1 end]
	}
    }
    lassign $args host port
    set so [{*}$sockcmd {*}$opts $host $port]
    set so [::tls::import $so -servername $host -require 0]
    ::tls::handshake $so
    return $so
}

# connect URL ?-timeout ms? ?-socketcmd cmd? ?-sec key?
#   Opens a relay connection and blocks until the socket is up.  -sec
#   enables automatic NIP-42 AUTH replies.  Returns a connection token.
proc nostr::relay::connect {url args} {
    variable conn
    variable counter
    set tok ::nostr::relay::c[incr counter]
    upvar #0 $tok C
    array set C {state opening events {} eose 0 ok {} auth {} \
	sec {} error {} sub {} wake 0}
    set C(url) $url
    set timeout 15000
    set wsopts {}
    foreach {k v} $args {
	switch -- $k {
	    -timeout   { set timeout $v }
	    -socketcmd { lappend wsopts -socketcmd $v }
	    -sec       { set C(sec) $v }
	    default    { return -code error "unknown option $k" }
	}
    }
    set C(sock) [websocket::open $url \
	[list ::nostr::relay::Handler $tok] {*}$wsopts]
    Wait $tok $timeout {expr {$C(state) ne "opening"}}
    if {$C(state) ne "open"} {
	set st $C(state)
	set err $C(error)
	catch {::websocket::close $C(sock)}
	unset C
	return -code error \
	    "connect to $url failed: [expr {$err eq {} ? $st : $err}]"
    }
    return $tok
}

# Block in the event loop until CONDBODY (evaluated in the caller's
# frame against C) is true or the timeout fires.  All state changes go
# through a single wake counter so one vwait serves every waiter.
proc nostr::relay::Wait {tok timeout condBody} {
    upvar #0 $tok C
    set aid [after $timeout [list ::nostr::relay::Poke $tok]]
    try {
	while {![uplevel 1 $condBody]} { vwait ${tok}(wake) }
    } finally {
	after cancel $aid
    }
}
proc nostr::relay::Poke {tok} {
    upvar #0 $tok C
    if {[info exists C(wake)]} { incr C(wake) }
}

proc nostr::relay::Handler {tok sock type msg} {
    upvar #0 $tok C
    if {![info exists C(state)]} return
    switch -glob -- $type {
	connect {
	    set C(state) open
	}
	text {
	    Dispatch $tok $msg
	}
	close - disconnect - timeout {
	    set C(state) closed
	}
	error {
	    set C(error) $msg
	    set C(state) closed
	}
    }
    if {[info exists C(wake)]} { incr C(wake) }
}

# Route one relay frame into the connection's per-kind state slots.
proc nostr::relay::Dispatch {tok frameJson} {
    upvar #0 $tok C
    if {[catch {nostr::frame $frameJson} frame]} return
    set verb [lindex $frame 0]
    switch -- $verb {
	EVENT {
	    lappend C(events) [lindex $frame 2]
	    incr C(evseq)
	}
	EOSE {
	    set C(eose) 1
	}
	OK {
	    # [OK, id, accepted(bool), message]
	    set C(ok) [list [lindex $frame 1] [lindex $frame 2] \
		[lindex $frame 3]]
	}
	CLOSED {
	    set C(closed-sub) [list [lindex $frame 1] [lindex $frame 2]]
	    set C(eose) 1
	}
	AUTH {
	    set C(auth) [lindex $frame 1]
	    if {$C(sec) ne ""} {
		AuthReply $tok [lindex $frame 1]
		set C(authsent) 1
	    }
	}
	NOTICE {
	    set C(notice) [lindex $frame 1]
	}
    }
}

# NIP-42: answer a challenge with a signed kind-22242 event.
proc nostr::relay::AuthReply {tok challenge} {
    upvar #0 $tok C
    set ev [nostr::sign -sec $C(sec) -kind 22242 -content "" \
	-tags [list [list relay $C(url)] [list challenge $challenge]]]
    Send $tok [list AUTH $ev]
}

# Send a frame: a Tcl list whose first element is the verb and whose
# remaining elements are either already-JSON (events/filters, detected
# by a leading '{') or plain strings.
proc nostr::relay::Send {tok frame} {
    upvar #0 $tok C
    set parts {}
    foreach el $frame {
	if {[string index [string trimleft $el] 0] eq "\{"} {
	    lappend parts $el
	} else {
	    lappend parts [EncodeJsonString $el]
	}
    }
    websocket::send $C(sock) text "\[[join $parts ,]\]"
}

proc nostr::relay::EncodeJsonString {s} {
    set map [list \\ \\\\ \" \\\" \n \\n \r \\r \t \\t \b \\b \f \\f / \\/]
    return "\"[string map $map $s]\""
}

# publish TOKEN eventJson ?-timeout ms?
#   Sends ["EVENT",ev], waits for the matching OK.  Returns
#   {accepted message}; throws on timeout.
proc nostr::relay::publish {tok ev args} {
    upvar #0 $tok C
    set timeout 15000
    foreach {k v} $args { if {$k eq "-timeout"} { set timeout $v } }
    set id [dict get [ParseIdField $ev] id]
    set accepted [PublishOnce $tok $ev $id $timeout]
    # NIP-42: a relay may reject with "auth-required"; connect's handler
    # auto-answers the AUTH challenge, so wait for that reply to go out
    # and retry once.
    if {[lindex $accepted 0] == 0 && $C(sec) ne ""
	    && [string match -nocase "auth-required*" [lindex $accepted 1]]} {
	Wait $tok $timeout \
	    {expr {[info exists C(authsent)] || $C(state) eq "closed"}}
	set accepted [PublishOnce $tok $ev $id $timeout]
    }
    return $accepted
}
proc nostr::relay::PublishOnce {tok ev id timeout} {
    upvar #0 $tok C
    set C(ok) {}
    Send $tok [list EVENT $ev]
    Wait $tok $timeout \
	{expr {[lindex $C(ok) 0] eq $id || $C(state) eq "closed"}}
    if {[lindex $C(ok) 0] ne $id} {
	return -code error "publish: no OK for $id ($C(state))"
    }
    return [list [lindex $C(ok) 1] [lindex $C(ok) 2]]
}

# minimal: pull the id out of a signed event without a full parse
proc nostr::relay::ParseIdField {ev} {
    if {[regexp {"id":"([0-9a-f]{64})"} $ev -> id]} {
	return [dict create id $id]
    }
    return [dict create id ""]
}

# subscribe TOKEN subid filterDict
#   filterDict is a Tcl dict rendered to a JSON filter object (values
#   that are lists become JSON arrays; #-prefixed keys and scalar
#   kinds/limit/since/until are handled).  Sends ["REQ",subid,filter].
proc nostr::relay::subscribe {tok subid filter} {
    upvar #0 $tok C
    set C(events) {}
    set C(eose) 0
    set C(evseq) 0
    set C(closed-sub) {}
    set C(filter) $filter
    Send $tok [list REQ $subid [FilterJson $filter]]
    set C(sub) $subid
}

proc nostr::relay::FilterJson {filter} {
    set parts {}
    foreach {k v} $filter {
	lappend parts "[EncodeJsonString $k]:[FilterValue $k $v]"
    }
    return "\{[join $parts ,]\}"
}
proc nostr::relay::FilterValue {k v} {
    # limit/since/until are scalar numbers; kinds is a number array;
    # everything else (ids, authors, #e, #p, ...) is a string array.
    if {$k in {limit since until}} {
	return $v
    }
    set nums [expr {$k eq "kinds"}]
    set out {}
    foreach e $v {
	lappend out [expr {$nums ? $e : [EncodeJsonString $e]}]
    }
    return "\[[join $out ,]\]"
}

# collect TOKEN ?-timeout ms?
#   Wait until EOSE (or CLOSED) for the active subscription and return
#   the raw event-JSON strings received.
proc nostr::relay::collect {tok args} {
    upvar #0 $tok C
    set timeout 15000
    foreach {k v} $args { if {$k eq "-timeout"} { set timeout $v } }
    Wait $tok $timeout {expr {$C(eose) || $C(state) eq "closed"}}
    # NIP-42: an auth-required CLOSED means re-issue the REQ once the
    # AUTH challenge (auto-answered by the handler) has been replied to.
    set closedMsg [lindex $C(closed-sub) 1]
    if {[llength $C(events)] == 0 && $C(sub) ne "" && $C(sec) ne ""
	    && [string match -nocase "auth-required*" $closedMsg]} {
	Wait $tok $timeout \
	    {expr {[info exists C(authsent)] || $C(state) eq "closed"}}
	subscribe $tok $C(sub) $C(filter)
	Wait $tok $timeout {expr {$C(eose) || $C(state) eq "closed"}}
    }
    if {$C(sub) ne ""} { catch { Send $tok [list CLOSE $C(sub)] } }
    set C(sub) {}
    return $C(events)
}

proc nostr::relay::close {tok} {
    upvar #0 $tok C
    catch {::websocket::close $C(sock)}
    catch {unset C}
}

# ------------------------------------------------------- NIP-17 DM ----

namespace eval nostr::dm {
    namespace export send fetch
}

# nostr::dm::send -sec K -to PUB -relays {url ...} ?-kind 14?
#     ?-tags {...}? ?-selfcopy 0? text
#   Build a rumor, gift-wrap it for the recipient, publish the wrap to
#   each relay, and (unless -selfcopy 0) a second wrap addressed to the
#   sender so the sender's own client can read the thread.  Returns a
#   dict: {wrap <id> results {url {accepted msg} ...}}.
proc nostr::dm::send {args} {
    set kind 14
    set tags {}
    set selfcopy 1
    set relays {}
    set sec ""; set to ""
    set text [lindex $args end]
    foreach {k v} [lrange $args 0 end-1] {
	switch -- $k {
	    -sec { set sec $v }
	    -to { set to $v }
	    -relays { set relays $v }
	    -kind { set kind $v }
	    -tags { set tags $v }
	    -selfcopy { set selfcopy $v }
	    default { return -code error "unknown option $k" }
	}
    }
    if {$sec eq "" || $to eq "" || $relays eq ""} {
	return -code error "-sec, -to and -relays are required"
    }
    set mypub [nostr::pubkey -hex $sec]
    set tohex [nostr::decode-or-hex $to]
    set alltags [linsert $tags 0 [list p $tohex]]
    set rumor [nostr::event -pubkey $mypub -kind $kind -content $text \
	-tags $alltags]
    set wrapTo [nostr::wrap -sec $sec -to $to $rumor]
    set results {}
    foreach url $relays {
	set c [nostr::relay::connect $url -sec $sec]
	try {
	    lappend results $url [nostr::relay::publish $c $wrapTo]
	    if {$selfcopy} {
		nostr::relay::publish $c [nostr::wrap -sec $sec -to $mypub \
		    $rumor]
	    }
	} finally {
	    nostr::relay::close $c
	}
    }
    return [dict create wrap [dict get [nostr::relay::ParseIdField \
	$wrapTo] id] results $results]
}

# nostr::dm::fetch -sec K -relays {url ...} ?-since T? ?-limit N?
#   Subscribe for gift wraps addressed to us, unwrap each, and return a
#   list of dicts {from <hex> rumor <json>}.  Wraps that fail to unwrap
#   (not for us, tampered) are skipped.
proc nostr::dm::fetch {args} {
    set sec ""; set relays {}; set since ""; set limit ""
    foreach {k v} $args {
	switch -- $k {
	    -sec { set sec $v }
	    -relays { set relays $v }
	    -since { set since $v }
	    -limit { set limit $v }
	    default { return -code error "unknown option $k" }
	}
    }
    if {$sec eq "" || $relays eq ""} {
	return -code error "-sec and -relays are required"
    }
    set mypub [nostr::pubkey -hex $sec]
    set filter [dict create kinds 1059 #p [list $mypub]]
    if {$since ne ""} { dict set filter since $since }
    if {$limit ne ""} { dict set filter limit $limit }
    set msgs {}
    set seen {}
    foreach url $relays {
	set c [nostr::relay::connect $url -sec $sec]
	try {
	    nostr::relay::subscribe $c dm $filter
	    foreach wrap [nostr::relay::collect $c] {
		if {[catch {nostr::unwrap -sec $sec $wrap} got]} continue
		set rumor [dict get $got rumor]
		set id [dict get [nostr::relay::ParseIdField $rumor] id]
		if {$id ne "" && [dict exists $seen $id]} continue
		dict set seen $id 1
		lappend msgs $got
	    }
	} finally {
	    nostr::relay::close $c
	}
    }
    return $msgs
}

# accept npub or hex, return hex (small helper used by the DM layer)
proc nostr::decode-or-hex {key} {
    if {[string match npub1* $key]} {
	return [dict get [nostr::decode $key] hex]
    }
    return $key
}

package provide nostr::relay 0.2
