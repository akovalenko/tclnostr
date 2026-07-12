# Development pkgIndex: serves the shared lib and the script layer built
# in this tree.  In a whale both packages are registered by the build
# recipe instead (nostr static, nostr::relay vfs'd from relay.tcl).
package ifneeded nostr 0.2 [list apply {{dir} {
    load [file join $dir libnostr[info sharedlibextension]] Nostr
}} $dir]
package ifneeded nostr::relay 0.2 \
    [list source [file join $dir relay.tcl]]
