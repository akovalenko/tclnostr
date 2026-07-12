# Development pkgIndex: serves the shared lib built in this tree.
# In a whale the package is static and registered by the build instead.
package ifneeded nostr 0.1 [list apply {{dir} {
    load [file join $dir libnostr[info sharedlibextension]] Nostr
}} $dir]
