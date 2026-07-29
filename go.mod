module github.com/luxfi/pq

go 1.26.4

require golang.org/x/crypto v0.41.0

require golang.org/x/sys v0.35.0 // indirect

// v1.0.3 was published twice. A history rewrite scrubbed a downstream brand
// name from a comment in mode.go and re-pointed the tag, so two different
// bodies of code have claimed this one version: the tag resolved first to
// h1:pFlQm1+5FuKTDUh2y/23bXWkN4I2Rc5iuxJypwDFFMs= and now resolves to
// h1:ksw1dmfTR0dqqNMRS7BjGcprCO2Fhc+3Iiq2/NMuONw=. The difference is a single
// comment line — no API, no behaviour, and go.mod is byte-identical across
// both, so only the zip hash moved.
//
// Which one is canonical is not ours to choose. proxy.golang.org still serves
// the FIRST content (commit e16b004d) and sum.golang.org has notarised its
// hash permanently, because a published version is immutable to them. So
// pFlQm1+5 is what v1.0.3 means to everyone, and ksw1dmf is only what our own
// machines see: GOPRIVATE=github.com/luxfi/* sends us straight to GitHub and
// skips the checksum database, which is the sole reason the moved tag looks
// fine here.
//
// Do NOT reconcile consumers onto ksw1dmf. That hash is unreproducible off
// this fleet, and recording it converts a loud checksum failure into a build
// that breaks for the first person outside our GOPRIVATE. Move off v1.0.3
// instead — that is what this retraction is for.
//
// Note also that re-pointing the tag did not achieve the scrub: the original
// commit, brand name and all, is still public and permanently fetchable from
// the module proxy. The rewrite bought no privacy and cost a stable identity.
//
// The original commit is deliberately NOT restored here: it carries a name
// that may not appear in this org's history, and restoring it is a call for a
// human, not a build fix. A version whose checksum is not a stable identity
// should not be selected by anything new, so it is retracted rather than
// laundered. Use v1.1.0 or later.
retract v1.0.3
