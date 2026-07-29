module github.com/luxfi/pq

go 1.26.4

require golang.org/x/crypto v0.41.0

require golang.org/x/sys v0.35.0 // indirect

// v1.0.3 was published twice. A history rewrite scrubbed a downstream brand
// name from a comment in mode.go and re-pointed the tag, so two different
// bodies of code have claimed this one version: the tag resolved first to
// h1:pFlQm1+5FuKTDUh2y/23bXWkN4I2Rc5iuxJypwDFFMs= and now resolves to
// h1:ksw1dmfTR0dqqNMRS7BjGcprCO2Fhc+3Iiq2/NMuONw=. The current content is the
// canonical one and the difference is a single comment line — no API, no
// behaviour, and go.mod is byte-identical across both. The original commit is
// deliberately NOT restorable: it carries a name that may not appear in this
// org's history. A version whose checksum is not a stable identity should not
// be selected by anything new, so it is retracted rather than laundered.
// Use v1.1.0 or later.
retract v1.0.3
