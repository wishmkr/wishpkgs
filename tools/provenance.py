#!/usr/bin/env python3
"""
Provenance-aware package identity for the wishpkgs catalog.

Backfilling .info metadata by NAME ALONE is unsafe: the same package name
can exist in Ubuntu's, Debian's, and Fedora's own archives simultaneously
as genuinely different packages -- Ubuntu's own "libgcc-s1"
(14-20240412-0ubuntu1, Depends: gcc-14-base) is not the same package as
Debian's own "libgcc-s1" (12.2.0-14+deb12u1, Depends: gcc-12-base), even
though wish's sanitized catalog gives them the same name. A name-only (or
even name+sanitized-version-only) backfill pass can silently let one
distro's stanza overwrite another distro's already-published package with
a completely unrelated dependency graph, for a version that was never
actually mirrored -- this happened once for real (see
project history / commit "Fix backfill cross-distro version mismatch").

This module defines the full identity a package's metadata may legally be
regenerated from, and the matching rule that decides whether a given
upstream stanza is provably the origin of a given canonical package:

    identity = (source_distro, suite, source_arch, component,
                upstream_name, upstream_version)

A canonical package's provenance is provable ONLY when EXACTLY ONE stanza,
across every distro/suite/component scanned for its wish arch, sanitizes
to its (name, version) pair. Zero matches means "not provable" (the
upstream package has moved on, been removed, or was never really this
one -- leave existing metadata alone, report unresolved). More than one
match means "ambiguous" (two different distros' archives coincidentally
sanitize to the same name+version) -- reject, do not guess, leave existing
metadata alone. This module NEVER picks a "best" or "last" candidate; it
only ever returns a unique match or an explicit failure reason.
"""
import hashlib


class ProvenanceRecord:
    """The exact upstream source that produced one canonical package's
    published .wsh -- what its .info may legally be regenerated from."""

    # A record's confidence tier -- NEVER conflate these. "verified" means
    # match_provenance found exactly one upstream stanza by name+version
    # (optionally strengthened by verify_continuity against prior history).
    # "bootstrap_semantic_match" means the name+version match was
    # genuinely ambiguous (2+ distinct upstream sources), and was ONLY
    # accepted because exactly one candidate's normalized identity+
    # relationship fingerprint (name/arch/version/depends/pre-depends/
    # provides/conflicts/breaks/replaces/essential/multi-arch -- NOT free
    # text like description) matched what's already live -- corroborating
    # evidence, not proof of which upstream source actually produced the
    # payload. A future run with stronger evidence (e.g. this same package
    # resolving unambiguously once upstream versions diverge) should
    # upgrade a bootstrap record to verified, never the reverse.
    CONFIDENCE_VERIFIED = "verified"
    CONFIDENCE_BOOTSTRAP = "bootstrap_semantic_match"

    __slots__ = (
        "name", "arch", "source_distro", "suite", "source_arch",
        "component", "upstream_name", "upstream_version", "wsh_filename",
        "payload_sha256", "upstream_filename", "confidence",
    )

    def __init__(self, name, arch, source_distro, suite, source_arch,
                 component, upstream_name, upstream_version, wsh_filename,
                 payload_sha256=None, upstream_filename=None,
                 confidence=CONFIDENCE_VERIFIED):
        self.name = name
        self.arch = arch
        self.source_distro = source_distro
        self.suite = suite
        self.source_arch = source_arch
        self.component = component
        self.upstream_name = upstream_name
        self.upstream_version = upstream_version
        self.wsh_filename = wsh_filename
        self.payload_sha256 = payload_sha256
        self.upstream_filename = upstream_filename
        self.confidence = confidence

    def to_dict(self):
        return {k: getattr(self, k) for k in self.__slots__}

    @classmethod
    def from_dict(cls, d):
        return cls(**{k: d.get(k) for k in cls.__slots__})

    def source_key(self):
        """The upstream-side identity tuple: which exact stanza this
        provenance claims to come from. Two ProvenanceRecords with the
        same source_key were (or claim to be) built from the same
        upstream package listing."""
        return (self.source_distro, self.suite, self.source_arch,
                self.component, self.upstream_name, self.upstream_version)

    def __eq__(self, other):
        if not isinstance(other, ProvenanceRecord):
            return NotImplemented
        return self.to_dict() == other.to_dict()

    def __repr__(self):
        return (f"ProvenanceRecord(name={self.name!r}, arch={self.arch!r}, "
                f"source={self.source_distro}/{self.suite}/{self.source_arch}"
                f"/{self.component}, upstream={self.upstream_name}="
                f"{self.upstream_version})")


class UpstreamStanza:
    """One scanned upstream package listing entry, reduced to exactly the
    fields provenance matching needs. `raw` holds the full parsed stanza
    (Debian dict or Fedora tuple-derived dict) for later .info regeneration
    once a match is confirmed -- matching itself never looks at it."""

    __slots__ = (
        "source_distro", "suite", "source_arch", "component",
        "upstream_name", "upstream_version", "sanitized_name",
        "sanitized_version", "raw", "wish_arch", "upstream_filename",
    )

    def __init__(self, source_distro, suite, source_arch, component,
                 upstream_name, upstream_version, sanitized_name,
                 sanitized_version, raw=None, wish_arch=None,
                 upstream_filename=None):
        self.source_distro = source_distro
        self.suite = suite
        self.source_arch = source_arch
        self.component = component
        self.upstream_name = upstream_name
        self.upstream_version = upstream_version
        self.sanitized_name = sanitized_name
        self.sanitized_version = sanitized_version
        self.raw = raw
        # The upstream archive's own path for this exact package build --
        # Debian/Ubuntu's "Filename:" field (e.g.
        # "pool/main/g/gcc-14/libgcc-s1_14-20240412-0ubuntu1_arm64.deb") or
        # Fedora's primary.xml "href". Used, where available, as an
        # additional continuity check beyond sanitized name+version (see
        # verify_continuity below) -- two packages can share a sanitized
        # name+version by coincidence far more easily than they can share
        # an exact upstream pool path.
        self.upstream_filename = upstream_filename
        # The wish-side arch this stanza was scanned FOR (e.g. "aarch64"),
        # not to be confused with source_arch (the upstream distro's own
        # arch string for that same scan, e.g. "arm64"). Kept so matching
        # can explicitly reject a stanza scanned for the wrong wish arch
        # ever being used as another arch's provenance -- defense in depth
        # even though the real pipeline already partitions scans per arch
        # and would never naturally mix them.
        self.wish_arch = wish_arch


class ProvenanceResult:
    """Outcome of matching one canonical (name, version) against a set of
    UpstreamStanza candidates. Exactly one of `record`/`ambiguous_with` is
    meaningful depending on `status`."""

    RESOLVED = "resolved"
    UNRESOLVED = "unresolved"   # zero candidates matched
    AMBIGUOUS = "ambiguous"     # more than one candidate matched

    def __init__(self, status, stanza=None, candidates=None):
        self.status = status
        self.stanza = stanza          # the single matching UpstreamStanza, if RESOLVED
        self.candidates = candidates or []  # all matching stanzas, if AMBIGUOUS

    @property
    def is_resolved(self):
        return self.status == self.RESOLVED


def match_provenance(name, version, arch, stanzas):
    """Finds the upstream stanza (if any, and only if unique) that
    produced canonical package `name`@`version` for wish arch `arch`.

    `stanzas` is every UpstreamStanza scanned across every distro/suite/
    component (source_arch may differ per distro's own naming, e.g.
    "arm64" for Ubuntu/Debian vs "aarch64" for Fedora -- wish `arch` is
    the wish-side name, never compared directly to source_arch). Any
    stanza whose OWN `wish_arch` doesn't equal `arch` is rejected outright
    before matching -- a stanza scanned for x86_64 can never be used as
    aarch64 provenance, or vice versa, even if its name+version happen to
    coincide. Pass `arch=None` to skip this filter (matching purely on
    name+version, used by callers that already pre-partitioned `stanzas`
    by arch themselves).

    Returns a ProvenanceResult. Matching is EXACT on (sanitized_name,
    sanitized_version) -- source_arch/component/suite are NOT additional
    match constraints beyond the wish_arch filter above (a package's
    sanitized name+version pair is already the full identity wish's
    catalog format can represent; the additional fields are provenance
    METADATA carried forward once a match is found). Reject (return
    AMBIGUOUS) if more than one distinct upstream stanza -- even from the
    SAME distro across two different suites/components -- sanitizes to
    the same name+version; picking either would be a guess."""
    pool = stanzas if arch is None else [
        s for s in stanzas if s.wish_arch is None or s.wish_arch == arch
    ]
    candidates = [
        s for s in pool
        if s.sanitized_name == name and s.sanitized_version == version
    ]
    if len(candidates) == 0:
        return ProvenanceResult(ProvenanceResult.UNRESOLVED)
    if len(candidates) > 1:
        # Multiple stanzas landing on the exact same (source_distro, suite,
        # source_arch, component, upstream_name, upstream_version) tuple is
        # not really "ambiguous" -- it's the same stanza seen twice (e.g.
        # scanned once directly and once via a mirrored component list).
        # Only genuinely DIFFERENT sources are ambiguous.
        distinct = {(c.source_distro, c.suite, c.source_arch, c.component,
                     c.upstream_name, c.upstream_version)
                    for c in candidates}
        if len(distinct) == 1:
            return ProvenanceResult(ProvenanceResult.RESOLVED, stanza=candidates[0])
        return ProvenanceResult(ProvenanceResult.AMBIGUOUS, candidates=candidates)
    return ProvenanceResult(ProvenanceResult.RESOLVED, stanza=candidates[0])


def verify_continuity(stanza, prior_record, live_payload_sha256):
    """Strengthens a name+version match with filename/checksum evidence,
    where available, instead of trusting sanitized name+version alone.

    `stanza`: the single UpstreamStanza match_provenance() resolved by
      name+version+arch.
    `prior_record`: the ProvenanceRecord this same canonical package was
      published under on a PREVIOUS trusted rebuild, or None if this is
      the first time a manifest is being established for it.
    `live_payload_sha256`: the sha256 currently published in this
      package's pkgs/<arch>/<name>.wsh.sha256, or None if unavailable.

    Returns True if the match should be TRUSTED, False if it must be
    downgraded to unresolved (fail closed) because continuity could not
    be proven:

      - No prior record and no live payload hash: nothing to verify
        against yet -- trusted (this establishes the baseline for future
        continuity checks; matches match_provenance's own name+version
        uniqueness guarantee, which is the only signal available on a
        catalog's very first provenance rebuild).
      - Prior record exists: its upstream_filename AND source identity
        (distro/suite/source_arch/component) must match the new stanza's
        exactly. A change here for the SAME canonical name+version is
        exactly what an undetected cross-distro or cross-suite collision
        would look like -- fail closed rather than silently re-pinning
        provenance to a different upstream artifact.
      - live_payload_sha256 exists in a prior record: it must match what
        was recorded before. A payload that changed underneath us without
        a corresponding provenance update means we can no longer prove
        what produced the CURRENTLY published .wsh -- fail closed.
    """
    if prior_record is None:
        return True
    if prior_record.upstream_filename and stanza.upstream_filename:
        if prior_record.upstream_filename != stanza.upstream_filename:
            return False
    if (prior_record.source_distro, prior_record.suite, prior_record.source_arch,
            prior_record.component) != (stanza.source_distro, stanza.suite,
                                         stanza.source_arch, stanza.component):
        return False
    if prior_record.payload_sha256 and live_payload_sha256:
        if prior_record.payload_sha256 != live_payload_sha256:
            return False
    return True


# The distro processing order backfill_metadata.py used BEFORE the
# cross-distro version-guard fix (ubuntu, debian, fedora) -- the exact
# order whose "last write wins" bug let Debian's libgcc-s1 silently
# overwrite Ubuntu's. A bootstrap content match landing on a distro that
# comes AFTER another candidate in this order is indistinguishable from
# what that historical bug would have produced (the live .info could be
# "correct" simply because the buggy backfill already overwrote it with
# that later distro's content) -- such matches are never trusted via
# bootstrap, see is_suspicious_contamination_order.
HISTORICAL_BACKFILL_ORDER = ["ubuntu", "debian", "fedora"]


def is_suspicious_contamination_order(matched_stanza, all_candidates):
    """True if some OTHER candidate for the same ambiguous package comes
    EARLIER than `matched_stanza` in HISTORICAL_BACKFILL_ORDER. A distro
    unknown to that order is never considered "earlier" than anything (no
    known bug pattern applies to it)."""
    def rank(distro):
        try:
            return HISTORICAL_BACKFILL_ORDER.index(distro)
        except ValueError:
            return -1
    matched_rank = rank(matched_stanza.source_distro)
    if matched_rank == -1:
        return False
    for c in all_candidates:
        if c is matched_stanza:
            continue
        other_rank = rank(c.source_distro)
        if other_rank != -1 and other_rank < matched_rank:
            return True
    return False


# The identity+relationship fields a semantic fingerprint compares.
# Deliberately excludes free-text fields (description, maintainer,
# homepage, section) that carry no relationship semantics and are the
# most likely to drift in wording/formatting between when a package was
# originally mirrored and today's rendering -- byte-for-byte comparison
# against these was the reason the first bootstrap attempt (comparing
# full rendered .info text) matched almost nothing: real packages, real
# provenance, but a stale description or reordered field made the exact
# string differ. Fields not representable on one side (e.g. wish's own
# .info format has never stored Pre-Depends/Replaces/Essential/Multi-Arch)
# are carried as None and skipped during comparison rather than forced
# into a false mismatch -- see fingerprints_semantically_equal.
FINGERPRINT_FIELDS = (
    "name", "architecture", "version", "depends", "pre_depends",
    "provides", "conflicts", "breaks", "replaces", "essential",
    "multi_arch",
)


def fingerprints_semantically_equal(a, b):
    """Two fingerprint dicts (see FINGERPRINT_FIELDS) are semantically
    equal when every field present (non-None) on BOTH sides is equal.
    A field that's None on either side (not representable there, e.g.
    Pre-Depends against wish's own .info format, which never stored it)
    is simply not compared -- neither counted as a match nor a mismatch.
    Empty-vs-missing is already collapsed to the same normalized empty
    value by whichever function BUILT the fingerprint (see
    rebuild_catalog.semantic_fingerprint_from_stanza /
    _from_live_info) -- this function only ever sees the two dicts, it
    doesn't re-normalize."""
    for key in FINGERPRINT_FIELDS:
        va, vb = a.get(key), b.get(key)
        if va is None or vb is None:
            continue
        if va != vb:
            return False
    return True


def try_bootstrap_match(name, candidates, live_fingerprint, excluded_names,
                         fingerprint_fn):
    """Attempts to disambiguate an AMBIGUOUS provenance match (see
    match_provenance) using a semantic fingerprint comparison against the
    currently-published .info -- NOT a guess: corroborating evidence, not
    proof. Only ever used as a BOOTSTRAP mechanism (no prior trusted
    manifest exists yet to check continuity against via verify_continuity)
    -- once a package resolves unambiguously on a later run (e.g. upstream
    versions have since diverged), the normal verified path takes over and
    this is never consulted again for it.

    Compares normalized package identity + relationship fields only (see
    FINGERPRINT_FIELDS) -- name, architecture, normalized version,
    depends, pre-depends, provides, conflicts, breaks, replaces,
    essential, multi-arch -- NOT free-text fields like description, and
    NOT sensitive to field order, whitespace, or empty-vs-missing
    differences (that normalization happens in whoever builds the
    fingerprints; see rebuild_catalog.semantic_fingerprint_from_stanza).
    `fingerprint_fn(stanza)` builds a candidate's fingerprint the same way
    `live_fingerprint` was built for the live side, so both are directly
    comparable.

    Accepts a candidate only when:
      - the package name isn't in `excluded_names` (known-contaminated or
        manually-repaired packages, whose live .info might itself be
        exactly the kind of content a bootstrap match would wrongly trust
        -- see CatalogRebuild._load_bootstrap_exclusions),
      - `live_fingerprint` exists (nothing to corroborate against otherwise),
      - EXACTLY ONE candidate's fingerprint is semantically equal to
        live_fingerprint -- zero or multiple matches both stay ambiguous,
        never guessed between,
      - the match isn't flagged by is_suspicious_contamination_order.

    Returns (stanza, ProvenanceRecord.CONFIDENCE_BOOTSTRAP) on acceptance,
    or (None, None) otherwise."""
    if name in excluded_names or live_fingerprint is None:
        return None, None
    matches = [c for c in candidates
               if fingerprints_semantically_equal(fingerprint_fn(c), live_fingerprint)]
    if len(matches) != 1:
        return None, None
    matched = matches[0]
    if is_suspicious_contamination_order(matched, candidates):
        return None, None
    return matched, ProvenanceRecord.CONFIDENCE_BOOTSTRAP


def sha256_of_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()
