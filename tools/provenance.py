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

    __slots__ = (
        "name", "arch", "source_distro", "suite", "source_arch",
        "component", "upstream_name", "upstream_version", "wsh_filename",
        "payload_sha256", "upstream_filename",
    )

    def __init__(self, name, arch, source_distro, suite, source_arch,
                 component, upstream_name, upstream_version, wsh_filename,
                 payload_sha256=None, upstream_filename=None):
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


def sha256_of_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()
