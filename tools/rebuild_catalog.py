#!/usr/bin/env python3
"""
Full provenance-aware catalog repair.

Replaces name-only (or name+sanitized-version-only) backfilling with a
strict identity model: a canonical package's .info may only ever be
regenerated from the single upstream stanza PROVABLY responsible for it
(see tools/provenance.py for the identity/matching rules and the exact
incident -- Debian's libgcc-s1 overwriting Ubuntu's -- that makes this
necessary). This script does NOT special-case any package name; the same
matching rule applies uniformly to all ~16k+ catalog entries.

Pipeline (mirrors the 12-step spec this was built against):
  1. Build a provenance manifest for every package currently canonical.
  2. Match each to exactly one upstream stanza (source distro/suite/arch/
     component/name/version) -- via tools/provenance.match_provenance --
     THEN verify continuity against the prior trusted manifest's recorded
     upstream filename and the live .wsh.sha256, where available (see
     tools/provenance.verify_continuity). A name+version match that fails
     continuity is downgraded to unresolved, not trusted on name+version
     alone.
  3. Regenerate .info for every package that stays RESOLVED after step 2's
     continuity check (not just failing ones).
  4. Rebuild the whole provides index from the regenerated + untouched
     metadata, from scratch (not incremental).
  5. Ambiguous matches (>1 distinct upstream source lands on the same
     sanitized name+version) are rejected, never guessed.
  6. UNRESOLVED packages (no matching upstream stanza, or a stanza that
     failed continuity verification) are left completely untouched.
  7. Orphan pkgs/<arch>/* objects (.info/.sha256/.wsh with no matching
     canonical index entry) are quarantined (moved under quarantine/,
     never deleted).
  8. Every provides target must resolve to a canonical package name.
  9. Every dependency group is classified as exactly one of: literal (a
     canonical name), virtual (satisfied via a provides target), or
     excluded (state/excluded-deps.txt). Anything else is unresolved.
  10. A full repair report is produced with per-arch, per-distro counts.
  11. STRICT publish gate: publishing is refused if ANY canonical package
     is ambiguous or unresolved, or ANY dependency group is unresolved
     (unclassified) -- "skip and report" is not sufficient, since an old,
     possibly-contaminated .info would otherwise stay live for exactly
     the packages this run couldn't prove. When the gate passes, the
     complete staged catalog (every touched .info + the rebuilt provides
     index) is uploaded to a staging prefix and verified there BEFORE any
     live key is overwritten -- see CatalogRebuild._publish for exactly
     what this does and does not guarantee (it is NOT a true atomic
     commit; see that method's docstring for the preferred
     generation-pointer design this stops short of). --dry-run (default,
     the absence of --publish) never touches B2's live OR staging keys.
  12. Triggering test-packages.yml afterward is the caller's job (see the
     rebuild-catalog.yml workflow).

Usage:
    python3 rebuild_catalog.py --arch aarch64 [--publish] [--report-dir DIR]

Without --publish, this only reads (upstream archives + current B2 state)
and writes a local report -- completely safe to run repeatedly against
production for inspection. Note that with the strict gate in step 11, a
real production run against a catalog with genuine upstream gaps (there
will always be some, at ~16k+ packages) is EXPECTED to refuse to publish
until every unresolved/ambiguous package is dealt with -- that is
deliberate, not a bug to work around.
"""
import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mirror_common import (
    b2_cp, b2_get, sh, sanitize_name, sanitize_version, is_blocked,
    redact, parse_dep_field, format_dep_field, provides_names,
    rpm_entries_to_groups, load_canonical_versions,
    parse_name_from_index_line, B2_BUCKET, B2_ENDPOINT,
)
from provenance import (
    UpstreamStanza, match_provenance, ProvenanceResult, ProvenanceRecord,
    verify_continuity, try_bootstrap_match, fingerprints_semantically_equal,
    BootstrapMatchResult, candidates_are_output_equivalent,
)

import mirror_ubuntu
import mirror_debian
import mirror_fedora

DEADLINE = time.monotonic() + float(os.environ.get("REBUILD_DEADLINE_SECONDS", "19500"))

UBUNTU_COMPONENTS = [c for c in os.environ.get(
    "REBUILD_COMPONENTS_UBUNTU", "main,universe,multiverse,restricted").split(",") if c]
DEBIAN_COMPONENTS = [c for c in os.environ.get(
    "REBUILD_COMPONENTS_DEBIAN", "main,contrib,non-free-firmware").split(",") if c]


def deadline_hit():
    return time.monotonic() > DEADLINE


# ---------------------------------------------------------------------
# Step 1 (part A): scan every upstream stanza across every distro, for
# one wish arch, into a flat list of UpstreamStanza.
# ---------------------------------------------------------------------

def scan_ubuntu_stanzas(arch_wish):
    cfg = mirror_ubuntu.ARCHES[arch_wish]
    out = []
    for comp in UBUNTU_COMPONENTS:
        if deadline_hit():
            break
        print(f"[scan] ubuntu/{comp} ({arch_wish}): fetching index...", file=sys.stderr, flush=True)
        try:
            text = mirror_ubuntu.fetch_packages_index(
                cfg["base"], mirror_ubuntu.RELEASE, comp, cfg["deb_arch"])
        except Exception as e:
            print(f"ubuntu/{comp}: fetch failed: {e}", file=sys.stderr, flush=True)
            continue
        before = len(out)
        for pkg in mirror_ubuntu.parse_packages(text):
            name_raw, ver_raw = pkg.get("Package"), pkg.get("Version")
            if not name_raw or not ver_raw or is_blocked(name_raw):
                continue
            out.append(UpstreamStanza(
                source_distro="ubuntu", suite=mirror_ubuntu.RELEASE,
                source_arch=cfg["deb_arch"], component=comp,
                upstream_name=name_raw, upstream_version=ver_raw,
                sanitized_name=sanitize_name(name_raw),
                sanitized_version=sanitize_version(ver_raw), raw=pkg,
                wish_arch=arch_wish, upstream_filename=pkg.get("Filename"),
            ))
        print(f"[scan] ubuntu/{comp} ({arch_wish}): {len(out) - before} stanzas "
              f"({len(out)} total so far)", file=sys.stderr, flush=True)
    return out


def scan_debian_stanzas(arch_wish):
    cfg = mirror_debian.ARCHES[arch_wish]
    out = []
    for comp in DEBIAN_COMPONENTS:
        if deadline_hit():
            break
        print(f"[scan] debian/{comp} ({arch_wish}): fetching index...", file=sys.stderr, flush=True)
        try:
            text = mirror_debian.fetch_packages_index(
                cfg["base"], mirror_debian.RELEASE, comp, cfg["deb_arch"])
        except Exception as e:
            print(f"debian/{comp}: fetch failed: {e}", file=sys.stderr, flush=True)
            continue
        before = len(out)
        for pkg in mirror_debian.parse_packages(text):
            name_raw, ver_raw = pkg.get("Package"), pkg.get("Version")
            if not name_raw or not ver_raw or is_blocked(name_raw):
                continue
            out.append(UpstreamStanza(
                source_distro="debian", suite=mirror_debian.RELEASE,
                source_arch=cfg["deb_arch"], component=comp,
                upstream_name=name_raw, upstream_version=ver_raw,
                sanitized_name=sanitize_name(name_raw),
                sanitized_version=sanitize_version(ver_raw), raw=pkg,
                wish_arch=arch_wish, upstream_filename=pkg.get("Filename"),
            ))
        print(f"[scan] debian/{comp} ({arch_wish}): {len(out) - before} stanzas "
              f"({len(out)} total so far)", file=sys.stderr, flush=True)
    return out


def scan_fedora_stanzas(arch_wish):
    cfg = mirror_fedora.ARCHES[arch_wish]
    out = []
    print(f"[scan] fedora ({arch_wish}): fetching primary.xml...", file=sys.stderr, flush=True)
    try:
        xml = mirror_fedora.fetch_primary_xml(cfg["rpm_arch"])
    except Exception as e:
        print(f"fedora: fetch failed: {e}", file=sys.stderr, flush=True)
        return out
    for pkg in mirror_fedora.parse_primary(xml):
        name_raw = pkg["name"]
        if is_blocked(name_raw):
            continue
        out.append(UpstreamStanza(
            source_distro="fedora", suite=mirror_fedora.RELEASE,
            source_arch=cfg["rpm_arch"], component=mirror_fedora.REPO,
            upstream_name=name_raw, upstream_version=pkg["version"],
            sanitized_name=sanitize_name(name_raw),
            sanitized_version=sanitize_version(pkg["version"]), raw=pkg,
            wish_arch=arch_wish, upstream_filename=pkg.get("href"),
        ))
    print(f"[scan] fedora ({arch_wish}): {len(out)} stanzas", file=sys.stderr, flush=True)
    return out


def scan_all_stanzas(arch_wish):
    stanzas = []
    stanzas.extend(scan_ubuntu_stanzas(arch_wish))
    stanzas.extend(scan_debian_stanzas(arch_wish))
    stanzas.extend(scan_fedora_stanzas(arch_wish))
    print(f"[scan] {arch_wish}: {len(stanzas)} total upstream stanzas scanned",
          file=sys.stderr, flush=True)
    return stanzas


# ---------------------------------------------------------------------
# Steps 1-2 (part B) + 5-6: match every canonical package against the
# scanned stanzas, classify RESOLVED / UNRESOLVED / AMBIGUOUS.
# ---------------------------------------------------------------------

def build_provenance_manifest(canonical_versions, stanzas, arch):
    """canonical_versions: {name: version} from load_canonical_versions().
    `arch` is the wish arch every candidate stanza must have been scanned
    for (see UpstreamStanza.wish_arch / match_provenance's arch filter) --
    a stanza scanned for a different arch is never eligible here, even if
    its name+version happen to coincide. Returns {name: ProvenanceResult}."""
    # Index stanzas by (name, version) for O(1) lookup instead of an O(n*m)
    # scan -- ties (multiple stanzas at the same key) are preserved as a
    # list so match_provenance can still tell duplicate-scan from genuine
    # cross-distro ambiguity.
    by_key = {}
    for s in stanzas:
        if s.wish_arch is not None and s.wish_arch != arch:
            continue
        by_key.setdefault((s.sanitized_name, s.sanitized_version), []).append(s)

    manifest = {}
    for name, version in canonical_versions.items():
        candidates = by_key.get((name, version), [])
        manifest[name] = _match_from_candidates(candidates)
    return manifest


def _match_from_candidates(candidates):
    """Same classification match_provenance() does, but operating on an
    already-filtered candidate list (avoids re-scanning all stanzas per
    package -- see build_provenance_manifest's index)."""
    if not candidates:
        return ProvenanceResult(ProvenanceResult.UNRESOLVED)
    distinct = {(c.source_distro, c.suite, c.source_arch, c.component,
                 c.upstream_name, c.upstream_version) for c in candidates}
    if len(distinct) == 1:
        return ProvenanceResult(ProvenanceResult.RESOLVED, stanza=candidates[0])
    return ProvenanceResult(ProvenanceResult.AMBIGUOUS, candidates=candidates)


# ---------------------------------------------------------------------
# Step 3: regenerate .info content from a matched stanza's raw data.
# ---------------------------------------------------------------------

def render_info_from_stanza(stanza):
    """Builds the exact .info text for a RESOLVED provenance stanza,
    using the same field-mapping each distro's own process_package()
    uses -- kept in sync deliberately, not re-derived ad hoc."""
    pkg = stanza.raw
    if stanza.source_distro in ("ubuntu", "debian"):
        depends = format_dep_field(parse_dep_field(pkg.get("Depends", "")))
        conflicts = format_dep_field(parse_dep_field(pkg.get("Conflicts", "")))
        breaks = format_dep_field(parse_dep_field(pkg.get("Breaks", "")))
        provides_groups = parse_dep_field(pkg.get("Provides", ""))
        provides = provides_names(provides_groups)
        desc_line = pkg.get("Description", "").splitlines()[0] if pkg.get("Description") else ""
    elif stanza.source_distro == "fedora":
        depends = format_dep_field(rpm_entries_to_groups(pkg["requires"]))
        conflicts = format_dep_field(rpm_entries_to_groups(pkg["conflicts"]))
        breaks = ""
        provides = provides_names(rpm_entries_to_groups(pkg["provides"]))
        desc_line = pkg["summary"].splitlines()[0] if pkg["summary"] else ""
    else:
        raise ValueError(f"unknown source_distro {stanza.source_distro!r}")

    lines = [
        f"description={redact(desc_line)}",
        "license=See included license/copyright files",
    ]
    if depends:
        lines.append(f"depends={depends}")
    if provides:
        lines.append(f"provides={','.join(provides)}")
    if conflicts:
        lines.append(f"conflicts={conflicts}")
    if breaks:
        lines.append(f"breaks={breaks}")
    return "\n".join(lines) + "\n"


def parse_info_provides(info_text):
    for line in info_text.splitlines():
        if line.startswith("provides="):
            return [p.strip() for p in line[len("provides="):].split(",") if p.strip()]
    return []


def parse_info_depends(info_text):
    for line in info_text.splitlines():
        if line.startswith("depends="):
            groups = []
            for slot in line[len("depends="):].split(","):
                slot = slot.strip()
                if not slot:
                    continue
                alts = [a.split("(", 1)[0].strip() for a in slot.split("|") if a.strip()]
                if alts:
                    groups.append(alts)
            return groups
    return []


# ---------------------------------------------------------------------
# Semantic fingerprints for bootstrap disambiguation (see
# provenance.try_bootstrap_match / fingerprints_semantically_equal).
# Compares normalized package identity + relationship fields ONLY --
# never free text like description/maintainer/homepage/section, which is
# exactly the kind of field that drifts in wording/formatting between when
# a package was originally mirrored and today's rendering without the
# underlying package actually being any different.
# ---------------------------------------------------------------------

def _normalize_dep_groups_semantic(groups):
    """`groups`: parse_dep_field()'s shape -- a list of OR-groups, each a
    list of (name, op, version) tuples. Normalizes to a frozenset of
    frozensets so that: comma-separated slot ORDER doesn't matter (AND is
    order-independent), '|' alternative ORDER within one slot doesn't
    matter ("A|B" == "B|A"), and version constraints are normalized via
    sanitize_version. Empty/missing both normalize to frozenset() (never
    None), so this field always participates in comparison -- "ignore
    empty-vs-missing differences" without ever silently skipping a real
    relationship field."""
    out = set()
    for group in groups:
        alts = frozenset(
            (sanitize_name(name), op, sanitize_version(version) if version else "")
            for name, op, version in group
        )
        if alts:
            out.add(alts)
    return frozenset(out)


def _normalize_provides_semantic(names):
    return frozenset(sanitize_name(n) for n in names if n)


def _get_raw_field(info_text, key):
    prefix = f"{key}="
    for line in info_text.splitlines():
        if line.startswith(prefix):
            return line[len(prefix):]
    return ""


def semantic_fingerprint_from_stanza(stanza):
    """Builds a candidate's fingerprint straight from the raw upstream
    stanza -- the richest side, since the full upstream control/primary.xml
    data is available. Fields the upstream format doesn't have (e.g.
    Fedora/RPM has no Debian-style Pre-Depends/Essential/Multi-Arch/
    Replaces concept) are left None, not forced to a false empty value --
    None means "not comparable here", not "empty", see
    fingerprints_semantically_equal."""
    pkg = stanza.raw
    fp = {
        "name": stanza.sanitized_name,
        "architecture": stanza.wish_arch,
        "version": stanza.sanitized_version,
    }
    if stanza.source_distro in ("ubuntu", "debian"):
        fp["depends"] = _normalize_dep_groups_semantic(parse_dep_field(pkg.get("Depends", "")))
        fp["pre_depends"] = _normalize_dep_groups_semantic(parse_dep_field(pkg.get("Pre-Depends", "")))
        fp["provides"] = _normalize_provides_semantic(
            provides_names(parse_dep_field(pkg.get("Provides", ""))))
        fp["conflicts"] = _normalize_dep_groups_semantic(parse_dep_field(pkg.get("Conflicts", "")))
        fp["breaks"] = _normalize_dep_groups_semantic(parse_dep_field(pkg.get("Breaks", "")))
        fp["replaces"] = _normalize_dep_groups_semantic(parse_dep_field(pkg.get("Replaces", "")))
        essential = (pkg.get("Essential") or "").strip().lower()
        fp["essential"] = essential or "no"  # Debian's own default when the field is absent
        multi_arch = (pkg.get("Multi-Arch") or "").strip().lower()
        fp["multi_arch"] = multi_arch or None
    elif stanza.source_distro == "fedora":
        fp["depends"] = _normalize_dep_groups_semantic(rpm_entries_to_groups(pkg["requires"]))
        fp["pre_depends"] = None
        fp["provides"] = _normalize_provides_semantic(
            provides_names(rpm_entries_to_groups(pkg["provides"])))
        fp["conflicts"] = _normalize_dep_groups_semantic(rpm_entries_to_groups(pkg["conflicts"]))
        fp["breaks"] = None
        fp["replaces"] = None
        fp["essential"] = None
        fp["multi_arch"] = None
    else:
        raise ValueError(f"unknown source_distro {stanza.source_distro!r}")
    return fp


def semantic_fingerprint_from_live_info(name, arch, version, info_text):
    """Builds the live side's fingerprint by parsing the ALREADY-PUBLISHED
    .info text. wish's .info wire format only ever stores
    depends/provides/conflicts/breaks -- it has never captured Pre-Depends/
    Replaces/Essential/Multi-Arch, so those come back None (not
    comparable) here, same as Fedora candidates. This is a real, current
    limitation of the .info format, not a bug in the comparison: it means
    those four fields can only ever help disambiguate once/if the format
    is extended to store them."""
    return {
        "name": name,
        "architecture": arch,
        "version": version,
        "depends": _normalize_dep_groups_semantic(parse_dep_field(_get_raw_field(info_text, "depends"))),
        "pre_depends": None,
        "provides": _normalize_provides_semantic(
            [p.strip() for p in _get_raw_field(info_text, "provides").split(",") if p.strip()]),
        "conflicts": _normalize_dep_groups_semantic(parse_dep_field(_get_raw_field(info_text, "conflicts"))),
        "breaks": _normalize_dep_groups_semantic(parse_dep_field(_get_raw_field(info_text, "breaks"))),
        "replaces": None,
        "essential": None,
        "multi_arch": None,
    }


def load_provenance_manifest(arch, workdir):
    """The provenance manifest published by the last TRUSTED rebuild for
    this arch -- {name: ProvenanceRecord}. Absent on a catalog's first
    ever provenance-tracked rebuild (returns {}), in which case
    verify_continuity() has nothing to check against yet and a fresh
    name+version match stands on its own (see verify_continuity's
    docstring)."""
    tmp = os.path.join(workdir, f"prior-provenance-{arch}.json")
    if not b2_get(f"state/provenance/{arch}.json", tmp):
        return {}
    with open(tmp) as f:
        raw = json.load(f)
    return {name: ProvenanceRecord.from_dict(d) for name, d in raw.items()}


def bulk_fetch_info_and_sha256(arch, workdir):
    """One-time bulk download of every currently-published pkgs/<arch>/
    .info and .wsh.sha256 object, instead of ~1-2 sequential B2 GETs PER
    canonical package during matching. The first real run of this script
    was network-latency-bound: ~10k packages x up to 2 individual small
    GETs each (0.4 pkg/s measured) projected to ~7 hours just for the
    matching phase, blowing well past both the script's own deadline and
    the GitHub Actions job timeout. `aws s3 sync` pulls an entire prefix
    in one parallelized operation; everything after this becomes in-memory
    dict lookups, i.e. CPU-bound, not network-bound.

    Returns (info_map: {name: text}, sha256_map: {wsh_filename: sha256}).
    Gracefully returns ({}, {}) if sync fails (e.g. no B2 credentials in a
    local/dry-run context) -- callers fall back to individual lookups
    returning "no prior content", same as before this optimization."""
    info_dir = os.path.join(workdir, "bulk-info")
    sha_dir = os.path.join(workdir, "bulk-sha256")
    os.makedirs(info_dir, exist_ok=True)
    os.makedirs(sha_dir, exist_ok=True)

    info_map, sha256_map = {}, {}
    try:
        sh(f'aws s3 sync "s3://{B2_BUCKET}/pkgs/{arch}/" "{info_dir}" '
           f'--endpoint-url {B2_ENDPOINT} --exclude "*" --include "*.info" '
           f'--no-progress --only-show-errors')
    except Exception as e:
        print(f"bulk .info sync failed, falling back to per-package GETs: {e}",
              file=sys.stderr, flush=True)
        return info_map, sha256_map
    for fname in os.listdir(info_dir):
        if fname.endswith(".info"):
            with open(os.path.join(info_dir, fname)) as f:
                info_map[fname[:-len(".info")]] = f.read()

    try:
        sh(f'aws s3 sync "s3://{B2_BUCKET}/pkgs/{arch}/" "{sha_dir}" '
           f'--endpoint-url {B2_ENDPOINT} --exclude "*" --include "*.wsh.sha256" '
           f'--no-progress --only-show-errors')
    except Exception as e:
        print(f"bulk .sha256 sync failed, live payload checks will be skipped: {e}",
              file=sys.stderr, flush=True)
        return info_map, sha256_map
    for fname in os.listdir(sha_dir):
        if fname.endswith(".sha256"):
            with open(os.path.join(sha_dir, fname)) as f:
                content = f.read().strip()
            if content:
                sha256_map[fname[:-len(".sha256")]] = content.split()[0]

    print(f"[run] {arch}: bulk-fetched {len(info_map)} .info + "
          f"{len(sha256_map)} .sha256 objects", file=sys.stderr, flush=True)
    return info_map, sha256_map


def stanza_to_record(name, arch, stanza, wsh_filename, payload_sha256,
                      confidence=ProvenanceRecord.CONFIDENCE_VERIFIED):
    return ProvenanceRecord(
        name=name, arch=arch, source_distro=stanza.source_distro,
        suite=stanza.suite, source_arch=stanza.source_arch,
        component=stanza.component, upstream_name=stanza.upstream_name,
        upstream_version=stanza.upstream_version, wsh_filename=wsh_filename,
        payload_sha256=payload_sha256, upstream_filename=stanza.upstream_filename,
        confidence=confidence,
    )


# ---------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------

class CatalogRebuild:
    def __init__(self, arch, workdir, publish=False, keep_orphans=False):
        self.arch = arch
        self.workdir = workdir
        self.publish = publish
        # keep_orphans=True skips the quarantine-move step in _publish() --
        # used for a canary/rollout publish where old objects must stay
        # exactly as they are until the canary is proven clean, per the
        # explicit "do not delete or quarantine old objects yet" directive.
        self.keep_orphans = keep_orphans
        self.report = {
            "arch": arch,
            # "ambiguous_output_conflict": a genuine name+version collision
            # where surviving candidates produce DIFFERENT output --
            # blocks publish. "equivalent_provenance_tie": the same kind
            # of collision, but every surviving candidate produces
            # byte-identical fingerprint+.info -- publish-safe, since the
            # choice is provably irrelevant (see
            # candidates_are_output_equivalent).
            "repaired": {}, "unchanged": {}, "ambiguous_output_conflict": {},
            "equivalent_provenance_tie": {},
            "orphaned": {}, "unresolved": {},
            # "rejected": a unique bootstrap fingerprint match that hit a
            # concrete contradiction (exclusion list, self-inconsistent
            # filename) -- distinct from "ambiguous_output_conflict"
            # (genuine multi-match ties with differing output) and from
            # "invalid_provides" (a different rejection: a provides target
            # that isn't a canonical package at all).
            "rejected": {},
            "invalid_provides": {},
            "continuity_mismatches": {},
            "bootstrap_matched": {},
        }
        self.staged_info = {}     # name -> new .info text
        self.provides_index = {} # virtual -> set(real names)
        self.new_manifest = {}    # name -> ProvenanceRecord, for RESOLVED-and-verified packages
        self.prior_manifest = {}  # name -> ProvenanceRecord, loaded from the last trusted rebuild
        self.canonical_versions = {}
        self.info_map = {}        # name -> current .info text, bulk-fetched once (see bulk_fetch_info_and_sha256)
        self.sha256_map = {}      # wsh_filename -> live sha256, bulk-fetched once
        self.stanzas = []          # every scanned upstream stanza (any distro, canonical or not) -- kept for classify_unresolved_dependencies
        self.unresolved_deps_full = []  # (name, group) for every unresolved dependency group -- see _validate_dependencies

    def _bump(self, bucket, distro):
        self.report[bucket][distro] = self.report[bucket].get(distro, 0) + 1

    def run(self):
        t_start = time.monotonic()
        canonical_versions = load_canonical_versions(self.arch, self.workdir)
        self.canonical_versions = canonical_versions
        canonical_names = set(canonical_versions)
        print(f"[run] {len(canonical_names)} canonical packages for {self.arch}",
              file=sys.stderr, flush=True)

        stanzas = scan_all_stanzas(self.arch)
        self.stanzas = stanzas

        print(f"[run] bulk-fetching current .info/.sha256 objects for {self.arch}...",
              file=sys.stderr, flush=True)
        self.info_map, self.sha256_map = bulk_fetch_info_and_sha256(self.arch, self.workdir)

        print(f"[run] loading prior provenance manifest for {self.arch}...",
              file=sys.stderr, flush=True)
        self.prior_manifest = load_provenance_manifest(self.arch, self.workdir)
        print(f"[run] {len(self.prior_manifest)} prior provenance records loaded",
              file=sys.stderr, flush=True)

        manifest = build_provenance_manifest(canonical_versions, stanzas, self.arch)
        print(f"[run] matching {len(manifest)} canonical packages against "
              f"{len(stanzas)} upstream stanzas -- this does one or two B2 GETs "
              f"per RESOLVED package (current .info + live .wsh.sha256), so it "
              f"is the slowest phase", file=sys.stderr, flush=True)

        bootstrap_excluded = self._load_bootstrap_exclusions()
        print(f"[run] {len(bootstrap_excluded)} package(s) excluded from "
              f"bootstrap live-info matching (known-contaminated/manually-"
              f"repaired list)", file=sys.stderr, flush=True)

        processed = 0
        deadline_stopped = False
        for name, result in manifest.items():
            if deadline_hit():
                deadline_stopped = True
                print(f"[run] {self.arch}: deadline reached at {processed}/"
                      f"{len(manifest)} -- stopping the matching pass cleanly "
                      f"(everything already matched stays valid; the rest "
                      f"reports as unresolved this run)", file=sys.stderr, flush=True)
                break
            processed += 1
            if processed % 250 == 0:
                elapsed = time.monotonic() - t_start
                rate = processed / elapsed if elapsed > 0 else 0
                remaining = len(manifest) - processed
                eta_s = remaining / rate if rate > 0 else float("inf")
                print(f"[run] {self.arch}: {processed}/{len(manifest)} matched "
                      f"({elapsed:.0f}s elapsed, {rate:.1f} pkg/s, "
                      f"~{eta_s / 60:.0f}min remaining) -- "
                      f"repaired={sum(self.report['repaired'].values())} "
                      f"unchanged={sum(self.report['unchanged'].values())} "
                      f"unresolved={sum(self.report['unresolved'].values())} "
                      f"ambiguous={sum(self.report['ambiguous_output_conflict'].values())}",
                      file=sys.stderr, flush=True)
            if result.status == ProvenanceResult.UNRESOLVED:
                self._bump("unresolved", "unknown")
                continue
            if result.status == ProvenanceResult.AMBIGUOUS:
                # Genuinely ambiguous by name+version+arch alone -- before
                # even reaching for live-info evidence, check whether it
                # actually matters: if EVERY surviving candidate renders
                # byte-identical semantic fingerprint AND .info text (see
                # candidates_are_output_equivalent), then no source needs
                # to be proven -- the published output is provably the
                # same no matter which candidate "wins". This is a
                # distinct claim from bootstrap matching below: it makes
                # no assertion about which upstream produced the payload,
                # only that the choice is irrelevant to what gets
                # published. Recorded as CONFIDENCE_EQUIVALENT_TIE with
                # the full tied candidate set kept in the manifest, never
                # collapsed into a single unproven source.
                if candidates_are_output_equivalent(
                        result.candidates, semantic_fingerprint_from_stanza,
                        render_info_from_stanza):
                    chosen = sorted(
                        result.candidates,
                        key=lambda c: (c.source_distro, c.suite, c.component,
                                        c.upstream_version,
                                        c.upstream_filename or ""))[0]
                    live_sha256 = self._fetch_live_payload_sha256(name)
                    prior_record = self.prior_manifest.get(name)
                    if not verify_continuity(chosen, prior_record, live_sha256):
                        self._bump("unresolved", "equivalent-tie-continuity-mismatch")
                        self._bump("continuity_mismatches", "equivalent-tie")
                        continue
                    wsh_filename = self._current_wsh_filename(name, canonical_versions[name])
                    record = stanza_to_record(
                        name, self.arch, chosen, wsh_filename, live_sha256,
                        confidence=ProvenanceRecord.CONFIDENCE_EQUIVALENT_TIE)
                    record.equivalent_candidates = [
                        {"source_distro": c.source_distro, "suite": c.suite,
                         "source_arch": c.source_arch, "component": c.component,
                         "upstream_name": c.upstream_name,
                         "upstream_version": c.upstream_version}
                        for c in result.candidates
                    ]
                    self.new_manifest[name] = record
                    self.staged_info[name] = render_info_from_stanza(chosen)
                    self._bump("equivalent_provenance_tie",
                               ",".join(sorted({c.source_distro for c in result.candidates})))
                    continue

                # Still genuinely ambiguous -- try bootstrap disambiguation
                # via a semantic identity+relationship fingerprint against
                # the already-live .info (see
                # tools/provenance.try_bootstrap_match).
                # This is NOT a guess: it only accepts when exactly one
                # candidate's normalized depends/pre-depends/provides/
                # conflicts/breaks/replaces/essential/multi-arch fields
                # match what's already published -- free-text fields like
                # description are deliberately excluded (they're what made
                # an earlier byte-for-byte attempt match almost nothing:
                # real provenance, but wording drift). Classification is
                # purely evidence-based (zero matches -> unresolved, one
                # match -> accepted, multiple -> still ambiguous); rejection
                # only ever happens for concrete contradictions (known-
                # contaminated exclusion list, a filename that doesn't
                # self-consistently name its own package, or -- checked
                # just below, same as for normally-verified matches -- a
                # conflict with the prior trusted manifest).
                live_info = self._fetch_current_info(name)
                live_fingerprint = (
                    semantic_fingerprint_from_live_info(
                        name, self.arch, canonical_versions[name], live_info)
                    if live_info is not None else None)
                bootstrap_result = try_bootstrap_match(
                    name, result.candidates, live_fingerprint, bootstrap_excluded,
                    semantic_fingerprint_from_stanza)

                if bootstrap_result.status == BootstrapMatchResult.UNRESOLVED:
                    self._bump("unresolved", "bootstrap-no-match")
                    continue
                if bootstrap_result.status == BootstrapMatchResult.AMBIGUOUS:
                    distros = ",".join(sorted({c.source_distro for c in result.candidates}))
                    self._bump("ambiguous_output_conflict", distros)
                    continue
                if bootstrap_result.status == BootstrapMatchResult.REJECTED:
                    # A concrete contradiction, not a mere tie -- tracked
                    # separately from "ambiguous_output_conflict" so the
                    # repair report (and the publish gate below) can name
                    # the actual reason.
                    rejected_distro = (bootstrap_result.stanza.source_distro
                                        if bootstrap_result.stanza else "unknown")
                    self._bump("rejected", rejected_distro)
                    continue

                # ACCEPTED by fingerprint -- still subject to the same
                # continuity check a normally-resolved match gets: a
                # conflict with the prior TRUSTED manifest (different
                # source, different filename, different payload hash) is a
                # concrete contradiction, not mere distro presence in the
                # pool, so it still fails closed here.
                bootstrap_stanza = bootstrap_result.stanza
                live_sha256 = self._fetch_live_payload_sha256(name)
                prior_record = self.prior_manifest.get(name)
                if not verify_continuity(bootstrap_stanza, prior_record, live_sha256):
                    self._bump("unresolved", "bootstrap-continuity-mismatch")
                    self._bump("continuity_mismatches", "bootstrap")
                    continue

                # Bootstrap-accepted: content already matches live, so this
                # is definitionally "unchanged" -- staged for the provides
                # rebuild same as any resolved package, but recorded with
                # the weaker CONFIDENCE_BOOTSTRAP tier, never verified.
                wsh_filename = self._current_wsh_filename(name, canonical_versions[name])
                self.new_manifest[name] = stanza_to_record(
                    name, self.arch, bootstrap_stanza, wsh_filename, live_sha256,
                    confidence=bootstrap_result.confidence)
                self.staged_info[name] = live_info
                self._bump("bootstrap_matched", bootstrap_stanza.source_distro)
                continue
            # RESOLVED by name+version+arch -- now strengthen with
            # filename/checksum continuity where available (item: "verify
            # the original upstream filename and payload checksum, not
            # only sanitized name/version/suite/architecture"). A stanza
            # that can't prove continuity against prior trusted provenance
            # is downgraded to UNRESOLVED -- fail closed, never guess.
            stanza = result.stanza
            live_sha256 = self._fetch_live_payload_sha256(name)
            prior_record = self.prior_manifest.get(name)
            if not verify_continuity(stanza, prior_record, live_sha256):
                self._bump("unresolved", "continuity-mismatch")
                self._bump("continuity_mismatches", "resolved")
                continue

            new_info = render_info_from_stanza(stanza)
            old_info = self._fetch_current_info(name)
            wsh_filename = self._current_wsh_filename(name, canonical_versions[name])
            self.new_manifest[name] = stanza_to_record(
                name, self.arch, stanza, wsh_filename, live_sha256)
            if old_info is not None and old_info == new_info:
                self._bump("unchanged", stanza.source_distro)
                self.staged_info[name] = new_info  # still needed for provides rebuild
            else:
                self._bump("repaired", stanza.source_distro)
                self.staged_info[name] = new_info

        elapsed = time.monotonic() - t_start
        print(f"[run] {self.arch}: matching pass done ({processed} packages, "
              f"{elapsed:.0f}s) -- repaired={sum(self.report['repaired'].values())} "
              f"unchanged={sum(self.report['unchanged'].values())} "
              f"unresolved={sum(self.report['unresolved'].values())} "
              f"ambiguous={sum(self.report['ambiguous_output_conflict'].values())}",
              file=sys.stderr, flush=True)

        # Step 4: rebuild provides index from ALL staged info (repaired +
        # unchanged) -- packages that stayed unresolved/ambiguous keep
        # whatever provides they already had live (we never touched them),
        # so fold those in too, unless they don't even have a live .info.
        print(f"[run] {self.arch}: rebuilding provides index from "
              f"{len(canonical_names)} canonical packages' metadata...",
              file=sys.stderr, flush=True)
        for i, name in enumerate(canonical_names, 1):
            if i % 2000 == 0:
                print(f"[run] {self.arch}: provides scan {i}/{len(canonical_names)}",
                      file=sys.stderr, flush=True)
            if name in self.staged_info:
                text = self.staged_info[name]
            else:
                text = self._fetch_current_info(name)
                if text is None:
                    continue
            for virtual in parse_info_provides(text):
                self.provides_index.setdefault(virtual, set()).add(name)
        print(f"[run] {self.arch}: provides index has {len(self.provides_index)} "
              f"virtual names", file=sys.stderr, flush=True)

        # Step 8: every provides target must be canonical.
        bad_provides = {v: r for v, r in self.provides_index.items()
                         if not (r & canonical_names)}
        for virtual, reals in bad_provides.items():
            self._bump("invalid_provides", virtual)
            del self.provides_index[virtual]

        # Step 9: classify every literal dependency across all staged info.
        print(f"[run] {self.arch}: classifying dependencies...", file=sys.stderr, flush=True)
        dep_report = self._validate_dependencies(canonical_names)
        print(f"[run] {self.arch}: dependency classes: "
              f"literal={dep_report['literal']} virtual={dep_report['virtual']} "
              f"excluded={dep_report['excluded']} unresolved={dep_report['unresolved']}",
              file=sys.stderr, flush=True)

        # Step 7: orphan sweep.
        print(f"[run] {self.arch}: sweeping for orphan objects...", file=sys.stderr, flush=True)
        orphans = self._find_orphans(canonical_names)
        print(f"[run] {self.arch}: {len(orphans)} orphan object(s) found",
              file=sys.stderr, flush=True)
        for _ in orphans:
            self._bump("orphaned", "unknown")

        self.report["dependency_classes"] = dep_report
        self.report["orphan_objects"] = orphans
        self.report["provides_pairs"] = sum(len(v) for v in self.provides_index.values())
        self.report["deadline_stopped"] = deadline_stopped

        # Step 11: publish gate -- STRICT. Publishing is allowed only when
        # EVERY canonical package has exactly one proven provenance match
        # and a staged .info, every provider target exists, and every
        # dependency classifies as literal/virtual/excluded. Any ambiguous
        # or unresolved canonical package, or any unclassified dependency,
        # blocks the ENTIRE publish -- not just that one package. This is
        # deliberately strict: "skip and report" is not sufficient, because
        # an old (possibly contaminated) .info stays live for that package
        # regardless of what the rest of the run did, and this repair
        # exists specifically to stop trusting metadata that can't be
        # proven. A partially-clean catalog is not published; the repair
        # report is still produced either way so unresolved/ambiguous
        # packages are visible and actionable before the next attempt.
        blockers = self._publish_blockers(canonical_names, stanzas, dep_report)
        self.report["publish_blockers"] = blockers
        self.report["published"] = bool(self.publish and not blockers)
        if self.publish:
            if blockers:
                print(f"REFUSING to publish ({len(blockers)} blocker(s)): "
                      f"{blockers[:10]}{'...' if len(blockers) > 10 else ''}",
                      file=sys.stderr)
            else:
                self._publish(orphans)

        return self.report

    def _publish_blockers(self, canonical_names, stanzas, dep_report):
        """Every reason publish must be refused. Two kinds:

        Run-level sanity failures (an empty canonical set or empty stanza
        scan looks like an auth/fetch failure, not a clean catalog --
        publishing in that state would look like "everything is
        unresolved" instead of failing loudly), AND

        Per-package coverage gaps: ANY ambiguous or unresolved canonical
        package, or any unresolved (unclassified) dependency, blocks
        publishing the WHOLE catalog -- not just that package. See run()'s
        comment on why "skip and report" isn't good enough here."""
        blockers = []
        if not canonical_names:
            blockers.append("zero canonical packages loaded for this arch "
                             "(index fetch or B2 auth likely failed)")
        if not stanzas:
            blockers.append("zero upstream stanzas scanned across all distros "
                             "(upstream fetch likely failed entirely)")
        if canonical_names and not self.staged_info:
            blockers.append("zero packages resolved out of a non-empty "
                             "canonical index (matching logic likely broken)")
        if self.report.get("deadline_stopped"):
            blockers.append("the matching pass hit its own deadline before "
                             "covering every canonical package -- an "
                             "incomplete pass must never publish (packages "
                             "past the cutoff would look like new "
                             "unresolved regressions instead of simply "
                             "'not reached yet')")

        ambiguous_count = sum(self.report["ambiguous_output_conflict"].values())
        if ambiguous_count:
            blockers.append(f"{ambiguous_count} canonical package(s) have "
                             f"ambiguous provenance -- must be resolved "
                             f"before publish, not skipped")
        unresolved_count = sum(self.report["unresolved"].values())
        if unresolved_count:
            blockers.append(f"{unresolved_count} canonical package(s) have "
                             f"no proven provenance (or failed continuity "
                             f"verification) -- must be resolved before "
                             f"publish, not skipped")
        rejected_count = sum(self.report["rejected"].values())
        if rejected_count:
            blockers.append(f"{rejected_count} canonical package(s) had a "
                             f"unique bootstrap fingerprint match rejected "
                             f"for a concrete contradiction (exclusion list "
                             f"or self-inconsistent upstream filename) -- "
                             f"must be resolved before publish, not skipped")
        invalid_provides_count = sum(self.report["invalid_provides"].values())
        if invalid_provides_count:
            blockers.append(f"{invalid_provides_count} provides target(s) "
                             f"do not resolve to any canonical package -- "
                             f"every provider target must exist before "
                             f"publish")
        continuity_count = sum(self.report["continuity_mismatches"].values())
        if continuity_count:
            blockers.append(f"{continuity_count} package(s) failed "
                             f"continuity verification against the prior "
                             f"trusted provenance manifest -- a name+version "
                             f"match alone is not enough")
        dep_unresolved = dep_report.get("unresolved", 0)
        if dep_unresolved:
            blockers.append(f"{dep_unresolved} dependency group(s) are not "
                             f"classified as literal/virtual/excluded -- "
                             f"every dependency must resolve to one of "
                             f"those three before publish")
        return blockers

    def _fetch_current_info(self, name):
        # Served from the bulk-fetched map (see bulk_fetch_info_and_sha256)
        # -- one aws s3 sync at the start of run() instead of a B2 GET per
        # package. Falls back to an individual GET only if the bulk map
        # came back empty (e.g. the sync itself failed), so this still
        # degrades gracefully rather than silently treating "sync failed"
        # as "nothing has a .info yet".
        if name in self.info_map:
            return self.info_map[name]
        if self.info_map:
            return None
        tmp = os.path.join(self.workdir, f"cur-{name}.info")
        key = f"pkgs/{self.arch}/{name}.info"
        if b2_get(key, tmp):
            with open(tmp) as f:
                return f.read()
        return None

    def _current_wsh_filename(self, name, version):
        # release is always "1" in this catalog's naming convention (see
        # every mirror script's process_package()) -- reconstructed rather
        # than fetched since the canonical index line already told us
        # name+version and this format is a fixed convention, not
        # per-package data.
        return f"{name}-{version}-1-{self.arch}.wsh"

    def _fetch_live_payload_sha256(self, name):
        """The sha256 currently published in this package's own
        .wsh.sha256 -- used, where available, as continuity evidence (see
        verify_continuity). Served from the bulk-fetched map (see
        bulk_fetch_info_and_sha256); falls back to an individual GET only
        if that map came back empty."""
        version = self.canonical_versions.get(name)
        if version is None:
            return None
        wsh_filename = self._current_wsh_filename(name, version)
        if wsh_filename in self.sha256_map:
            return self.sha256_map[wsh_filename]
        if self.sha256_map:
            return None
        tmp = os.path.join(self.workdir, f"sha-{wsh_filename}.sha256")
        key = f"pkgs/{self.arch}/{wsh_filename}.sha256"
        if b2_get(key, tmp):
            with open(tmp) as f:
                content = f.read().strip()
            return content.split()[0] if content else None
        return None

    def _validate_dependencies(self, canonical_names):
        """Every literal dependency group must classify as exactly one of:
        literal (a name in the group is itself canonical), virtual
        (satisfied only via a provides target), excluded (deliberately
        listed in state/excluded-deps.txt), or unresolved. Unresolved is
        the ONLY blocking class -- see _publish_blockers, which refuses to
        publish at all while this count is nonzero (an unclassified
        dependency is exactly the kind of unproven state this rewrite
        exists to stop shipping)."""
        excluded = self._load_excluded()
        classes = {"literal": 0, "virtual": 0, "excluded": 0, "unresolved": 0}
        unresolved_examples = []
        # Full, uncapped list of every unresolved (package, OR-group) pair
        # -- unresolved_examples above is capped at 200 for a readable
        # report, but classify_unresolved_dependencies() needs the whole
        # set to root-cause every one of them, not just a sample.
        self.unresolved_deps_full = []
        for name, text in self.staged_info.items():
            for group in parse_info_depends(text):
                if any(a in canonical_names for a in group):
                    classes["literal"] += 1
                    continue
                if any(a in self.provides_index for a in group):
                    classes["virtual"] += 1
                    continue
                if any(a in excluded for a in group):
                    classes["excluded"] += 1
                    continue
                classes["unresolved"] += 1
                self.unresolved_deps_full.append((name, group))
                if len(unresolved_examples) < 200:
                    unresolved_examples.append(f"{name}: {'|'.join(group)}")
        classes["unresolved_examples"] = unresolved_examples
        return classes

    def _load_excluded(self):
        tmp = os.path.join(self.workdir, "excluded-deps.txt")
        if b2_get("state/excluded-deps.txt", tmp):
            with open(tmp) as f:
                return {l.strip() for l in f if l.strip()}
        return set()

    def _load_bootstrap_exclusions(self):
        """Package names that must NEVER go through bootstrap live-info
        matching -- known-contaminated (e.g. anything the cross-distro
        backfill version-mismatch incident touched) or manually-repaired
        packages, whose live .info might itself be exactly the kind of
        content a bootstrap match would wrongly treat as trustworthy
        corroboration. Maintained at state/bootstrap-excluded.txt (one
        canonical name per line, '#' comments allowed); empty/absent is
        valid (no exclusions yet known)."""
        tmp = os.path.join(self.workdir, "bootstrap-excluded.txt")
        if b2_get("state/bootstrap-excluded.txt", tmp):
            with open(tmp) as f:
                return {l.strip() for l in f if l.strip() and not l.startswith("#")}
        return set()

    def _find_orphans(self, canonical_names):
        """Lists every object under pkgs/<arch>/ and flags any whose
        package name isn't canonical. Requires B2 list access (aws s3
        ls) -- skipped gracefully (returns []) if that fails, e.g. no
        credentials in a local/dry-run context."""
        prefix = f"pkgs/{self.arch}/"
        try:
            r = subprocess.run(
                f'aws s3 ls "s3://{B2_BUCKET}/{prefix}" --endpoint-url {B2_ENDPOINT}',
                shell=True, capture_output=True, text=True, check=True)
        except Exception as e:
            print(f"orphan sweep skipped (no list access): {e}", file=sys.stderr)
            return []
        orphans = []
        for line in r.stdout.splitlines():
            parts = line.split()
            if not parts:
                continue
            fname = parts[-1]
            if fname.endswith(".info"):
                name = fname[:-len(".info")]
            elif fname.endswith(".wsh.sha256"):
                name = parse_name_from_index_line(fname[:-len(".sha256")])
            elif fname.endswith(".wsh"):
                name = parse_name_from_index_line(fname)
            else:
                continue
            if name and name not in canonical_names:
                orphans.append(prefix + fname)
        return orphans

    def _snapshot_live_state(self):
        """Copies the complete current live state for this arch -- every
        .info under pkgs/<arch>/, the canonical index, the provides index,
        and the provenance manifest -- to a timestamped snapshot/<arch>/
        <generation>/ prefix, BEFORE anything staged is uploaded or any
        live key is touched. This is the rollback point: the previous live
        generation stays fully intact and fetchable even after publish,
        since publish only ever overwrites pkgs/<arch>/*.info and the two
        index/manifest objects in place, never deletes anything. Uses
        server-side S3 copy (source and dest are both s3:// URIs) so this
        never round-trips the ~16k .info objects through local disk."""
        generation = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        snapshot_prefix = f"snapshot/{self.arch}/{generation}/"
        print(f"[publish] snapshotting live state for {self.arch} to "
              f"{snapshot_prefix} before touching anything...",
              file=sys.stderr, flush=True)
        sh(f'aws s3 sync "s3://{B2_BUCKET}/pkgs/{self.arch}/" '
           f'"s3://{B2_BUCKET}/{snapshot_prefix}pkgs/{self.arch}/" '
           f'--exclude "*" --include "*.info" '
           f'--endpoint-url {B2_ENDPOINT} --no-progress')
        sh(f'aws s3 cp "s3://{B2_BUCKET}/index/{self.arch}.txt" '
           f'"s3://{B2_BUCKET}/{snapshot_prefix}index/{self.arch}.txt" '
           f'--endpoint-url {B2_ENDPOINT} --no-progress')
        sh(f'aws s3 cp "s3://{B2_BUCKET}/index/{self.arch}-provides.txt" '
           f'"s3://{B2_BUCKET}/{snapshot_prefix}index/{self.arch}-provides.txt" '
           f'--endpoint-url {B2_ENDPOINT} --no-progress')
        sh(f'aws s3 cp "s3://{B2_BUCKET}/state/provenance/{self.arch}.json" '
           f'"s3://{B2_BUCKET}/{snapshot_prefix}state/provenance/{self.arch}.json" '
           f'--endpoint-url {B2_ENDPOINT} --no-progress')
        print(f"[publish] snapshot complete: {snapshot_prefix}",
              file=sys.stderr, flush=True)
        self.report["snapshot_prefix"] = snapshot_prefix
        return snapshot_prefix

    def _publish(self, orphans):
        # Only ever called after run() has fully computed the report AND
        # the strict gate in _publish_blockers found nothing to block on
        # -- every canonical package resolved, every provides target is
        # canonical, every dependency classified.
        #
        # NOT a true atomic commit. The preferred design is generation-
        # scoped staging plus a single active-generation pointer that CDN
        # reads flip through (e.g. clients resolve pkgs/<arch>/<name>.info
        # via a redirect/rewrite layer keyed on a current-generation
        # pointer object) -- that requires a change to how cdn.wishpkgs.org
        # serves requests (a Cloudflare Worker rewrite layer), which is
        # out of this script's scope and not implemented here. What IS
        # implemented is the minimum safety bar: the ENTIRE new catalog
        # (every .info this run touched, plus the rebuilt provides index)
        # is written in full to a staging prefix FIRST and verified there
        # before a single LIVE key is overwritten. This bounds the damage
        # of a mid-publish crash to "some live .info files got the new,
        # already-verified-correct content, the rest still have their old
        # content" -- it can never leave a live object partially written,
        # and it never touches live content while the staged catalog is
        # still incomplete or unverified.
        self._snapshot_live_state()

        staging_prefix = f"staging/{self.arch}/pkgs/"
        staged_keys = []
        for name, text in self.staged_info.items():
            tmp = os.path.join(self.workdir, f"stage-{name}.info")
            with open(tmp, "w") as f:
                f.write(text)
            key = f"{staging_prefix}{name}.info"
            b2_cp(tmp, key)
            staged_keys.append((name, key))

        provides_tmp = os.path.join(self.workdir, "provides-rebuilt.txt")
        with open(provides_tmp, "w") as f:
            for virtual in sorted(self.provides_index):
                for real in sorted(self.provides_index[virtual]):
                    f.write(f"{virtual} {real}\n")
        provides_staging_key = f"staging/{self.arch}/provides.txt"
        b2_cp(provides_tmp, provides_staging_key)

        # Verify every staged object round-trips before touching anything
        # live -- a failed/partial upload here aborts the whole publish
        # with nothing live touched yet.
        for name, key in staged_keys:
            check_tmp = os.path.join(self.workdir, f"verify-{name}.info")
            if not b2_get(key, check_tmp):
                raise RuntimeError(
                    f"staged object {key} did not round-trip -- aborting "
                    f"publish before any live key was touched")
            with open(check_tmp) as f:
                if f.read() != self.staged_info[name]:
                    raise RuntimeError(
                        f"staged object {key} content mismatch on "
                        f"verification -- aborting publish before any "
                        f"live key was touched")

        # Only now, with the complete staged catalog verified, overwrite
        # live .info keys.
        for name, text in self.staged_info.items():
            tmp = os.path.join(self.workdir, f"pub-{name}.info")
            with open(tmp, "w") as f:
                f.write(text)
            b2_cp(tmp, f"pkgs/{self.arch}/{name}.info")

        # The provides index and the provenance manifest are the closest
        # thing this design has to a commit point (small, single-object
        # writes clients/future runs treat as the source of truth) --
        # written last, after every .info is already live.
        b2_cp(provides_tmp, f"index/{self.arch}-provides.txt")

        manifest_tmp = os.path.join(self.workdir, "new-provenance-manifest.json")
        with open(manifest_tmp, "w") as f:
            json.dump({name: rec.to_dict() for name, rec in self.new_manifest.items()},
                       f, indent=2, sort_keys=True)
        b2_cp(manifest_tmp, f"state/provenance/{self.arch}.json")

        if self.keep_orphans:
            print(f"[publish] keep_orphans set -- leaving {len(orphans)} "
                  f"orphan object(s) exactly as they are, not quarantining "
                  f"this run", file=sys.stderr, flush=True)
        else:
            for key in orphans:
                dest = "quarantine/" + key[len("pkgs/"):] if key.startswith("pkgs/") else "quarantine/" + key
                sh(f'aws s3 mv "s3://{B2_BUCKET}/{key}" "s3://{B2_BUCKET}/{dest}" '
                   f'--endpoint-url {B2_ENDPOINT}')


def diagnose_ambiguous(arch, sample_size, out_path):
    """Explains WHY packages are landing as ambiguous, instead of guessing.
    Runs only the scan + name/version matching (no per-package .info/
    .sha256 fetches -- those are irrelevant to *why* multiple candidates
    survived the name+version match, and skipping them keeps this fast
    enough to run standalone against production). For the first
    `sample_size` ambiguous canonical packages, dumps every candidate's
    full identity (source distro/suite/component/arch, upstream name,
    upstream version, sanitized version, upstream filename) side by side
    so the actual colliding field(s) are visible instead of assumed."""
    canonical_versions = load_canonical_versions(arch, tempfile.mkdtemp())
    print(f"[diagnose] {len(canonical_versions)} canonical packages for {arch}",
          file=sys.stderr, flush=True)
    stanzas = scan_all_stanzas(arch)
    manifest = build_provenance_manifest(canonical_versions, stanzas, arch)

    samples = []
    for name, result in manifest.items():
        if result.status != ProvenanceResult.AMBIGUOUS:
            continue
        version = canonical_versions[name]
        candidates = [
            {
                "source_distro": c.source_distro,
                "suite": c.suite,
                "source_arch": c.source_arch,
                "component": c.component,
                "upstream_name": c.upstream_name,
                "upstream_version": c.upstream_version,
                "sanitized_version": c.sanitized_version,
                "upstream_filename": c.upstream_filename,
            }
            for c in result.candidates
        ]
        # Which fields are actually identical across every candidate --
        # this is the direct answer to "why do multiple candidates
        # survive": whatever's listed here is what the current match key
        # (name+version) cannot distinguish between them on.
        keys = candidates[0].keys()
        equal_fields = [k for k in keys if len({c[k] for c in candidates}) == 1]
        samples.append({
            "name": name, "canonical_version": version,
            "equal_fields": equal_fields, "candidates": candidates,
        })
        if len(samples) >= sample_size:
            break

    total_ambiguous = sum(1 for r in manifest.values()
                           if r.status == ProvenanceResult.AMBIGUOUS)
    out = {
        "arch": arch,
        "total_canonical": len(canonical_versions),
        "total_ambiguous": total_ambiguous,
        "ambiguous_fraction": total_ambiguous / len(canonical_versions) if canonical_versions else 0,
        "samples": samples,
    }
    with open(out_path, "w") as f:
        json.dump(out, f, indent=2, sort_keys=True)
    print(f"[diagnose] {arch}: {total_ambiguous}/{len(canonical_versions)} "
          f"({out['ambiguous_fraction']:.1%}) ambiguous; wrote "
          f"{len(samples)}-package sample to {out_path}", file=sys.stderr, flush=True)
    return out


def evaluate_bootstrap_semantic(arch, sample_size, out_path):
    """Dry-run evaluation of the semantic-fingerprint bootstrap mechanism
    against a SAMPLE of real ambiguous packages, before trusting it against
    the whole catalog. For each sampled ambiguous package: calls the exact
    same try_bootstrap_match() the real run uses, and buckets the outcome
    by its evidence-based status -- accepted / unresolved (zero matches) /
    ambiguous (multiple matches) / rejected (one match, but a concrete
    contradiction: excluded, or a self-inconsistent filename). "False
    matches" have no automatic ground truth -- every ACCEPTED match's full
    candidate identity (source distro/suite/component/version) is
    reported in full for manual audit, not just a count."""
    workdir = tempfile.mkdtemp()
    canonical_versions = load_canonical_versions(arch, workdir)
    print(f"[evaluate] {len(canonical_versions)} canonical packages for {arch}",
          file=sys.stderr, flush=True)
    stanzas = scan_all_stanzas(arch)
    info_map, _ = bulk_fetch_info_and_sha256(arch, workdir)
    print(f"[evaluate] {len(info_map)} live .info objects bulk-fetched",
          file=sys.stderr, flush=True)
    manifest = build_provenance_manifest(canonical_versions, stanzas, arch)

    buckets = {"accepted": [], "unresolved": [], "ambiguous": [], "rejected": []}
    checked = 0
    for name, result in manifest.items():
        if result.status != ProvenanceResult.AMBIGUOUS:
            continue
        if checked >= sample_size:
            break
        checked += 1

        live_info = info_map.get(name)
        live_fp = (semantic_fingerprint_from_live_info(
                       name, arch, canonical_versions[name], live_info)
                   if live_info is not None else None)
        candidates = result.candidates

        bootstrap_result = try_bootstrap_match(
            name, candidates, live_fp, set(), semantic_fingerprint_from_stanza)

        detail = {
            "name": name, "canonical_version": canonical_versions[name],
            "candidate_count": len(candidates),
            "candidate_distros": sorted({c.source_distro for c in candidates}),
            "status": bootstrap_result.status,
            "reason": bootstrap_result.reason,
        }
        if bootstrap_result.status == BootstrapMatchResult.ACCEPTED:
            m = bootstrap_result.stanza
            detail["accepted_distro"] = m.source_distro
            detail["accepted_suite"] = m.suite
            detail["accepted_component"] = m.component
            detail["accepted_upstream_version"] = m.upstream_version
            detail["confidence"] = bootstrap_result.confidence
            buckets["accepted"].append(detail)
        elif bootstrap_result.status == BootstrapMatchResult.UNRESOLVED:
            buckets["unresolved"].append(detail)
        elif bootstrap_result.status == BootstrapMatchResult.AMBIGUOUS:
            buckets["ambiguous"].append(detail)
        else:
            detail["rejected_candidate_distro"] = (
                bootstrap_result.stanza.source_distro if bootstrap_result.stanza else None)
            buckets["rejected"].append(detail)

    out = {
        "arch": arch,
        "sample_size_requested": sample_size,
        "sample_size_checked": checked,
        "accepted": len(buckets["accepted"]),
        "unresolved": len(buckets["unresolved"]),
        "ambiguous": len(buckets["ambiguous"]),
        "rejected": len(buckets["rejected"]),
        "accepted_detail": buckets["accepted"],
        "unresolved_detail": buckets["unresolved"][:30],
        "ambiguous_detail": buckets["ambiguous"][:30],
        "rejected_detail": buckets["rejected"],
    }
    with open(out_path, "w") as f:
        json.dump(out, f, indent=2, sort_keys=True)
    print(f"[evaluate] {arch}: of {checked} sampled ambiguous packages -- "
          f"accepted={len(buckets['accepted'])} "
          f"unresolved={len(buckets['unresolved'])} "
          f"ambiguous={len(buckets['ambiguous'])} "
          f"rejected={len(buckets['rejected'])}; "
          f"wrote {out_path}", file=sys.stderr, flush=True)
    return out


def classify_orphans(arch, out_path):
    """Read-only: lists every object under pkgs/<arch>/, classifies each
    orphan NAME (no matching canonical index entry) by which of its
    .info/.wsh/.wsh.sha256 siblings actually exist, and totals their
    storage size. Deliberately does NOT quarantine or delete anything --
    this is purely for deciding what to do with each pattern before any
    destructive action, per the request to classify aarch64's orphans
    (1018 found, vs x86_64's 33 -- a large enough gap to want a breakdown,
    not a blind sweep) before touching them."""
    workdir = tempfile.mkdtemp()
    canonical_versions = load_canonical_versions(arch, workdir)
    canonical_names = set(canonical_versions)

    prefix = f"pkgs/{arch}/"
    r = subprocess.run(
        f'aws s3 ls "s3://{B2_BUCKET}/{prefix}" --endpoint-url {B2_ENDPOINT}',
        shell=True, capture_output=True, text=True, check=True)

    by_name = {}
    for line in r.stdout.splitlines():
        parts = line.split()
        if not parts:
            continue
        fname = parts[-1]
        size_str = parts[-2] if len(parts) >= 4 else None
        if fname.endswith(".info"):
            name, kind = fname[:-len(".info")], "info"
        elif fname.endswith(".wsh.sha256"):
            name, kind = parse_name_from_index_line(fname[:-len(".sha256")]), "sha256"
        elif fname.endswith(".wsh"):
            name, kind = parse_name_from_index_line(fname), "wsh"
        else:
            continue
        if not name:
            continue
        entry = by_name.setdefault(name, {"info": False, "wsh": False,
                                           "sha256": False, "size_bytes": 0})
        entry[kind] = True
        if size_str and size_str.isdigit():
            entry["size_bytes"] += int(size_str)

    orphan_names = {n: v for n, v in by_name.items() if n not in canonical_names}

    pattern_counts = Counter()
    pattern_bytes = Counter()
    pattern_samples = {}
    for name, v in orphan_names.items():
        pattern = f"info={v['info']},wsh={v['wsh']},sha256={v['sha256']}"
        pattern_counts[pattern] += 1
        pattern_bytes[pattern] += v["size_bytes"]
        pattern_samples.setdefault(pattern, []).append(name)

    result = {
        "arch": arch,
        "total_objects_listed": len(by_name),
        "total_canonical_names": len(canonical_names),
        "total_orphan_names": len(orphan_names),
        "total_orphan_bytes": sum(v["size_bytes"] for v in orphan_names.values()),
        "pattern_counts": dict(pattern_counts),
        "pattern_bytes": dict(pattern_bytes),
        "pattern_samples": {p: sorted(names)[:25] for p, names in pattern_samples.items()},
    }
    with open(out_path, "w") as f:
        json.dump(result, f, indent=2, sort_keys=True)
    print(f"[classify-orphans] {arch}: {len(orphan_names)} orphan name(s) across "
          f"{len(by_name)} listed objects -- patterns: {dict(pattern_counts)}",
          file=sys.stderr, flush=True)
    return result


# Heuristic patterns for "this dependency looks like packaging/build
# tooling that was never meant to be an installable runtime dependency."
# This is a CANDIDATE classification only -- it does not read or write
# state/excluded-deps.txt and never excludes anything by itself; a human
# still has to review and add entries there. Kept narrow and pattern-
# based (not a growing name list) so it stays auditable.
_EXCLUDED_DEP_HEURISTIC_RES = [
    re.compile(p) for p in [
        r"^dpkg(-dev)?$", r"^debhelper$", r"^cdbs$", r"^dh-",
        r"^libdpkg-perl$", r"^devscripts$", r"^build-essential$",
        r"^apt(-utils)?$", r"^dpkg-dev$",
        r"^gir1-2-",                       # GObject introspection -dev typelibs
        r"^perlapi-",                      # Perl internal ABI virtual packages
        r".*-i386-cross$",                 # cross-compilation toolchain packages
        r"^rpm(-build)?$", r"^dnf$", r"^yum$",
        r"^pkgconfig$", r"^pkg-config$",
        r"^kernel-devel", r"^kmodtool$", r"^createrepo-c$",
        r"^policycoreutils", r"^selinux-policy",
        r"^systemd-devel",
    ]
]


def _looks_intentionally_excluded(dep_name):
    return any(p.match(dep_name) for p in _EXCLUDED_DEP_HEURISTIC_RES)


def _fuzzy_key(name):
    """Loosened comparison key: strip everything but lowercase alnum, so
    naming-convention noise (dashes vs dots, RPM's soname parens/suffixes,
    duplicate separators) doesn't hide an otherwise-real match. Used ONLY
    to flag normalization_mismatch candidates for human review -- never to
    silently accept a dependency as resolved."""
    return re.sub(r"[^a-z0-9]", "", name.lower())


def classify_unresolved_dependencies(arch, out_path):
    """Root-causes EVERY unresolved dependency group (not a sample) into
    exactly one of:
      - intentionally_excluded_dependency: matches a known packaging/
        build-tool-only naming pattern (see _EXCLUDED_DEP_HEURISTIC_RES).
        A CANDIDATE for state/excluded-deps.txt, not an automatic
        exclusion -- this function never writes that file.
      - missing_literal_package: the exact sanitized name is a real
        upstream package (any distro, any component) that simply isn't
        part of our canonical/mirrored set yet.
      - missing_virtual_provider_mapping: the exact sanitized name is
        something SOME upstream package's Provides: declares, but no
        canonical package currently carries that provides entry (either
        the providing package isn't mirrored, or our provides extraction
        missed a real entry for one that is).
      - normalization_mismatch: neither of the above matched exactly, but
        a punctuation/case-insensitive loosened match against every
        upstream name/provides target DOES find a plausible candidate --
        this is very likely a sanitize_name()/extraction bug, not a real
        gap, and is reported with the matched candidate for verification.
      - genuinely_absent_upstream_package: no candidate found anywhere,
        by any of the above -- the dependency does not appear to exist
        upstream at all (dead/renamed/virtual-implicit package).
    Reuses a full (non-publishing) CatalogRebuild.run() to get the exact
    same unresolved set the real gate would see, then cross-references
    every unique unresolved name against ALL scanned upstream stanzas
    (every distro, whether canonical/mirrored or not) -- not just the
    canonical subset -- since a "missing" dependency's whole point is
    that it may exist upstream without being part of our mirrored set."""
    workdir = tempfile.mkdtemp()
    rebuild = CatalogRebuild(arch, workdir, publish=False)
    rebuild.run()

    all_upstream_names = set()
    all_upstream_provides = set()
    for st in rebuild.stanzas:
        all_upstream_names.add(st.sanitized_name)
        if st.source_distro in ("ubuntu", "debian"):
            groups = parse_dep_field(st.raw.get("Provides", ""))
        elif st.source_distro == "fedora":
            groups = rpm_entries_to_groups(st.raw["provides"])
        else:
            continue
        all_upstream_provides.update(provides_names(groups))

    fuzzy_names = {_fuzzy_key(n): n for n in all_upstream_names}
    fuzzy_provides = {_fuzzy_key(n): n for n in all_upstream_provides}

    # Classify per UNIQUE dependency name (many packages share the same
    # missing dependency -- e.g. hundreds depend on "dpkg-dev") but keep
    # every (package, group) occurrence for accurate counts and examples.
    occurrences = {}  # dep_name -> list of "pkg: alt1|alt2" strings
    for pkg_name, group in rebuild.unresolved_deps_full:
        # A group is only unresolved as a WHOLE -- classify by its first
        # alternative, which is representative for the overwhelming
        # majority of unresolved groups (single-alternative in practice).
        dep_name = group[0]
        occurrences.setdefault(dep_name, []).append(f"{pkg_name}: {'|'.join(group)}")

    buckets = {
        "intentionally_excluded_dependency": {},
        "missing_literal_package": {},
        "missing_virtual_provider_mapping": {},
        "normalization_mismatch": {},
        "genuinely_absent_upstream_package": {},
    }
    for dep_name, examples in occurrences.items():
        if _looks_intentionally_excluded(dep_name):
            bucket = "intentionally_excluded_dependency"
            extra = {}
        elif dep_name in all_upstream_names:
            bucket = "missing_literal_package"
            extra = {}
        elif dep_name in all_upstream_provides:
            bucket = "missing_virtual_provider_mapping"
            extra = {}
        else:
            fk = _fuzzy_key(dep_name)
            candidate = fuzzy_names.get(fk) or fuzzy_provides.get(fk)
            if candidate:
                bucket = "normalization_mismatch"
                extra = {"fuzzy_matched_candidate": candidate}
            else:
                bucket = "genuinely_absent_upstream_package"
                extra = {}
        buckets[bucket][dep_name] = {
            "occurrence_count": len(examples),
            "examples": sorted(examples)[:5],
            **extra,
        }

    summary = {
        bucket: {
            "unique_dependency_names": len(entries),
            "total_occurrences": sum(e["occurrence_count"] for e in entries.values()),
        }
        for bucket, entries in buckets.items()
    }
    out = {
        "arch": arch,
        "total_unresolved_occurrences": len(rebuild.unresolved_deps_full),
        "total_unique_unresolved_names": len(occurrences),
        "summary": summary,
        "buckets": buckets,
    }
    with open(out_path, "w") as f:
        json.dump(out, f, indent=2, sort_keys=True)
    print(f"[classify-deps] {arch}: {len(rebuild.unresolved_deps_full)} unresolved "
          f"occurrence(s), {len(occurrences)} unique name(s) -- {summary}",
          file=sys.stderr, flush=True)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--arch", required=True, choices=["aarch64", "x86_64"])
    ap.add_argument("--publish", action="store_true")
    ap.add_argument("--keep-orphans", action="store_true",
                     help="Skip quarantining orphan objects this run, even "
                          "if publishing -- for a canary/rollout publish "
                          "where old objects must be left exactly as they "
                          "are until the canary is proven clean.")
    ap.add_argument("--report-dir", default=".")
    ap.add_argument("--diagnose-ambiguous", type=int, metavar="N", default=0,
                     help="Instead of a full run, sample N ambiguous packages "
                          "and explain exactly why each is ambiguous, then exit.")
    ap.add_argument("--evaluate-bootstrap", type=int, metavar="N", default=0,
                     help="Instead of a full run, evaluate the semantic-"
                          "fingerprint bootstrap mechanism against N sampled "
                          "ambiguous packages (accepted/zero_match/multi_match/"
                          "contamination_blocked with full detail), then exit. "
                          "Never publishes anything.")
    ap.add_argument("--classify-orphans", action="store_true",
                     help="Instead of a full run, list pkgs/<arch>/ and classify "
                          "orphan objects by which siblings exist, then exit. "
                          "Read-only -- never quarantines or deletes anything.")
    ap.add_argument("--classify-unresolved-deps", action="store_true",
                     help="Instead of a full run, root-cause every unresolved "
                          "dependency group into missing_literal_package/"
                          "missing_virtual_provider_mapping/normalization_"
                          "mismatch/intentionally_excluded_dependency/"
                          "genuinely_absent_upstream_package, then exit. "
                          "Read-only -- never writes state/excluded-deps.txt.")
    args = ap.parse_args()

    if args.diagnose_ambiguous:
        os.makedirs(args.report_dir, exist_ok=True)
        out_path = os.path.join(args.report_dir, f"ambiguous-diagnosis-{args.arch}.json")
        diagnose_ambiguous(args.arch, args.diagnose_ambiguous, out_path)
        return

    if args.evaluate_bootstrap:
        os.makedirs(args.report_dir, exist_ok=True)
        out_path = os.path.join(args.report_dir, f"bootstrap-evaluation-{args.arch}.json")
        evaluate_bootstrap_semantic(args.arch, args.evaluate_bootstrap, out_path)
        return

    if args.classify_orphans:
        os.makedirs(args.report_dir, exist_ok=True)
        out_path = os.path.join(args.report_dir, f"orphan-classification-{args.arch}.json")
        classify_orphans(args.arch, out_path)
        return

    if args.classify_unresolved_deps:
        os.makedirs(args.report_dir, exist_ok=True)
        out_path = os.path.join(args.report_dir, f"unresolved-deps-classification-{args.arch}.json")
        classify_unresolved_dependencies(args.arch, out_path)
        return

    workdir = tempfile.mkdtemp()
    rebuild = CatalogRebuild(args.arch, workdir, publish=args.publish,
                              keep_orphans=args.keep_orphans)
    report = rebuild.run()

    os.makedirs(args.report_dir, exist_ok=True)
    out_path = os.path.join(args.report_dir, f"repair-report-{args.arch}.json")
    with open(out_path, "w") as f:
        json.dump(report, f, indent=2, sort_keys=True, default=list)
    print(f"wrote {out_path}", file=sys.stderr)
    print(json.dumps({k: v for k, v in report.items()
                       if k not in ("orphan_objects", "dependency_classes")},
                      indent=2, default=list), file=sys.stderr)


if __name__ == "__main__":
    main()
