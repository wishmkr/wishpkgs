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
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mirror_common import (
    b2_cp, b2_get, sh, sanitize_name, sanitize_version, is_blocked,
    redact, parse_dep_field, format_dep_field, provides_names,
    rpm_entries_to_groups, load_canonical_versions,
    parse_name_from_index_line, B2_BUCKET, B2_ENDPOINT,
)
from provenance import (
    UpstreamStanza, match_provenance, ProvenanceResult, ProvenanceRecord,
    verify_continuity,
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


def stanza_to_record(name, arch, stanza, wsh_filename, payload_sha256):
    return ProvenanceRecord(
        name=name, arch=arch, source_distro=stanza.source_distro,
        suite=stanza.suite, source_arch=stanza.source_arch,
        component=stanza.component, upstream_name=stanza.upstream_name,
        upstream_version=stanza.upstream_version, wsh_filename=wsh_filename,
        payload_sha256=payload_sha256, upstream_filename=stanza.upstream_filename,
    )


# ---------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------

class CatalogRebuild:
    def __init__(self, arch, workdir, publish=False):
        self.arch = arch
        self.workdir = workdir
        self.publish = publish
        self.report = {
            "arch": arch,
            "repaired": {}, "unchanged": {}, "ambiguous": {},
            "orphaned": {}, "unresolved": {}, "rejected": {},
        }
        self.staged_info = {}     # name -> new .info text
        self.provides_index = {} # virtual -> set(real names)
        self.new_manifest = {}    # name -> ProvenanceRecord, for RESOLVED-and-verified packages
        self.prior_manifest = {}  # name -> ProvenanceRecord, loaded from the last trusted rebuild
        self.canonical_versions = {}

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

        processed = 0
        for name, result in manifest.items():
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
                      f"ambiguous={sum(self.report['ambiguous'].values())}",
                      file=sys.stderr, flush=True)
            if result.status == ProvenanceResult.UNRESOLVED:
                self._bump("unresolved", "unknown")
                continue
            if result.status == ProvenanceResult.AMBIGUOUS:
                distros = ",".join(sorted({c.source_distro for c in result.candidates}))
                self._bump("ambiguous", distros)
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
              f"ambiguous={sum(self.report['ambiguous'].values())}",
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
            self._bump("rejected", "provides:" + virtual)
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

        ambiguous_count = sum(self.report["ambiguous"].values())
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
        dep_unresolved = dep_report.get("unresolved", 0)
        if dep_unresolved:
            blockers.append(f"{dep_unresolved} dependency group(s) are not "
                             f"classified as literal/virtual/excluded -- "
                             f"every dependency must resolve to one of "
                             f"those three before publish")
        return blockers

    def _fetch_current_info(self, name):
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
        verify_continuity). A cheap small-file GET, never a payload
        re-download."""
        version = self.canonical_versions.get(name)
        if version is None:
            return None
        wsh_filename = self._current_wsh_filename(name, version)
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

        for key in orphans:
            dest = "quarantine/" + key[len("pkgs/"):] if key.startswith("pkgs/") else "quarantine/" + key
            sh(f'aws s3 mv "s3://{B2_BUCKET}/{key}" "s3://{B2_BUCKET}/{dest}" '
               f'--endpoint-url {B2_ENDPOINT}')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--arch", required=True, choices=["aarch64", "x86_64"])
    ap.add_argument("--publish", action="store_true")
    ap.add_argument("--report-dir", default=".")
    args = ap.parse_args()

    workdir = tempfile.mkdtemp()
    rebuild = CatalogRebuild(args.arch, workdir, publish=args.publish)
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
