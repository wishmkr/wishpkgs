#!/usr/bin/env python3
"""
Regression tests for the provenance-aware catalog rebuild
(tools/provenance.py + tools/rebuild_catalog.py), added 2026-07-22 after a
full-pipeline rewrite triggered by a real incident: name-only backfill
matching let Debian's "libgcc-s1" silently overwrite Ubuntu's
already-published "libgcc-s1" with an unrelated dependency graph, because
the two are genuinely different packages that happen to share a name.

Covers exactly the eight properties the rewrite was required to prove:
  1. same package name across different distributions never overwrites
     metadata
  2. same sanitized version across different distributions is still
     distinguished (treated as ambiguous, not silently merged)
  3. mismatched source/suite/architecture is rejected
  4. ambiguous provenance fails closed (nothing gets staged/published)
  5. every provides target exists in the canonical package index
  6. orphan metadata is detected
  7. rebuilding the same catalog twice is deterministic
  8. no metadata changes occur when the upstream source and payload
     identity are unchanged

Also covers the hardening pass added the same day after review:
  9. the publish gate is STRICT -- any ambiguous or unresolved canonical
     package blocks the entire catalog's publish, not just that package
  10. any unclassified ("unresolved") dependency group blocks publish too
  11. provenance matching verifies upstream filename / payload checksum
      continuity against the prior trusted manifest where available, and
      fails closed (downgrades to unresolved) on a mismatch, rather than
      trusting a fresh name+version match alone

No network access, no B2 credentials -- everything here runs against
synthetic stanzas and a stubbed b2_get/b2_cp/subprocess, so it's safe and
fast to run in CI on every push.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from provenance import (
    UpstreamStanza, match_provenance, ProvenanceResult, ProvenanceRecord,
    verify_continuity,
)
import rebuild_catalog as rc

# This whole test module is offline-only: never let a real b2_get/b2_cp/sh
# call escape to the network or B2 credentials, regardless of which test
# runs or what it forgets to stub locally.
rc.b2_get = lambda key, local: False
rc.b2_cp = lambda local, key: None
rc.sh = lambda cmd: None


def stanza(distro, suite, source_arch, component, name, version, wish_arch="aarch64", raw=None):
    from mirror_common import sanitize_name, sanitize_version
    return UpstreamStanza(
        source_distro=distro, suite=suite, source_arch=source_arch,
        component=component, upstream_name=name, upstream_version=version,
        sanitized_name=sanitize_name(name), sanitized_version=sanitize_version(version),
        raw=raw if raw is not None else {
            "Package": name, "Version": version, "Depends": "", "Provides": "",
            "Conflicts": "", "Breaks": "", "Description": f"test package {name}",
        },
        wish_arch=wish_arch,
    )


class ProvenanceMatchingTests(unittest.TestCase):
    """Items 1-4: the core matching rule in tools/provenance.py."""

    def test_same_name_different_distro_never_overwrites(self):
        # Ubuntu's libgcc-s1 (v14) and Debian's libgcc-s1 (v12.2.0) both
        # scanned; canonical is pinned to Ubuntu's version -- the result
        # must be Ubuntu's stanza, never Debian's, regardless of scan order.
        stanzas = [
            stanza("debian", "bookworm", "arm64", "main", "libgcc-s1", "12.2.0-14+deb12u1"),
            stanza("ubuntu", "noble", "arm64", "main", "libgcc-s1", "14-20240412-0ubuntu1"),
        ]
        r = match_provenance("libgcc-s1", "14", "aarch64", stanzas)
        self.assertTrue(r.is_resolved)
        self.assertEqual(r.stanza.source_distro, "ubuntu")

        r2 = match_provenance("libgcc-s1", "12.2.0", "aarch64", stanzas)
        self.assertTrue(r2.is_resolved)
        self.assertEqual(r2.stanza.source_distro, "debian")

    def test_same_sanitized_version_different_distro_distinguished(self):
        # Two DIFFERENT distros' archives coincidentally produce the exact
        # same sanitized name+version -- must be recognized as two
        # distinct, irreconcilable sources (ambiguous), not merged into
        # "the same package."
        stanzas = [
            stanza("ubuntu", "noble", "arm64", "main", "foo", "1.0-1ubuntu1"),
            stanza("debian", "bookworm", "arm64", "main", "foo", "1.0-1"),
        ]
        r = match_provenance("foo", "1.0", "aarch64", stanzas)
        self.assertEqual(r.status, ProvenanceResult.AMBIGUOUS)
        self.assertEqual({c.source_distro for c in r.candidates}, {"ubuntu", "debian"})

    def test_mismatched_wish_arch_rejected(self):
        # A stanza scanned for x86_64 must never satisfy an aarch64
        # canonical package, even with an identical name+version.
        stanzas = [
            stanza("ubuntu", "noble", "amd64", "main", "foo", "1.0", wish_arch="x86_64"),
        ]
        r = match_provenance("foo", "1.0", "aarch64", stanzas)
        self.assertEqual(r.status, ProvenanceResult.UNRESOLVED)

        r_ok = match_provenance("foo", "1.0", "x86_64", stanzas)
        self.assertTrue(r_ok.is_resolved)

    def test_ambiguous_fails_closed(self):
        # At the orchestration level: an ambiguous package must never end
        # up in staged_info (nothing would ever be published for it).
        rebuild = rc.CatalogRebuild("aarch64", "/tmp", publish=False)
        rc_stanzas = [
            stanza("ubuntu", "noble", "arm64", "main", "foo", "1.0-1ubuntu1"),
            stanza("debian", "bookworm", "arm64", "main", "foo", "1.0-1"),
        ]
        rc.scan_all_stanzas = lambda arch: rc_stanzas
        rc.load_canonical_versions = lambda arch, workdir: {"foo": "1.0"}
        rebuild._fetch_current_info = lambda name: None
        rebuild._find_orphans = lambda names: []
        report = rebuild.run()
        self.assertNotIn("foo", rebuild.staged_info)
        self.assertEqual(sum(report["ambiguous"].values()), 1)
        self.assertEqual(sum(report.get("repaired", {}).values()), 0)


class ProvidesValidationTests(unittest.TestCase):
    """Item 5: every provides target must exist in the canonical index."""

    def test_provides_target_must_exist_in_canonical(self):
        rebuild = rc.CatalogRebuild("aarch64", "/tmp", publish=False)
        real_stanza = stanza(
            "ubuntu", "noble", "arm64", "main", "libqt5core5a", "5.15.8",
            raw={"Package": "libqt5core5a", "Version": "5.15.8", "Depends": "",
                 "Provides": "qtbase-abi-5-15-8, ghost-provider-nobody-real",
                 "Conflicts": "", "Breaks": "", "Description": "Qt core"})
        rc.scan_all_stanzas = lambda arch: [real_stanza]
        rc.load_canonical_versions = lambda arch, workdir: {"libqt5core5a": "5.15.8"}
        rebuild._fetch_current_info = lambda name: None
        rebuild._find_orphans = lambda names: []
        report = rebuild.run()

        # ghost-provider-nobody-real doesn't correspond to any actual
        # provides target we asserted -- but qtbase-abi-5-15-8 legitimately
        # maps to libqt5core5a, which IS canonical, so it must survive.
        self.assertIn("qtbase-abi-5-15-8", rebuild.provides_index)
        self.assertEqual(rebuild.provides_index["qtbase-abi-5-15-8"], {"libqt5core5a"})

    def test_provides_pointing_nowhere_canonical_is_rejected(self):
        rebuild = rc.CatalogRebuild("aarch64", "/tmp", publish=False)
        real_stanza = stanza(
            "ubuntu", "noble", "arm64", "main", "onlypkg", "1.0",
            raw={"Package": "onlypkg", "Version": "1.0", "Depends": "",
                 "Provides": "virtual-thing-nobody-provides-for-real",
                 "Conflicts": "", "Breaks": "", "Description": "x"})
        # onlypkg itself is NOT canonical (only some other package is) --
        # so its Provides can never resolve to anything in the index.
        rc.scan_all_stanzas = lambda arch: [real_stanza]
        rc.load_canonical_versions = lambda arch, workdir: {"other-pkg": "1.0"}
        rebuild._fetch_current_info = lambda name: None
        rebuild._find_orphans = lambda names: []
        report = rebuild.run()
        self.assertNotIn("virtual-thing-nobody-provides-for-real", rebuild.provides_index)


class OrphanDetectionTests(unittest.TestCase):
    """Item 6: orphan .info/.sha256/.wsh objects (no canonical index
    entry) must be found, never silently ignored."""

    def test_orphan_detection(self):
        rebuild = rc.CatalogRebuild("aarch64", "/tmp", publish=False)

        class FakeProc:
            stdout = (
                "2026-01-01 00:00:00        123 gcc-12-base.info\n"
                "2026-01-01 00:00:00        456 real-pkg.info\n"
                "2026-01-01 00:00:00        789 real-pkg-1.0-1-aarch64.wsh\n"
            )

        orig_run = rc.subprocess.run
        rc.subprocess.run = lambda *a, **k: FakeProc()
        try:
            orphans = rebuild._find_orphans({"real-pkg"})
        finally:
            rc.subprocess.run = orig_run

        self.assertIn("pkgs/aarch64/gcc-12-base.info", orphans)
        self.assertNotIn("pkgs/aarch64/real-pkg.info", orphans)
        self.assertNotIn("pkgs/aarch64/real-pkg-1.0-1-aarch64.wsh", orphans)


class DeterminismTests(unittest.TestCase):
    """Item 7: rebuilding the same catalog twice must be byte-for-byte
    deterministic (no ordering-dependent or time-dependent output)."""

    def _run_once(self):
        rebuild = rc.CatalogRebuild("aarch64", "/tmp", publish=False)
        stanzas = [
            stanza("ubuntu", "noble", "arm64", "main", "pkg-a", "1.0",
                   raw={"Package": "pkg-a", "Version": "1.0",
                        "Depends": "pkg-b, pkg-c (>= 2.0)", "Provides": "",
                        "Conflicts": "", "Breaks": "", "Description": "a"}),
            stanza("ubuntu", "noble", "arm64", "main", "pkg-b", "1.0",
                   raw={"Package": "pkg-b", "Version": "1.0", "Depends": "",
                        "Provides": "virtual-b", "Conflicts": "", "Breaks": "",
                        "Description": "b"}),
        ]
        rc.scan_all_stanzas = lambda arch: stanzas
        rc.load_canonical_versions = lambda arch, workdir: {"pkg-a": "1.0", "pkg-b": "1.0"}
        rebuild._fetch_current_info = lambda name: None
        rebuild._find_orphans = lambda names: []
        report = rebuild.run()
        return rebuild.staged_info, rebuild.provides_index, report

    def test_deterministic_rebuild(self):
        info1, provides1, report1 = self._run_once()
        info2, provides2, report2 = self._run_once()
        self.assertEqual(info1, info2)
        self.assertEqual(provides1, provides2)
        self.assertEqual(report1["repaired"], report2["repaired"])
        self.assertEqual(report1["unresolved"], report2["unresolved"])


class NoOpWhenUnchangedTests(unittest.TestCase):
    """Item 8: if the live .info already matches what would be freshly
    regenerated from the matched stanza, it must be classified
    'unchanged', not 'repaired' -- rebuilding must be idempotent in effect,
    not just in the sense of producing the same result twice."""

    def test_no_change_when_unchanged(self):
        rebuild = rc.CatalogRebuild("aarch64", "/tmp", publish=False)
        s = stanza(
            "ubuntu", "noble", "arm64", "main", "stable-pkg", "1.0",
            raw={"Package": "stable-pkg", "Version": "1.0", "Depends": "",
                 "Provides": "", "Conflicts": "", "Breaks": "",
                 "Description": "already correct"})
        expected_info = rc.render_info_from_stanza(s)

        rc.scan_all_stanzas = lambda arch: [s]
        rc.load_canonical_versions = lambda arch, workdir: {"stable-pkg": "1.0"}
        rebuild._fetch_current_info = lambda name: expected_info
        rebuild._find_orphans = lambda names: []
        report = rebuild.run()

        self.assertEqual(sum(report["unchanged"].values()), 1)
        self.assertEqual(sum(report.get("repaired", {}).values()), 0)

    def test_changed_when_content_differs(self):
        rebuild = rc.CatalogRebuild("aarch64", "/tmp", publish=False)
        s = stanza(
            "ubuntu", "noble", "arm64", "main", "drifted-pkg", "1.0",
            raw={"Package": "drifted-pkg", "Version": "1.0", "Depends": "",
                 "Provides": "", "Conflicts": "", "Breaks": "",
                 "Description": "current correct description"})

        rc.scan_all_stanzas = lambda arch: [s]
        rc.load_canonical_versions = lambda arch, workdir: {"drifted-pkg": "1.0"}
        rebuild._fetch_current_info = lambda name: "description=stale old text\nlicense=x\n"
        rebuild._find_orphans = lambda names: []
        report = rebuild.run()

        self.assertEqual(sum(report["repaired"].values()), 1)
        self.assertEqual(sum(report.get("unchanged", {}).values()), 0)


class StrictPublishGateTests(unittest.TestCase):
    """Items 9-10: the hardened gate blocks the WHOLE catalog's publish
    on any ambiguous/unresolved package or any unclassified dependency --
    "skip and report" is explicitly not good enough, since an old,
    possibly-contaminated .info would otherwise stay live for exactly the
    packages the run couldn't prove."""

    def test_ambiguous_package_blocks_entire_publish(self):
        rebuild = rc.CatalogRebuild("aarch64", "/tmp", publish=True)
        good = stanza("ubuntu", "noble", "arm64", "main", "clean-pkg", "1.0",
                       raw={"Package": "clean-pkg", "Version": "1.0", "Depends": "",
                            "Provides": "", "Conflicts": "", "Breaks": "",
                            "Description": "fine"})
        ambiguous_a = stanza("ubuntu", "noble", "arm64", "main", "shared-name", "1.0-1ubuntu1")
        ambiguous_b = stanza("debian", "bookworm", "arm64", "main", "shared-name", "1.0-1")

        rc.scan_all_stanzas = lambda arch: [good, ambiguous_a, ambiguous_b]
        rc.load_canonical_versions = lambda arch, workdir: {
            "clean-pkg": "1.0", "shared-name": "1.0"}
        rebuild._fetch_current_info = lambda name: None
        rebuild._find_orphans = lambda names: []

        published_calls = []
        rebuild._publish = lambda orphans: published_calls.append(orphans)

        report = rebuild.run()
        self.assertFalse(report["published"])
        self.assertEqual(published_calls, [])
        self.assertTrue(any("ambiguous" in b for b in report["publish_blockers"]))
        # clean-pkg resolved fine on its own -- but the WHOLE publish is
        # still blocked because shared-name didn't, not just shared-name's
        # own metadata.
        self.assertIn("clean-pkg", rebuild.staged_info)

    def test_unresolved_dependency_blocks_publish(self):
        rebuild = rc.CatalogRebuild("aarch64", "/tmp", publish=True)
        s = stanza("ubuntu", "noble", "arm64", "main", "needs-ghost", "1.0",
                    raw={"Package": "needs-ghost", "Version": "1.0",
                         "Depends": "totally-unknown-dependency", "Provides": "",
                         "Conflicts": "", "Breaks": "", "Description": "x"})
        rc.scan_all_stanzas = lambda arch: [s]
        rc.load_canonical_versions = lambda arch, workdir: {"needs-ghost": "1.0"}
        rebuild._fetch_current_info = lambda name: None
        rebuild._find_orphans = lambda names: []
        published_calls = []
        rebuild._publish = lambda orphans: published_calls.append(orphans)

        report = rebuild.run()
        self.assertFalse(report["published"])
        self.assertEqual(published_calls, [])
        self.assertTrue(any("dependency group" in b for b in report["publish_blockers"]))

    def test_fully_clean_catalog_is_allowed_to_publish(self):
        # Sanity check the gate isn't ALWAYS closed -- a catalog where
        # everything resolves cleanly with zero ambiguous/unresolved
        # packages and zero unresolved dependencies must be allowed
        # through.
        rebuild = rc.CatalogRebuild("aarch64", "/tmp", publish=True)
        a = stanza("ubuntu", "noble", "arm64", "main", "pkg-a", "1.0",
                   raw={"Package": "pkg-a", "Version": "1.0", "Depends": "pkg-b",
                        "Provides": "", "Conflicts": "", "Breaks": "",
                        "Description": "a"})
        b = stanza("ubuntu", "noble", "arm64", "main", "pkg-b", "1.0",
                   raw={"Package": "pkg-b", "Version": "1.0", "Depends": "",
                        "Provides": "", "Conflicts": "", "Breaks": "",
                        "Description": "b"})
        rc.scan_all_stanzas = lambda arch: [a, b]
        rc.load_canonical_versions = lambda arch, workdir: {"pkg-a": "1.0", "pkg-b": "1.0"}
        rebuild._fetch_current_info = lambda name: None
        rebuild._find_orphans = lambda names: []
        published_calls = []
        rebuild._publish = lambda orphans: published_calls.append(orphans)

        report = rebuild.run()
        self.assertEqual(report["publish_blockers"], [])
        self.assertTrue(report["published"])
        self.assertEqual(len(published_calls), 1)


class ContinuityVerificationTests(unittest.TestCase):
    """Item 11: matching a name+version pair to an upstream stanza is not
    enough on its own -- continuity against the prior trusted manifest's
    recorded filename/checksum must also hold, where available, or the
    match fails closed."""

    def test_filename_mismatch_against_prior_manifest_fails_closed(self):
        s = stanza("ubuntu", "noble", "arm64", "main", "pkg", "1.0")
        s.upstream_filename = "pool/main/p/pkg/pkg_1.0_arm64.deb"
        prior = ProvenanceRecord(
            name="pkg", arch="aarch64", source_distro="ubuntu", suite="noble",
            source_arch="arm64", component="main", upstream_name="pkg",
            upstream_version="1.0",
            wsh_filename="pkg-1.0-1-aarch64.wsh",
            payload_sha256=None,
        )
        prior.upstream_filename = "pool/main/p/pkg/pkg_1.0_arm64_DIFFERENT.deb"
        self.assertFalse(verify_continuity(s, prior, None))

    def test_matching_filename_continuity_holds(self):
        s = stanza("ubuntu", "noble", "arm64", "main", "pkg", "1.0")
        s.upstream_filename = "pool/main/p/pkg/pkg_1.0_arm64.deb"
        prior = ProvenanceRecord(
            name="pkg", arch="aarch64", source_distro="ubuntu", suite="noble",
            source_arch="arm64", component="main", upstream_name="pkg",
            upstream_version="1.0", wsh_filename="pkg-1.0-1-aarch64.wsh",
            payload_sha256=None,
        )
        prior.upstream_filename = "pool/main/p/pkg/pkg_1.0_arm64.deb"
        self.assertTrue(verify_continuity(s, prior, None))

    def test_payload_checksum_mismatch_fails_closed(self):
        s = stanza("ubuntu", "noble", "arm64", "main", "pkg", "1.0")
        prior = ProvenanceRecord(
            name="pkg", arch="aarch64", source_distro="ubuntu", suite="noble",
            source_arch="arm64", component="main", upstream_name="pkg",
            upstream_version="1.0", wsh_filename="pkg-1.0-1-aarch64.wsh",
            payload_sha256="a" * 64,
        )
        live_sha256 = "b" * 64
        self.assertFalse(verify_continuity(s, prior, live_sha256))

    def test_no_prior_manifest_trusts_first_establishment(self):
        # First-ever provenance rebuild for this package: nothing to
        # verify continuity against yet -- the name+version+arch match
        # (already unique, per match_provenance) is the baseline this
        # establishes for FUTURE runs to verify against.
        s = stanza("ubuntu", "noble", "arm64", "main", "brand-new-pkg", "1.0")
        self.assertTrue(verify_continuity(s, None, None))

    def test_source_identity_change_fails_closed_even_with_matching_filename(self):
        # Defense in depth: even if the filename string somehow matched,
        # a change in WHICH distro/suite/component produced it is exactly
        # the kind of thing that must never be silently accepted.
        s = stanza("debian", "bookworm", "arm64", "main", "pkg", "1.0")
        s.upstream_filename = "pool/main/p/pkg/pkg_1.0_arm64.deb"
        prior = ProvenanceRecord(
            name="pkg", arch="aarch64", source_distro="ubuntu", suite="noble",
            source_arch="arm64", component="main", upstream_name="pkg",
            upstream_version="1.0", wsh_filename="pkg-1.0-1-aarch64.wsh",
            payload_sha256=None,
        )
        prior.upstream_filename = "pool/main/p/pkg/pkg_1.0_arm64.deb"
        self.assertFalse(verify_continuity(s, prior, None))

    def test_end_to_end_continuity_failure_downgrades_to_unresolved(self):
        # Full pipeline: a package that matches cleanly on name+version
        # but fails continuity against a stubbed prior manifest must end
        # up unresolved, not staged, and must not be published.
        rebuild = rc.CatalogRebuild("aarch64", "/tmp", publish=True)
        s = stanza("debian", "bookworm", "arm64", "main", "pkg", "1.0",
                   raw={"Package": "pkg", "Version": "1.0", "Depends": "",
                        "Provides": "", "Conflicts": "", "Breaks": "",
                        "Description": "x"})
        s.upstream_filename = "pool/main/p/pkg/pkg_1.0_arm64.deb"

        prior_record = ProvenanceRecord(
            name="pkg", arch="aarch64", source_distro="ubuntu", suite="noble",
            source_arch="arm64", component="main", upstream_name="pkg",
            upstream_version="1.0", wsh_filename="pkg-1.0-1-aarch64.wsh",
            payload_sha256=None,
        )

        rc.scan_all_stanzas = lambda arch: [s]
        rc.load_canonical_versions = lambda arch, workdir: {"pkg": "1.0"}
        rebuild._fetch_current_info = lambda name: None
        rebuild._find_orphans = lambda names: []
        rebuild.prior_manifest = {}  # populated below, before run() overwrites it
        orig_load = rc.load_provenance_manifest
        rc.load_provenance_manifest = lambda arch, workdir: {"pkg": prior_record}
        try:
            report = rebuild.run()
        finally:
            rc.load_provenance_manifest = orig_load

        self.assertNotIn("pkg", rebuild.staged_info)
        self.assertEqual(sum(report["unresolved"].values()), 1)
        self.assertFalse(report["published"])


if __name__ == "__main__":
    unittest.main()
