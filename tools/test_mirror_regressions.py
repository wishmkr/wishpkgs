#!/usr/bin/env python3
"""
Regression tests for the mirror-pipeline bugs found 2026-07-22:

  1. Debian multiarch qualifiers (":any", ":native", ":<arch>") were never
     stripped before sanitize_name() ran, so "python3:any" became the
     nonexistent "python3-any" wherever it appeared in a Depends/Provides/
     Conflicts/Breaks field.
  2. "Architecture: all" packages were suspected of being excluded from
     both catalogs -- turned out NOT to be a real bug (Debian/Ubuntu's
     archive already inlines arch:all packages into every binary-<arch>
     Packages.gz). What WAS a real bug: is_blocked()'s substring filter
     ("ubuntu" in lower(name)) caught ubuntu-mono, breaking every package
     that Depends on it directly for its GTK icon theme -- a real runtime
     dependency, not distro branding. Fixed by switching to an exact-name
     blocklist plus an explicit allowlist. Also caught in the same pass: a
     couple of call sites were checking is_blocked() against a FULL
     ".wsh" index-line filename instead of the bare package name, which an
     exact-match check can never match -- silently disabling merge_index()'s
     purge-persistence filtering. Fixed via _index_line_is_blocked().
  3. tools/test_packages.py's check_package() reported ANY dependency with
     no literal .info as "missing_info", even when it was a virtual/ABI
     name (e.g. "qtbase-abi-5-15-8") satisfied by another package's
     Provides -- and even when it just had unparsed constraint/OR syntax
     stuck to it ("foo (>=1.2)|bar" looked up as one literal name). Fixed
     by parsing the full wire format and consulting the provides index
     before giving up.
  4. tools/backfill_metadata.py originally had every shard (up to 16
     running concurrently) read-modify-write the SAME canonical
     index/<arch>-provides.txt directly -- a classic race where the last
     shard to finish overwrites everyone else's additions with whatever it
     read at ITS start, silently losing entries from shards that finished
     first. Fixed before ever running against production: each shard now
     writes only its own partial file
     (state/backfill/<arch>/shard<N>-provides.txt); a single separate
     merge job unions all of them plus the existing canonical file and
     uploads once, so there is exactly one writer of the canonical key.
  5. tools/backfill_metadata.py processed Ubuntu then Debian (then Fedora)
     in one run without checking that an upstream stanza's VERSION matched
     what was actually canonically published. The same package name can
     exist in more than one distro's archive at a genuinely different
     version (Ubuntu's own "libgcc-s1" vs Debian's own "libgcc-s1" --
     different packages, same name) -- Debian's stanza silently overwrote
     an Ubuntu-sourced package's .info with Debian's own unrelated
     dependency graph (Depends: gcc-14-base -> Depends: gcc-12-base, a
     package that was never mirrored at all, since Ubuntu noble doesn't
     ship it), which is exactly what caused a large cluster of
     "missing_from_index" failures cascading from libgcc-s1 in a live
     catalog test. Fixed by checking the stanza's sanitized version against
     mirror_common.load_canonical_versions() before trusting it.

No network access, no B2 credentials -- everything here runs against
synthetic Packages-file text and a stubbed http_get/b2_get/b2_cp, so it's
safe and fast to run in CI on every push.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import mirror_common
import test_packages as tp


class MultiarchQualifierTests(unittest.TestCase):
    """Item 1: strip :any/:native/:<arch> before sanitize_name mangles ':'
    into '-'."""

    def test_python3_any(self):
        self.assertEqual(mirror_common.sanitize_name("python3:any"), "python3")

    def test_perl_any(self):
        self.assertEqual(mirror_common.sanitize_name("perl:any"), "perl")

    def test_native_qualifier(self):
        self.assertEqual(mirror_common.sanitize_name("libc6:native"), "libc6")

    def test_specific_arch_qualifier(self):
        self.assertEqual(mirror_common.sanitize_name("libfoo:armhf"), "libfoo")

    def test_unqualified_name_unaffected(self):
        self.assertEqual(mirror_common.sanitize_name("libfoo"), "libfoo")

    def test_qualifier_stripped_inside_depends_field(self):
        # End-to-end through the same parser the mirror scripts use to
        # build a .info's depends= line -- not just the bare sanitize_name
        # unit, since that's the actual path the original bug was in.
        groups = mirror_common.parse_dep_field(
            "python3-alembic (= 1.13.1-3), python3:any, libjs-sphinxdoc (>= 7.2.2)")
        names = [alt[0] for group in groups for alt in group]
        self.assertIn("python3", names)
        self.assertNotIn("python3-any", names)

    def test_perl_any_inside_depends_field(self):
        groups = mirror_common.parse_dep_field("perl:any, libfoo")
        names = [alt[0] for group in groups for alt in group]
        self.assertIn("perl", names)
        self.assertNotIn("perl-any", names)


class ArchitectureAllTests(unittest.TestCase):
    """Item 2: arch:all packages must still parse and flow through the
    normal todo-building path (they're inlined in binary-<arch>, no special
    fetch needed). ubuntu-mono was initially thought to be a missing-arch:all
    bug; turned out to be is_blocked()'s substring filter catching a real,
    needed runtime dependency (several desktop packages Depend on it
    directly for their icon theme) -- fixed by switching is_blocked() from a
    substring check to an exact-name blocklist with an explicit allowlist,
    so ubuntu-mono must now resolve like any other package. A real
    packaging-tool name (e.g. "apt") must still be blocked."""

    SAMPLE_PACKAGES_TEXT = (
        "Package: ubuntu-mono\n"
        "Architecture: all\n"
        "Version: 24.04-0ubuntu1\n"
        "Description: mono icon theme\n"
        "\n"
        "Package: adwaita-icon-theme\n"
        "Architecture: all\n"
        "Version: 46.0-1\n"
        "Description: default icon theme\n"
        " long description continues\n"
        "\n"
    )

    def test_arch_all_stanza_parses(self):
        import mirror_ubuntu
        stanzas = list(mirror_ubuntu.parse_packages(self.SAMPLE_PACKAGES_TEXT))
        names = {s["Package"] for s in stanzas}
        self.assertEqual(names, {"ubuntu-mono", "adwaita-icon-theme"})
        self.assertEqual(
            next(s for s in stanzas if s["Package"] == "adwaita-icon-theme")["Architecture"],
            "all")

    def test_ubuntu_mono_is_not_blocked(self):
        # Regression: was blocked by the old substring filter, breaking
        # every package that Depends on it directly (a real GTK icon theme,
        # not distro branding with no function).
        self.assertFalse(mirror_common.is_blocked("ubuntu-mono"))

    def test_ubuntu_mono_in_always_allowed_names(self):
        self.assertIn("ubuntu-mono", mirror_common.ALWAYS_ALLOWED_NAMES)

    def test_non_distro_named_arch_all_package_not_blocked(self):
        self.assertFalse(mirror_common.is_blocked("adwaita-icon-theme"))

    def test_real_packaging_tool_still_blocked(self):
        # apt/dpkg genuinely are meaningless without a live package
        # database this project doesn't ship -- the exact-name blocklist
        # must still catch these on purpose.
        self.assertTrue(mirror_common.is_blocked("apt"))
        self.assertTrue(mirror_common.is_blocked("dpkg"))

    def test_index_line_blocklist_check_uses_bare_name(self):
        # is_blocked() is EXACT-match now -- calling it directly on a full
        # ".wsh" index-line filename would never match anything, silently
        # disabling merge_index()'s purge-persistence filtering. Callers
        # that filter full index lines must go through
        # _index_line_is_blocked(), which extracts the bare name first.
        self.assertFalse(mirror_common.is_blocked("apt-2.7.3-1-x86_64.wsh"))
        self.assertTrue(
            mirror_common._index_line_is_blocked("apt-2.7.3-1-x86_64.wsh"))
        self.assertFalse(
            mirror_common._index_line_is_blocked("ubuntu-mono-24.04-1-x86_64.wsh"))


class ProvidesAwareTestPipelineTests(unittest.TestCase):
    """Item 3: test_packages.py must check literal names first, then the
    provides index, before reporting missing_info -- and must correctly
    parse OR-alternatives/version-constrained depends= entries instead of
    treating the raw wire-format string as one literal name."""

    def setUp(self):
        tp._INFO_CACHE.clear()
        tp._CHECKED.clear()
        tp._PROVIDES_CACHE.clear()
        self._orig_http_get = tp.http_get
        self._orig_find_wsh = tp.find_wsh_filename

    def tearDown(self):
        tp.http_get = self._orig_http_get
        tp.find_wsh_filename = self._orig_find_wsh

    def test_depends_field_parses_or_alternatives_and_constraints(self):
        groups = tp._parse_depends_field(
            "qtbase-abi-5-15-8,libc6 (>=2.31)|libc6-compat,perl")
        self.assertEqual(groups, [
            ["qtbase-abi-5-15-8"],
            ["libc6", "libc6-compat"],
            ["perl"],
        ])

    def test_qtbase_abi_resolved_via_provides_not_reported_missing(self):
        # qtbase-abi-5-15-8 has no .info of its own (it's a pure ABI/virtual
        # marker), but libqt5core5a provides it and is itself fully healthy
        # -- simulate that by pre-seeding _CHECKED so we're testing the
        # resolution/classification logic in isolation, not the download
        # chain (already exercised by test_packages.py's own extract/
        # checksum steps elsewhere).
        tp._CHECKED["libqt5core5a"] = "ok"
        tp._PROVIDES_CACHE["aarch64"] = {"qtbase-abi-5-15-8": ["libqt5core5a"]}
        tp._INFO_CACHE["qtbase-abi-5-15-8"] = None

        result = tp.check_package("aarch64", "qtbase-abi-5-15-8", ())
        self.assertEqual(result, "ok")
        self.assertNotIn("qtbase-abi-5-15-8",
                          [n for n, o in tp._CHECKED.items() if o == "missing_info"])

    def test_qtbase_abi_with_no_working_provider_is_not_missing_info(self):
        # Every provider fails -> qtbase-abi-5-15-8 must NOT show up as
        # missing_info (heal_missing.py would then pointlessly try to
        # mirror-in a package literally named "qtbase-abi-5-15-8", which
        # will never exist upstream under that name).
        tp._CHECKED["libqt5core5a"] = "checksum_mismatch:deadbeef"
        tp._PROVIDES_CACHE["aarch64"] = {"qtbase-abi-5-15-8": ["libqt5core5a"]}
        tp._INFO_CACHE["qtbase-abi-5-15-8"] = None

        result = tp.check_package("aarch64", "qtbase-abi-5-15-8", ())
        self.assertNotEqual(result, "missing_info")
        self.assertTrue(result.startswith("virtual_unsatisfied:"))

    def test_genuinely_unknown_name_still_reported_missing(self):
        # No .info AND no provides entry at all -- must still be
        # missing_info so heal_missing.py keeps trying to mirror it in.
        tp._PROVIDES_CACHE["aarch64"] = {}
        tp._INFO_CACHE["totally-fake-pkg"] = None

        result = tp.check_package("aarch64", "totally-fake-pkg", ())
        self.assertEqual(result, "missing_info")

    def test_perl_any_dependency_resolves_after_multiarch_fix(self):
        # End-to-end: a package depending on the wire-format-sanitized name
        # "perl" (what "perl:any" becomes post-fix) must resolve cleanly,
        # not be looked up as a nonexistent "perl-any".
        tp._CHECKED["perl"] = "ok"
        tp._INFO_CACHE["some-pkg"] = None  # unused directly; groups checked below
        groups = tp._parse_depends_field("perl")
        self.assertEqual(tp.check_dep_group("aarch64", groups[0], ()), "ok")


class ProvidesShardMergeTests(unittest.TestCase):
    """Item 4: per-shard partial provides files must merge without losing
    any shard's contribution -- the exact failure mode of the old
    read-modify-write-the-shared-file race, simulated here by writing
    several shards' files to a fake in-memory B2 and confirming the merge
    step's output contains every one of them."""

    def setUp(self):
        import backfill_metadata as bm
        self.bm = bm
        self._fake_b2 = {}  # remote_key -> file content (str)

        def fake_b2_cp(local, remote_key):
            with open(local) as f:
                self._fake_b2[remote_key] = f.read()

        def fake_b2_get(remote_key, local):
            if remote_key not in self._fake_b2:
                return False
            with open(local, "w") as f:
                f.write(self._fake_b2[remote_key])
            return True

        self._orig_b2_cp, self._orig_b2_get = bm.b2_cp, bm.b2_get
        bm.b2_cp, bm.b2_get = fake_b2_cp, fake_b2_get

    def tearDown(self):
        self.bm.b2_cp, self.bm.b2_get = self._orig_b2_cp, self._orig_b2_get

    def test_shards_never_touch_canonical_file_directly(self):
        self.bm.publish_provides_shard("aarch64", 0, [("virt-a", "real-a")])
        self.bm.publish_provides_shard("aarch64", 1, [("virt-b", "real-b")])
        self.assertNotIn("index/aarch64-provides.txt", self._fake_b2)
        self.assertIn(self.bm.shard_provides_key("aarch64", 0), self._fake_b2)
        self.assertIn(self.bm.shard_provides_key("aarch64", 1), self._fake_b2)

    def test_merge_unions_every_shard_without_dropping_any(self):
        # Simulates 4 shards finishing concurrently, each with its own
        # distinct contribution -- the exact scenario a shared
        # read-modify-write would lose entries under.
        for shard, pair in enumerate(
                [("virt-a", "real-a"), ("virt-b", "real-b"),
                 ("virt-c", "real-c"), ("virt-d", "real-d")]):
            self.bm.publish_provides_shard("aarch64", shard, [pair])

        self.bm.merge_provides_shards("aarch64", 4)

        merged = self._fake_b2["index/aarch64-provides.txt"]
        for virt, real in [("virt-a", "real-a"), ("virt-b", "real-b"),
                            ("virt-c", "real-c"), ("virt-d", "real-d")]:
            self.assertIn(f"{virt} {real}", merged)

    def test_merge_preserves_preexisting_canonical_entries(self):
        self._fake_b2["index/aarch64-provides.txt"] = "old-virt old-real\n"
        self.bm.publish_provides_shard("aarch64", 0, [("new-virt", "new-real")])

        self.bm.merge_provides_shards("aarch64", 1)

        merged = self._fake_b2["index/aarch64-provides.txt"]
        self.assertIn("old-virt old-real", merged)
        self.assertIn("new-virt new-real", merged)


class BackfillCrossDistroVersionGuardTests(unittest.TestCase):
    """Item 5: backfill_deb() must only trust an upstream stanza whose
    version matches what's actually canonically published for that name --
    the exact bug that let Debian's libgcc-s1 overwrite Ubuntu's."""

    UBUNTU_LIBGCC_S1 = (
        "Package: libgcc-s1\n"
        "Version: 14-20240412-0ubuntu1\n"
        "Depends: gcc-14-base (= 14-20240412-0ubuntu1), libc6 (>= 2.35)\n"
        "Provides: libgcc1 (= 1:14-20240412-0ubuntu1)\n"
        "Description: GCC support library\n"
        "\n"
    )
    DEBIAN_LIBGCC_S1 = (
        "Package: libgcc-s1\n"
        "Version: 12.2.0-14+deb12u1\n"
        "Depends: gcc-12-base (= 12.2.0-14+deb12u1), libc6 (>= 2.35)\n"
        "Description: GCC support library\n"
        "\n"
    )

    def setUp(self):
        import backfill_metadata as bm
        import mirror_ubuntu, mirror_debian
        self.bm, self.mu, self.md = bm, mirror_ubuntu, mirror_debian
        self._orig = {
            "bm_b2_cp": bm.b2_cp, "bm_b2_get": bm.b2_get,
            "mu_fetch": mirror_ubuntu.fetch_packages_index,
            "md_fetch": mirror_debian.fetch_packages_index,
        }
        self.calls = []
        bm.b2_cp = lambda local, key: self.calls.append(
            (key, open(local).read()))
        bm.b2_get = lambda key, local: False
        mirror_ubuntu.fetch_packages_index = lambda *a, **k: self.UBUNTU_LIBGCC_S1
        mirror_debian.fetch_packages_index = lambda *a, **k: self.DEBIAN_LIBGCC_S1
        bm.NUM_SHARDS = 1

    def tearDown(self):
        self.bm.b2_cp, self.bm.b2_get = self._orig["bm_b2_cp"], self._orig["bm_b2_get"]
        self.mu.fetch_packages_index = self._orig["mu_fetch"]
        self.md.fetch_packages_index = self._orig["md_fetch"]

    def test_debian_stanza_rejected_when_canonical_version_is_ubuntus(self):
        canonical_versions = {"libgcc-s1": "14"}  # matches the Ubuntu stanza
        import tempfile
        workdir = tempfile.mkdtemp()

        n_ubuntu, _ = self.bm.backfill_deb(
            self.mu, "ubuntu", "x86_64", canonical_versions, workdir, ["main"])
        n_debian, _ = self.bm.backfill_deb(
            self.md, "debian", "x86_64", canonical_versions, workdir, ["main"])

        self.assertEqual(n_ubuntu, 1)
        self.assertEqual(n_debian, 0)
        info_content = dict(self.calls)["pkgs/x86_64/libgcc-s1.info"]
        self.assertIn("gcc-14-base", info_content)
        self.assertNotIn("gcc-12-base", info_content)

    def test_ubuntu_stanza_rejected_when_canonical_version_is_debians(self):
        # Symmetric case: if the ACTUALLY-mirrored payload was Debian's,
        # Ubuntu's differently-versioned stanza must be the one rejected.
        canonical_versions = {"libgcc-s1": "12.2.0"}
        import tempfile
        workdir = tempfile.mkdtemp()

        n_ubuntu, _ = self.bm.backfill_deb(
            self.mu, "ubuntu", "x86_64", canonical_versions, workdir, ["main"])
        n_debian, _ = self.bm.backfill_deb(
            self.md, "debian", "x86_64", canonical_versions, workdir, ["main"])

        self.assertEqual(n_ubuntu, 0)
        self.assertEqual(n_debian, 1)
        info_content = dict(self.calls)["pkgs/x86_64/libgcc-s1.info"]
        self.assertIn("gcc-12-base", info_content)
        self.assertNotIn("gcc-14-base", info_content)


if __name__ == "__main__":
    unittest.main()
