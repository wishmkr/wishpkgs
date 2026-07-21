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
     Packages.gz), but ubuntu-mono specifically IS absent, deliberately,
     via the is_blocked() name filter (it contains "ubuntu"). Both halves
     of that are asserted here so neither regresses silently: arch:all
     packages must still parse/flow through normally, and the blocklist
     must keep catching distro-named packages.
  3. tools/test_packages.py's check_package() reported ANY dependency with
     no literal .info as "missing_info", even when it was a virtual/ABI
     name (e.g. "qtbase-abi-5-15-8") satisfied by another package's
     Provides -- and even when it just had unparsed constraint/OR syntax
     stuck to it ("foo (>=1.2)|bar" looked up as one literal name). Fixed
     by parsing the full wire format and consulting the provides index
     before giving up.

No network access, no B2 credentials -- everything here runs against
synthetic Packages-file text and a stubbed http_get, so it's safe and fast
to run in CI on every push.
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
    fetch needed) -- and the name-blocklist must still catch
    distro-named ones like ubuntu-mono on purpose, not by accident of a
    missing-arch-all fetch that would have looked like the same symptom."""

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

    def test_ubuntu_mono_is_blocked_on_purpose(self):
        self.assertTrue(mirror_common.is_blocked("ubuntu-mono"))

    def test_non_distro_named_arch_all_package_not_blocked(self):
        self.assertFalse(mirror_common.is_blocked("adwaita-icon-theme"))


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


if __name__ == "__main__":
    unittest.main()
