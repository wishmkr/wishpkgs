#!/usr/bin/env python3
"""
Rebuilds .info metadata (depends/conflicts/breaks/provides/description) and
the shared provides index for packages that are ALREADY mirrored, straight
from the upstream Packages/primary.xml files -- without re-downloading,
re-extracting, or re-uploading a single .deb/.rpm payload or .wsh.

Why this exists: mirror_common.sanitize_name() had a real bug (multiarch
qualifiers like ":any"/":native" were never stripped before sanitization,
so "python3:any" became the nonexistent "python3-any" in every Depends
field that referenced it) that has now been fixed. Packages mirrored
*before* that fix carry stale/wrong dependency metadata in their .info
files even though their actual payload (.wsh) is completely fine and
doesn't need to change. Re-running the full mirror to fix this would mean
re-downloading and re-uploading ~17k packages' payloads for a metadata-only
problem -- wasteful and slow. This script instead:

  1. Loads the set of package names already published to index/<arch>.txt
     (mirror_common.load_canonical_names) -- the only things eligible for
     backfill; anything not already mirrored is left alone (that's the
     regular mirror's job).
  2. Re-fetches the upstream Packages.gz (Ubuntu/Debian) / primary.xml
     (Fedora) index files -- same as the regular mirror scripts already do
     -- and, for every stanza whose sanitized name is in the canonical set,
     regenerates just the .info content using the CURRENT (fixed)
     sanitize/parse logic.
  3. Uploads only the new pkgs/<arch>/<name>.info, and accumulates
     Provides pairs into the shared index/<arch>-provides.txt. Never
     touches pkgs/<arch>/<name>-*.wsh or its .sha256.

Sharded the same way the mirror scripts are (stable md5-of-name partition)
so a full-catalog backfill can be split across parallel jobs; each shard's
provides contribution is published via the same read-union-write pattern
heal_missing.py uses (last-writer-wins on a race between concurrent
shards finishing at the exact same moment is an accepted, pre-existing
tradeoff of that pattern -- a later re-run always converges).
"""
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mirror_common import (
    b2_cp, b2_get, is_blocked, in_shard, redact, sanitize_name,
    load_canonical_names, parse_dep_field, format_dep_field, provides_names,
    rpm_entries_to_groups,
)

import mirror_ubuntu
import mirror_debian
import mirror_fedora

ARCH = os.environ.get("MIRROR_ARCH", "aarch64")
SHARD = int(os.environ.get("BACKFILL_SHARD", "0"))
NUM_SHARDS = max(1, int(os.environ.get("BACKFILL_SHARDS", "1")))
DEADLINE = time.monotonic() + float(os.environ.get("BACKFILL_DEADLINE_SECONDS", "19500"))
DISTROS = [d for d in os.environ.get("BACKFILL_DISTROS", "ubuntu,debian,fedora").split(",") if d]


def deadline_hit():
    if time.monotonic() > DEADLINE:
        print("deadline reached, stopping cleanly", file=sys.stderr)
        return True
    return False


def write_info(workdir, name, description, license_line, depends, provides, conflicts, breaks=""):
    info_path = os.path.join(workdir, f"{name}.info")
    with open(info_path, "w") as f:
        f.write(f"description={redact(description)}\n")
        f.write(f"license={license_line}\n")
        if depends:
            f.write(f"depends={depends}\n")
        if provides:
            f.write(f"provides={','.join(provides)}\n")
        if conflicts:
            f.write(f"conflicts={conflicts}\n")
        if breaks:
            f.write(f"breaks={breaks}\n")
    return info_path


def backfill_deb(distro_mod, distro_name, arch_wish, canonical, workdir):
    """Shared logic for mirror_ubuntu / mirror_debian, whose Packages-file
    stanza shape and .info fields are identical."""
    cfg = distro_mod.ARCHES[arch_wish]
    base = cfg["base"]
    rewritten, provides_pairs = 0, []

    for comp in distro_mod.COMPONENTS:
        if deadline_hit():
            break
        try:
            text = distro_mod.fetch_packages_index(base, distro_mod.RELEASE, comp, cfg["deb_arch"])
        except Exception as e:
            print(f"{distro_name}/{comp}: index fetch failed: {e}", file=sys.stderr)
            continue

        for pkg in distro_mod.parse_packages(text):
            if deadline_hit():
                break
            name_raw = pkg.get("Package")
            if not name_raw or is_blocked(name_raw):
                continue
            if not in_shard(name_raw, SHARD, NUM_SHARDS):
                continue
            name = sanitize_name(name_raw)
            if name not in canonical:
                continue  # never mirrored -- not this script's job

            depends = format_dep_field(parse_dep_field(pkg.get("Depends", "")))
            conflicts = format_dep_field(parse_dep_field(pkg.get("Conflicts", "")))
            breaks = format_dep_field(parse_dep_field(pkg.get("Breaks", "")))
            provides_groups = parse_dep_field(pkg.get("Provides", ""))
            provides = provides_names(provides_groups)
            desc_line = pkg.get("Description", "").splitlines()[0] if pkg.get("Description") else ""

            info_path = write_info(
                workdir, name, desc_line, "See included license/copyright files",
                depends, provides, conflicts, breaks)
            b2_cp(info_path, f"pkgs/{arch_wish}/{name}.info")
            os.remove(info_path)
            rewritten += 1
            provides_pairs.extend((v, name) for v in provides)

    return rewritten, provides_pairs


def backfill_fedora(arch_wish, canonical, workdir):
    cfg = mirror_fedora.ARCHES[arch_wish]
    rpm_arch = cfg["rpm_arch"]
    rewritten, provides_pairs = 0, []

    try:
        xml = mirror_fedora.fetch_primary_xml(rpm_arch)
    except Exception as e:
        print(f"fedora: primary.xml fetch failed: {e}", file=sys.stderr)
        return rewritten, provides_pairs

    for pkg in mirror_fedora.parse_primary(xml):
        if deadline_hit():
            break
        name_raw = pkg["name"]
        if is_blocked(name_raw):
            continue
        if not in_shard(name_raw, SHARD, NUM_SHARDS):
            continue
        name = sanitize_name(name_raw)
        if name not in canonical:
            continue

        depends = format_dep_field(rpm_entries_to_groups(pkg["requires"]))
        conflicts = format_dep_field(rpm_entries_to_groups(pkg["conflicts"]))
        provides_groups = rpm_entries_to_groups(pkg["provides"])
        provides = provides_names(provides_groups)
        desc_line = pkg["summary"].splitlines()[0] if pkg["summary"] else ""

        info_path = write_info(
            workdir, name, desc_line, "See included license/copyright files",
            depends, provides, conflicts)
        b2_cp(info_path, f"pkgs/{arch_wish}/{name}.info")
        os.remove(info_path)
        rewritten += 1
        provides_pairs.extend((v, name) for v in provides)

    return rewritten, provides_pairs


def publish_provides(arch, provides_pairs):
    """Read-union-write, same pattern as heal_missing.py's publish_provides
    -- appends this shard's freshly-regenerated Provides pairs to the
    shared index/<arch>-provides.txt without dropping anything already
    published by other shards/distros."""
    if not provides_pairs:
        return
    tmp = tempfile.mktemp()
    lines = set()
    if b2_get(f"index/{arch}-provides.txt", tmp):
        with open(tmp) as f:
            lines.update(l.strip() for l in f if l.strip())
        os.remove(tmp)
    lines.update(f"{v} {r}" for v, r in provides_pairs)
    out = tempfile.mktemp()
    with open(out, "w") as f:
        f.writelines(f"{l}\n" for l in sorted(lines))
    b2_cp(out, f"index/{arch}-provides.txt")
    os.remove(out)


def main():
    print(f"backfill shard {SHARD}/{NUM_SHARDS} arch={ARCH} distros={DISTROS}", file=sys.stderr)
    workdir = tempfile.mkdtemp()
    canonical = load_canonical_names(ARCH, workdir)
    print(f"{len(canonical)} canonical names loaded for {ARCH}", file=sys.stderr)

    total_rewritten = 0
    all_provides = []
    for distro in DISTROS:
        if deadline_hit():
            break
        if distro == "ubuntu":
            n, p = backfill_deb(mirror_ubuntu, "ubuntu", ARCH, canonical, workdir)
        elif distro == "debian":
            n, p = backfill_deb(mirror_debian, "debian", ARCH, canonical, workdir)
        elif distro == "fedora":
            n, p = backfill_fedora(ARCH, canonical, workdir)
        else:
            print(f"unknown distro {distro!r}, skipping", file=sys.stderr)
            continue
        print(f"{distro}: rewrote {n} .info files", file=sys.stderr)
        total_rewritten += n
        all_provides.extend(p)

    publish_provides(ARCH, all_provides)
    print(f"total: rewrote {total_rewritten} .info files, "
          f"{len(all_provides)} provides pairs published", file=sys.stderr)

    out = os.environ.get("GITHUB_OUTPUT")
    if out:
        with open(out, "a") as f:
            f.write(f"rewritten={total_rewritten}\n")


if __name__ == "__main__":
    main()
