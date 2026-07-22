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


def backfill_deb(distro_mod, distro_name, arch_wish, canonical, workdir, components):
    """Shared logic for mirror_ubuntu / mirror_debian, whose Packages-file
    stanza shape and .info fields are identical. `components` is passed in
    explicitly rather than read from distro_mod.COMPONENTS -- both mirror
    modules are imported into this ONE process and read the shared
    MIRROR_COMPONENTS env var at import time, so there's no way to give
    Ubuntu and Debian their own component lists (they don't even share
    component names -- "universe" isn't a Debian thing) through that
    module-global alone."""
    cfg = distro_mod.ARCHES[arch_wish]
    base = cfg["base"]
    rewritten, provides_pairs = 0, []

    for comp in components:
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


def shard_provides_key(arch, shard):
    return f"state/backfill/{arch}/shard{shard}-provides.txt"


def publish_provides_shard(arch, shard, provides_pairs):
    """Writes ONLY this shard's own regenerated Provides pairs to a
    per-shard file -- never read-modify-writes the shared canonical
    index/<arch>-provides.txt directly. With up to 16 shards (2 arches x 8
    shards) finishing around the same time, a naive read-union-write race
    on ONE shared file silently loses entries: two shards that both read
    the same base snapshot and then write back independently leave only
    the LAST writer's additions in place, dropping whatever every other
    concurrent shard contributed. merge_provides_shards() below is the
    only thing that ever writes the canonical file, exactly once, after
    every shard has finished -- a single-writer merge instead of N racing
    read-modify-writers."""
    tmp = tempfile.mktemp()
    with open(tmp, "w") as f:
        f.writelines(f"{v} {r}\n" for v, r in sorted(set(provides_pairs)))
    b2_cp(tmp, shard_provides_key(arch, shard))
    os.remove(tmp)


def merge_provides_shards(arch, num_shards):
    """Single-writer merge: unions every shard's partial provides file for
    `arch` (plus whatever's already canonical) and uploads the result
    exactly once. Must only run after every backfill shard for `arch` has
    completed -- there is deliberately no retry/re-merge safety net here
    beyond running this step again, since it always re-derives the full
    union from scratch (never destructive)."""
    lines = set()
    tmp = tempfile.mktemp()
    if b2_get(f"index/{arch}-provides.txt", tmp):
        with open(tmp) as f:
            lines.update(l.strip() for l in f if l.strip())
        os.remove(tmp)
    found_shards = 0
    for s in range(num_shards):
        shard_tmp = tempfile.mktemp()
        if b2_get(shard_provides_key(arch, s), shard_tmp):
            found_shards += 1
            with open(shard_tmp) as f:
                lines.update(l.strip() for l in f if l.strip())
            os.remove(shard_tmp)
    out = tempfile.mktemp()
    with open(out, "w") as f:
        f.writelines(f"{l}\n" for l in sorted(lines))
    b2_cp(out, f"index/{arch}-provides.txt")
    os.remove(out)
    print(f"{arch}: merged {len(lines)} provides pairs from "
          f"{found_shards}/{num_shards} shard files", file=sys.stderr)


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
            comps = [c for c in os.environ.get(
                "BACKFILL_COMPONENTS_UBUNTU", "main").split(",") if c]
            n, p = backfill_deb(mirror_ubuntu, "ubuntu", ARCH, canonical, workdir, comps)
        elif distro == "debian":
            comps = [c for c in os.environ.get(
                "BACKFILL_COMPONENTS_DEBIAN", "main").split(",") if c]
            n, p = backfill_deb(mirror_debian, "debian", ARCH, canonical, workdir, comps)
        elif distro == "fedora":
            n, p = backfill_fedora(ARCH, canonical, workdir)
        else:
            print(f"unknown distro {distro!r}, skipping", file=sys.stderr)
            continue
        print(f"{distro}: rewrote {n} .info files", file=sys.stderr)
        total_rewritten += n
        all_provides.extend(p)

    publish_provides_shard(ARCH, SHARD, all_provides)
    print(f"total: rewrote {total_rewritten} .info files, "
          f"{len(all_provides)} provides pairs written to this shard's "
          f"partial file (not yet merged into the canonical index)",
          file=sys.stderr)

    out = os.environ.get("GITHUB_OUTPUT")
    if out:
        with open(out, "a") as f:
            f.write(f"rewritten={total_rewritten}\n")


def main_merge():
    """CLI entry for the single merge job that runs after every backfill
    shard finishes: `python3 backfill_metadata.py merge-provides aarch64
    x86_64`. Never run this concurrently with itself or while any shard for
    the same arch is still writing its partial file."""
    arches = sys.argv[2:] or ["aarch64", "x86_64"]
    for arch in arches:
        merge_provides_shards(arch, NUM_SHARDS)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "merge-provides":
        main_merge()
    else:
        main()
