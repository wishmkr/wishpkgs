#!/usr/bin/env python3
"""
Takes a set of package names that tools/test_packages.py found missing (a
package some other package's Depends referenced, but that has no .info on
the CDN) and tries to mirror each one in for real, checking every source in
order: Ubuntu (main, universe, multiverse, restricted) -> Debian (main,
contrib, non-free-firmware) -> Fedora (Everything). First source whose
sanitized package name matches wins; the package is mirrored through that
distro's own process_package() (same repackaging path the regular mirror
uses) and appended to the canonical index/<arch>.txt.

Whatever's left after checking all three sources genuinely doesn't exist
upstream under that name -- almost always because it's a Debian/Ubuntu
"virtual" package name (dpkg-dev, perl-any, default-dbus-system-bus, ...:
alternatives-system markers, not real installable packages) rather than a
mirroring gap. Those are reported as not_found_anywhere for a human to
judge, never guessed at.
"""
import json
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mirror_common import sanitize_name, is_blocked, b2_cp, b2_get, sh

import mirror_ubuntu
import mirror_debian
import mirror_fedora

ARCH = os.environ.get("HEAL_ARCH", "aarch64")
DEADLINE = time.monotonic() + float(os.environ.get("HEAL_DEADLINE_SECONDS", "19500"))


def deadline_hit():
    if time.monotonic() > DEADLINE:
        print("deadline reached, stopping cleanly", file=sys.stderr)
        return True
    return False


def try_ubuntu(wanted, arch_wish, workdir):
    healed = {}
    cfg = mirror_ubuntu.ARCHES[arch_wish]
    for comp in ("main", "universe", "multiverse", "restricted"):
        if not wanted or deadline_hit():
            break
        try:
            text = mirror_ubuntu.fetch_packages_index(
                cfg["base"], mirror_ubuntu.RELEASE, comp, cfg["deb_arch"])
        except Exception as e:
            print(f"ubuntu/{comp}: index fetch failed: {e}", file=sys.stderr)
            continue
        for pkg in mirror_ubuntu.parse_packages(text):
            if not wanted or deadline_hit():
                break
            name_raw = pkg.get("Package")
            if not name_raw or is_blocked(name_raw):
                continue
            sanitized = sanitize_name(name_raw)
            if sanitized not in wanted:
                continue
            wsh = mirror_ubuntu.process_package(arch_wish, cfg["base"], pkg, workdir)
            if wsh:
                healed[sanitized] = ("ubuntu", wsh)
                wanted.discard(sanitized)
                print(f"healed via ubuntu/{comp}: {sanitized} -> {wsh}", file=sys.stderr)
    return healed


def try_debian(wanted, arch_wish, workdir):
    healed = {}
    cfg = mirror_debian.ARCHES[arch_wish]
    for comp in ("main", "contrib", "non-free-firmware"):
        if not wanted or deadline_hit():
            break
        try:
            text = mirror_debian.fetch_packages_index(
                cfg["base"], mirror_debian.RELEASE, comp, cfg["deb_arch"])
        except Exception as e:
            print(f"debian/{comp}: index fetch failed: {e}", file=sys.stderr)
            continue
        for pkg in mirror_debian.parse_packages(text):
            if not wanted or deadline_hit():
                break
            name_raw = pkg.get("Package")
            if not name_raw or is_blocked(name_raw):
                continue
            sanitized = sanitize_name(name_raw)
            if sanitized not in wanted:
                continue
            wsh = mirror_debian.process_package(arch_wish, cfg["base"], pkg, workdir)
            if wsh:
                healed[sanitized] = ("debian", wsh)
                wanted.discard(sanitized)
                print(f"healed via debian/{comp}: {sanitized} -> {wsh}", file=sys.stderr)
    return healed


def try_fedora(wanted, arch_wish, workdir):
    healed = {}
    if not wanted:
        return healed
    cfg = mirror_fedora.ARCHES[arch_wish]
    rpm_arch = cfg["rpm_arch"]
    try:
        xml = mirror_fedora.fetch_primary_xml(rpm_arch)
    except Exception as e:
        print(f"fedora: primary.xml fetch failed: {e}", file=sys.stderr)
        return healed
    for pkg in mirror_fedora.parse_primary(xml):
        if not wanted or deadline_hit():
            break
        name_raw = pkg["name"]
        if is_blocked(name_raw):
            continue
        sanitized = sanitize_name(name_raw)
        if sanitized not in wanted:
            continue
        wsh = mirror_fedora.process_package(arch_wish, rpm_arch, pkg, workdir)
        if wsh:
            healed[sanitized] = ("fedora", wsh)
            wanted.discard(sanitized)
            print(f"healed via fedora: {sanitized} -> {wsh}", file=sys.stderr)
    return healed


def publish_healed(arch, wsh_names):
    """Appends the newly-mirrored packages to the canonical index/<arch>.txt.
    Read-union-write, same pattern merge_index() uses elsewhere, just not
    shard-scoped since this is a one-off addition rather than a periodic
    per-shard flush."""
    if not wsh_names:
        return
    tmp = tempfile.mktemp()
    lines = set()
    if b2_get(f"index/{arch}.txt", tmp):
        with open(tmp) as f:
            lines.update(l.strip() for l in f if l.strip())
        os.remove(tmp)
    lines.update(wsh_names)
    lines = {l for l in lines if not is_blocked(l)}
    out = tempfile.mktemp()
    with open(out, "w") as f:
        f.writelines(f"{l}\n" for l in sorted(lines))
    b2_cp(out, f"index/{arch}.txt")
    os.remove(out)


def main():
    names_file = sys.argv[1] if len(sys.argv) > 1 else "missing-names.txt"
    with open(names_file) as f:
        wanted = {l.strip() for l in f if l.strip()}

    print(f"healing {len(wanted)} missing names for arch={ARCH}", file=sys.stderr)

    workdir = tempfile.mkdtemp()
    all_healed = {}

    for try_fn in (try_ubuntu, try_debian, try_fedora):
        found = try_fn(wanted, ARCH, workdir)
        all_healed.update(found)

    publish_healed(ARCH, [wsh for _, wsh in all_healed.values()])

    report = {
        name: {"status": "healed", "source": src, "file": wsh}
        for name, (src, wsh) in all_healed.items()
    }
    for name in wanted:
        report[name] = {"status": "not_found_anywhere"}

    out_dir = os.environ.get("HEAL_OUTPUT_DIR", ".")
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, f"heal-report-{ARCH}.json")
    with open(out_path, "w") as f:
        json.dump(report, f, indent=2, sort_keys=True)

    print(f"healed {len(all_healed)}, unresolved {len(wanted)}", file=sys.stderr)
    print(f"wrote {out_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
