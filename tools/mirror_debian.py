#!/usr/bin/env python3
"""
Repackage upstream .deb binaries from Debian's own archive (deb.debian.org)
into wish's .wsh format, uploaded straight to the B2 bucket that backs
cdn.wishpkgs.org. Same repackaging approach as tools/mirror_ubuntu.py (which
mirrors Ubuntu, a different upstream) -- dpkg-deb -x only extracts the data
tree, never DEBIAN/control or any other dpkg bookkeeping, so no
package-manager fingerprint travels into the .wsh. Shares one catalog with
every other mirror script: skips any package name already published by
ANY distro (see mirror_common.load_canonical_names), and never emits
metadata that would reveal a package came from Debian specifically (see
mirror_common.redact / is_blocked).

Resumable by design: progress lives in B2 (state/debian/<arch>/shard<N>.done
/.failed), so a fresh process -- manual or self-re-triggered -- picks up
exactly where the last one stopped, even mid-package.
"""
import gzip
import hashlib
import os
import shutil
import sys
import tarfile
import tempfile
import time
from urllib.request import urlopen

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mirror_common import (
    sh, b2_cp, b2_get, is_blocked, in_shard, redact, sanitize_name,
    sanitize_version, sanitize_depends_list, load_state_set,
    load_canonical_names, merge_index, parse_dep_field, format_dep_field,
    provides_names, merge_provides, provides_shard_key,
)

DISTRO = "debian"
DEADLINE = time.monotonic() + float(os.environ.get("MIRROR_DEADLINE_SECONDS", "19500"))
RELEASE = os.environ.get("MIRROR_RELEASE", "bookworm")
COMPONENTS = [c for c in os.environ.get("MIRROR_COMPONENTS", "main").split(",") if c]
FLUSH_EVERY = int(os.environ.get("MIRROR_FLUSH_EVERY", "20"))
ARCH = os.environ.get("MIRROR_ARCH", "aarch64")
SHARD = int(os.environ.get("MIRROR_SHARD", "0"))
NUM_SHARDS = max(1, int(os.environ.get("MIRROR_SHARDS", "6")))

ARCHES = {
    "x86_64":  {"deb_arch": "amd64", "base": "https://deb.debian.org/debian"},
    "aarch64": {"deb_arch": "arm64", "base": "https://deb.debian.org/debian"},
}


def sanitize_depends(field):
    """Preserves version constraints and OR-alternatives (see
    mirror_common.parse_dep_field) instead of the old behavior of keeping
    only the bare name of the first alternative."""
    return format_dep_field(parse_dep_field(field))


def parse_packages(text):
    stanza, key = {}, None
    for line in text.splitlines():
        if not line:
            if stanza:
                yield stanza
            stanza, key = {}, None
            continue
        if line[0] in " \t" and key:
            stanza[key] += "\n" + line.strip()
            continue
        if ":" in line:
            key, _, val = line.partition(":")
            key = key.strip()
            stanza[key] = val.strip()
    if stanza:
        yield stanza


def fetch_packages_index(base, dist, component, deb_arch):
    url = f"{base}/dists/{dist}/{component}/binary-{deb_arch}/Packages.gz"
    print(f"fetching {url}", file=sys.stderr)
    with urlopen(url, timeout=60) as r:
        return gzip.decompress(r.read()).decode("utf-8", "replace")


def process_package(arch_wish, base, pkg, workdir):
    """Returns (wsh_filename, provides_list) on success, (None, []) on
    failure -- provides_list feeds the caller's cross-package provides-index
    accumulation."""
    name_raw, ver_raw, filename = pkg.get("Package"), pkg.get("Version"), pkg.get("Filename")
    if not (name_raw and ver_raw and filename):
        return None, []

    name = sanitize_name(name_raw)
    version = sanitize_version(ver_raw)
    release = "1"
    wsh_name = f"{name}-{version}-{release}-{arch_wish}.wsh"

    deb_path = os.path.join(workdir, "pkg.deb")
    extract_dir = os.path.join(workdir, "extract")
    shutil.rmtree(extract_dir, ignore_errors=True)
    os.makedirs(extract_dir, exist_ok=True)

    try:
        sh(f'curl -fsSL --retry 3 --max-time 120 -o "{deb_path}" "{base}/{filename}"')
        sh(f'dpkg-deb -x "{deb_path}" "{extract_dir}"')

        wsh_path = os.path.join(workdir, wsh_name)
        with tarfile.open(wsh_path, "w:gz") as tar:
            for entry in sorted(os.listdir(extract_dir)):
                tar.add(os.path.join(extract_dir, entry), arcname=entry)

        sha = hashlib.sha256(open(wsh_path, "rb").read()).hexdigest()
        sha_path = wsh_path + ".sha256"
        with open(sha_path, "w") as f:
            f.write(f"{sha}  {wsh_name}\n")

        depends = sanitize_depends(pkg.get("Depends", ""))
        conflicts = sanitize_depends(pkg.get("Conflicts", ""))
        breaks = sanitize_depends(pkg.get("Breaks", ""))
        provides_groups = parse_dep_field(pkg.get("Provides", ""))
        provides = provides_names(provides_groups)

        desc_line = pkg.get("Description", "").splitlines()[0] if pkg.get("Description") else ""
        info_path = os.path.join(workdir, f"{name}.info")
        with open(info_path, "w") as f:
            f.write(f"description={redact(desc_line)}\n")
            f.write("license=See included license/copyright files\n")
            if depends:
                f.write(f"depends={depends}\n")
            if provides:
                f.write(f"provides={','.join(provides)}\n")
            if conflicts:
                f.write(f"conflicts={conflicts}\n")
            if breaks:
                f.write(f"breaks={breaks}\n")

        b2_cp(wsh_path, f"pkgs/{arch_wish}/{wsh_name}")
        b2_cp(sha_path, f"pkgs/{arch_wish}/{wsh_name}.sha256")
        b2_cp(info_path, f"pkgs/{arch_wish}/{name}.info")
        return wsh_name, [(v, name) for v in provides]
    except Exception as e:
        print(f"FAILED {name_raw}={ver_raw}: {e}", file=sys.stderr)
        return None, []
    finally:
        if os.path.exists(deb_path):
            os.remove(deb_path)
        shutil.rmtree(extract_dir, ignore_errors=True)


def mirror_arch(arch_wish, state_dir):
    cfg = ARCHES[arch_wish]
    base = cfg["base"]
    label = f"{arch_wish} [debian-shard{SHARD}]"
    print(f"=== {label} (upstream: {cfg['deb_arch']}, {RELEASE}) ===", file=sys.stderr)

    state_prefix = f"state/debian/{arch_wish}/shard{SHARD}"
    index_key = f"index/{arch_wish}/debian-shard{SHARD}.txt"
    done_key, failed_key = f"{state_prefix}.done", f"{state_prefix}.failed"

    done_path = os.path.join(state_dir, "done")
    failed_path = os.path.join(state_dir, "failed")
    index_path = os.path.join(state_dir, "index")

    done = load_state_set(done_key)
    failed = load_state_set(failed_key)
    with open(done_path, "w") as f:
        f.writelines(f"{u}\n" for u in sorted(done))
    with open(failed_path, "w") as f:
        f.writelines(f"{u}\n" for u in sorted(failed))
    if not b2_get(index_key, index_path):
        open(index_path, "w").close()

    # Anything already published to the shared catalog (by this mirror or
    # any other distro's) is skipped outright -- existing packages are never
    # re-added.
    existing_names = load_canonical_names(arch_wish, state_dir)

    todo, seen_names = [], set()
    for comp in COMPONENTS:
        for pkg in parse_packages(fetch_packages_index(base, RELEASE, comp, cfg["deb_arch"])):
            name_raw, ver_raw = pkg.get("Package"), pkg.get("Version")
            if not name_raw or not ver_raw or name_raw in seen_names:
                continue
            if is_blocked(name_raw):
                continue
            sanitized = sanitize_name(name_raw)
            if sanitized in existing_names:
                continue
            if not in_shard(name_raw, SHARD, NUM_SHARDS):
                continue
            uid = f"{name_raw}={ver_raw}"
            if uid in done or uid in failed:
                continue
            seen_names.add(name_raw)
            todo.append((uid, pkg))

    print(f"{len(todo)} packages left for {label}", file=sys.stderr)

    workdir = os.path.join(state_dir, "work")
    os.makedirs(workdir, exist_ok=True)
    provides_path = os.path.join(state_dir, "provides")

    def flush():
        b2_cp(done_path, done_key)
        b2_cp(failed_path, failed_key)
        b2_cp(index_path, index_key)
        merge_index(arch_wish, DISTRO, index_path, state_dir, NUM_SHARDS, SHARD)
        if os.path.exists(provides_path):
            b2_cp(provides_path, provides_shard_key(DISTRO, arch_wish, SHARD))
        merge_provides(arch_wish, DISTRO, provides_path, state_dir, NUM_SHARDS, SHARD)

    processed = 0
    for uid, pkg in todo:
        if time.monotonic() > DEADLINE:
            print("deadline reached, stopping cleanly", file=sys.stderr)
            break
        wsh_name, provides = process_package(arch_wish, base, pkg, workdir)
        if wsh_name:
            with open(done_path, "a") as f:
                f.write(uid + "\n")
            with open(index_path, "a") as f:
                f.write(wsh_name + "\n")
            if provides:
                with open(provides_path, "a") as f:
                    for virtual_name, real_name in provides:
                        f.write(f"{virtual_name} {real_name}\n")
        else:
            with open(failed_path, "a") as f:
                f.write(uid + "\n")
        processed += 1
        if processed % FLUSH_EVERY == 0:
            flush()
            print(f"  ...{processed}/{len(todo)}", file=sys.stderr)

    flush()

    remaining = len(todo) - processed
    print(f"{label}: processed {processed}, remaining {remaining}", file=sys.stderr)
    return remaining


def main():
    if ARCH not in ARCHES:
        print(f"Unknown MIRROR_ARCH={ARCH!r}", file=sys.stderr)
        sys.exit(1)
    print(f"Shard {SHARD}/{NUM_SHARDS}, arch={ARCH}, distro={DISTRO}", file=sys.stderr)

    state_dir = tempfile.mkdtemp()
    remaining = mirror_arch(ARCH, state_dir)

    out = os.environ.get("GITHUB_OUTPUT")
    if out:
        with open(out, "a") as f:
            f.write(f"remaining={remaining}\n")


if __name__ == "__main__":
    main()
