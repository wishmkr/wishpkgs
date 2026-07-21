#!/usr/bin/env python3
"""
Repackage upstream .deb binaries into wish's .wsh package format and upload
them straight to the B2 bucket that backs cdn.wishpkgs.org.

Runs as one shard of MIRROR_SHARDS (default 1, i.e. unsharded) working a
single arch (MIRROR_ARCH) chosen by the caller -- the workflow's
determine-arch job reads/advances state/current-arch.txt, not this script,
since with multiple shards running concurrently only a single writer may
ever flip that pointer. Each shard partitions the package list by a stable
hash of the package name, so the same package always lands on the same
shard across runs (never processed twice, never dropped).

Resumable by design: progress (done/failed package ids, per-shard index)
lives in B2 itself, so a fresh process -- whether started manually or by the
workflow re-triggering itself after its internal deadline -- picks up
exactly where the last one stopped, even mid-package. Per-shard files avoid
concurrent-write races; the canonical index/<arch>.txt is produced by
merging all shards' index files, refreshed periodically during the run (not
just at the end) so newly-mirrored packages show up quickly.

Only the two package archs wish actually uses are ever written:
  x86_64  <- upstream "amd64"  (archive.ubuntu.com)
  aarch64 <- upstream "arm64"  (ports.ubuntu.com/ubuntu-ports)

Generated metadata never mentions the upstream distro or its build system --
no "debian"/"ubuntu" wording, no dpkg control-file cruft (dpkg-deb -x only
extracts the data tree, never DEBIAN/control, postinst, conffiles, etc.).
Copyright/license files that ship *inside* the package's own data (e.g.
/usr/share/doc/<pkg>/copyright) are left completely untouched -- most of
their licenses (GPL, LGPL, MIT, Apache, BSD) require preserving them
verbatim, and that requirement is honored here regardless of naming.
"""
import gzip
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
from urllib.request import urlopen

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mirror_common import (
    parse_dep_field, format_dep_field, provides_names,
    merge_provides, provides_shard_key,
)

DEADLINE = time.monotonic() + float(os.environ.get("MIRROR_DEADLINE_SECONDS", "19500"))
RELEASE = os.environ.get("MIRROR_RELEASE", "noble")
COMPONENTS = [c for c in os.environ.get("MIRROR_COMPONENTS", "main").split(",") if c]
FLUSH_EVERY = int(os.environ.get("MIRROR_FLUSH_EVERY", "20"))
ARCH = os.environ.get("MIRROR_ARCH", "aarch64")
SHARD = int(os.environ.get("MIRROR_SHARD", "0"))
NUM_SHARDS = max(1, int(os.environ.get("MIRROR_SHARDS", "1")))

ARCHES = {
    "x86_64":  {"deb_arch": "amd64", "base": "http://archive.ubuntu.com/ubuntu"},
    "aarch64": {"deb_arch": "arm64", "base": "http://ports.ubuntu.com/ubuntu-ports"},
}

B2_ENDPOINT = "https://s3.eu-central-003.backblazeb2.com"
B2_BUCKET = "wishpkgs"

_REDACT_RE = re.compile(r"\b(ubuntu|debian)\b", re.IGNORECASE)


def redact(text):
    """Drop literal distro-name mentions from text WE generate. Never applied
    to the package's own shipped files (copyright/license/docs stay verbatim)."""
    return _REDACT_RE.sub("the system", text) if text else text


BLOCKED_NAME_SUBSTRINGS = ("debian", "ubuntu", "apt", "dpkg")


def is_blocked(name_raw):
    """Packages whose upstream name itself names the distro or its own
    packaging tools (apt, dpkg, ubuntu-*, debian-*) are excluded outright --
    they're either meaningless without the Debian packaging stack we don't
    ship (apt/dpkg need a live package database, sources.list, etc.) or they
    just name-drop the distro directly."""
    lower = name_raw.lower()
    return any(s in lower for s in BLOCKED_NAME_SUBSTRINGS)


def in_shard(name):
    """Stable partition: hashlib (not the built-in hash()) so the same
    package always maps to the same shard across separate processes/runs --
    Python's str hash() is randomized per-process by default."""
    if NUM_SHARDS <= 1:
        return True
    digest = hashlib.md5(name.encode()).hexdigest()
    return int(digest, 16) % NUM_SHARDS == SHARD


def sh(cmd):
    subprocess.run(cmd, shell=True, check=True)


def b2_cp(local, remote_key):
    sh(f'aws s3 cp "{local}" "s3://{B2_BUCKET}/{remote_key}" '
       f'--endpoint-url {B2_ENDPOINT} --no-progress')


def b2_get(remote_key, local):
    r = subprocess.run(
        f'aws s3 cp "s3://{B2_BUCKET}/{remote_key}" "{local}" '
        f'--endpoint-url {B2_ENDPOINT} --no-progress',
        shell=True, capture_output=True)
    return r.returncode == 0


# ---- sanitization: map arbitrary upstream package metadata onto wish's
# strict filename/name regexes (PathValidator::is_safe_package_name allows
# only [a-z0-9][a-z0-9-]*; RemoteIndex's index-line regex requires the
# version group to be [0-9.]+ and release to be \d+) ----

def sanitize_name(raw):
    n = raw.lower().replace("+", "plus").replace(".", "-")
    n = re.sub(r"[^a-z0-9-]", "-", n)
    n = re.sub(r"-{2,}", "-", n).strip("-")
    if not n or not n[0].isalnum():
        n = "pkg-" + n
    return n


def sanitize_version(raw):
    core = raw.split(":", 1)[-1]  # drop epoch
    m = re.match(r"[0-9]+(?:\.[0-9]+)*", core)
    version = m.group(0) if m else "0"
    return version or "0"


def sanitize_depends(field):
    """Preserves version constraints and OR-alternatives now (previously
    dropped both -- e.g. "foo (>= 1.2) | bar" became just "foo"). Returns
    the .info-ready textual form directly; see mirror_common.parse_dep_field
    for the structure this round-trips through."""
    return format_dep_field(parse_dep_field(field))


def parse_packages(text):
    """Yield one dict per RFC822-ish stanza in a Packages file."""
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


def load_state_set(key):
    tmp = tempfile.mktemp()
    try:
        if b2_get(key, tmp):
            with open(tmp) as f:
                return {l.strip() for l in f if l.strip()}
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)
    return set()


def process_package(arch_wish, base, pkg, workdir):
    """Downloads, repackages, and uploads one package. Returns
    (wsh_filename, provides_list) on success, or (None, []) on failure --
    the caller owns index/state bookkeeping (this function only touches
    pkgs/<arch>/ in B2). provides_list feeds the caller's cross-package
    provides-index accumulation."""
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
        # dpkg-deb -x extracts only the data tree (real files this package
        # installs) -- never DEBIAN/control, postinst/prerm, conffiles, or any
        # other dpkg bookkeeping, so no package-manager fingerprint travels
        # into the .wsh.
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


def merge_index(arch, own_index_path, state_dir):
    """Union this shard's fresh index with a snapshot of every other shard's
    (fetched from B2) AND whatever the canonical index/<arch>.txt already
    lists, then publish the result. Including the current canonical file
    matters during the transition to a new NUM_SHARDS value (or right after
    switching from unsharded state): without it, the merge would only ever
    reflect what these specific shards have (re)confirmed so far, silently
    hiding previously-published packages until every shard catches back up.
    Two shards merging around the same moment can race and drop each other's
    latest line -- harmless here, since the next periodic merge (by
    whichever shard writes next) re-derives the union from scratch, and now
    always includes the current canonical file too, so it self-heals and
    never *shrinks*."""
    lines = set()
    if os.path.exists(own_index_path):
        with open(own_index_path) as f:
            lines.update(l.strip() for l in f if l.strip())
    current = os.path.join(state_dir, f"current-{arch}.index")
    if b2_get(f"index/{arch}.txt", current):
        with open(current) as f:
            lines.update(l.strip() for l in f if l.strip())
    for s in range(NUM_SHARDS):
        if s == SHARD:
            continue
        tmp = os.path.join(state_dir, f"other-{arch}-shard{s}.index")
        if b2_get(f"index/{arch}/shard{s}.txt", tmp):
            with open(tmp) as f:
                lines.update(l.strip() for l in f if l.strip())
    # Defensive: a shard that started before a purge ran is still carrying
    # the purged names in its own local index file (nothing ever removes
    # them from there mid-run), and the union above would otherwise merge
    # them straight back into the canonical file on every flush, silently
    # undoing the purge for as long as that shard keeps running. Filtering
    # here -- not just at todo-build time -- makes a block permanent
    # regardless of what any already-running process still has cached.
    lines = {l for l in lines if not is_blocked(l)}

    merged_path = os.path.join(state_dir, f"{arch}.merged.index")
    with open(merged_path, "w") as f:
        f.writelines(f"{l}\n" for l in sorted(lines))
    b2_cp(merged_path, f"index/{arch}.txt")


def mirror_arch(arch_wish, state_dir):
    cfg = ARCHES[arch_wish]
    base = cfg["base"]
    tag = f"shard{SHARD}" if NUM_SHARDS > 1 else None
    label = f"{arch_wish} [{tag}]" if tag else arch_wish
    print(f"=== arch: {label} (upstream: {cfg['deb_arch']}) ===", file=sys.stderr)

    state_prefix = f"state/{arch_wish}/{tag}" if tag else f"state/{arch_wish}"
    index_key = f"index/{arch_wish}/{tag}.txt" if tag else f"index/{arch_wish}.txt"
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

    def collect(text):
        for pkg in parse_packages(text):
            name_raw, ver_raw = pkg.get("Package"), pkg.get("Version")
            if not name_raw or not ver_raw or name_raw in seen_names:
                continue
            if is_blocked(name_raw):
                continue
            if not in_shard(name_raw):
                continue
            uid = f"{name_raw}={ver_raw}"
            if uid in done or uid in failed:
                continue
            seen_names.add(name_raw)
            todo.append((uid, pkg))

    # NOTE: "Architecture: all" packages need no special handling here --
    # unlike e.g. an RPM-style repo layout, Debian/Ubuntu's binary-<arch>
    # Packages.gz ALREADY inlines every arch:all package for that arch
    # (confirmed directly against archive.ubuntu.com: ubuntu-mono, adduser,
    # adwaita-icon-theme etc. all appear in binary-amd64/Packages.gz with
    # "Architecture: all"). There is no separate binary-all index to fetch.
    # A package like "ubuntu-mono" missing from the catalog is NOT this --
    # it's is_blocked() correctly doing its job (name contains "ubuntu").
    todo, seen_names = [], set()
    for comp in COMPONENTS:
        collect(fetch_packages_index(base, RELEASE, comp, cfg["deb_arch"]))

    print(f"{len(todo)} packages left for {label}", file=sys.stderr)

    workdir = os.path.join(state_dir, "work")
    os.makedirs(workdir, exist_ok=True)

    provides_path = os.path.join(state_dir, "provides")
    provides_key = provides_shard_key("ubuntu", arch_wish, SHARD) if tag else f"index/{arch_wish}-provides.txt"

    def flush():
        b2_cp(done_path, done_key)
        b2_cp(failed_path, failed_key)
        b2_cp(index_path, index_key)
        if os.path.exists(provides_path):
            b2_cp(provides_path, provides_key)
        if NUM_SHARDS > 1:
            merge_index(arch_wish, index_path, state_dir)
            merge_provides(arch_wish, "ubuntu", provides_path, state_dir, NUM_SHARDS, SHARD)

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
    if NUM_SHARDS > 1:
        print(f"Shard {SHARD}/{NUM_SHARDS}, arch={ARCH}", file=sys.stderr)

    state_dir = tempfile.mkdtemp()
    remaining = mirror_arch(ARCH, state_dir)

    out = os.environ.get("GITHUB_OUTPUT")
    if out:
        with open(out, "a") as f:
            f.write(f"remaining={remaining}\n")


if __name__ == "__main__":
    main()
