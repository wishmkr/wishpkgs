#!/usr/bin/env python3
"""
Repackage upstream .rpm binaries from Fedora's own repo (dl.fedoraproject.org)
into wish's .wsh format, uploaded straight to the B2 bucket that backs
cdn.wishpkgs.org. RPM extraction goes through `rpm2cpio | cpio -idm` (the
rpm/cpio CLI tools, installed by the workflow -- not preinstalled on GitHub's
runners) so only the package's real payload ends up in the .wsh, never any
rpm database/scriptlet metadata. Shares one catalog with every other mirror
script: skips any package name already published by ANY distro (see
mirror_common.load_canonical_names), and never emits metadata that would
reveal a package came from Fedora specifically (see mirror_common.redact /
is_blocked).

Resumable by design: progress lives in B2 (state/fedora/<arch>/shard<N>.done
/.failed), so a fresh process -- manual or self-re-triggered -- picks up
exactly where the last one stopped, even mid-package.
"""
import hashlib
import lzma
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import xml.etree.ElementTree as ET
from urllib.request import urlopen

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mirror_common import (
    sh, b2_cp, b2_get, is_blocked, in_shard, redact, sanitize_name,
    sanitize_version, sanitize_depends_list, load_state_set,
    load_canonical_names, merge_index, rpm_entries_to_groups,
    format_dep_field, provides_names, merge_provides, provides_shard_key,
)

DISTRO = "fedora"
DEADLINE = time.monotonic() + float(os.environ.get("MIRROR_DEADLINE_SECONDS", "19500"))
RELEASE = os.environ.get("MIRROR_RELEASE", "40")
REPO = os.environ.get("MIRROR_REPO", "Everything")  # Everything | Fedora
FLUSH_EVERY = int(os.environ.get("MIRROR_FLUSH_EVERY", "20"))
ARCH = os.environ.get("MIRROR_ARCH", "aarch64")
SHARD = int(os.environ.get("MIRROR_SHARD", "0"))
NUM_SHARDS = max(1, int(os.environ.get("MIRROR_SHARDS", "13")))

# Fedora uses the same arch names wish does -- no translation needed.
ARCHES = {
    "x86_64":  {"rpm_arch": "x86_64"},
    "aarch64": {"rpm_arch": "aarch64"},
}

# dl.fedoraproject.org retires each release to the archive host once it's no
# longer current -- archives.fedoraproject.org has every past release too,
# so pin there directly rather than racing EOL.
BASE = "https://archives.fedoraproject.org/pub/archive/fedora/linux/releases"

NS = {
    "common": "http://linux.duke.edu/metadata/common",
    "rpm": "http://linux.duke.edu/metadata/rpm",
    "repo": "http://linux.duke.edu/metadata/repo",
}


def repo_base(rpm_arch):
    return f"{BASE}/{RELEASE}/{REPO}/{rpm_arch}/os"


def decompress_any(data, url):
    if url.endswith(".xz"):
        return lzma.decompress(data)
    if url.endswith(".gz"):
        import gzip
        return gzip.decompress(data)
    if url.endswith(".zst"):
        # No zstd in the stdlib -- shell out to the `zstd` CLI (installed by
        # the workflow) via a temp file round-trip.
        with tempfile.NamedTemporaryFile(suffix=".zst", delete=False) as tf:
            tf.write(data)
            tmp_in = tf.name
        tmp_out = tmp_in[:-4]
        try:
            sh(f'zstd -d -f -q "{tmp_in}" -o "{tmp_out}"')
            with open(tmp_out, "rb") as f:
                return f.read()
        finally:
            for p in (tmp_in, tmp_out):
                if os.path.exists(p):
                    os.remove(p)
    raise ValueError(f"Unknown compression for {url}")


def fetch_primary_xml(rpm_arch):
    repomd_url = f"{repo_base(rpm_arch)}/repodata/repomd.xml"
    print(f"fetching {repomd_url}", file=sys.stderr)
    with urlopen(repomd_url, timeout=60) as r:
        repomd = r.read()
    root = ET.fromstring(repomd)
    primary_href = None
    for data in root.findall("repo:data", NS):
        if data.get("type") == "primary":
            loc = data.find("repo:location", NS)
            primary_href = loc.get("href")
            break
    if not primary_href:
        raise RuntimeError("no primary.xml entry in repomd.xml")

    primary_url = f"{repo_base(rpm_arch)}/{primary_href}"
    print(f"fetching {primary_url}", file=sys.stderr)
    with urlopen(primary_url, timeout=120) as r:
        raw = r.read()
    return decompress_any(raw, primary_href)


# rpm Requires entries include a lot of internal/virtual machinery
# (rpmlib(...) feature markers, soname-style "libfoo.so.N()(64bit)" provides)
# that don't map onto any real installable package name -- only keep entries
# that look like plain package names.
_PLAIN_NAME_RE = re.compile(r"^[A-Za-z0-9._+-]+$")


def _read_entries(container):
    """<rpm:entry name=".." flags=".." ver=".."/> tuples, skipping rpmlib(...)
    feature markers and soname-style "libfoo.so.N()(64bit)" virtual entries
    (parenthesized names) that don't map onto any real installable
    package."""
    out = []
    if container is None:
        return out
    for entry in container.findall("rpm:entry", NS):
        rname = entry.get("name", "")
        if rname.startswith("rpmlib(") or not _PLAIN_NAME_RE.match(rname):
            continue
        out.append((rname, entry.get("flags", ""), entry.get("ver", "")))
    return out


def parse_primary(xml_bytes):
    root = ET.fromstring(xml_bytes)
    for pkg in root.findall("common:package", NS):
        if pkg.get("type") != "rpm":
            continue
        name = pkg.findtext("common:name", default="", namespaces=NS)
        arch = pkg.findtext("common:arch", default="", namespaces=NS)
        if arch == "src":
            continue
        version_el = pkg.find("common:version", NS)
        version = version_el.get("ver") if version_el is not None else None
        location_el = pkg.find("common:location", NS)
        href = location_el.get("href") if location_el is not None else None
        summary = pkg.findtext("common:summary", default="", namespaces=NS)

        requires, provides, conflicts = [], [], []
        fmt = pkg.find("common:format", NS)
        if fmt is not None:
            requires = _read_entries(fmt.find("rpm:requires", NS))
            provides = _read_entries(fmt.find("rpm:provides", NS))
            conflicts = _read_entries(fmt.find("rpm:conflicts", NS))

        if not (name and version and href):
            continue
        yield {
            "name": name,
            "version": version,
            "href": href,
            "summary": summary,
            "requires": requires,
            "provides": provides,
            "conflicts": conflicts,
        }


def process_package(arch_wish, rpm_arch, pkg, workdir):
    name_raw, ver_raw, href = pkg["name"], pkg["version"], pkg["href"]

    name = sanitize_name(name_raw)
    version = sanitize_version(ver_raw)
    release = "1"
    wsh_name = f"{name}-{version}-{release}-{arch_wish}.wsh"

    rpm_path = os.path.join(workdir, "pkg.rpm")
    extract_dir = os.path.join(workdir, "extract")
    shutil.rmtree(extract_dir, ignore_errors=True)
    os.makedirs(extract_dir, exist_ok=True)

    try:
        url = f"{repo_base(rpm_arch)}/{href}"
        sh(f'curl -fsSL --retry 3 --max-time 120 -o "{rpm_path}" "{url}"')
        # rpm2cpio + cpio only unpacks the payload (real installed files) --
        # no %pre/%post scriptlets, no rpm database entries.
        subprocess.run(
            f'rpm2cpio "{rpm_path}" | (cd "{extract_dir}" && cpio -idm --quiet)',
            shell=True, check=True,
        )

        wsh_path = os.path.join(workdir, wsh_name)
        with tarfile.open(wsh_path, "w:gz") as tar:
            for entry in sorted(os.listdir(extract_dir)):
                tar.add(os.path.join(extract_dir, entry), arcname=entry)

        sha = hashlib.sha256(open(wsh_path, "rb").read()).hexdigest()
        sha_path = wsh_path + ".sha256"
        with open(sha_path, "w") as f:
            f.write(f"{sha}  {wsh_name}\n")

        depends = format_dep_field(rpm_entries_to_groups(pkg["requires"]))
        conflicts = format_dep_field(rpm_entries_to_groups(pkg["conflicts"]))
        provides_groups = rpm_entries_to_groups(pkg["provides"])
        provides = provides_names(provides_groups)

        desc_line = pkg["summary"].splitlines()[0] if pkg["summary"] else ""
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

        b2_cp(wsh_path, f"pkgs/{arch_wish}/{wsh_name}")
        b2_cp(sha_path, f"pkgs/{arch_wish}/{wsh_name}.sha256")
        b2_cp(info_path, f"pkgs/{arch_wish}/{name}.info")
        return wsh_name, [(v, name) for v in provides]
    except Exception as e:
        print(f"FAILED {name_raw}={ver_raw}: {e}", file=sys.stderr)
        return None, []
    finally:
        if os.path.exists(rpm_path):
            os.remove(rpm_path)
        shutil.rmtree(extract_dir, ignore_errors=True)


def mirror_arch(arch_wish, state_dir):
    cfg = ARCHES[arch_wish]
    rpm_arch = cfg["rpm_arch"]
    label = f"{arch_wish} [fedora-shard{SHARD}]"
    print(f"=== {label} (upstream: {rpm_arch}, fedora {RELEASE}) ===", file=sys.stderr)

    state_prefix = f"state/fedora/{arch_wish}/shard{SHARD}"
    index_key = f"index/{arch_wish}/fedora-shard{SHARD}.txt"
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

    existing_names = load_canonical_names(arch_wish, state_dir)

    todo, seen_names = [], set()
    for pkg in parse_primary(fetch_primary_xml(rpm_arch)):
        name_raw = pkg["name"]
        if name_raw in seen_names:
            continue
        if is_blocked(name_raw):
            continue
        sanitized = sanitize_name(name_raw)
        if sanitized in existing_names:
            continue
        if not in_shard(name_raw, SHARD, NUM_SHARDS):
            continue
        uid = f"{name_raw}={pkg['version']}"
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
        wsh_name, provides = process_package(arch_wish, rpm_arch, pkg, workdir)
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
