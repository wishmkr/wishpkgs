#!/usr/bin/env python3
"""
Exercises every package in the live catalog through the exact same steps
`wish install <pkg>` performs -- resolve dependencies, download the .wsh +
.sha256, verify the checksum, confirm the archive actually extracts -- but
standalone in Python, reading straight from the public CDN (no B2
credentials needed, no need to build/ship the wish binary, and no
architecture constraint since checking an archive's checksum/contents
doesn't require running anything built for that arch).

Sharded the same way the mirror scripts are: a stable hash of the package
name decides which shard tests it, so results are reproducible across runs.
Each shard writes its own JSON report; a separate aggregate step merges them
into one pass/fail-with-reason list per architecture.

This never touches B2 or the catalog -- it's read-only against the public
CDN, so it's safe to run as often as needed and doesn't need any repo
secrets.
"""
import hashlib
import json
import os
import re
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
import urllib.error

CDN = os.environ.get("WISH_CDN", "https://cdn.wishpkgs.org")
ARCH = os.environ.get("TEST_ARCH", "aarch64")
SHARD = int(os.environ.get("TEST_SHARD", "0"))
NUM_SHARDS = max(1, int(os.environ.get("TEST_SHARDS", "1")))
DEADLINE = time.monotonic() + float(os.environ.get("TEST_DEADLINE_SECONDS", "19500"))
TIMEOUT = 30

_INFO_CACHE = {}   # name -> parsed .info dict (depends/description/license), or None if 404
_CHECKED = {}       # name -> "ok" | reason string, memoized so a shared dep is only fetched once


def in_shard(name):
    if NUM_SHARDS <= 1:
        return True
    digest = hashlib.md5(name.encode()).hexdigest()
    return int(digest, 16) % NUM_SHARDS == SHARD


def http_get(url, binary=False):
    req = urllib.request.Request(url, headers={"User-Agent": "wishpkgs-test-packages"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        data = r.read()
    return data if binary else data.decode("utf-8", "replace")


def fetch_index(arch):
    # TEST_NAMES_FILE restricts the run to a specific set of packages (phase
    # 2 of the test-and-heal pipeline: re-verify only what phase 1 flagged
    # and heal_missing.py tried to fix, instead of re-scanning everything).
    names_file = os.environ.get("TEST_NAMES_FILE")
    if names_file:
        with open(names_file) as f:
            return [l.strip() for l in f if l.strip()]

    text = http_get(f"{CDN}/index/{arch}.txt")
    names = []
    pattern = re.compile(r"^(?P<name>.+)-[0-9][0-9.]*-\d+-(?:x86_64|aarch64)\.wsh$")
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        m = pattern.match(line)
        if m:
            names.append(m.group("name"))
    return names


def fetch_info(arch, name):
    if name in _INFO_CACHE:
        return _INFO_CACHE[name]
    try:
        text = http_get(f"{CDN}/pkgs/{arch}/{name}.info")
    except urllib.error.HTTPError as e:
        _INFO_CACHE[name] = None
        return None
    except Exception:
        _INFO_CACHE[name] = None
        return None

    depends = []
    for line in text.splitlines():
        if line.startswith("depends="):
            depends = [d.strip() for d in line[len("depends="):].split(",") if d.strip()]
    info = {"depends": depends}
    _INFO_CACHE[name] = info
    return info


def find_wsh_filename(arch, name):
    """The index only tells us names existed at some point -- re-derive the
    exact current filename (version/release can differ) by checking the
    index text itself, cached per-arch."""
    key = f"__index_lines_{arch}"
    if key not in _INFO_CACHE:
        text = http_get(f"{CDN}/index/{arch}.txt")
        _INFO_CACHE[key] = text.splitlines()
    prefix = name + "-"
    for line in _INFO_CACHE[key]:
        line = line.strip()
        if line.startswith(prefix) and line.endswith(f"-{arch}.wsh"):
            # Guard against prefix collisions (e.g. "foo" matching "foo-bar-...")
            rest = line[len(prefix):]
            if re.match(r"^[0-9][0-9.]*-\d+-(?:x86_64|aarch64)\.wsh$", rest):
                return line
    return None


def check_package(arch, name, chain):
    """Recursively resolves + verifies `name` and its dependency closure.
    `chain` is the current DFS ancestry, used to break cycles exactly like
    wish's own resolver (a cycle is not an error -- see the resolver's
    3-state DFS in the C++ source)."""
    if name in _CHECKED:
        return _CHECKED[name]
    if name in chain:
        return "ok"  # cycle -- ancestor call will finish resolving it

    chain = chain + (name,)

    info = fetch_info(arch, name)
    if info is None:
        result = "missing_info"
        _CHECKED[name] = result
        return result

    for dep in info["depends"]:
        dep_result = check_package(arch, dep, chain)
        if dep_result != "ok":
            result = f"dep_failed:{dep}={dep_result}"
            _CHECKED[name] = result
            return result

    wsh_name = find_wsh_filename(arch, name)
    if not wsh_name:
        result = "missing_from_index"
        _CHECKED[name] = result
        return result

    try:
        sha_text = http_get(f"{CDN}/pkgs/{arch}/{wsh_name}.sha256")
        expected_sha = sha_text.split()[0].strip()
    except Exception as e:
        result = f"sha256_fetch_failed:{e}"
        _CHECKED[name] = result
        return result

    try:
        data = http_get(f"{CDN}/pkgs/{arch}/{wsh_name}", binary=True)
    except Exception as e:
        result = f"download_failed:{e}"
        _CHECKED[name] = result
        return result

    actual_sha = hashlib.sha256(data).hexdigest()
    if actual_sha != expected_sha:
        result = f"checksum_mismatch:expected={expected_sha[:12]}..got={actual_sha[:12]}.."
        _CHECKED[name] = result
        return result

    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(suffix=".wsh", delete=False) as tf:
            tf.write(data)
            tmp_path = tf.name
        with tarfile.open(tmp_path, "r:gz") as tar:
            members = tar.getnames()
        if not members:
            result = "empty_archive"
            _CHECKED[name] = result
            return result
    except Exception as e:
        result = f"extract_failed:{e}"
        _CHECKED[name] = result
        return result
    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.remove(tmp_path)

    _CHECKED[name] = "ok"
    return "ok"


def main():
    names = [n for n in fetch_index(ARCH) if in_shard(n)]
    print(f"shard {SHARD}/{NUM_SHARDS} arch={ARCH}: {len(names)} top-level packages to test",
          file=sys.stderr)

    results = {}
    tested = 0
    for name in names:
        if time.monotonic() > DEADLINE:
            print("deadline reached, stopping cleanly", file=sys.stderr)
            break
        outcome = check_package(ARCH, name, ())
        results[name] = outcome
        tested += 1
        if outcome != "ok":
            print(f"  FAIL {name}: {outcome}", file=sys.stderr)
        if tested % 200 == 0:
            print(f"  ...{tested}/{len(names)}", file=sys.stderr)

    failed = {k: v for k, v in results.items() if v != "ok"}
    print(f"shard {SHARD}: tested {tested}, failed {len(failed)}", file=sys.stderr)

    # Every name anywhere in the dependency graphs we walked (not just the
    # top-level packages in `names`) that came back with no .info at all --
    # this is the actual set heal_missing.py needs, since a top-level
    # package's failure is usually caused by some dependency several levels
    # down, not the top-level name itself.
    missing_names = sorted(n for n, outcome in _CHECKED.items() if outcome == "missing_info")

    out_dir = os.environ.get("TEST_OUTPUT_DIR", ".")
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, f"results-{ARCH}-shard{SHARD}.json")
    with open(out_path, "w") as f:
        json.dump({
            "arch": ARCH, "shard": SHARD, "tested": tested,
            "failed_count": len(failed), "missing_names": missing_names,
            "results": results,
        }, f, indent=2, sort_keys=True)
    print(f"wrote {out_path}", file=sys.stderr)

    out = os.environ.get("GITHUB_OUTPUT")
    if out:
        with open(out, "a") as f:
            f.write(f"tested={tested}\n")
            f.write(f"failed={len(failed)}\n")


if __name__ == "__main__":
    main()
