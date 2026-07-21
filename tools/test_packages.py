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

_INFO_CACHE = {}    # name -> parsed .info dict (depends/description/license), or None if 404
_CHECKED = {}       # name -> "ok" | reason string, memoized so a shared dep is only fetched once
_PROVIDES_CACHE = {}  # arch -> {virtual_name: [real_name, ...]}


def _parse_depends_field(value):
    """Parses wish's own .info wire format for a depends=/conflicts=/
    breaks= line: comma-separated independent dependency slots, '|'
    separates OR-alternatives within one slot, "name (OPversion)" carries
    an optional version constraint this script doesn't need to evaluate
    (it only checks resolvability, not version satisfaction -- that's the
    C++ resolver's job). Returns a list of OR-groups, each a list of
    alternative names -- mirrors DepSpec::parse's shape. Previously this
    was naively `value.split(",")`, which for ANY constrained or
    OR-alternative dependency produced a garbage literal like
    "foo (>=1.2)|bar" and looked it up as one nonexistent package name --
    a real bug independent of, but compounding, the virtual-provides gap."""
    groups = []
    for slot in value.split(","):
        slot = slot.strip()
        if not slot:
            continue
        alts = []
        for alt in slot.split("|"):
            alt = alt.strip()
            if not alt:
                continue
            name = alt.split("(", 1)[0].strip()
            if name:
                alts.append(name)
        if alts:
            groups.append(alts)
    return groups


def load_provides_index(arch):
    """Fetches index/<arch>-provides.txt (published by the mirror scripts'
    Provides extraction) exactly once per arch per run -- the same file
    wish's own RemoteIndex::get_providers() reads, so a name that has no
    .info of its own but IS a known virtual/ABI name (e.g.
    "qtbase-abi-5-15-8") can be resolved through whichever real package
    provides it instead of being misreported as missing."""
    if arch in _PROVIDES_CACHE:
        return _PROVIDES_CACHE[arch]
    idx = {}
    try:
        text = http_get(f"{CDN}/index/{arch}-provides.txt")
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split(None, 1)
            if len(parts) == 2:
                virtual, real = parts
                idx.setdefault(virtual, []).append(real)
    except Exception as e:
        print(f"warning: could not load provides index for {arch}: {e}", file=sys.stderr)
    _PROVIDES_CACHE[arch] = idx
    return idx


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

    depends = []  # list of OR-groups, each a list of alternative names
    for line in text.splitlines():
        if line.startswith("depends="):
            depends = _parse_depends_field(line[len("depends="):])
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


def check_dep_group(arch, alt_names, chain):
    """One comma-separated dependency slot, possibly with '|' alternatives
    (e.g. "foo|bar"): satisfied if ANY alternative resolves ok, mirroring
    wish's own resolve_dep_spec fallback-through-alternatives behavior.
    Reports the last-tried alternative's failure reason if none succeed."""
    last_reason = "?"
    for alt in alt_names:
        r = check_package(arch, alt, chain)
        if r == "ok":
            return "ok"
        last_reason = f"{alt}={r}"
    return last_reason


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
        # No literal .info -- before declaring this missing, check whether
        # `name` is actually a known virtual/ABI name (e.g.
        # "qtbase-abi-5-15-8") satisfied by some real package's Provides.
        # Checking literal-name-first, provides-second matches wish's own
        # resolver order (DependencyResolver::resolve_dep_spec: direct name
        # match always shadows a same-named Provides entry). A name that
        # genuinely isn't anywhere -- not a real package, not in the
        # provides index either -- is still "missing_info" and still goes
        # to heal_missing.py to try mirroring in for real.
        providers = load_provides_index(arch).get(name)
        if providers:
            for provider in providers:
                if check_package(arch, provider, chain) == "ok":
                    _CHECKED[name] = "ok"
                    return "ok"
            # Every provider is broken/missing -- but `name` itself is a
            # virtual name, not a real package, so it must NOT be added to
            # missing_names (heal_missing.py would try to mirror-in a
            # package literally called "qtbase-abi-5-15-8", which upstream
            # simply does not have -- that's the exact bug being fixed
            # here). The real provider package(s) already recorded their
            # own failure reason under their own name via the recursive
            # check_package call above, which IS heal-actionable.
            result = "virtual_unsatisfied:" + ",".join(providers)
            _CHECKED[name] = result
            return result
        result = "missing_info"
        _CHECKED[name] = result
        return result

    for group in info["depends"]:
        group_result = check_dep_group(arch, group, chain)
        if group_result != "ok":
            result = f"dep_failed:{group_result}"
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
