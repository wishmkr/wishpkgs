"""
Shared helpers for the mirror_<distro>.py scripts (currently ubuntu, debian,
fedora). All distros publish into the SAME canonical index/<arch>.txt so wish
clients see one catalog regardless of which upstream a package came from --
that's also why the blocklist/redaction below is a single shared list across
every distro, not per-script: a Debian-sourced package must never be
identifiable as such, and neither should a Fedora one.
"""
import gzip
import hashlib
import os
import re
import subprocess
import tempfile

B2_ENDPOINT = "https://s3.eu-central-003.backblazeb2.com"
B2_BUCKET = "wishpkgs"

# Every upstream/tool name that would give away where a package really came
# from. Shared across all mirrors so the catalog is uniformly anonymous no
# matter which script produced a given entry.
BLOCKED_NAME_SUBSTRINGS = (
    "debian", "ubuntu", "apt", "dpkg",
    "fedora", "redhat", "rhel", "centos", "rpm", "dnf", "yum",
)

_REDACT_RE = re.compile(
    r"\b(ubuntu|debian|fedora|red ?hat|rhel|centos)\b", re.IGNORECASE
)

# Every distro's shard fan-out, fixed here so merge_index() can always union
# every other distro's per-shard index files (not just its own) into the one
# shared canonical index/<arch>.txt -- this is what makes the catalog a
# single unified list instead of three parallel ones.
DISTRO_SHARD_COUNTS = {
    "ubuntu": 4,
    "debian": 6,
    "fedora": 13,
}

# Ubuntu's shard index files predate this shared module and live at
# index/<arch>/shard<N>.txt (no distro prefix); newer distros use
# index/<arch>/<distro>-shard<N>.txt to avoid colliding with that.
def shard_index_key(distro, arch, shard):
    if distro == "ubuntu":
        return f"index/{arch}/shard{shard}.txt"
    return f"index/{arch}/{distro}-shard{shard}.txt"


def redact(text):
    """Drop literal distro-name mentions from text WE generate. Never applied
    to a package's own shipped files (copyright/license/docs stay verbatim)."""
    return _REDACT_RE.sub("the system", text) if text else text


def is_blocked(name_raw):
    lower = name_raw.lower()
    return any(s in lower for s in BLOCKED_NAME_SUBSTRINGS)


def in_shard(name, shard, num_shards):
    """Stable partition via hashlib (not the randomized-per-process builtin
    hash()) so the same package always maps to the same shard across
    separate processes/runs."""
    if num_shards <= 1:
        return True
    digest = hashlib.md5(name.encode()).hexdigest()
    return int(digest, 16) % num_shards == shard


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


def sanitize_depends_list(names):
    out, seen = [], set()
    for name in names:
        if not name:
            continue
        dep = sanitize_name(name)
        if dep not in seen:
            seen.add(dep)
            out.append(dep)
    return out


# Reverse-parses a .wsh index line back into its package name. Anchored from
# the right (version/release/arch are all tightly constrained patterns) so
# this is reliable even for names that themselves contain digits or dashes.
_WSH_LINE_RE = re.compile(
    r"^(?P<name>.+)-(?P<version>[0-9][0-9.]*)-(?P<release>\d+)-"
    r"(?:x86_64|aarch64)\.wsh$"
)


def parse_name_from_index_line(line):
    m = _WSH_LINE_RE.match(line.strip())
    return m.group("name") if m else None


def load_canonical_names(arch, state_dir):
    """Every package name already published for this arch, regardless of
    which distro mirror put it there. Callers must skip anything in this set
    outright -- packages already in the catalog are never re-added, from any
    upstream."""
    tmp = os.path.join(state_dir, f"canonical-{arch}.index")
    names = set()
    if b2_get(f"index/{arch}.txt", tmp):
        with open(tmp) as f:
            for line in f:
                name = parse_name_from_index_line(line)
                if name:
                    names.add(name)
    return names


def merge_index(arch, distro, own_index_path, state_dir, num_shards, shard):
    """Union this shard's fresh index with every OTHER shard's index across
    ALL distros (not just this one) plus whatever the canonical
    index/<arch>.txt already lists, then publish the result. This is what
    keeps every distro's contributions in the same single catalog file wish
    clients read. Re-applies is_blocked() at merge time too (not just at
    todo-build time) so a purge/block sticks even against a shard that
    already had the name cached in memory from before the block existed."""
    lines = set()
    if os.path.exists(own_index_path):
        with open(own_index_path) as f:
            lines.update(l.strip() for l in f if l.strip())

    current = os.path.join(state_dir, f"current-{arch}.index")
    if b2_get(f"index/{arch}.txt", current):
        with open(current) as f:
            lines.update(l.strip() for l in f if l.strip())

    for d, count in DISTRO_SHARD_COUNTS.items():
        for s in range(count):
            if d == distro and s == shard:
                continue
            tmp = os.path.join(state_dir, f"other-{arch}-{d}-shard{s}.index")
            if b2_get(shard_index_key(d, arch, s), tmp):
                with open(tmp) as f:
                    lines.update(l.strip() for l in f if l.strip())

    lines = {l for l in lines if not is_blocked(l)}

    merged_path = os.path.join(state_dir, f"{arch}.merged.index")
    with open(merged_path, "w") as f:
        f.writelines(f"{l}\n" for l in sorted(lines))
    b2_cp(merged_path, f"index/{arch}.txt")
