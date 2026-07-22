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

# Exact package names known to be pure Debian/Ubuntu/Fedora packaging
# tooling or distro-branding metapackages: things with no function outside
# their origin distro's package-management stack (need a live apt/dpkg/dnf
# database, sources.list, live repo config -- none of which this project
# ships) or that are nothing but a curated-set marker with no real payload.
# EXACT match only -- this used to be a substring check against
# ("debian","ubuntu","apt","dpkg","fedora",...), which also caught real,
# needed runtime/data packages any number of OTHER packages legitimately
# Depend on directly: "ubuntu-mono" (a GTK icon theme), "fonts-ubuntu"/
# "fonts-ubuntu-console", "gsettings-ubuntu-schemas", "ubuntu-wallpapers"
# (-noble), "debianutils" (8 real Depends references in one Ubuntu Packages
# snapshot alone), "python3-debian", "libdebian-installer4"(-dev). Blocking
# those left their dependency permanently unresolvable for every package
# that named them, silently breaking real install chains (found via a
# real-world report, not proactively). Extend this set one exact name at a
# time -- never reintroduce a broad substring rule.
BLOCKED_EXACT_NAMES = {
    # apt/dpkg tooling -- needs a live package database this project
    # doesn't have.
    "apt", "apt-utils", "apt-transport-https", "apt-listchanges",
    "apt-listbugs", "dpkg", "dpkg-dev", "dpkg-repack",
    # Ubuntu subscription/update/branding tooling and metapackages.
    "ubuntu-advantage-tools", "ubuntu-advantage-desktop-daemon",
    "ubuntu-pro-client", "ubuntu-pro-client-l10n",
    "ubuntu-release-upgrader-core", "ubuntu-release-upgrader-gtk",
    "ubuntu-release-upgrader-qt", "update-manager", "update-manager-core",
    "update-notifier", "software-properties-common",
    "software-properties-gtk", "software-properties-qt",
    "ubuntu-drivers-common", "ubuntu-report", "ubuntu-keyring",
    "ubuntu-cloud-keyring", "ubuntu-dbgsym-keyring", "ubuntu-oem-keyring",
    "debian-archive-keyring", "debian-keyring", "debian-goodies",
    "popularity-contest", "ubiquity-ubuntu-artwork", "ubuntu-docs",
    "ubuntu-server", "ubuntu-server-minimal", "ubuntu-desktop",
    "ubuntu-desktop-minimal", "ubuntu-minimal", "ubuntu-standard",
    "ubuntu-session", "ubuntu-settings", "ubuntu-raspi-settings",
    "ubuntu-raspi-settings-desktop", "ubuntu-raspi-settings-server",
    "ubuntu-wsl", "ubuntu-cloud-minimal", "ubuntu-kernel-accessories",
    "gnome-shell-extension-ubuntu-dock",
    "gnome-shell-extension-ubuntu-tiling-assistant",
    "network-manager-config-connectivity-ubuntu", "intltool-debian",
    # Fedora/RHEL-family packaging tooling and release/branding markers.
    "dnf", "dnf-plugins-core", "yum", "yum-utils",
    "fedora-release", "fedora-repos", "fedora-gpg-keys",
    "centos-release", "centos-stream-release", "rhel-release",
    "redhat-release",
}

# Real runtime/data packages that must NEVER be blocked even though their
# name contains a distro-name substring -- kept explicit (not just "absent
# from BLOCKED_EXACT_NAMES") so a future addition to that set can't
# accidentally re-catch one of these by name collision. See the comment on
# BLOCKED_EXACT_NAMES for why each of these matters.
ALWAYS_ALLOWED_NAMES = {
    "ubuntu-mono", "fonts-ubuntu", "fonts-ubuntu-console",
    "gsettings-ubuntu-schemas", "ubuntu-wallpapers", "ubuntu-wallpapers-noble",
    "debianutils", "python3-debian", "libdebian-installer4",
    "libdebian-installer4-dev", "libdebian-installer-extra4",
    "libdebian-dpkgcross-perl",
}

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
    """Exact-name check against BLOCKED_EXACT_NAMES, with ALWAYS_ALLOWED_NAMES
    as an override. `name_raw` must be a bare package name (upstream or
    already-sanitized) -- NOT a full ".wsh" index-line filename; callers
    filtering full index lines must extract the name first (see
    parse_name_from_index_line), since an exact-match check against a
    "name-version-release-arch.wsh" string can never match a bare blocked
    name."""
    lower = name_raw.lower()
    if lower in ALWAYS_ALLOWED_NAMES:
        return False
    return lower in BLOCKED_EXACT_NAMES


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


# Debian relationship fields (Depends/Pre-Depends/Recommends/Provides/
# Conflicts/Breaks/...) can suffix a package name with a multiarch
# qualifier: ":any" (satisfied by any architecture's build), ":native"
# (build-architecture specific), or a literal architecture name (e.g.
# ":armhf"). None of that concept exists in wish's single-arch-per-catalog
# model. MUST be stripped before sanitize_name ever sees the name -- its
# [^a-z0-9-] cleanup below turns ':' into '-', so "python3:any" silently
# became the nonexistent "python3-any" (a real bug: this made every
# multiarch-qualified dependency unresolvable).
_MULTIARCH_QUALIFIER_RE = re.compile(r":(any|native|[a-z0-9][a-z0-9-]*)$")


def strip_multiarch_qualifier(name):
    return _MULTIARCH_QUALIFIER_RE.sub("", name)


def sanitize_name(raw):
    raw = strip_multiarch_qualifier(raw)
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


# ---- structured dependency/provides/conflicts fields ----
#
# Older mirror code threw away version constraints and every alternative
# after the first "|" in a Depends field -- there was no way to use that
# information (no version comparison, no virtual-package resolution). The
# resolver on the wish side now understands both, so this preserves them
# instead: a dependency field is a list of OR-groups, each an alternation
# of (name, op, version) triples where op is one of ">=","<=","=","<",">"
# or "" for "any version".
_CONSTRAINT_RE = re.compile(r"\(\s*(>=|<=|=|>>|<<|>|<)\s*([^)]+)\)")
_RPM_FLAG_TO_OP = {"GE": ">=", "LE": "<=", "EQ": "=", "LT": "<", "GT": ">"}


def parse_dep_field(field):
    """Parses a Debian-style Depends/Conflicts/Breaks/Provides field, e.g.
    "foo (>= 1.2) | bar, baz" -> [[("foo",">=","1.2"), ("bar","","")],
    [("baz","","")]] (outer list = comma-separated OR-groups, inner list =
    pipe-separated alternatives within one group)."""
    if not field:
        return []
    groups = []
    for group in field.split(","):
        alts = []
        for alt in group.split("|"):
            alt = alt.strip()
            if not alt:
                continue
            m = _CONSTRAINT_RE.search(alt)
            name_part = alt[:m.start()].strip() if m else alt
            name_part = name_part.split()[0] if name_part else ""
            if not name_part:
                continue
            op, ver = "", ""
            if m:
                op = m.group(1)
                if op == ">>":
                    op = ">"
                elif op == "<<":
                    op = "<"
                ver = sanitize_version(m.group(2))
            alts.append((sanitize_name(name_part), op, ver))
        if alts:
            groups.append(alts)
    return groups


def rpm_entries_to_groups(entries):
    """Same output shape as parse_dep_field(), but from parsed RPM
    <rpm:entry name=".." flags=".." ver=".."/> tuples (each entry is its
    own OR-group of one -- RPM doesn't have Debian's "|" alternation)."""
    groups = []
    for name, flags, ver in entries:
        op = _RPM_FLAG_TO_OP.get(flags, "")
        version = sanitize_version(ver) if (op and ver) else ""
        if not op or not version:
            op, version = "", ""
        groups.append([(sanitize_name(name), op, version)])
    return groups


def format_dep_field(groups):
    """Serializes parse_dep_field()'s output back to the .info textual
    form: comma-separated OR-groups, pipe-separated alternatives,
    "name (OPversion)" per alternative that carries a constraint."""
    parts = []
    for group in groups:
        alt_strs = []
        for name, op, ver in group:
            alt_strs.append(f"{name} ({op}{ver})" if op and ver else name)
        parts.append("|".join(alt_strs))
    return ",".join(parts)


def provides_names(groups):
    """Flat list of every real name mentioned across all OR-groups --
    Provides fields don't have meaningful alternation, this is just used to
    build the flat virtual-name list for a package's `provides=` line and
    for populating the cross-package provides index."""
    return [alt[0] for group in groups for alt in group]


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


def parse_name_version_from_index_line(line):
    """Same as parse_name_from_index_line but also returns the version --
    needed by backfill_metadata.py to confirm an upstream stanza it found
    actually corresponds to what's canonically published before trusting
    its dependency data (see load_canonical_versions)."""
    m = _WSH_LINE_RE.match(line.strip())
    return (m.group("name"), m.group("version")) if m else (None, None)


def _index_line_is_blocked(line):
    """is_blocked() takes a bare package name, not a full
    "name-version-release-arch.wsh" index line -- extract the name first.
    A line that doesn't even parse as a valid index entry is left alone
    here (not this function's job to drop malformed lines)."""
    name = parse_name_from_index_line(line)
    return is_blocked(name) if name else False


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


def load_canonical_versions(arch, state_dir):
    """name -> version map for everything canonically published. The SAME
    package name can legitimately exist in more than one upstream distro's
    archive at a DIFFERENT version (e.g. Ubuntu's own "libgcc-s1" vs
    Debian's own "libgcc-s1" -- real, separate packages, not duplicates).
    Only one of them is ever actually mirrored (whichever distro's mirror
    script got there first); backfill_metadata.py needs to know WHICH
    version that was so it only trusts a distro's upstream stanza for a
    package when that stanza's version matches what's actually published --
    otherwise a later distro pass in the same backfill run can silently
    overwrite a package's dependency metadata with a completely different
    distro's dependency graph, for a version that was never mirrored at
    all. This is a real bug that shipped once: Debian's libgcc-s1
    (12.2.0-14+deb12u1, Depends: gcc-12-base) overwrote the .info of an
    Ubuntu-sourced libgcc-s1 payload (version 14-20240412-0ubuntu1,
    Depends: gcc-14-base) during a backfill run, because both distros
    happen to ship a same-named package and nothing checked the version
    matched before trusting the stanza."""
    tmp = os.path.join(state_dir, f"canonical-versions-{arch}.index")
    versions = {}
    if b2_get(f"index/{arch}.txt", tmp):
        with open(tmp) as f:
            for line in f:
                name, version = parse_name_version_from_index_line(line)
                if name:
                    versions[name] = version
    return versions


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

    lines = {l for l in lines if not _index_line_is_blocked(l)}

    merged_path = os.path.join(state_dir, f"{arch}.merged.index")
    with open(merged_path, "w") as f:
        f.writelines(f"{l}\n" for l in sorted(lines))
    b2_cp(merged_path, f"index/{arch}.txt")


def provides_shard_key(distro, arch, shard):
    return f"index/{arch}/{distro}-shard{shard}-provides.txt"


def merge_provides(arch, distro, own_provides_path, state_dir, num_shards, shard):
    """Same union-and-republish shape as merge_index(), for the separate
    virtual-name -> real-package-name mapping. Kept as its own small file
    (index/<arch>-provides.txt, "virtual_name real_name" per line) instead
    of folded into the main package list, because the resolver only needs
    to fetch it ONCE per run (not per-package) to resolve a dependency on a
    virtual/provided name -- that's the whole point of not re-introducing
    the eager-full-catalog-fetch performance bug fixed earlier."""
    lines = set()
    if os.path.exists(own_provides_path):
        with open(own_provides_path) as f:
            lines.update(l.strip() for l in f if l.strip())

    current = os.path.join(state_dir, f"current-{arch}.provides")
    if b2_get(f"index/{arch}-provides.txt", current):
        with open(current) as f:
            lines.update(l.strip() for l in f if l.strip())

    for d, count in DISTRO_SHARD_COUNTS.items():
        for s in range(count):
            if d == distro and s == shard:
                continue
            tmp = os.path.join(state_dir, f"other-{arch}-{d}-shard{s}.provides")
            if b2_get(provides_shard_key(d, arch, s), tmp):
                with open(tmp) as f:
                    lines.update(l.strip() for l in f if l.strip())

    merged_path = os.path.join(state_dir, f"{arch}.merged.provides")
    with open(merged_path, "w") as f:
        f.writelines(f"{l}\n" for l in sorted(lines))
    b2_cp(merged_path, f"index/{arch}-provides.txt")
