#!/usr/bin/env python3
"""
Repackage upstream .deb binaries into wish's .wsh package format and upload
them straight to the B2 bucket that backs cdn.wishpkgs.org.

Resumable by design: progress (done/failed package ids, the live per-arch
index, and which arch is "current") is stored in B2 itself, so a fresh
process -- whether started manually or by the workflow re-triggering itself
after its internal deadline -- picks up exactly where the last one stopped,
even if that one was mid-package when it got cut off.

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

DEADLINE = time.monotonic() + float(os.environ.get("MIRROR_DEADLINE_SECONDS", "19800"))  # 5h30m default
RELEASE = os.environ.get("MIRROR_RELEASE", "noble")
COMPONENTS = [c for c in os.environ.get("MIRROR_COMPONENTS", "main").split(",") if c]
FLUSH_EVERY = int(os.environ.get("MIRROR_FLUSH_EVERY", "20"))

ARCHES = {
    "x86_64":  {"deb_arch": "amd64", "base": "http://archive.ubuntu.com/ubuntu"},
    "aarch64": {"deb_arch": "arm64", "base": "http://ports.ubuntu.com/ubuntu-ports"},
}
ARCH_ORDER = ["aarch64", "x86_64"]

B2_ENDPOINT = "https://s3.eu-central-003.backblazeb2.com"
B2_BUCKET = "wishpkgs"

_REDACT_RE = re.compile(r"\b(ubuntu|debian)\b", re.IGNORECASE)


def redact(text):
    """Drop literal distro-name mentions from text WE generate. Never applied
    to the package's own shipped files (copyright/license/docs stay verbatim)."""
    return _REDACT_RE.sub("the system", text) if text else text


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
    if not field:
        return []
    out, seen = [], set()
    for group in field.split(","):
        first = group.strip().split("|", 1)[0].strip()
        name = re.split(r"[\s(]", first, 1)[0].strip()
        if not name:
            continue
        dep = sanitize_name(name)
        if dep not in seen:
            seen.add(dep)
            out.append(dep)
    return out


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


def process_package(arch_wish, base, pkg, workdir, index_path):
    name_raw, ver_raw, filename = pkg.get("Package"), pkg.get("Version"), pkg.get("Filename")
    if not (name_raw and ver_raw and filename):
        return False

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
        desc_line = pkg.get("Description", "").splitlines()[0] if pkg.get("Description") else ""
        info_path = os.path.join(workdir, f"{name}.info")
        with open(info_path, "w") as f:
            f.write(f"description={redact(desc_line)}\n")
            f.write("license=See included license/copyright files\n")
            if depends:
                f.write(f"depends={','.join(depends)}\n")

        b2_cp(wsh_path, f"pkgs/{arch_wish}/{wsh_name}")
        b2_cp(sha_path, f"pkgs/{arch_wish}/{wsh_name}.sha256")
        b2_cp(info_path, f"pkgs/{arch_wish}/{name}.info")

        with open(index_path, "a") as f:
            f.write(wsh_name + "\n")
        b2_cp(index_path, f"index/{arch_wish}.txt")
        return True
    except Exception as e:
        print(f"FAILED {name_raw}={ver_raw}: {e}", file=sys.stderr)
        return False
    finally:
        if os.path.exists(deb_path):
            os.remove(deb_path)
        shutil.rmtree(extract_dir, ignore_errors=True)


def mirror_arch(arch_wish, state_dir):
    cfg = ARCHES[arch_wish]
    base = cfg["base"]
    print(f"=== arch: {arch_wish} (upstream: {cfg['deb_arch']}) ===", file=sys.stderr)

    done_key, failed_key, index_key = (
        f"state/{arch_wish}.done", f"state/{arch_wish}.failed", f"index/{arch_wish}.txt")
    done_path = os.path.join(state_dir, f"{arch_wish}.done")
    failed_path = os.path.join(state_dir, f"{arch_wish}.failed")
    index_path = os.path.join(state_dir, f"{arch_wish}.index")

    done = load_state_set(done_key)
    failed = load_state_set(failed_key)
    with open(done_path, "w") as f:
        f.writelines(f"{u}\n" for u in sorted(done))
    with open(failed_path, "w") as f:
        f.writelines(f"{u}\n" for u in sorted(failed))
    if not b2_get(index_key, index_path):
        open(index_path, "w").close()

    todo, seen_names = [], set()
    for comp in COMPONENTS:
        for pkg in parse_packages(fetch_packages_index(base, RELEASE, comp, cfg["deb_arch"])):
            name_raw, ver_raw = pkg.get("Package"), pkg.get("Version")
            if not name_raw or not ver_raw or name_raw in seen_names:
                continue
            uid = f"{name_raw}={ver_raw}"
            if uid in done or uid in failed:
                continue
            seen_names.add(name_raw)
            todo.append((uid, pkg))

    print(f"{len(todo)} packages left for {arch_wish}", file=sys.stderr)

    workdir = os.path.join(state_dir, "work")
    os.makedirs(workdir, exist_ok=True)

    processed = 0
    for uid, pkg in todo:
        if time.monotonic() > DEADLINE:
            print("deadline reached, stopping cleanly", file=sys.stderr)
            break
        ok = process_package(arch_wish, base, pkg, workdir, index_path)
        with open(done_path if ok else failed_path, "a") as f:
            f.write(uid + "\n")
        processed += 1
        if processed % FLUSH_EVERY == 0:
            b2_cp(done_path, done_key)
            b2_cp(failed_path, failed_key)
            print(f"  ...{processed}/{len(todo)}", file=sys.stderr)

    b2_cp(done_path, done_key)
    b2_cp(failed_path, failed_key)

    remaining = len(todo) - processed
    print(f"{arch_wish}: processed {processed}, remaining {remaining}", file=sys.stderr)
    return remaining


def main():
    state_dir = tempfile.mkdtemp()
    current_path = os.path.join(state_dir, "current-arch.txt")
    current = ARCH_ORDER[0]
    if b2_get("state/current-arch.txt", current_path):
        val = open(current_path).read().strip()
        if val in ARCH_ORDER:
            current = val
        elif val == "done":
            print("ALL DONE (state marks completion)", file=sys.stderr)
            _write_output(continue_=False)
            return

    start_idx = ARCH_ORDER.index(current)
    for arch_wish in ARCH_ORDER[start_idx:]:
        remaining = mirror_arch(arch_wish, state_dir)
        if remaining > 0:
            with open(current_path, "w") as f:
                f.write(arch_wish)
            b2_cp(current_path, "state/current-arch.txt")
            _write_output(continue_=True, arch=arch_wish)
            return
        if time.monotonic() > DEADLINE:
            # Ran out of time exactly between arches; resume at the next one.
            next_idx = ARCH_ORDER.index(arch_wish) + 1
            nxt = ARCH_ORDER[next_idx] if next_idx < len(ARCH_ORDER) else "done"
            with open(current_path, "w") as f:
                f.write(nxt)
            b2_cp(current_path, "state/current-arch.txt")
            _write_output(continue_=(nxt != "done"), arch=nxt)
            return

    with open(current_path, "w") as f:
        f.write("done")
    b2_cp(current_path, "state/current-arch.txt")
    print("ALL DONE", file=sys.stderr)
    _write_output(continue_=False)


def _write_output(continue_, arch=""):
    out = os.environ.get("GITHUB_OUTPUT")
    if not out:
        return
    with open(out, "a") as f:
        f.write(f"continue={'true' if continue_ else 'false'}\n")
        f.write(f"arch={arch}\n")


if __name__ == "__main__":
    main()
