// lib.wishpkgs.org — home (wiki-style guides + update notes), Packages
// (live-refreshing search/table), Releases (ISO downloads once published).
// The page's JS only ever talks to this same Worker (never directly to B2),
// so there's no cross-origin fetch to worry about -- the Worker fetches B2
// server-side and relays it.
//
// Deliberately uncached, with a brute-force guarantee: every upstream fetch
// carries a unique query-string cache-buster, so it can never collide with
// any previously-cached copy of that URL no matter which caching layer (a
// Worker's own fetch cache, tiered cache, etc.) is involved -- plain
// cf.cacheTtl/cacheEverything toggles weren't reliably enough to stop a
// stale response from a completely different Worker (cdn.wishpkgs.org, same
// upstream URL, longer TTL) from being served here. Given the whole point
// of the Packages tab is live data, guaranteed freshness beats a cache hit.
const B2 = "https://s3.eu-central-003.backblazeb2.com/wishpkgs";

function bust(url) {
  return url + (url.includes("?") ? "&" : "?") + "cb=" + Date.now() + Math.random().toString(36).slice(2);
}

export default {
  async fetch(request) {
    const url = new URL(request.url);
    const path = url.pathname;

    // GET /data/index/<arch>.txt -> proxy the plain package-filename list.
    let m = path.match(/^\/data\/index\/([a-z0-9_]+)\.txt$/);
    if (m) {
      const resp = await fetch(bust(`${B2}/index/${m[1]}.txt`), { cf: { cacheTtl: 0 } });
      return new Response(resp.body, { status: resp.status, headers: { "content-type": "text/plain; charset=utf-8" } });
    }

    // GET /data/info/<arch>/<name>.info -> proxy one package's metadata.
    m = path.match(/^\/data\/info\/([a-z0-9_]+)\/([a-z0-9-]+)\.info$/);
    if (m) {
      const resp = await fetch(bust(`${B2}/pkgs/${m[1]}/${m[2]}.info`), { cf: { cacheTtl: 0 } });
      return new Response(resp.body, { status: resp.status, headers: { "content-type": "text/plain; charset=utf-8" } });
    }

    // GET /data/releases.json -> proxy the release manifest (doesn't exist
    // yet; the page treats any non-200 here as "no releases published").
    if (path === "/data/releases.json") {
      const resp = await fetch(bust(`${B2}/releases/releases.json`), { cf: { cacheTtl: 0 } });
      return new Response(resp.body, { status: resp.status, headers: { "content-type": "application/json; charset=utf-8" } });
    }

    return new Response(PAGE, { headers: { "content-type": "text/html; charset=utf-8" } });
  },
};

const PAGE = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>wishpkgs — the wish package manager</title>
<meta name="description" content="Guides, update notes, packages, and releases for wish, the WishOS package manager.">
<style>
  :root {
    color-scheme: light dark;
    --bg: #fff; --fg: #1a1a1a; --muted: #6b7280; --line: #e5e7eb;
    --accent: #0f7a63; --row-hover: #f4faf8; --code-bg: #f4f5f7;
    --tip-bg: #fff8ea; --tip-line: #e2b53f;
    --mono: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --bg: #14161a; --fg: #e8e8e8; --muted: #9aa1ab; --line: #2a2d33;
      --accent: #35c9a5; --row-hover: #1b2320; --code-bg: #1c1f24;
      --tip-bg: #2a230f; --tip-line: #a5822c;
    }
  }
  * { box-sizing: border-box; }
  body { margin: 0; background: var(--bg); color: var(--fg); font: 15px/1.6 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
  header { display: flex; align-items: center; justify-content: space-between; padding: 16px 24px; border-bottom: 1px solid var(--line); flex-wrap: wrap; gap: 12px; }
  header .brand { font-weight: 700; font-size: 18px; letter-spacing: -0.02em; }
  header .brand .dot { color: var(--accent); }
  header .tabs { display: flex; gap: 4px; }
  header .tabs button { border: 0; background: none; color: var(--muted); font-size: 14px; padding: 6px 12px; border-radius: 6px; cursor: pointer; font-weight: 500; }
  header .tabs button:hover { color: var(--fg); }
  header .tabs button.active { color: var(--accent); background: var(--row-hover); }
  header .ext { display: flex; }
  header .ext a { color: var(--muted); text-decoration: none; font-size: 13px; margin-left: 16px; }
  header .ext a:hover { color: var(--fg); }
  main { max-width: 900px; margin: 0 auto; padding: 24px; }
  .view { display: none; }
  .view.active { display: block; }

  /* ---- Home: intro + updates + guides (wiki-style) ---- */
  .intro { margin-bottom: 32px; }
  .intro h1 { font-size: 22px; margin: 0 0 8px; letter-spacing: -0.01em; }
  .intro p { color: var(--muted); margin: 6px 0; max-width: 62ch; }
  .home-grid { display: grid; grid-template-columns: 1fr; gap: 40px; }
  section.block h2 { font-size: 13px; text-transform: uppercase; letter-spacing: .06em; color: var(--muted); font-weight: 700; margin: 0 0 16px; padding-bottom: 8px; border-bottom: 1px solid var(--line); }
  .update { border-bottom: 1px solid var(--line); padding: 14px 0; }
  .update:last-child { border-bottom: 0; }
  .update time { display: block; color: var(--muted); font-size: 12px; font-family: var(--mono); margin-bottom: 3px; }
  .update h3 { margin: 0 0 5px; font-size: 15px; }
  .update p { margin: 0; color: var(--muted); }

  .guide h3 { font-size: 15px; margin: 26px 0 4px; }
  .guide h3:first-child { margin-top: 0; }
  .guide > p.lead { color: var(--muted); margin: 0 0 6px; }
  .guide pre { background: var(--code-bg); border: 1px solid var(--line); border-radius: 6px; padding: 12px 14px; overflow-x: auto; font-family: var(--mono); font-size: 13px; line-height: 1.65; margin: 8px 0 14px; }
  .guide code { font-family: var(--mono); font-size: 13px; background: var(--code-bg); padding: 1px 5px; border-radius: 4px; }
  .callout { border-left: 3px solid var(--accent); background: var(--row-hover); padding: 8px 14px; border-radius: 0 6px 6px 0; margin: 10px 0 16px; font-size: 13.5px; color: var(--fg); }
  .callout.tip { border-left-color: var(--tip-line); background: var(--tip-bg); }
  .callout strong { text-transform: uppercase; font-size: 10.5px; letter-spacing: .05em; display: block; margin-bottom: 3px; color: var(--muted); }

  /* ---- Packages ---- */
  .toolbar { display: flex; gap: 12px; align-items: center; margin-bottom: 16px; flex-wrap: wrap; }
  .toolbar input { flex: 1; min-width: 200px; padding: 8px 12px; border: 1px solid var(--line); border-radius: 6px; background: var(--bg); color: var(--fg); font-size: 14px; }
  .toolbar input:focus { outline: none; border-color: var(--accent); }
  .arch-tabs { display: flex; border: 1px solid var(--line); border-radius: 6px; overflow: hidden; }
  .arch-tabs button { border: 0; background: var(--bg); color: var(--muted); padding: 7px 14px; font-size: 13px; cursor: pointer; font-family: var(--mono); }
  .arch-tabs button + button { border-left: 1px solid var(--line); }
  .arch-tabs button.active { background: var(--accent); color: #fff; }
  #count { color: var(--muted); font-size: 13px; white-space: nowrap; }
  .live { display: inline-flex; align-items: center; gap: 5px; color: var(--muted); font-size: 12px; margin-bottom: 12px; }
  .live .pulse { width: 7px; height: 7px; border-radius: 50%; background: var(--accent); animation: pulse 1.8s ease-in-out infinite; }
  @keyframes pulse { 0%,100% { opacity: .35; } 50% { opacity: 1; } }
  table { width: 100%; border-collapse: collapse; }
  thead th { text-align: left; font-size: 12px; text-transform: uppercase; letter-spacing: .04em; color: var(--muted); font-weight: 600; padding: 8px 10px; border-bottom: 1px solid var(--line); }
  tbody td { padding: 9px 10px; border-bottom: 1px solid var(--line); vertical-align: top; }
  tbody tr { cursor: pointer; }
  tbody tr:hover { background: var(--row-hover); }
  td.name { font-family: var(--mono); font-weight: 600; white-space: nowrap; }
  td.ver { font-family: var(--mono); color: var(--muted); white-space: nowrap; }
  td.desc { color: var(--muted); }
  td.desc.loading { font-style: italic; }
  .empty { text-align: center; color: var(--muted); padding: 40px 0; }

  /* ---- Releases ---- */
  .release-card { border: 1px solid var(--line); border-radius: 8px; padding: 16px; margin-bottom: 12px; }
  .release-card h3 { margin: 0 0 4px; font-size: 15px; }
  .release-card .meta { color: var(--muted); font-size: 13px; margin-bottom: 8px; }
  .release-card a.dl { display: inline-block; font-family: var(--mono); font-size: 13px; color: var(--accent); text-decoration: none; }
  .release-card a.dl:hover { text-decoration: underline; }

  footer { text-align: center; color: var(--muted); font-size: 12px; padding: 32px 24px; }
  footer a { color: var(--muted); }
</style>
</head>
<body>
<header>
  <div class="brand">wish<span class="dot">pkgs</span></div>
  <div class="tabs">
    <button data-view="home" class="active">Home</button>
    <button data-view="packages">Packages</button>
    <button data-view="releases">Releases</button>
  </div>
  <div class="ext">
    <a href="https://wishpkgs.org">wishpkgs.org</a>
    <a href="https://github.com/wishmkr/wishpkgs">source</a>
  </div>
</header>
<main>

  <section id="view-home" class="view active">
    <div class="intro">
      <h1>wish — the WishOS package manager</h1>
      <p>A transactional, rollback-capable package manager with generations, Bedrock-style layers, and bidirectional bundling (system → package, not just the other way around).</p>
      <p>This page covers what's changed recently and how to use it. See <b>Packages</b> for the live index, <b>Releases</b> for ISO images once published.</p>
    </div>

    <div class="home-grid">
      <section class="block" id="updates">
        <h2>Latest updates</h2>

        <div class="update">
          <time datetime="2026-07-20">2026-07-20</time>
          <h3>Ubuntu package mirror underway (aarch64 first)</h3>
          <p>A resumable pipeline now repackages upstream precompiled binaries (main component) into <code>.wsh</code> for both wish archs, uploading each finished package straight to the repo without waiting for the rest of the batch. aarch64 is being mirrored first; x86_64 follows once ready. Progress survives restarts, so this runs unattended across many sessions.</p>
        </div>

        <div class="update">
          <time datetime="2026-07-20">2026-07-20</time>
          <h3>Package library and CDN launched</h3>
          <p>Packages now serve from <code>cdn.wishpkgs.org</code> (Backblaze B2 behind Cloudflare — free egress), and this site (<code>lib.wishpkgs.org</code>) went live as a browsable, live-refreshing package index.</p>
        </div>

        <div class="update">
          <time datetime="2026-07-20">2026-07-20</time>
          <h3>wish gains generations, rollback, bundling, services, layer federation</h3>
          <p>Every install/remove now snapshots the full system (packages, plus managed config like <code>/etc</code>), and <code>wish rollback &lt;id&gt;</code> reverts all of it atomically. New: a service supervisor, Bedrock-style layers with OverlayFS/shares/snapshots, cross-layer command &amp; library federation, and two-way bundling — repackage an installed system back into a <code>.wsh</code>, not just install one.</p>
        </div>
      </section>

      <section class="block guide" id="guides">
        <h2>Guides</h2>

        <h3>Getting started</h3>
        <p class="lead">Install a package, then explore from there.</p>
        <pre># wish init                 # first-time system setup (mounts, dirs, databases)
# wish install &lt;pkg&gt;        # install with dependencies, transactional
$ wish search &lt;query&gt;       # search the package index
$ wish list                 # list installed packages
$ wish info                 # show repo url, arch, cache/lib paths
$ wish help                 # full command reference</pre>
        <div class="callout"><strong>Note</strong>Commands that change system state (install, remove, upgrade, rollback, service control, entering a layer) require root. Read-only ones (search, list, graph, info) don't.</div>

        <h3>Package management</h3>
        <pre># wish install &lt;pkg&gt;        # wish -I &lt;pkg&gt;
# wish remove &lt;pkg&gt;         # wish --remove &lt;pkg&gt;
$ wish update                # wish --update
# wish upgrade                # wish --upgrade
$ wish pull &lt;pkg&gt;            # download to cache only, don't install
$ wish graph &lt;pkg&gt;           # show dependency tree
$ wish graph --history       # show transaction history</pre>

        <h3>Generations &amp; rollback</h3>
        <p class="lead">Every install/remove snapshots the full system state — packages and managed config together.</p>
        <pre>$ wish generation list       # list generations (* = current)
# wish generation create      # snapshot current state manually
# wish rollback &lt;id&gt;          # atomically revert to a generation</pre>
        <div class="callout tip"><strong>Tip</strong>Rollback restores three things together: the package database, the files those packages own, and any config path listed in <code>WISH_MANAGED_PATHS</code> (defaults to <code>/etc</code>).</div>

        <h3>Bundling — system → package, not just package → system</h3>
        <pre># wish bundle &lt;pkg&gt;           # repackage an installed pkg + its config/overrides
# wish bundle --system        # snapshot the whole system into one .wsh
# wish install &lt;file.wsh&gt;     # install from a local bundle file
# wish restore &lt;file.wsh&gt;     # rehydrate a full system from a system bundle</pre>

        <h3>Services</h3>
        <pre># wish service define &lt;name&gt; &lt;cmd&gt; [--restart=&lt;policy&gt;] [--enable]
# wish service start|stop|status|enable|disable &lt;name&gt;
$ wish service list</pre>

        <h3>Layers (Bedrock-style)</h3>
        <p class="lead">Isolated filesystem roots sharing one kernel: chroot + a private mount namespace, with configurable shares, OverlayFS, and snapshots.</p>
        <pre># wish layer add|remove &lt;name&gt;   $ wish layer list|info &lt;name&gt;
# wish layer share &lt;name&gt; &lt;src&gt; [target] [--ro]
# wish layer overlay &lt;name&gt; add &lt;lowerdir&gt; | off
# wish layer clone &lt;src&gt; &lt;dst&gt;
# wish layer snapshot &lt;name&gt; [snap-name]
# wish layer gui &lt;name&gt; on|off        # share X11/Wayland/PipeWire/D-Bus
# wish layer expose &lt;name&gt; &lt;binary&gt; [alias]   # global wrapper on host PATH
# wish run &lt;layer&gt; &lt;cmd&gt; [args]</pre>

        <h3>Federation</h3>
        <pre># wish layer priority set &lt;l1&gt; &lt;l2&gt; ...
# wish federate       # expose every layer's commands + libraries globally
# wish defederate</pre>

        <h3>Peer networking (LAN)</h3>
        <pre># wish serve          # share cached packages with peers on port 44449
$ wish peer scan      # scan the LAN for other wish peers</pre>

        <h3>Environment variables</h3>
        <pre>WISH_REPO_URL       WISH_CACHE_DIR      WISH_LIB_DIR
WISH_ROOT           WISH_SERVICES_DIR   WISH_RUN_DIR
WISH_WRAPPERS_DIR   WISH_MANAGED_PATHS</pre>
      </section>
    </div>
  </section>

  <section id="view-packages" class="view">
    <div class="live"><span class="pulse"></span><span id="live-text">live — loading…</span></div>
    <div class="toolbar">
      <input id="q" type="search" placeholder="Search packages…">
      <div class="arch-tabs">
        <button data-arch="aarch64" class="active">aarch64</button>
        <button data-arch="x86_64">x86_64</button>
      </div>
      <span id="count"></span>
    </div>
    <table>
      <thead><tr><th>Name</th><th>Version</th><th>Description</th></tr></thead>
      <tbody id="pkgbody"></tbody>
    </table>
    <div class="empty" id="empty" hidden>No packages match.</div>
  </section>

  <section id="view-releases" class="view">
    <div id="releases-list"></div>
    <div class="empty" id="releases-empty" hidden>No releases published yet — check back soon.</div>
  </section>

</main>
<footer>wishpkgs — packages for WishOS's <code>wish</code> package manager · <a href="https://wishpkgs.org">wishpkgs.org</a></footer>
<script>
(function () {
  const FILENAME_RE = /^([a-z0-9-]+)-([0-9.]+)-(\\d+)-([a-z0-9_]+)\\.wsh$/;
  const REFRESH_MS = 30000;
  const state = { arch: "aarch64", rows: [], started: false };
  const q = document.getElementById("q");
  const body = document.getElementById("pkgbody");
  const count = document.getElementById("count");
  const empty = document.getElementById("empty");
  const liveText = document.getElementById("live-text");

  function parseFilename(fn) {
    const m = FILENAME_RE.exec(fn);
    if (!m) return null;
    return { file: fn, name: m[1], version: m[2], release: m[3], arch: m[4], desc: null };
  }

  function rowKey(rows) {
    return rows.map((r) => r.file).sort().join("|");
  }

  async function loadArch(arch, opts) {
    opts = opts || {};
    state.arch = arch;
    if (!opts.silent) {
      body.innerHTML = "";
      count.textContent = "loading…";
    }
    const res = await fetch("/data/index/" + arch + ".txt", { cache: "no-store" });
    const text = await res.text();
    const fresh = text.split("\\n").map((s) => s.trim()).filter(Boolean).map(parseFilename).filter(Boolean);
    fresh.sort((a, b) => a.name.localeCompare(b.name));

    if (opts.silent && rowKey(fresh) === rowKey(state.rows)) {
      liveText.textContent = "live — no changes";
      return;
    }
    // Preserve already-fetched descriptions across a silent refresh.
    if (opts.silent) {
      const known = new Map(state.rows.map((r) => [r.file, r.desc]));
      for (const r of fresh) if (known.has(r.file)) r.desc = known.get(r.file);
    }
    state.rows = fresh;
    render();
    liveText.textContent = "live — updated just now";
  }

  function render() {
    const term = q.value.trim().toLowerCase();
    body.innerHTML = "";
    let shown = 0;
    for (const row of state.rows) {
      if (term && !row.name.includes(term)) continue;
      shown++;
      const tr = document.createElement("tr");
      const descCell = document.createElement("td");
      descCell.className = "desc";
      descCell.textContent = row.desc !== null ? row.desc : "";
      const nameCell = document.createElement("td");
      nameCell.className = "name";
      nameCell.textContent = row.name;
      const verCell = document.createElement("td");
      verCell.className = "ver";
      verCell.textContent = row.version + "-" + row.release;
      tr.append(nameCell, verCell, descCell);
      tr.addEventListener("click", () => loadDesc(row, descCell));
      body.appendChild(tr);
    }
    count.textContent = shown + " / " + state.rows.length + " packages";
    empty.hidden = shown !== 0;
  }

  async function loadDesc(row, cell) {
    if (row.desc !== null) return;
    cell.classList.add("loading");
    cell.textContent = "loading…";
    try {
      const res = await fetch("/data/info/" + row.arch + "/" + row.name + ".info");
      const text = await res.text();
      const m = /^description=(.*)$/m.exec(text);
      row.desc = m ? m[1] : "(no description)";
    } catch (e) {
      row.desc = "(unavailable)";
    }
    cell.classList.remove("loading");
    cell.textContent = row.desc;
  }

  document.querySelectorAll(".arch-tabs button").forEach((b) => {
    b.addEventListener("click", () => {
      document.querySelectorAll(".arch-tabs button").forEach((x) => x.classList.remove("active"));
      b.classList.add("active");
      loadArch(b.dataset.arch);
    });
  });
  q.addEventListener("input", render);

  // ---- view switching (Home / Packages / Releases) ----
  const tabs = document.querySelectorAll("header .tabs button");
  const views = document.querySelectorAll(".view");
  tabs.forEach((b) => {
    b.addEventListener("click", () => {
      tabs.forEach((x) => x.classList.remove("active"));
      views.forEach((v) => v.classList.remove("active"));
      b.classList.add("active");
      document.getElementById("view-" + b.dataset.view).classList.add("active");
      if (b.dataset.view === "packages" && !state.started) {
        state.started = true;
        loadArch("aarch64");
        setInterval(() => loadArch(state.arch, { silent: true }), REFRESH_MS);
      }
      if (b.dataset.view === "releases") loadReleases();
    });
  });

  // ---- releases (empty until an ISO is published to B2 releases/releases.json) ----
  let releasesLoaded = false;
  async function loadReleases() {
    if (releasesLoaded) return;
    releasesLoaded = true;
    const list = document.getElementById("releases-list");
    const empty2 = document.getElementById("releases-empty");
    try {
      const res = await fetch("/data/releases.json", { cache: "no-store" });
      if (!res.ok) throw new Error("no releases");
      const releases = await res.json();
      if (!Array.isArray(releases) || releases.length === 0) throw new Error("empty");
      for (const r of releases) {
        const card = document.createElement("div");
        card.className = "release-card";
        card.innerHTML =
          "<h3>" + (r.name || "release") + "</h3>" +
          "<div class=\\"meta\\">" + (r.date || "") + (r.arch ? " · " + r.arch : "") +
          (r.size_mb ? " · " + r.size_mb + " MB" : "") + "</div>" +
          (r.notes ? "<p>" + r.notes + "</p>" : "") +
          (r.url ? "<a class=\\"dl\\" href=\\"" + r.url + "\\">Download ISO →</a>" : "");
        list.appendChild(card);
      }
    } catch (e) {
      empty2.hidden = false;
    }
  }
})();
</script>
</body>
</html>`;
