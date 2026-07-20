// lib.wishpkgs.org — package library for wish (WishOS package manager).
//
// Serves a single self-contained HTML page (search box + sortable table,
// deliberately minimal). The page's JS talks to this same Worker for data
// (never directly to B2), so there is no cross-origin fetch to worry about:
// the Worker fetches B2 server-side and relays it.
const B2 = "https://s3.eu-central-003.backblazeb2.com/wishpkgs";

export default {
  async fetch(request) {
    const url = new URL(request.url);
    const path = url.pathname;

    // GET /data/index/<arch>.txt  -> proxy the plain package-filename list
    let m = path.match(/^\/data\/index\/([a-z0-9_]+)\.txt$/);
    if (m) {
      const resp = await fetch(`${B2}/index/${m[1]}.txt`, { cf: { cacheEverything: true, cacheTtl: 300 } });
      return new Response(resp.body, { status: resp.status, headers: { "content-type": "text/plain; charset=utf-8" } });
    }

    // GET /data/info/<arch>/<name>.info -> proxy one package's metadata
    m = path.match(/^\/data\/info\/([a-z0-9_]+)\/([a-z0-9-]+)\.info$/);
    if (m) {
      const resp = await fetch(`${B2}/pkgs/${m[1]}/${m[2]}.info`, { cf: { cacheEverything: true, cacheTtl: 300 } });
      return new Response(resp.body, { status: resp.status, headers: { "content-type": "text/plain; charset=utf-8" } });
    }

    return new Response(PAGE, { headers: { "content-type": "text/html; charset=utf-8" } });
  },
};

const PAGE = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>wishpkgs — package library</title>
<meta name="description" content="Browse packages available to the wish package manager.">
<style>
  :root {
    color-scheme: light dark;
    --bg: #fff; --fg: #1a1a1a; --muted: #6b7280; --line: #e5e7eb;
    --accent: #0f7a63; --row-hover: #f4faf8; --mono: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  }
  @media (prefers-color-scheme: dark) {
    :root { --bg: #14161a; --fg: #e8e8e8; --muted: #9aa1ab; --line: #2a2d33; --accent: #35c9a5; --row-hover: #1b2320; }
  }
  * { box-sizing: border-box; }
  body { margin: 0; background: var(--bg); color: var(--fg); font: 15px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
  header { display: flex; align-items: baseline; justify-content: space-between; padding: 20px 24px; border-bottom: 1px solid var(--line); }
  header .brand { font-weight: 700; font-size: 18px; letter-spacing: -0.02em; }
  header .brand .dot { color: var(--accent); }
  header nav a { color: var(--muted); text-decoration: none; font-size: 13px; margin-left: 16px; }
  header nav a:hover { color: var(--fg); }
  main { max-width: 900px; margin: 0 auto; padding: 24px; }
  .toolbar { display: flex; gap: 12px; align-items: center; margin-bottom: 16px; flex-wrap: wrap; }
  .toolbar input { flex: 1; min-width: 200px; padding: 8px 12px; border: 1px solid var(--line); border-radius: 6px; background: var(--bg); color: var(--fg); font-size: 14px; }
  .toolbar input:focus { outline: none; border-color: var(--accent); }
  .arch-tabs { display: flex; border: 1px solid var(--line); border-radius: 6px; overflow: hidden; }
  .arch-tabs button { border: 0; background: var(--bg); color: var(--muted); padding: 7px 14px; font-size: 13px; cursor: pointer; font-family: var(--mono); }
  .arch-tabs button + button { border-left: 1px solid var(--line); }
  .arch-tabs button.active { background: var(--accent); color: #fff; }
  #count { color: var(--muted); font-size: 13px; white-space: nowrap; }
  table { width: 100%; border-collapse: collapse; }
  thead th { text-align: left; font-size: 12px; text-transform: uppercase; letter-spacing: .04em; color: var(--muted); font-weight: 600; padding: 8px 10px; border-bottom: 1px solid var(--line); }
  tbody td { padding: 9px 10px; border-bottom: 1px solid var(--line); vertical-align: top; }
  tbody tr { cursor: pointer; }
  tbody tr:hover { background: var(--row-hover); }
  td.name { font-family: var(--mono); font-weight: 600; white-space: nowrap; }
  td.ver { font-family: var(--mono); color: var(--muted); white-space: nowrap; }
  td.desc { color: var(--muted); }
  td.desc.loading { font-style: italic; }
  footer { text-align: center; color: var(--muted); font-size: 12px; padding: 32px 24px; }
  footer a { color: var(--muted); }
  .empty { text-align: center; color: var(--muted); padding: 40px 0; }
</style>
</head>
<body>
<header>
  <div class="brand">wish<span class="dot">pkgs</span></div>
  <nav>
    <a href="https://wishpkgs.org">wishpkgs.org</a>
    <a href="https://github.com/wishmkr/wishpkgs">source</a>
  </nav>
</header>
<main>
  <div class="toolbar">
    <input id="q" type="search" placeholder="Search packages…" autofocus>
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
</main>
<footer>wishpkgs — packages for WishOS's <code>wish</code> package manager · <a href="https://wishpkgs.org">wishpkgs.org</a></footer>
<script>
(function () {
  const FILENAME_RE = /^([a-z0-9-]+)-([0-9.]+)-(\\d+)-([a-z0-9_]+)\\.wsh$/;
  const state = { arch: "aarch64", rows: [] };
  const q = document.getElementById("q");
  const body = document.getElementById("pkgbody");
  const count = document.getElementById("count");
  const empty = document.getElementById("empty");

  function parseFilename(fn) {
    const m = FILENAME_RE.exec(fn);
    if (!m) return null;
    return { file: fn, name: m[1], version: m[2], release: m[3], arch: m[4], desc: null };
  }

  async function loadArch(arch) {
    state.arch = arch;
    body.innerHTML = "";
    count.textContent = "loading…";
    const res = await fetch("/data/index/" + arch + ".txt");
    const text = await res.text();
    state.rows = text.split("\\n").map((s) => s.trim()).filter(Boolean).map(parseFilename).filter(Boolean);
    state.rows.sort((a, b) => a.name.localeCompare(b.name));
    render();
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
  loadArch("aarch64");
})();
</script>
</body>
</html>`;
