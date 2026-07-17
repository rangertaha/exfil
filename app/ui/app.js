// Talks to the `exfil server` HTTP API the desktop app launches on startup.
// 127.0.0.1 is a "potentially trustworthy" origin, so the webview may fetch it
// over http from the app's secure context.
const API = "http://127.0.0.1:8080";
const el = (id) => document.getElementById(id);

async function api(path) {
  const res = await fetch(API + path);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

// The server is a child process that may still be starting; poll until it's up.
async function waitForServer() {
  for (;;) {
    try {
      await api("/health");
      return;
    } catch {
      setStatus("starting server…", "");
      await new Promise((r) => setTimeout(r, 700));
    }
  }
}

function setStatus(text, cls) {
  const s = el("status");
  s.textContent = text;
  s.className = "status " + cls;
}

function escapeHtml(s) {
  return String(s).replace(
    /[&<>"]/g,
    (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c],
  );
}

function renderStats(s) {
  const tiles = [
    ["critical", "Critical"],
    ["high", "High"],
    ["medium", "Medium"],
    ["low", "Low"],
    ["info", "Info"],
  ];
  el("stats").innerHTML =
    `<div class="tile total"><b>${s.total}</b><span>findings</span></div>` +
    tiles
      .map(
        ([k, label]) =>
          `<div class="tile sev-${k}"><b>${s.by_severity[k]}</b><span>${label}</span></div>`,
      )
      .join("");
}

function renderRows(list) {
  if (!list.length) {
    el("rows").innerHTML =
      `<tr><td colspan="4" class="empty">No findings. Run <code>exfil scan</code> in the store directory.</td></tr>`;
    return;
  }
  el("rows").innerHTML = list
    .map((f) => {
      const sev = (f.severity || "none").toLowerCase();
      return (
        `<tr><td><span class="pill sev-${sev}">${(f.severity || "—").toUpperCase()}</span></td>` +
        `<td>${escapeHtml(f.rule)}</td>` +
        `<td class="loc">${escapeHtml(f.path)}:${f.line}</td>` +
        `<td class="snippet">${escapeHtml(f.snippet || "")}</td></tr>`
      );
    })
    .join("");
}

async function refresh() {
  const q = el("filter").value.trim();
  try {
    renderStats(await api("/stats"));
    const path = "/findings" + (q ? "?q=" + encodeURIComponent(q) : "");
    renderRows(await api(path));
    setStatus("connected", "ok");
  } catch {
    setStatus("disconnected", "err");
  }
}

function debounce(fn, ms) {
  let t;
  return (...a) => {
    clearTimeout(t);
    t = setTimeout(() => fn(...a), ms);
  };
}

el("filter").addEventListener("input", debounce(refresh, 250));

(async () => {
  await waitForServer();
  await refresh();
  setInterval(refresh, 5000);
})();
