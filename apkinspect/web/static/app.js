"use strict";
(function () {
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => [...r.querySelectorAll(s)];
  const SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
  const GRADE_COLOR = { A: "#2ecc71", B: "#4cc9f0", C: "#ffd166", D: "#ff8c42", F: "#ff4d6d" };
  const CIRC = 2 * Math.PI * 52;

  let CATALOG = { threats: [], severities: {}, categories: {} };
  let ID_TO_THREAT = {};
  let activeSevFilter = "ALL";

  function el(tag, props = {}, kids = []) {
    const n = document.createElement(tag);
    for (const [k, v] of Object.entries(props)) {
      if (k === "class") n.className = v;
      else if (k === "text") n.textContent = v;
      else if (k === "html") n.innerHTML = v;
      else if (k === "style") n.setAttribute("style", v);
      else if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
      else n.setAttribute(k, v);
    }
    (Array.isArray(kids) ? kids : [kids]).forEach((c) => c != null && n.append(c));
    return n;
  }
  const sevColor = (s) => (CATALOG.severities[s] || {}).color || "#9aa5b1";
  const sevLabel = (s) => (CATALOG.severities[s] || {}).label || s;

  /* ---------------- view + book navigation ---------------- */
  function switchView(name) {
    $$(".tab").forEach((t) => t.classList.toggle("is-active", t.dataset.view === name));
    $$(".view").forEach((v) => v.classList.toggle("is-active", v.id === "view-" + name));
    window.scrollTo({ top: 0, behavior: "smooth" });
  }
  function switchBookPage(name) {
    $$(".book-tab").forEach((t) => t.classList.toggle("is-active", t.dataset.page === name));
    $$(".book-page").forEach((p) => p.classList.toggle("is-active", p.id === "page-" + name));
    if (name === "threats") ensureThreatSelected();
  }
  function ensureThreatSelected() {
    if (!document.querySelector(".threat-item.is-active")) {
      const first = document.querySelector(".threat-item");
      if (first) selectThreat(first.dataset.key);
    }
  }
  $$(".tab").forEach((t) => t.addEventListener("click", () => switchView(t.dataset.view)));
  $$(".book-tab").forEach((t) => t.addEventListener("click", () => switchBookPage(t.dataset.page)));

  /* ---------------- dropzone + scanning ---------------- */
  const dz = $("#dropzone"), input = $("#fileInput");
  $("#browseBtn").addEventListener("click", (e) => { e.stopPropagation(); input.click(); });
  dz.addEventListener("click", () => input.click());
  dz.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") input.click(); });
  input.addEventListener("change", () => input.files[0] && scan(input.files[0]));
  ["dragenter", "dragover"].forEach((ev) =>
    dz.addEventListener(ev, (e) => { e.preventDefault(); dz.classList.add("is-drag"); }));
  ["dragleave", "drop"].forEach((ev) =>
    dz.addEventListener(ev, (e) => { e.preventDefault(); dz.classList.remove("is-drag"); }));
  dz.addEventListener("drop", (e) => { const f = e.dataTransfer.files[0]; if (f) scan(f); });
  $("#rescanBtn").addEventListener("click", reset);
  $("#demoBtn").addEventListener("click", (e) => { e.stopPropagation(); scanDemo(); });

  async function scanDemo() {
    dz.hidden = true; $("#scanError").hidden = true; $("#results").hidden = true;
    $("#scanning").hidden = false; $("#scanningName").textContent = "a bundled sample app";
    try {
      const res = await fetch("/api/demo");
      const data = await res.json();
      if (!res.ok || data.error) throw new Error(data.error || ("HTTP " + res.status));
      $("#scanning").hidden = true;
      renderResults(data, data.path || "sample.apk");
    } catch (err) {
      showError("Demo unavailable: " + err.message);
    }
  }

  function reset() {
    $("#results").hidden = true;
    $("#scanError").hidden = true;
    dz.hidden = false;
    input.value = "";
  }
  function showError(msg) {
    $("#scanning").hidden = true;
    const b = $("#scanError"); b.hidden = false; b.textContent = msg; dz.hidden = false;
  }

  async function scan(file) {
    const name = (file.name || "").toLowerCase();
    if (!/\.(apk|aab|zip|xapk)$/.test(name)) {
      showError("Please choose an .apk or .aab file (got “" + file.name + "”).");
      return;
    }
    dz.hidden = true; $("#scanError").hidden = true; $("#results").hidden = true;
    $("#scanning").hidden = false; $("#scanningName").textContent = file.name;
    try {
      const res = await fetch("/api/scan", {
        method: "POST", headers: { "X-Filename": file.name }, body: file,
      });
      const data = await res.json();
      if (!res.ok || data.error) throw new Error(data.error || ("HTTP " + res.status));
      $("#scanning").hidden = true;
      renderResults(data, file.name);
    } catch (err) {
      showError("Scan failed: " + err.message);
    }
  }

  /* ---------------- results ---------------- */
  function renderResults(data, fileName) {
    $("#results").hidden = false;
    $("#rFileType").textContent = (data.file_type || "?").toUpperCase();
    $("#rFileName").textContent = fileName;

    // gauge
    const bar = $("#gaugeBar"), color = GRADE_COLOR[data.grade] || "#7c8cff";
    bar.style.strokeDasharray = CIRC.toFixed(1);
    requestAnimationFrame(() => {
      bar.style.strokeDashoffset = (CIRC * (1 - data.score / 100)).toFixed(1);
      bar.style.stroke = color;
    });
    countUp($("#gaugeScore"), data.score);
    const gb = $("#gradeBadge"); gb.textContent = data.grade; gb.style.background = color;
    $("#riskLabel").textContent = data.risk_label || "";

    // meta
    const m = $("#metaList"); m.innerHTML = "";
    const rows = [
      ["Package", data.package || "—"],
      ["Version", data.version_name ? `${data.version_name} (${data.version_code || "?"})` : "—"],
      ["Min / Target SDK", `${data.min_sdk ?? "?"} / ${data.target_sdk ?? "?"}`],
      ["Size", humanSize(data.file_size)],
      ["DEX files", (data.meta && data.meta.dex_count) ?? "?"],
      ["Entries", (data.meta && data.meta.entry_count) ?? "?"],
      ["Native libs", data.meta && data.meta.has_native_libs ? "yes" : "no"],
    ];
    rows.forEach(([k, v]) => { m.append(el("dt", { text: k }), el("dd", { text: String(v) })); });

    // chips
    const chips = $("#sevChips"); chips.innerHTML = "";
    const counts = data.counts || {};
    const total = SEV_ORDER.reduce((a, s) => a + (counts[s] || 0), 0);
    if (total === 0) {
      chips.append(el("span", { class: "chip chip--empty", html: "✓ No issues detected" }));
    } else {
      SEV_ORDER.forEach((s) => {
        if (!counts[s]) return;
        chips.append(el("span", { class: "chip" }, [
          el("span", { class: "dot", style: `background:${sevColor(s)}` }),
          el("span", { text: sevLabel(s) }),
          el("span", { class: "n", text: " " + counts[s] }),
        ]));
      });
    }

    // findings
    const wrap = $("#findings"); wrap.innerHTML = "";
    if (total === 0) {
      wrap.append(el("div", { class: "clean-state" }, [
        el("div", { class: "big", text: "🎉" }),
        el("p", { text: "No security issues were found. Still, review permissions and test deep links manually." }),
      ]));
    } else {
      const byId = data.findings || [];
      SEV_ORDER.forEach((s) => {
        const group = byId.filter((f) => f.severity === s);
        if (!group.length) return;
        wrap.append(el("div", { class: "sev-group__head" }, [
          el("span", { text: `${sevLabel(s)} · ${group.length}` }), el("span", { class: "bar" }),
        ]));
        group.forEach((f) => wrap.append(findingCard(f)));
      });
    }

    if (data.errors && data.errors.length) {
      wrap.append(el("p", { class: "muted", style: "margin-top:16px;font-size:12.5px",
        text: "Notes: " + data.errors.join(" · ") }));
    }
  }

  function findingCard(f) {
    const head = el("div", { class: "finding__head" }, [
      el("span", { class: "finding__sev", text: sevLabel(f.severity), style: `background:${sevColor(f.severity)}` }),
      el("span", { class: "finding__title", text: f.title }),
      el("span", { class: "finding__loc", text: f.location || "" }),
      el("span", { class: "finding__chev", text: "›" }),
    ]);
    const body = el("div", { class: "finding__body" });
    if (f.detail) body.append(row("What", f.detail));
    if (f.evidence) body.append(rowEvidence(f.evidence));
    if (f.recommendation) body.append(row("Fix", f.recommendation));
    if (ID_TO_THREAT[f.id]) {
      body.append(el("button", { class: "finding__book", text: "How to block this →",
        onclick: (e) => { e.stopPropagation(); openThreat(f.id); } }));
    }
    const card = el("div", { class: "finding", style: `--sev:${sevColor(f.severity)}` }, [head, body]);
    head.addEventListener("click", () => card.classList.toggle("is-open"));
    return card;
  }
  const row = (label, text) => el("div", { class: "finding__row" }, [el("b", { text: label }), el("span", { text })]);
  const rowEvidence = (text) => el("div", { class: "finding__row" }, [el("b", { text: "Evidence" }), el("div", { class: "evidence", text })]);

  function countUp(node, target) {
    const start = performance.now(), dur = 900;
    function step(t) {
      const p = Math.min(1, (t - start) / dur);
      node.textContent = Math.round(target * (1 - Math.pow(1 - p, 3)));
      if (p < 1) requestAnimationFrame(step);
    }
    requestAnimationFrame(step);
  }
  function humanSize(n) {
    if (!n && n !== 0) return "—";
    const u = ["B", "KiB", "MiB", "GiB"]; let i = 0, s = n;
    while (s >= 1024 && i < u.length - 1) { s /= 1024; i++; }
    return (i === 0 ? s : s.toFixed(2)) + " " + u[i];
  }

  /* ---------------- threat book ---------------- */
  function buildLegend() {
    const grades = [["A", "90–100", "minimal"], ["B", "75–89", "low"], ["C", "60–74", "moderate"],
      ["D", "40–59", "high"], ["F", "0–39", "critical"]];
    const box = $("#gradeLegend"); box.innerHTML = "";
    grades.forEach(([g, r, label]) => box.append(el("div", { class: "g" }, [
      el("i", { text: g, style: `background:${GRADE_COLOR[g]}` }),
      el("span", { html: `<b>${r}</b> · ${label} risk` }),
    ])));
  }

  function buildSevFilter() {
    const seg = $("#sevFilter"); seg.innerHTML = "";
    const opts = ["ALL", ...SEV_ORDER.filter((s) => CATALOG.threats.some((t) => t.severity === s))];
    opts.forEach((s) => {
      const b = el("button", { text: s === "ALL" ? "All" : sevLabel(s), class: s === activeSevFilter ? "is-active" : "" });
      b.addEventListener("click", () => { activeSevFilter = s; $$("#sevFilter button").forEach((x) => x.classList.toggle("is-active", x === b)); renderThreatList(); });
      seg.append(b);
    });
  }

  function renderThreatList() {
    const q = ($("#threatSearch").value || "").toLowerCase();
    const list = $("#threatsList"); list.innerHTML = "";
    const items = CATALOG.threats
      .filter((t) => activeSevFilter === "ALL" || t.severity === activeSevFilter)
      .filter((t) => !q || (t.title + " " + t.what + " " + t.category).toLowerCase().includes(q))
      .sort((a, b) => (CATALOG.severities[a.severity].order - CATALOG.severities[b.severity].order)
        || a.category.localeCompare(b.category));
    if (!items.length) { list.append(el("p", { class: "muted", text: "No threats match." })); return; }
    items.forEach((t) => {
      const item = el("button", { class: "threat-item", "data-key": t.key }, [
        el("span", { class: "sev-dot", style: `background:${sevColor(t.severity)}` }),
        el("span", {}, [el("div", { class: "ti-title", text: t.title }),
          el("div", { class: "ti-cat", text: (CATALOG.categories[t.category] || {}).label || t.category })]),
      ]);
      item.addEventListener("click", () => selectThreat(t.key));
      list.append(item);
    });
  }

  function selectThreat(key) {
    const t = CATALOG.threats.find((x) => x.key === key);
    if (!t) return;
    $$(".threat-item").forEach((i) => i.classList.toggle("is-active", i.dataset.key === key));
    const d = $("#threatDetail"); d.innerHTML = "";
    d.append(el("div", { class: "td-head" }, [
      el("h3", { text: t.title }),
      el("span", { class: "td-sev", text: sevLabel(t.severity), style: `background:${sevColor(t.severity)}` }),
      el("span", { class: "td-cat", text: (CATALOG.categories[t.category] || {}).label || t.category }),
    ]));
    const sec = (cls, title, text) => el("div", { class: "td-section " + cls }, [el("h4", { text: title }), el("p", { text })]);
    d.append(sec("", "What it is", t.what));
    d.append(sec("", "Why it's dangerous", t.risk));
    d.append(sec("", "How APKInspect detects it", t.detect));
    d.append(sec("block", "How to block it", t.block));
    d.append(el("div", { class: "td-ids", html: "Finding ids: " + t.ids.map((i) => `<code>${i}</code>`).join(" ") }));
  }

  function openThreat(findingId) {
    const key = ID_TO_THREAT[findingId];
    if (!key) return;
    switchView("book"); switchBookPage("threats");
    activeSevFilter = "ALL"; $("#threatSearch").value = "";
    buildSevFilter(); renderThreatList(); selectThreat(key);
    const item = $(`.threat-item[data-key="${key}"]`);
    if (item) item.scrollIntoView({ block: "nearest" });
    $("#threatDetail").scrollIntoView({ behavior: "smooth", block: "center" });
  }

  /* ---------------- boot ---------------- */
  async function boot() {
    try {
      CATALOG = await (await fetch("/api/catalog")).json();
    } catch (e) { /* offline catalog still lets the scanner work */ }
    ID_TO_THREAT = {};
    (CATALOG.threats || []).forEach((t) => t.ids.forEach((id) => (ID_TO_THREAT[id] = t.key)));
    buildLegend(); buildSevFilter(); renderThreatList();
    $("#threatSearch").addEventListener("input", renderThreatList);
    applyHash();
  }
  function applyHash() {
    const h = location.hash.replace("#", "");
    if (h.startsWith("book")) {
      switchView("book");
      if (h.includes("threat")) switchBookPage("threats");
    } else if (h === "demo") {
      scanDemo();
    }
  }
  boot();
})();
