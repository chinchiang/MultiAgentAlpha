/* MARA workbench (docs/adr/0006-local-web-workbench.md).
 *
 * One page, no dependencies, no build step. The Content-Security-Policy allows exactly this script by hash and
 * requires Trusted Types, so the DOM is built only through element and text APIs (h(), textContent, append,
 * fill()): repository-derived text - titles, quotes, arguments, file names - is always text, never markup.
 * Every number on the page comes from the server, which reads the validated report; nothing is re-derived here.
 *
 * The read-only demo on GitHub Pages (scripts/build_workbench_demo.py) is this same page with a "demo" data block:
 * it holds the server's answers to every GET the page makes for one offline mock review, so api() answers from it,
 * refuses everything else and never calls fetch(). The served page never carries that block.
 */
"use strict";

(function () {
  const DICT = JSON.parse(document.getElementById("i18n").textContent || "{}");
  const DEMO = (() => {
    const el = document.getElementById("demo");
    if (!el) return null;
    try { return JSON.parse(el.textContent || "null"); } catch (e) { return null; }
  })();
  const LANGS = ["zh-TW", "en"];
  const STAGES = ["bundle", "tools", "context", "reviewers", "skeptic", "redteam", "jury", "scoring", "report"];
  const STAGE_LAYER = { bundle: "L1", tools: "L0", context: "L1", reviewers: "L2", skeptic: "L3", redteam: "L3", jury: "L4", scoring: "L5", report: "L5" };
  const OUTCOMES = ["accepted", "needs_human", "rejected", "dropped"];
  const SEVERITIES = ["Critical", "High", "Medium", "Low", "None"];
  const TIERS = ["A", "B", "C", "D"];
  const ROLES = ["context", "reviewers", "skeptic", "redteam", "judges"];
  const ROLE_ICON = { context: "layers", reviewers: "cpu", skeptic: "search", redteam: "target", judges: "checkCircle" };
  const TABS = ["overview", "findings", "dimensions", "tools", "queue", "log"];
  const ACTIVE = ["running"];
  const RUN_POLL_MS = 2000;
  const LIST_POLL_MS = 4000;
  const IDLE_LIST_POLL_MS = 20000;
  const HEALTH_MS = 10000;
  const own = (obj, key) => obj !== null && typeof obj === "object" && Object.prototype.hasOwnProperty.call(obj, key);

  // ---------------------------------------------------------------- storage (private windows may refuse it)
  const store = {
    get(key) { try { return window.localStorage.getItem(key); } catch (e) { return null; } },
    set(key, value) { try { window.localStorage.setItem(key, value); } catch (e) { /* not persisted */ } },
    remove(key) { try { window.localStorage.removeItem(key); } catch (e) { /* nothing stored */ } },
  };

  // ---------------------------------------------------------------- i18n
  let lang = LANGS.includes(store.get("mara.lang")) ? store.get("mara.lang") : "zh-TW";

  function t(key, params) {
    const table = DICT[lang] || {};
    let s = own(table, key) ? table[key] : (DICT["zh-TW"] || {})[key];
    if (typeof s !== "string") return key;
    if (params) s = s.replace(/\{(\w+)\}/g, (m, k) => (own(params, k) ? String(params[k]) : m));
    return s;
  }
  const known = (key) => own(DICT[lang] || {}, key);
  const tCode = (prefix, code) => (known(prefix + code) ? t(prefix + code) : String(code));
  const locale = () => (lang === "en" ? "en" : "zh-TW");

  function fmtTime(iso, withYear) {
    if (!iso) return "—";
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return String(iso);
    const opts = { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" };
    if (withYear) { opts.year = "numeric"; opts.second = "2-digit"; }
    return new Intl.DateTimeFormat(locale(), opts).format(d);
  }
  const fmtNum = (n) => (typeof n === "number" && Number.isFinite(n) ? new Intl.NumberFormat(locale()).format(n) : "—");
  function fmtDuration(seconds) {
    if (typeof seconds !== "number" || !Number.isFinite(seconds) || seconds < 0) return "—";
    const s = Math.round(seconds);
    if (s < 60) return t("dur.s", { s });
    if (s < 3600) return t("dur.ms", { m: Math.floor(s / 60), s: s % 60 });
    return t("dur.hm", { h: Math.floor(s / 3600), m: Math.floor((s % 3600) / 60) });
  }
  function elapsed(start, end) {
    if (!start) return null;
    const a = new Date(start).getTime();
    const b = end ? new Date(end).getTime() : Date.now();
    return Number.isFinite(a) && Number.isFinite(b) ? (b - a) / 1000 : null;
  }
  const baseName = (p) => (p ? String(p).split(/[\\/]/).filter(Boolean).pop() || String(p) : "—");

  // ---------------------------------------------------------------- DOM
  function h(tag, attrs, ...children) {
    const el = document.createElement(tag);
    if (attrs) {
      for (const [k, v] of Object.entries(attrs)) {
        if (v === null || v === undefined || v === false) continue;
        if (k.startsWith("on") && k !== "on") throw new Error("no inline handlers");
        if (k === "class") el.className = v;
        else if (k === "text") el.textContent = String(v);
        else if (k === "on") for (const [ev, fn] of Object.entries(v)) el.addEventListener(ev, fn);
        else if (k === "style") for (const [p, val] of Object.entries(v)) el.style.setProperty(p, String(val));
        else if (k === "value") el.value = String(v);
        else if (k === "checked" || k === "selected" || k === "disabled") el[k] = Boolean(v);
        else el.setAttribute(k, v === true ? "" : String(v));
      }
    }
    append(el, children);
    return el;
  }
  // replaceChildren() would turn a null or false child into the text "null"; fill() skips them like h() does
  function fill(el, ...children) {
    el.replaceChildren();
    return append(el, children);
  }
  function append(el, children) {
    for (const c of children.flat(Infinity)) {
      if (c === null || c === undefined || c === false) continue;
      el.append(c instanceof Node ? c : String(c));
    }
    return el;
  }

  const SVG_NS = "http://www.w3.org/2000/svg";
  const ICONS = {
    grid: ["M4 4h6v6H4z", "M14 4h6v6h-6z", "M4 14h6v6H4z", "M14 14h6v6h-6z"],
    plus: ["M12 5v14", "M5 12h14"],
    tool: ["M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"],
    shield: ["M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z", "M9 12l2 2 4-4"],
    lock: ["M5 11h14v10H5z", "M8 11V7a4 4 0 0 1 8 0v4"],
    code: ["M16 18l6-6-6-6", "M8 6l-6 6 6 6"],
    link: ["M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71", "M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"],
    alert: ["M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z", "M12 9v4", "M12 17h.01"],
    file: ["M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z", "M14 2v6h6"],
    check: ["M20 6L9 17l-5-5"],
    x: ["M18 6L6 18", "M6 6l12 12"],
    chevron: ["M9 18l6-6-6-6"],
    download: ["M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4", "M7 10l5 5 5-5", "M12 15V3"],
    arrow: ["M5 12h14", "M12 5l7 7-7 7"],
    users: ["M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2", "M9 3a4 4 0 1 0 0 8a4 4 0 1 0 0-8z", "M23 21v-2a4 4 0 0 0-3-3.87", "M16 3.13a4 4 0 0 1 0 7.75"],
    cpu: ["M4 4h16v16H4z", "M9 9h6v6H9z", "M9 1v3", "M15 1v3", "M9 20v3", "M15 20v3", "M20 9h3", "M20 14h3", "M1 9h3", "M1 14h3"],
    target: ["M12 2a10 10 0 1 0 0 20a10 10 0 1 0 0-20z", "M12 6a6 6 0 1 0 0 12a6 6 0 1 0 0-12z", "M12 10a2 2 0 1 0 0 4a2 2 0 1 0 0-4z"],
    checkCircle: ["M22 11.08V12a10 10 0 1 1-5.93-9.14", "M22 4L12 14.01l-3-3"],
    search: ["M11 3a8 8 0 1 0 0 16a8 8 0 1 0 0-16z", "M21 21l-4.35-4.35"],
    layers: ["M12 2L2 7l10 5 10-5-10-5z", "M2 17l10 5 10-5", "M2 12l10 5 10-5"],
    activity: ["M22 12h-4l-3 9L9 3l-3 9H2"],
    stop: ["M6 6h12v12H6z"],
    play: ["M5 3l14 9-14 9V3z"],
    refresh: ["M23 4v6h-6", "M1 20v-6h6", "M3.51 9a9 9 0 0 1 14.85-3.36L23 10", "M1 14l4.64 4.36A9 9 0 0 0 20.49 15"],
    info: ["M12 2a10 10 0 1 0 0 20a10 10 0 1 0 0-20z", "M12 16v-4", "M12 8h.01"],
    database: ["M3 5c0-1.66 4-3 9-3s9 1.34 9 3-4 3-9 3-9-1.34-9-3z", "M21 12c0 1.66-4 3-9 3s-9-1.34-9-3", "M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"],
    folder: ["M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"],
    key: ["M21 2l-2 2", "M11.39 11.61a5.5 5.5 0 1 1-7.78 7.78 5.5 5.5 0 0 1 7.78-7.78z", "M11.39 11.61L15.5 7.5", "M15.5 7.5l3 3L22 7l-3-3", "M15.5 7.5L19 4"],
    clock: ["M12 2a10 10 0 1 0 0 20a10 10 0 1 0 0-20z", "M12 6v6l4 2"],
    terminal: ["M4 17l6-6-6-6", "M12 19h8"],
    sliders: ["M4 21v-7", "M4 10V3", "M12 21v-9", "M12 8V3", "M20 21v-5", "M20 12V3", "M1 14h6", "M9 8h6", "M17 16h6"],
  };
  function icon(name, cls) {
    const svg = document.createElementNS(SVG_NS, "svg");
    svg.setAttribute("viewBox", "0 0 24 24");
    svg.setAttribute("class", "icon" + (cls ? " " + cls : ""));
    svg.setAttribute("aria-hidden", "true");
    svg.setAttribute("focusable", "false");
    for (const d of ICONS[name] || ICONS.info) {
      const path = document.createElementNS(SVG_NS, "path");
      path.setAttribute("d", d);
      svg.append(path);
    }
    return svg;
  }

  const chip = (text, cls, title) => h("span", { class: "chip" + (cls ? " " + cls : ""), title: title || null }, text);
  const dot = (cls) => h("span", { class: "dot" + (cls ? " " + cls : ""), "aria-hidden": "true" });
  const mono = (text, title) => h("code", { class: "mono", title: title || null }, text === null || text === undefined || text === "" ? "—" : String(text));

  function btn(label, opts) {
    const o = opts || {};
    const el = h(o.href ? "a" : "button", {
      class: "btn" + (o.kind ? " " + o.kind : "") + (o.small ? " small" : ""),
      type: o.href ? null : "button",
      href: o.href || null,
      download: o.download || null,
      disabled: o.disabled || null,
      "aria-label": o.aria || null,
      on: o.onClick ? { click: o.onClick } : null,
    }, o.icon ? icon(o.icon, "sm") : null, label);
    return el;
  }

  function pageHead(eyebrow, title, sub, action) {
    return h("div", { class: "page-head" },
      h("div", null, h("div", { class: "eyebrow" }, eyebrow), h("h1", { id: "page-title", tabindex: "-1" }, title), sub ? h("p", { class: "sub" }, sub) : null),
      action || null);
  }
  const newRunButton = () => btn(t("action.new_review"), { kind: "primary", icon: "plus", href: "#/new" });

  function card(label, title, body, extra) {
    return h("section", { class: "card" + (extra && extra.cls ? " " + extra.cls : ""), "aria-label": title || label || null },
      label || title ? h("div", { class: "card-head" }, h("div", null, label ? h("div", { class: "card-label" }, label) : null, title ? h("h2", null, title) : null),
        extra && extra.right ? extra.right : null) : null,
      body);
  }

  function tableWrap(label, head, rows) {
    // the region is named apart from the card around it, which is a region of its own (axe landmark-unique)
    return h("div", { class: "tablewrap", tabindex: "0", role: "region", "aria-label": t("a11y.table", { name: label }) },
      h("table", null, h("caption", { class: "sr-only" }, label),
        h("thead", null, h("tr", null, head.map((c) => h("th", { scope: "col", class: c.num ? "num" : null }, c.label || c)))),
        h("tbody", null, rows)));
  }

  function kv(pairs) {
    const dl = h("dl", { class: "kv" });
    for (const [k, v, text] of pairs) {
      dl.append(h("dt", null, k), h("dd", { class: text ? "text" : null }, v === null || v === undefined || v === "" ? "—" : v));
    }
    return dl;
  }

  function emptyState(text, iconName) {
    return h("div", { class: "empty-state" }, icon(iconName || "info"), h("p", null, text));
  }

  function bar(value, max, cls) {
    const pct = max > 0 ? Math.max(0, Math.min(100, (value / max) * 100)) : 0;
    const fill = h("span");
    fill.style.setProperty("width", pct.toFixed(1) + "%");
    return h("div", { class: "bar" + (cls ? " " + cls : ""), role: "presentation" }, fill);
  }

  // ---------------------------------------------------------------- API
  class ApiError extends Error {
    constructor(code, message, status) { super(message || code); this.code = code; this.detail = message || ""; this.status = status || 0; }
  }
  // The server's token arrives in the URL fragment (#token=...), which no server, log or Referer ever sees. It is kept in
  // this origin's localStorage - scoped to scheme, host and port, unlike a cookie, which every service on 127.0.0.1
  // would receive - and sent in a header no other origin can send without a CORS preflight the server never grants.
  const TOKEN_KEY = "mara.token";
  let TOKEN = "";
  let loggedOut = false;

  function takeToken() {
    const m = /^#token=([A-Za-z0-9_-]{20,200})$/.exec(location.hash);
    if (m) {
      TOKEN = m[1];
      store.set(TOKEN_KEY, TOKEN);
      history.replaceState(null, "", location.pathname + "#/");  // out of the address bar and the history entry
      return true;
    }
    TOKEN = TOKEN || store.get(TOKEN_KEY) || "";
    return false;
  }

  async function demoApi(method, path) {
    if (method !== "GET") throw new ApiError("demo_read_only", "");
    const key = path.split("?")[0];
    if (!own(DEMO.api || {}, key)) throw new ApiError("not_found", "", 404);
    setService(true);
    return JSON.parse(JSON.stringify(DEMO.api[key]));
  }

  async function api(method, path, body) {
    if (DEMO) return demoApi(method, path);
    const headers = { Accept: "application/json", "X-MARA-Token": TOKEN };
    const opts = { method, headers, credentials: "omit", cache: "no-store", redirect: "error" };
    if (body !== undefined) { headers["Content-Type"] = "application/json"; opts.body = JSON.stringify(body); }
    let res;
    try {
      res = await fetch(path, opts);
    } catch (e) {
      setService(false);
      throw new ApiError("network", "");
    }
    setService(true);
    let data = null;
    try { data = await res.json(); } catch (e) { data = null; }
    if (!res.ok) {
      const err = (data && data.error) || {};
      if (res.status === 401) { store.remove(TOKEN_KEY); TOKEN = ""; showLoggedOut(); }
      throw new ApiError(err.code || "http_" + res.status, err.message || "", res.status);
    }
    return data;
  }
  const enc = encodeURIComponent;

  async function download(runId, name) {
    // artifacts need the token header too, so they are fetched and handed to the browser as a local blob
    try {
      let blob;
      if (DEMO) {
        const text = own(DEMO.files || {}, runId) && own(DEMO.files[runId], name) ? DEMO.files[runId][name] : null;
        if (typeof text !== "string") throw new ApiError("demo_read_only", "");
        blob = new Blob([text], { type: "text/plain;charset=utf-8" });
      } else {
        const res = await fetch("/api/runs/" + enc(runId) + "/files/" + enc(name),
          { headers: { "X-MARA-Token": TOKEN }, credentials: "omit", cache: "no-store", redirect: "error" });
        if (!res.ok) throw new ApiError(res.status === 401 ? "unauthenticated" : "not_found", "", res.status);
        blob = await res.blob();
      }
      const href = URL.createObjectURL(blob);
      const a = h("a", { href, download: "mara-" + runId + "-" + name, hidden: true });
      document.body.append(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(href), 30000);
    } catch (e) {
      showError(e instanceof ApiError ? e : new ApiError("network", ""));
    }
  }

  // ---------------------------------------------------------------- banners
  function showError(err) {
    const area = document.getElementById("banner-area");
    const code = err && err.code ? err.code : "internal_error";
    const detail = err && err.detail ? err.detail : "";
    const close = h("button", { type: "button", class: "icon-btn close", "aria-label": t("action.dismiss") }, icon("x", "sm"));
    const el = h("div", { class: "banner", role: "alert" }, icon("alert"),
      h("div", null, h("strong", null, t("banner.failed")), h("div", { class: "detail" }, tCode("error.", code) + (detail ? " — " + detail : ""))),
      close);
    close.addEventListener("click", () => el.remove());
    while (area.children.length >= 3) area.firstElementChild.remove();
    area.append(el);
  }
  function showOk(text) {
    const area = document.getElementById("banner-area");
    const close = h("button", { type: "button", class: "icon-btn close", "aria-label": t("action.dismiss") }, icon("x", "sm"));
    const el = h("div", { class: "banner ok", role: "status" }, icon("check"), h("div", null, h("strong", null, text)), close);
    close.addEventListener("click", () => el.remove());
    area.append(el);
    setTimeout(() => el.remove(), 6000);
  }
  const clearBanners = () => document.getElementById("banner-area").replaceChildren();

  // ---------------------------------------------------------------- state
  const state = { session: null, runs: [], busy: false, env: null, envAt: 0, configs: null, route: { name: "home" }, filters: new Map() };
  let viewTimers = [];
  let renderSeq = 0;
  function every(ms, fn) { viewTimers.push(setInterval(fn, ms)); }
  function clearViewTimers() { viewTimers.forEach((id) => clearInterval(id)); viewTimers = []; }

  function setService(ok) {
    const el = document.getElementById("svc-status");
    if (!el) return;
    if (DEMO) { fill(el, dot("info"), h("span", null, t("top.demo"))); return; }
    fill(el, dot(ok ? "" : "danger"), h("span", null, t(ok ? "top.connected" : "top.disconnected")));
  }

  async function refreshRuns() {
    try {
      const data = await api("GET", "/api/runs");
      state.runs = data.runs || [];
      state.busy = Boolean(data.busy);
    } catch (e) {
      if (e.code !== "unauthenticated") throw e;
    }
    renderNav();
    renderRecent();
  }

  async function loadEnv(force) {
    if (!force && state.env && Date.now() - state.envAt < 30000) return state.env;
    state.env = await api("GET", "/api/env");
    state.envAt = Date.now();
    return state.env;
  }
  async function loadConfigs(force) {
    if (!force && state.configs) return state.configs;
    state.configs = (await api("GET", "/api/configs")).configs || [];
    return state.configs;
  }

  // ---------------------------------------------------------------- labels
  function runStatus(run) {
    const s = run.status;
    if (s === "running") return { key: "running", cls: "info", dot: "info pulse" };
    if (s === "finished") {
      const sum = run.summary;
      if (sum && sum.review_status === "complete") return { key: "complete", cls: "ok", dot: "" };
      return { key: "incomplete", cls: "warn", dot: "warn" };
    }
    if (s === "failed") return { key: "failed", cls: "danger", dot: "danger" };
    if (s === "cancelled") return { key: "cancelled", cls: "", dot: "muted" };
    return { key: "interrupted", cls: "warn", dot: "warn" };
  }
  const statusChip = (run) => { const st = runStatus(run); return chip(t("status." + st.key), st.cls); };
  const modeLabel = (mode) => (mode ? tCode("mode.", mode) : "—");
  function gateChip(sum) {
    if (!sum) return chip("—");
    return sum.gate_passed ? chip(t("gate.passed"), "ok") : chip(t("gate.blocked"), "danger");
  }
  const scoreText = (sum) => (sum && typeof sum.overall_score === "number" ? sum.overall_score + " / 100" : t("score.unavailable"));
  const outcomeChip = (o) => chip(tCode("outcome.", o), { accepted: "danger", needs_human: "warn", rejected: "", dropped: "" }[o] || "");
  const tierChip = (tier) => chip(t("tier.label", { tier }), { A: "ok", B: "info", C: "warn", D: "" }[tier] || "", tCode("tier.desc.", tier));
  const sevChip = (sev) => chip(tCode("severity.", sev || "None"), "sev-" + (SEVERITIES.includes(sev) ? sev : "None"));
  const dimLabel = (d) => tCode("dimension.", d);

  // ---------------------------------------------------------------- shell
  function parseRoute() {
    const parts = (location.hash || "#/").replace(/^#\/?/, "").split("/").filter(Boolean).map((p) => decodeURIComponent(p));
    if (!parts.length) return { name: "home" };
    if (parts[0] === "new") return { name: "new" };
    if (parts[0] === "env") return { name: "env" };
    if (parts[0] === "runs" && parts[1]) return { name: "run", id: parts[1], tab: TABS.includes(parts[2]) ? parts[2] : "overview" };
    return { name: "notfound" };
  }

  function renderNav() {
    const nav = document.getElementById("main-nav");
    const r = state.route.name;
    const item = (href, ic, label, active, badge) => h("a", { href, "aria-current": active ? "page" : null }, icon(ic), h("span", null, label),
      badge !== undefined ? h("span", { class: "badge", "aria-label": t("nav.count", { n: badge }) }, String(badge)) : null);
    fill(nav, 
      item("#/", "grid", t("nav.workbench"), r === "home" || r === "run", state.runs.length),
      item("#/new", "plus", t("nav.new"), r === "new"),
      item("#/env", "tool", t("nav.env"), r === "env"));
  }

  function renderRecent() {
    const list = document.getElementById("recent-list");
    if (!state.runs.length) { fill(list, h("li", { class: "empty" }, t("nav.no_runs"))); return; }
    const current = state.route.name === "run" ? state.route.id : null;
    fill(list, ...state.runs.slice(0, 12).map((run) => {
      const st = runStatus(run);
      return h("li", null, h("a", { href: "#/runs/" + enc(run.id), "aria-current": run.id === current ? "page" : null },
        h("span", { class: "r-title" }, dot(st.dot), h("span", null, run.title || run.id)),
        h("span", { class: "r-sub" }, [modeLabel(run.provider), t("status." + st.key), fmtTime(run.started_at)].join(" · "))));
    }));
  }

  function renderCrumbs(route) {
    const el = document.getElementById("crumbs");
    const parts = [h("a", { href: "#/" }, t("crumb.workspace"))];
    const sep = () => icon("chevron", "sm");
    if (route.name === "home") parts.push(sep(), h("span", null, t("nav.workbench")));
    if (route.name === "new") parts.push(sep(), h("span", null, t("nav.new")));
    if (route.name === "env") parts.push(sep(), h("span", null, t("nav.env")));
    if (route.name === "run") {
      const run = state.runs.find((x) => x.id === route.id);
      parts.push(sep(), h("a", { href: "#/" }, t("nav.workbench")), sep(), h("span", null, run ? run.title : route.id));
    }
    fill(el, ...parts);
  }

  function applyStatic() {
    document.documentElement.lang = lang === "en" ? "en" : "zh-Hant";
    document.title = t("app.title");
    for (const el of document.querySelectorAll("[data-i18n]")) el.textContent = t(el.getAttribute("data-i18n"));
    for (const el of document.querySelectorAll("[data-i18n-aria]")) el.setAttribute("aria-label", t(el.getAttribute("data-i18n-aria")));
    document.getElementById("lang-toggle").textContent = t("top.lang_switch");
    document.getElementById("lang-toggle").setAttribute("aria-label", t("top.lang_switch_aria"));
  }

  async function render(focusMain) {
    const seq = ++renderSeq;
    clearViewTimers();
    closeDrawer(false);
    const route = parseRoute();
    state.route = route;
    applyStatic();
    renderNav();
    renderCrumbs(route);
    renderRecent();
    const main = document.getElementById("content");
    if (loggedOut) { fill(main, loggedOutView()); return; }
    if (!main.firstChild) fill(main, emptyState(t("common.loading"), "clock"));
    try {
      if (route.name === "home") await viewHome(main, seq);
      else if (route.name === "new") await viewNew(main, seq);
      else if (route.name === "env") await viewEnv(main, seq);
      else if (route.name === "run") await viewRun(main, seq, route);
      else fill(main, pageHead("404", t("notfound.title"), t("notfound.sub"), newRunButton()));
    } catch (e) {
      if (seq !== renderSeq || loggedOut) return;
      fill(main, emptyState(tCode("error.", e.code || "internal_error") + (e.detail ? " — " + e.detail : ""), "alert"));
    }
    if (seq === renderSeq) {
      renderCrumbs(route);
      if (focusMain) { const title = document.getElementById("page-title"); (title || main).focus({ preventScroll: false }); }
    }
  }

  function loggedOutView() {
    return h("div", { class: "stack" }, pageHead(t("logout.eyebrow"), t("logout.title"), t("logout.sub")),
      h("div", { class: "callout" }, icon("key"), h("div", null, t("logout.how"), " ", mono("mara"))));
  }
  function showLoggedOut() {
    if (loggedOut) return;
    loggedOut = true;
    clearViewTimers();
    render(false);
  }

  // ---------------------------------------------------------------- home
  async function viewHome(main, seq) {
    await refreshRuns();
    if (seq !== renderSeq) return;
    const runs = state.runs;
    const toolsKpi = h("div", { class: "value" }, "…");
    const toolsSub = h("div", { class: "s-sub" }, t("common.loading"));
    const active = runs.filter((r) => ACTIVE.includes(r.status)).length;
    const last = runs.find((r) => r.summary);
    const kpi = (label, ic, value, sub, cls) => h("div", { class: "card stat" },
      h("div", { class: "s-top" }, h("span", null, label), icon(ic, "sm")),
      value instanceof Node ? value : h("div", { class: "value" + (cls ? " " + cls : "") }, value), sub instanceof Node ? sub : h("div", { class: "s-sub" }, sub));
    const rows = runs.map((run) => {
      const sum = run.summary;
      const go = () => { location.hash = "#/runs/" + enc(run.id); };
      return h("tr", { class: "clickable", tabindex: "0", on: { click: go, keydown: (ev) => { if (ev.key === "Enter") go(); } } },
        h("td", null, h("a", { href: "#/runs/" + enc(run.id), class: "t-title" }, run.title || run.id), h("div", { class: "t-sub" }, run.id)),
        h("td", null, mono(baseName(run.target), run.target)),
        h("td", null, chip(modeLabel(run.provider), run.provider === "live" ? "ok" : "info")),
        h("td", null, statusChip(run)),
        h("td", null, gateChip(sum)),
        h("td", { class: "num" }, sum && typeof sum.overall_score === "number" ? String(sum.overall_score) : "—"),
        h("td", { class: "num" }, sum ? t("home.findings_cell", { accepted: sum.counts.accepted, total: sum.findings }) : "—"),
        h("td", null, fmtTime(run.started_at)));
    });
    const table = runs.length
      ? tableWrap(t("home.runs"), [t("col.review"), t("col.target"), t("col.mode"), t("col.status"), t("col.gate"), { label: t("col.score"), num: true },
        { label: t("col.findings"), num: true }, t("col.started")], rows)
      : emptyState(t("home.no_runs"), "folder");
    const orbit = h("div", { class: "orbit", "aria-hidden": "true" }, h("div", { class: "ring" }), h("div", { class: "ring r2" }),
      h("div", { class: "core" }, icon("shield", "lg")), h("div", { class: "sat s1" }, icon("code", "sm")), h("div", { class: "sat s2" }, icon("cpu", "sm")),
      h("div", { class: "sat s3" }, icon("file", "sm")), h("div", { class: "sat s4" }, icon("search", "sm")));
    fill(main, h("div", null,
      pageHead(t("home.eyebrow"), t("home.title"), t("home.sub"), newRunButton()),
      h("div", { class: "hero-grid" },
        h("section", { class: "card feature", "aria-labelledby": "feature-h" }, orbit,
          h("div", { class: "eyebrow" }, t("home.feature.eyebrow")),
          h("h2", { id: "feature-h" }, t("home.feature.l1"), h("br"), t("home.feature.l2")),
          h("p", null, t("home.feature.body")),
          h("div", null, btn(runs.length ? t("action.new_review") : t("home.feature.cta"), { kind: "primary", href: "#/new", icon: "arrow" }))),
        h("div", { class: "numbered" },
          ...[["01", "code", "home.c01.title", "home.c01.body"], ["02", "shield", "home.c02.title", "home.c02.body"],
            ["03", "link", "home.c03.title", "home.c03.body"]].map(([n, ic, title, body]) => h("section", { class: "card", "aria-labelledby": "num-" + n },
            h("span", { class: "num", "aria-hidden": "true" }, n), h("span", { class: "ic" }, icon(ic)),
            h("div", null, h("h3", { id: "num-" + n }, t(title)), h("p", null, t(body))))))),
      h("div", { class: "kpis" },
        kpi(t("home.kpi.runs"), "grid", fmtNum(runs.length), t("home.kpi.runs_sub", { n: active })),
        kpi(t("home.kpi.last_gate"), "shield", last ? (last.summary.gate_passed ? t("gate.passed") : t("gate.blocked")) : "—",
          last ? last.title : t("home.kpi.none"), last && !last.summary.gate_passed ? "danger" : ""),
        kpi(t("home.kpi.last_score"), "activity", last && typeof last.summary.overall_score === "number" ? last.summary.overall_score + " / 100" : "—",
          last ? (typeof last.summary.overall_score === "number" ? "" : t("score.unavailable") + " · ") + fmtTime(last.summary.generated_at) : t("home.kpi.none")),
        kpi(t("home.kpi.tools"), "tool", toolsKpi, toolsSub)),
      card(t("home.runs.label"), t("home.runs"), table),
      h("div", { class: "callout" }, icon("file"), h("p", null, t("home.first_use")))));
    if (runs.some((r) => ACTIVE.includes(r.status))) every(LIST_POLL_MS, () => { if (seq === renderSeq) render(false); });
    loadEnv(false).then((env) => {
      if (seq !== renderSeq) return;
      const scanners = env.tools.rows.filter((r) => r.role !== "verifier");
      const ok = scanners.filter((r) => r.status === "ok").length;
      toolsKpi.textContent = ok + " / " + scanners.length;
      if (ok < scanners.length) toolsKpi.className = "value warn";
      toolsSub.textContent = env.trivy_db.ok ? t("home.kpi.tools_sub_ok") : t("home.kpi.tools_sub_db");
    }).catch(() => { toolsKpi.textContent = "—"; toolsSub.textContent = ""; });
  }

  // ---------------------------------------------------------------- new review
  async function viewNew(main, seq) {
    const [configs] = await Promise.all([loadConfigs(true), refreshRuns()]);
    if (seq !== renderSeq) return;
    const settings = (state.session && state.session.settings) || {};
    const workspace = state.session ? state.session.workspace : "";
    const f = {
      target: h("input", { type: "text", id: "f-target", required: true, autocomplete: "off", spellcheck: "false", placeholder: t("new.target_ph") }),
      title: h("input", { type: "text", id: "f-title", maxlength: "120", autocomplete: "off", placeholder: t("new.title_ph") }),
      config: h("select", { id: "f-config" }),
      base: h("input", { type: "text", id: "f-base", autocomplete: "off", spellcheck: "false", placeholder: "origin/main" }),
      sarif: h("input", { type: "text", id: "f-sarif", autocomplete: "off", spellcheck: "false", placeholder: "fixtures/vuln-sample-sarif" }),
      fixtures: h("input", { type: "text", id: "f-fixtures", autocomplete: "off", spellcheck: "false", placeholder: "fixtures/mock-responses" }),
      failGate: h("input", { type: "checkbox", id: "f-failgate" }),
      calib: h("input", { type: "checkbox", id: "f-calib" }),
    };
    let provider = settings.default_provider === "live" ? "live" : "mock";
    const providerRadio = (value, title, desc, ic) => {
      const input = h("input", { type: "radio", name: "provider", value, checked: provider === value });
      input.addEventListener("change", () => { provider = value; fillConfigs(); update(); });
      return h("label", { class: "radio-card" }, input, icon(ic), h("span", null, h("strong", null, title), h("span", { class: "d" }, desc)));
    };
    const configInfo = h("div", { class: "stack" });
    const preview = h("pre", { class: "log", tabindex: "0", "aria-live": "off" });
    const submit = btn(t("new.submit"), { kind: "primary", icon: "play" });
    submit.setAttribute("type", "submit");

    function fillConfigs() {
      const wanted = configs.filter((c) => c.provider_mode === provider);
      const preferred = settings.default_config && wanted.some((c) => c.path === settings.default_config) ? settings.default_config
        : provider === "mock" ? "config/mara.mock.yaml" : "config/mara.yaml";
      fill(f.config, ...wanted.map((c) => h("option", { value: c.path, selected: c.path === preferred },
        c.path + (c.loadable ? "" : " — " + t("new.config_refused")))));
    }
    function selected() { return configs.find((c) => c.path === f.config.value) || null; }
    function update() {
      const cfg = selected();
      const parts = ["mara", "review", f.target.value.trim() || "<target>", "--provider", provider, "--config", f.config.value || "—"];
      if (f.sarif.value.trim()) parts.push("--sarif-dir", f.sarif.value.trim());
      if (f.fixtures.value.trim()) parts.push("--mock-fixtures", f.fixtures.value.trim());
      if (f.base.value.trim()) parts.push("--base=" + f.base.value.trim());
      if (f.failGate.checked) parts.push("--fail-on-gate");
      if (f.calib.checked) parts.push("--calibration-sample");
      preview.textContent = parts.join(" ");
      if (!cfg) { fill(configInfo, emptyState(t("new.no_config"), "alert")); return; }
      const passed = cfg.policies.filter((p) => p.passed).length;
      const missing = cfg.models.filter((m) => m.credential && !m.credential.present);
      const models = cfg.models.map((m) => h("div", { class: "member" },
        h("div", { class: "avatar" }, icon(m.provider === "mock" ? "cpu" : "lock")),
        h("div", { class: "m-main" },
          h("div", { class: "m-role" }, m.name, h("code", null, m.family)),
          h("div", { class: "m-model" }, tCode("provider.", m.provider) + " · " + m.model),
          h("div", { class: "m-sub" }, tCode("residency.", m.data_residency) + (m.endpoint_host ? " · " + m.endpoint_host : ""))),
        h("div", { class: "m-side" }, m.credential && m.credential.env
          ? chip(m.credential.env + " · " + t(m.credential.present ? "cred.present" : "cred.missing"), m.credential.present ? "ok" : "warn")
          : chip(t("cred.none")))));
      fill(configInfo, 
        h("div", { class: "row" }, chip(t("new.policies", { passed, total: cfg.policies.length }), passed === cfg.policies.length ? "ok" : "danger"),
          chip(t("new.rollout", { phase: tCode("rollout.", cfg.rollout_phase) })), chip(t("new.dimensions", { n: cfg.dimensions.length }))),
        provider === "live"
          ? h("div", { class: "strip" }, icon("lock"), h("div", null, h("strong", null, t("new.live_notice")), h("span", { class: "d" },
            missing.length ? t("new.live_missing", { names: missing.map((m) => m.credential.env).join(", ") }) : t("new.live_notice_d"))))
          : h("div", { class: "strip mock" }, icon("info"), h("div", null, h("strong", null, t("new.mock_notice")), h("span", { class: "d" }, t("new.mock_notice_d")))),
        h("div", null, ...models),
        cfg.loadable ? null : h("div", { class: "gap-item" }, icon("alert"), h("span", null, t("new.config_refused_d"))));
    }
    for (const el of [f.target, f.base, f.sarif, f.fixtures, f.config, f.failGate, f.calib]) el.addEventListener("input", update);
    f.config.addEventListener("change", update);

    const demo = btn(t("new.demo"), { icon: "play", onClick: () => {
      provider = "mock";
      for (const r of form.querySelectorAll("input[name=provider]")) r.checked = r.value === "mock";
      fillConfigs();
      f.config.value = "config/mara.mock.yaml";
      f.target.value = "fixtures/vuln-sample";
      f.sarif.value = "fixtures/vuln-sample-sarif";
      f.fixtures.value = "";
      f.base.value = "";
      f.title.value = t("new.demo_title");
      advanced.open = true;
      update();
      f.target.focus();
    } });

    const field = (id, label, input, hint) => h("div", { class: "field" }, h("label", { for: id }, label), input, hint ? h("span", { class: "hint" }, hint) : null);
    const advanced = h("details", null, h("summary", null, t("new.advanced")),
      h("div", { class: "stack", style: { "margin-top": "14px" } },
        field("f-base", t("new.base"), f.base, t("new.base_hint")),
        field("f-sarif", t("new.sarif"), f.sarif, t("new.sarif_hint")),
        field("f-fixtures", t("new.fixtures"), f.fixtures, t("new.fixtures_hint")),
        h("label", { class: "check", for: "f-failgate" }, f.failGate, h("span", null, t("new.fail_gate"))),
        h("label", { class: "check", for: "f-calib" }, f.calib, h("span", null, t("new.calib")))));

    const form = h("form", { class: "grid two", novalidate: true },
      h("div", { class: "stack" },
        card(t("new.s1.label"), t("new.s1.title"), h("div", null,
          field("f-target", t("new.target"), f.target, t("new.target_hint", { workspace })),
          field("f-title", t("new.title"), f.title, t("new.title_hint")))),
        card(t("new.s2.label"), t("new.s2.title"), h("div", { class: "stack" },
          h("div", { class: "radio-cards", role: "radiogroup", "aria-label": t("new.provider") },
            providerRadio("mock", t("mode.mock"), t("new.mock_d"), "cpu"), providerRadio("live", t("mode.live"), t("new.live_d"), "lock")),
          field("f-config", t("new.config"), f.config, t("new.config_hint")),
          advanced)),
        card(t("new.s3.label"), t("new.s3.title"), h("div", { class: "stack" }, preview,
          h("div", { class: "row" }, demo, h("span", { class: "spacer" }), submit)))),
      h("div", { class: "stack" }, card(t("new.panel.label"), t("new.panel.title"), configInfo)));
    form.addEventListener("submit", async (ev) => {
      ev.preventDefault();
      if (!f.target.value.trim()) { showError(new ApiError("target_required", "")); f.target.focus(); return; }
      submit.disabled = true;
      clearBanners();
      try {
        const body = { target: f.target.value.trim(), provider, config: f.config.value, title: f.title.value.trim(), sarif_dir: f.sarif.value.trim(),
          mock_fixtures: f.fixtures.value.trim(), base: f.base.value.trim(), fail_on_gate: f.failGate.checked, calibration_sample: f.calib.checked };
        const data = await api("POST", "/api/runs", body);
        await refreshRuns();
        location.hash = "#/runs/" + enc(data.run.id);
      } catch (e) {
        showError(e);
        submit.disabled = false;
      }
    });
    fillConfigs();
    update();
    fill(main, h("div", null, pageHead(t("new.eyebrow"), t("new.heading"), t("new.sub")),
      state.busy ? h("div", { class: "gap-item", style: { "margin-bottom": "16px" } }, icon("alert"), h("span", null, t("new.busy"))) : null, form));
  }

  // ---------------------------------------------------------------- run page
  async function viewRun(main, seq, route) {
    const id = route.id;
    const data = await api("GET", "/api/runs/" + enc(id));
    let view = null;
    if (data.run.has_report) {
      try { view = await api("GET", "/api/runs/" + enc(id) + "/report"); } catch (e) { if (e.code !== "no_report") throw e; }
    }
    if (seq !== renderSeq) return;
    const page = buildRunPage(data, view, route, seq);
    fill(main, page.root);
    if (ACTIVE.includes(data.run.status)) {
      let inFlight = false;
      every(RUN_POLL_MS, async () => {
        if (inFlight || seq !== renderSeq) return;
        inFlight = true;
        try {
          const next = await api("GET", "/api/runs/" + enc(id));
          if (seq !== renderSeq) return;
          if (!ACTIVE.includes(next.run.status)) { await refreshRuns(); render(false); return; }
          page.update(next);
        } catch (e) { /* the service dot shows a lost connection */ } finally { inFlight = false; }
      });
    }
  }

  function buildRunPage(data, view, route, seq) {
    const run = data.run;
    const id = run.id;
    const mode = run.provider || (view && view.meta.provider_mode) || "mock";
    const statusSlot = h("span");
    const stepperSlot = h("div");
    const actionsSlot = h("div", { class: "actions" });
    const tabPanel = h("div", { role: "tabpanel", id: "run-panel", "aria-labelledby": "tab-" + route.tab });
    const logParts = { slot: null };

    function renderStatus(r) { fill(statusSlot, statusChip(r)); }
    function renderActions(r) {
      const items = [];
      if (ACTIVE.includes(r.status)) {
        items.push(btn(t("action.cancel"), { kind: "danger", small: true, icon: "stop", onClick: async (ev) => {
          ev.currentTarget.disabled = true;
          try { await api("POST", "/api/runs/" + enc(id) + "/cancel"); await refreshRuns(); render(false); } catch (e) { showError(e); }
        } }));
      } else if (!r.imported) {
        items.push(btn(t("action.rerun"), { small: true, icon: "refresh", onClick: async (ev) => {
          ev.currentTarget.disabled = true;
          try {
            const res = await api("POST", "/api/runs/" + enc(id) + "/rerun");
            await refreshRuns();
            location.hash = "#/runs/" + enc(res.run.id);
          } catch (e) { showError(e); ev.currentTarget.disabled = false; }
        } }));
      }
      const files = r.artifacts || [];
      if (files.length) {
        items.push(h("details", { class: "menu" }, h("summary", { class: "btn small" }, icon("download", "sm"), t("action.export")),
          h("div", { class: "menu-list" }, files.map((name) => h("button", { type: "button", on: { click: () => download(id, name) } },
            icon("file", "sm"), name)))));
      }
      fill(actionsSlot, ...items);
    }
    function renderStepper(r, progress) {
      const active = ACTIVE.includes(r.status);
      // a review that is no longer running has no stage at work, whatever a killed child left in its record
      const stages = (progress && Array.isArray(progress.stages) ? progress.stages : STAGES.map((s) => ({ id: s, status: "pending" })))
        .map((s) => (s.status === "running" && !active ? { ...s, status: "failed" } : s));
      const done = stages.filter((s) => s.status === "done" || s.status === "skipped").length;
      const current = stages.find((s) => s.status === "running");
      const failed = stages.find((s) => s.status === "failed");
      const list = h("ol", { class: "stepper" }, stages.map((s, i) => {
        const node = s.status === "done" ? icon("check", "sm") : s.status === "failed" ? icon("x", "sm") : s.status === "skipped" ? "–" : String(i + 1).padStart(2, "0");
        return h("li", { class: "step " + (s.status || "pending"), "aria-current": s.status === "running" ? "step" : null, title: s.note || null },
          h("span", { class: "node" }, node),
          h("span", { class: "s-label" }, tCode("stage.", s.id)),
          h("span", { class: "s-layer" }, STAGE_LAYER[s.id] || ""),
          h("span", { class: "sr-only" }, tCode("stage_status.", s.status || "pending")));
      }));
      let note = "";
      if (current) note = t("stage.now", { stage: tCode("stage.", current.id) }) + (current.started_at ? " · " + fmtDuration(elapsed(current.started_at)) : "");
      else if (failed) note = t("stage.failed_at", { stage: tCode("stage.", failed.id) }) + (progress.error ? " · " + progress.error : "");
      else if (r.status === "finished") note = t("stage.all_done", { n: STAGES.length });
      else if (r.status === "cancelled") note = t("status.cancelled");
      else if (r.status === "failed" && !progress) note = t("stage.no_progress");
      fill(stepperSlot, card(t("run.pipeline.label"), null, h("div", null, list, h("p", { class: "stage-note", "aria-live": "polite" }, note)),
        { cls: "pipeline", right: h("span", { class: "small muted" }, t("run.pipeline.count", { done, total: stages.length })) }));
    }

    renderStatus(run);
    renderActions(run);
    renderStepper(run, data.progress);

    const live = mode === "live";
    const strip = h("div", { class: "strip" + (live ? "" : " mock") }, icon(live ? "lock" : "info"),
      h("div", null, h("strong", null, t(live ? "run.strip.live" : "run.strip.mock")), h("span", { class: "d" }, t(live ? "run.strip.live_d" : "run.strip.mock_d"))),
      h("span", { class: "spacer" }), statusSlot);
    const meta = h("div", { class: "meta-row" }, h("span", { class: "row" }, icon("file", "sm"), mono(id)),
      h("span", null, t("run.created", { time: fmtTime(run.started_at) })),
      run.target ? h("span", null, t("run.target"), " ", mono(baseName(run.target), run.target)) : null,
      run.config ? h("span", null, t("run.config"), " ", mono(run.config)) : null, actionsSlot);

    const sum = view ? view.stats : null;
    const statCard = (label, ic, value, sub, cls) => h("div", { class: "card stat" },
      h("div", { class: "s-top" }, h("span", null, label), icon(ic, "sm")), h("div", { class: "value" + (cls ? " " + cls : "") }, value), h("div", { class: "s-sub" }, sub));
    const stats = h("div", { class: "grid four", style: { "margin-top": "16px" } },
      statCard(t("card.findings"), "shield", sum ? fmtNum(sum.accepted) : "—",
        sum ? t("card.findings_sub", { rejected: sum.rejected, dropped: sum.dropped, total: sum.findings }) : t("card.pending")),
      statCard(t("card.queue"), "users", sum ? fmtNum(sum.human_queue) : "—", sum ? t("card.queue_sub", { n: sum.needs_human }) : t("card.pending"), sum && sum.human_queue ? "warn" : ""),
      statCard(t("card.tools"), "code", sum ? fmtNum(sum.tool_results_blocking) : "—",
        sum ? t("card.tools_sub", { ran: sum.tools_ran, total: sum.tools_total, n: sum.tool_results }) : t("card.pending")),
      statCard(t("card.gaps"), "alert", sum ? fmtNum(sum.incomplete_reasons) : "—", sum ? t("card.gaps_sub") : t("card.pending"), sum && sum.incomplete_reasons ? "warn" : ""));

    const verdicts = view ? h("div", { class: "verdicts" },
      view.meta.gate_passed ? chip(t("gate.passed_long"), "ok") : chip(t("gate.blocked_long"), "danger"),
      chip(t("score.label") + " " + scoreText(view.meta)),
      chip(t("review_status." + view.meta.review_status), view.meta.review_status === "complete" ? "ok" : "warn"),
      chip(t("scope.label") + " " + tCode("scope.", view.meta.review_scope)),
      chip(t("families.label", { n: (view.meta.families_used || []).length })),
      view.meta.rollout_phase ? chip(t("new.rollout", { phase: tCode("rollout.", view.meta.rollout_phase) })) : null) : null;

    const tabLink = (tab, label) => h("a", { href: "#/runs/" + enc(id) + "/" + tab, role: "tab", id: "tab-" + tab, "aria-selected": tab === route.tab ? "true" : "false",
      "aria-controls": "run-panel" }, label);
    const tabs = h("div", { class: "tabs", role: "tablist", "aria-label": t("run.tabs") },
      tabLink("overview", t("tab.overview")),
      tabLink("findings", t("tab.findings", { n: sum ? sum.findings : 0 })),
      tabLink("dimensions", t("tab.dimensions")),
      tabLink("tools", t("tab.tools")),
      tabLink("queue", t("tab.queue", { n: sum ? sum.human_queue : 0 })),
      tabLink("log", t("tab.log")));

    const panel = data.panel || [];
    if (route.tab === "overview") tabPanel.append(tabOverview(run, view, panel, data.progress));
    else if (route.tab === "log") logParts.slot = tabLog(run, data.progress, tabPanel, seq);
    else if (!view) tabPanel.append(emptyState(t(ACTIVE.includes(run.status) ? "run.no_report_yet" : "run.no_report"), "clock"));
    else if (route.tab === "findings") tabPanel.append(tabFindings(view, id));
    else if (route.tab === "dimensions") tabPanel.append(tabDimensions(view, run));
    else if (route.tab === "tools") tabPanel.append(tabTools(view));
    else if (route.tab === "queue") tabPanel.append(tabQueue(view));

    const root = h("div", null,
      pageHead(t("run.eyebrow"), run.title || id, t("run.sub"), newRunButton()),
      strip, meta, stepperSlot, verdicts, stats, tabs, tabPanel);
    return {
      root,
      update(next) {
        renderStatus(next.run);
        renderActions(next.run);
        renderStepper(next.run, next.progress);
        if (logParts.slot) logParts.slot(next.progress, next.run);
      },
    };
  }

  function tabOverview(run, view, panel, progress) {
    const audit = view ? view.budget : null;
    const members = [];
    for (const group of panel) {
      for (const m of group.members) {
        const fails = Object.values(m.failures || {}).reduce((a, b) => a + b, 0) + (m.canary_echoes || 0);
        const side = [];
        if (view) {
          side.push(m.calls ? chip(t("member.calls", { n: m.calls }), "ok") : chip(t("member.no_calls")));
          if (fails) side.push(chip(t("member.failures", { n: fails }), "warn", Object.entries(m.failures).filter(([, v]) => v).map(([k, v]) => k + " " + v).join(", ")));
          if (!m.configured) side.push(chip(t("member.reassigned"), "info", t("member.reassigned_d")));
        } else {
          side.push(chip(ACTIVE.includes(run.status) ? t("member.waiting") : "—"));
        }
        members.push(h("div", { class: "member" },
          h("div", { class: "avatar " + group.role }, icon(ROLE_ICON[group.role] || "cpu")),
          h("div", { class: "m-main" },
            h("div", { class: "m-role" }, tCode("role.", group.role), h("code", null, m.name || m.family)),
            h("div", { class: "m-model" }, (m.provider ? tCode("provider.", m.provider) + " · " : "") + (m.model || "—")),
            h("div", { class: "m-sub" }, [t("member.family", { family: m.family || "—" }), m.data_residency ? tCode("residency.", m.data_residency) : null,
              m.served_models && m.served_models.length ? t("member.served", { models: m.served_models.join(", ") }) : null].filter(Boolean).join(" · "))),
          h("div", { class: "m-side" }, side)));
      }
    }
    const attribution = card(t("run.attr.label"), t("run.attr.title"), h("div", null,
      members.length ? members : emptyState(t("run.attr.none")), h("p", { class: "note" }, t("run.attr.note"))));

    const meta = view ? view.meta : {};
    const gate = run.gate || {};
    const context = card(t("run.scope.label"), t("run.scope.title"), kv([
      [t("scope.target"), mono(meta.target || run.target)],
      [t("scope.target_id"), mono(meta.target_id)],
      [t("scope.revision"), mono(meta.revision)],
      [t("scope.content_hash"), mono(meta.content_hash)],
      [t("scope.commit"), mono(meta.commit)],
      [t("scope.config"), mono(run.config)],
      [t("scope.config_hash"), mono(meta.config_hash)],
      [t("scope.scope"), meta.review_scope ? tCode("scope.", meta.review_scope) : "—", true],
      [t("scope.mode"), modeLabel(meta.provider_mode || run.provider), true],
      [t("scope.families"), (meta.families_used || []).join(", ") || "—", true],
      [t("scope.generated"), fmtTime(meta.generated_at, true), true],
      [t("scope.gate"), gate.min_dimension_score !== undefined ? t("scope.gate_v", { min: gate.min_dimension_score, tiers: (gate.block_on_tiers || []).join("/"),
        sev: (gate.block_on_severity || []).map((s) => tCode("severity.", s)).join("/") }) : "—", true],
      [t("scope.exchange"), meta.exchange_version !== undefined && meta.exchange_version !== null ? String(meta.exchange_version) : "—", true],
    ]));

    const budgetBody = h("div");
    if (audit) {
      const maxCalls = Math.max(1, ...ROLES.map((r) => audit.calls[r] || 0));
      for (const r of ROLES) {
        budgetBody.append(h("div", { class: "bar-row" }, h("div", { class: "b-top" }, h("span", null, t("budget.calls_role", { role: tCode("role.", r) })),
          h("span", { class: "mono" }, fmtNum(audit.calls[r] || 0))), bar(audit.calls[r] || 0, maxCalls)));
      }
      const tokens = audit.input_tokens + audit.output_tokens;
      budgetBody.append(h("hr", { class: "divider" }),
        h("div", { class: "bar-row" }, h("div", { class: "b-top" }, h("span", null, t("budget.tokens_in")), h("span", { class: "mono" }, fmtNum(audit.input_tokens))),
          bar(audit.input_tokens, tokens || 1)),
        h("div", { class: "bar-row" }, h("div", { class: "b-top" }, h("span", null, t("budget.tokens_out")), h("span", { class: "mono" }, fmtNum(audit.output_tokens))),
          bar(audit.output_tokens, tokens || 1)),
        h("hr", { class: "divider" }),
        kv([
          [t("budget.total_calls"), fmtNum(audit.calls_total), true],
          [t("budget.elapsed"), fmtDuration(elapsed(audit.started_at, audit.finished_at)), true],
          [t("budget.findings"), t("budget.findings_v", { raw: audit.findings_raw, deduped: audit.findings_deduped }), true],
          [t("budget.alpha"), audit.global_krippendorff_alpha === null || audit.global_krippendorff_alpha === undefined ? "—" : String(audit.global_krippendorff_alpha), true],
          [t("budget.flips"), fmtNum(audit.position_flips), true],
          [t("budget.backlog"), audit.human_queue_backlog === undefined || audit.human_queue_backlog === null ? "—"
            : (typeof audit.human_queue_backlog === "number" ? fmtNum(audit.human_queue_backlog) : t("budget.backlog_unknown"))
              + (audit.human_queue_tightened ? " · " + t("budget.tightened") : ""), true],
        ]));
    } else {
      budgetBody.append(kv([[t("budget.elapsed"), fmtDuration(elapsed(run.started_at, run.finished_at)), true]]));
    }
    budgetBody.append(h("p", { class: "note" }, t("budget.note")));
    const budget = card(t("run.budget.label"), t("run.budget.title"), budgetBody);

    const gaps = h("div");
    if (view) {
      const ku = view.known_unknowns;
      const item = (text, code) => h("div", { class: "gap-item" }, icon("alert", "sm"), h("div", null, text, code ? h("div", null, mono(code)) : null));
      const counters = ku.audit_failures || {};
      // an audit counter that made the review incomplete is listed once, with its count
      for (const r of ku.incomplete_reasons) gaps.append(item(own(counters, r) ? t("gap.counter", { name: tCode("reason.", r), n: counters[r] }) : tCode("reason.", r), r));
      for (const tool of ku.tools_not_run) gaps.append(item(t("gap.tool_not_run", { tool: tool.tool }), tool.note));
      for (const [k, v] of Object.entries(counters)) if (!ku.incomplete_reasons.includes(k)) gaps.append(item(t("gap.counter", { name: tCode("reason.", k), n: v }), k));
      const omitted = Object.entries(ku.coverage.omitted || {});
      for (const [file, why] of omitted.slice(0, 12)) gaps.append(item(t("gap.omitted", { file }), why));
      if (omitted.length > 12) gaps.append(item(t("gap.more", { n: omitted.length - 12 })));
      const excluded = Object.keys(ku.coverage.excluded || {}).length;
      if (excluded) gaps.append(h("div", { class: "gap-item ok" }, icon("info", "sm"), h("div", null, t("gap.excluded", { n: excluded }))));
      if (!gaps.childNodes.length) gaps.append(h("div", { class: "gap-item ok" }, icon("check", "sm"), h("div", null, t("gap.none"))));
    } else {
      gaps.append(emptyState(t(ACTIVE.includes(run.status) ? "run.no_report_yet" : "run.no_report"), "clock"));
    }
    const unknowns = card(t("run.gaps.label"), t("run.gaps.title"), gaps);
    return h("div", { class: "grid two" }, h("div", { class: "stack" }, attribution, context), h("div", { class: "stack" }, budget, unknowns));
  }

  function tabFindings(view, runId) {
    const fs = view.findings;
    if (!state.filters.has(runId)) state.filters.set(runId, { q: "", outcome: "", dimension: "", severity: "", tier: "" });
    const filters = state.filters.get(runId);
    const sel = (key, label, options) => {
      const s = h("select", { "aria-label": label, on: { change: () => { filters[key] = s.value; draw(); } } },
        h("option", { value: "" }, label), options.map(([v, l]) => h("option", { value: v, selected: filters[key] === v }, l)));
      return s;
    };
    const search = h("input", { type: "search", class: "f-search", placeholder: t("findings.search"), "aria-label": t("findings.search"), value: filters.q });
    search.addEventListener("input", () => { filters.q = search.value; draw(); });
    const dims = [...new Set(fs.map((f) => f.dimension))];
    const bar = h("div", { class: "filters" }, search,
      sel("outcome", t("findings.f_outcome"), OUTCOMES.map((o) => [o, tCode("outcome.", o)])),
      sel("dimension", t("findings.f_dimension"), dims.map((d) => [d, dimLabel(d)])),
      sel("severity", t("findings.f_severity"), SEVERITIES.map((s) => [s, tCode("severity.", s)])),
      sel("tier", t("findings.f_tier"), TIERS.map((x) => [x, t("tier.label", { tier: x })])));
    const count = h("p", { class: "small muted", "aria-live": "polite" });
    const slot = h("div");
    function draw() {
      const q = filters.q.trim().toLowerCase();
      const shown = fs.filter((f) => {
        const c = f.consensus || {};
        if (filters.outcome && c.final_outcome !== filters.outcome) return false;
        if (filters.dimension && f.dimension !== filters.dimension) return false;
        if (filters.severity && f.severity !== filters.severity) return false;
        if (filters.tier && c.tier !== filters.tier) return false;
        if (!q) return true;
        const hay = [f.id, f.title, f.cwe, f.dimension, ...(f.provenance || []).map((p) => p.file)].join(" ").toLowerCase();
        return hay.includes(q);
      });
      count.textContent = t("findings.count", { shown: shown.length, total: fs.length });
      if (!shown.length) { fill(slot, emptyState(t("findings.none"), "search")); return; }
      fill(slot, tableWrap(t("tab.findings", { n: fs.length }),
        ["ID", t("col.severity"), t("col.title"), t("col.dimension"), "CWE", t("col.tier"), t("col.outcome"), t("col.families")],
        shown.map((f) => {
          const c = f.consensus || {};
          const p = (f.provenance || [])[0];
          const open = (ev) => openDrawer(f, ev.currentTarget);
          return h("tr", { class: "clickable", tabindex: "0", on: { click: open, keydown: (ev) => { if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); open(ev); } } } },
            h("td", null, mono(f.id)),
            h("td", null, sevChip(f.severity)),
            h("td", null, h("div", { class: "t-title" }, f.title), p ? h("div", { class: "t-sub" }, p.file + ":" + p.line) : null),
            h("td", null, dimLabel(f.dimension)),
            h("td", null, mono(f.cwe)),
            h("td", null, c.tier ? tierChip(c.tier) : "—"),
            h("td", null, c.final_outcome ? outcomeChip(c.final_outcome) : "—", c.resolved_by_human ? h("div", { class: "t-sub" }, t("findings.human_resolved")) : null),
            h("td", null, (f.finder_families || [f.source_family]).join(", ")));
        })));
    }
    draw();
    return h("div", null, bar, count, slot);
  }

  let drawerReturn = null;
  function closeDrawer(restore) {
    const el = document.getElementById("drawer");
    const bd = document.getElementById("drawer-backdrop");
    if (el) el.remove();
    if (bd) bd.remove();
    document.removeEventListener("keydown", drawerKey);
    if (restore && drawerReturn && document.contains(drawerReturn)) drawerReturn.focus();
    drawerReturn = null;
  }
  function drawerKey(ev) {
    if (ev.key === "Escape") { closeDrawer(true); return; }
    const el = document.getElementById("drawer");
    if (ev.key !== "Tab" || !el) return;
    // keep the keyboard inside the dialog while it is open
    const focusable = Array.from(el.querySelectorAll("button, a[href], summary, [tabindex]:not([tabindex='-1'])"));
    if (!focusable.length) return;
    const first = focusable[0];
    const last = focusable[focusable.length - 1];
    const inside = el.contains(document.activeElement);
    if (ev.shiftKey && (!inside || document.activeElement === first || document.activeElement === el.querySelector("#drawer-title"))) {
      ev.preventDefault();
      last.focus();
    } else if (!ev.shiftKey && (!inside || document.activeElement === last)) {
      ev.preventDefault();
      first.focus();
    }
  }

  function openDrawer(f, from) {
    closeDrawer(false);
    drawerReturn = from || null;
    const c = f.consensus || {};
    const section = (title, ...body) => h("section", null, h("h3", null, title), ...body);
    const prov = (f.provenance || []).map((p) => h("div", { class: "stack", style: { gap: "6px" } },
      h("div", { class: "row" }, mono(p.file + ":" + p.line), p.verified ? chip(t("drawer.verified"), "ok") : chip(t("drawer.unverified"), "danger")),
      h("pre", { class: "quote" + (p.verified ? "" : " unverified") }, p.quote)));
    const votes = (f.votes || []).map((v) => h("tr", null, h("td", null, v.judge_family + (v.self_family ? " *" : "")), h("td", null, tCode("pass.", v.pass_id)),
      h("td", null, tCode("verdict.", v.verdict)), h("td", null, tCode("severity.", v.severity_band)), h("td", null, v.reason)));
    const sk = f.skeptic;
    const rt = f.redteam;
    const close = h("button", { type: "button", class: "icon-btn", "aria-label": t("action.close") }, icon("x"));
    close.addEventListener("click", () => closeDrawer(true));
    const heading = h("h2", { id: "drawer-title", tabindex: "-1" }, f.title);
    const drawer = h("div", { class: "drawer", id: "drawer", role: "dialog", "aria-modal": "true", "aria-labelledby": "drawer-title" },
      h("div", { class: "drawer-head" }, h("div", { style: { flex: "1" } }, h("div", { class: "card-label" }, f.id + " · " + dimLabel(f.dimension) + " · " + f.cwe), heading,
        h("div", { class: "row", style: { "margin-top": "8px" } }, sevChip(f.severity), c.tier ? tierChip(c.tier) : null, c.final_outcome ? outcomeChip(c.final_outcome) : null,
          typeof c.cvss4_score === "number" ? chip("CVSS 4.0 " + c.cvss4_score) : null, c.ssvc_decision ? chip("SSVC " + c.ssvc_decision) : null)), close),
      h("div", { class: "d-body" },
        section(t("drawer.evidence"), ...prov),
        section(t("drawer.reachability"), h("p", null, tCode("reach.", f.reachability)), h("p", null, f.reachability_argument)),
        section(t("drawer.exploit"), h("p", null, f.exploit_sketch || "—")),
        section(t("drawer.refs"), h("div", { class: "row" }, chip(f.cwe, "mono"), (f.standard_refs || []).map((r) => chip(r, "mono")))),
        section(t("drawer.skeptic"), sk ? h("div", null, h("div", { class: "row" }, chip(tCode("skeptic.", sk.verdict), sk.verdict === "refuted" ? "warn" : sk.verdict === "stands" ? "ok" : "info"),
          mono(sk.source_family + " · " + sk.source_model)), h("p", { style: { "margin-top": "8px" } }, sk.reason),
          sk.sanitizer_or_control ? h("p", { class: "small muted" }, t("drawer.control", { control: sk.sanitizer_or_control })) : null)
          : h("p", { class: "muted" }, c.skeptic_abstained ? t("drawer.skeptic_abstained") : t("drawer.none"))),
        section(t("drawer.redteam"), rt ? h("div", null, h("div", { class: "row" }, chip(tCode("exploitable.", rt.exploitable), rt.exploitable === "yes" ? "danger" : ""),
          mono(rt.source_family + " · " + rt.source_model)), h("p", { style: { "margin-top": "8px" } }, rt.preconditions)) : h("p", { class: "muted" }, t("drawer.none"))),
        section(t("drawer.votes"), votes.length ? tableWrap(t("drawer.votes"), [t("col.family"), t("col.pass"), t("col.verdict"), t("col.severity"), t("col.reason")], votes)
          : h("p", { class: "muted" }, t("drawer.none")), h("p", { class: "note" }, t("drawer.votes_note"))),
        section(t("drawer.consensus"), kv([
          [t("drawer.weighted"), typeof c.weighted_score === "number" ? c.weighted_score.toFixed(3) : "—", true],
          [t("drawer.votes_split"), t("drawer.votes_v", { tp: c.votes_tp || 0, fp: c.votes_fp || 0, human: c.votes_human || 0 }), true],
          [t("drawer.agreeing"), (c.families_agreeing || []).join(", ") || "—", true],
          [t("drawer.independent"), String(c.independent_judges ?? "—"), true],
          [t("drawer.agreement"), c.agreement_proxy === null || c.agreement_proxy === undefined ? "—" : String(c.agreement_proxy), true],
          [t("drawer.tool"), t(c.tool_corroborated ? "common.yes" : "common.no"), true],
          [t("drawer.position"), t(c.position_consistent ? "common.yes" : "common.no"), true],
          [t("drawer.jury"), tCode("outcome.", c.jury_outcome), true],
          [t("drawer.final"), tCode("outcome.", c.final_outcome) + (c.resolved_by_human ? " · " + t("findings.human_resolved") : ""), true],
          [t("drawer.reasons"), (c.human_reasons || []).map((r) => tCode("hreason.", r.split(":")[0])).join("、") || "—", true],
        ])),
        section(t("drawer.source"), kv([
          [t("drawer.finder"), (f.finder_families || []).join(", ") || f.source_family, true],
          [t("drawer.model"), mono(f.source_family + " · " + f.source_model)],
          [t("drawer.confidence"), t("drawer.confidence_v", { v: f.model_confidence }), true],
        ]))));
    const backdrop = h("div", { class: "drawer-backdrop", id: "drawer-backdrop" });
    backdrop.addEventListener("click", () => closeDrawer(true));
    document.body.append(backdrop, drawer);
    document.addEventListener("keydown", drawerKey);
    heading.focus();
  }

  function tabDimensions(view, run) {
    const min = run.gate && typeof run.gate.min_dimension_score === "number" ? run.gate.min_dimension_score : 60;
    const cards = view.dimensions.map((d) => {
      const cls = d.score < min ? "danger" : d.score < 80 ? "warn" : "";
      return h("section", { class: "card dim", "aria-label": dimLabel(d.dimension) },
        h("div", { class: "row between" }, h("h2", null, dimLabel(d.dimension)), d.tool_ran ? chip(t("dim.tool_ran"), "ok") : chip(t("dim.tool_not_ran"), "warn")),
        h("div", { class: "d-score" + (cls ? " " + cls : "") }, String(d.score), h("span", { class: "small muted" }, " / 100")),
        bar(d.score, 100, cls),
        h("div", { class: "d-counts" }, h("span", null, t("dim.accepted"), " ", h("strong", null, String(d.accepted_findings))),
          h("span", null, t("dim.rejected"), " ", h("strong", null, String(d.rejected_findings))),
          h("span", null, t("dim.awaiting"), " ", h("strong", null, String(d.human_queue)))));
    });
    return h("div", { class: "stack" },
      h("div", { class: "row" }, view.meta.gate_passed ? chip(t("gate.passed_long"), "ok") : chip(t("gate.blocked_long"), "danger"),
        chip(t("score.label") + " " + scoreText(view.meta)), chip(t("dim.min", { min }))),
      h("div", { class: "dim-grid" }, cards),
      h("p", { class: "note" }, t("dim.note")));
  }

  function tabTools(view) {
    const health = tableWrap(t("tools.health"), [t("col.tool"), t("col.ran"), t("col.note")], view.tool_health.map((x) => h("tr", null,
      h("td", null, mono(x.tool)), h("td", null, x.ran ? chip(t("common.yes"), "ok") : chip(t("common.no"), "warn")), h("td", null, h("span", { class: "small" }, x.note || "—")))));
    const tools = [...new Set(view.tool_results.map((r) => r.tool))];
    const which = h("select", { "aria-label": t("tools.filter") }, h("option", { value: "" }, t("tools.all")), tools.map((x) => h("option", { value: x }, x)));
    const slot = h("div");
    const levelCls = { error: "danger", warning: "warn", note: "info" };
    function draw() {
      const rows = view.tool_results.filter((r) => !which.value || r.tool === which.value).slice(0, 500);
      fill(slot, rows.length ? tableWrap(t("tools.results"), [t("col.tool"), t("col.level"), t("col.rule"), t("col.location"), t("col.message")], rows.map((r) =>
        h("tr", null, h("td", null, mono(r.tool)), h("td", null, chip(tCode("level.", r.level), levelCls[r.level] || "")), h("td", null, mono(r.rule_id)),
          h("td", null, mono((r.file || "—") + (r.line ? ":" + r.line : ""))), h("td", null, h("span", { class: "small" }, String(r.message || "").slice(0, 400))))))
        : emptyState(t("tools.none"), "code"));
    }
    which.addEventListener("change", draw);
    draw();
    return h("div", { class: "stack" }, card(t("tools.health_label"), t("tools.health"), health),
      card(t("tools.results_label"), t("tools.results"), h("div", { class: "stack" }, h("div", { style: { "max-width": "260px" } }, which), slot,
        h("p", { class: "note" }, t("tools.note")))));
  }

  function tabQueue(view) {
    if (!view.human_queue.length) return emptyState(t("queue.none"), "users");
    return h("div", { class: "stack" }, h("p", { class: "note" }, t("queue.note")), ...view.human_queue.map((q) => card(q.finding_id + " · " + dimLabel(q.dimension), q.title,
      h("div", { class: "stack" },
        h("div", { class: "row" }, chip(q.cwe, "mono"), tierChip(q.tier), chip(t("queue.score", { v: q.weighted_score.toFixed(3) })),
          chip(t("drawer.votes_v", { tp: q.votes_tp, fp: q.votes_fp, human: q.votes_human }))),
        h("div", { class: "row" }, mono(q.file + ":" + q.line)),
        h("pre", { class: "quote" }, q.quote),
        h("div", { class: "row" }, q.reasons.map((r) => chip(tCode("hreason.", r.split(":")[0]), "warn", r))),
        h("div", { class: "small muted" }, t("queue.key"), " ", mono(q.key))))));
  }

  function tabLog(run, progress, panel, seq) {
    const stagesSlot = h("div");
    const progressLog = h("pre", { class: "log", tabindex: "0" });
    const pipelineLog = h("pre", { class: "log", tabindex: "0" });
    const runLog = h("pre", { class: "log", tabindex: "0" });
    function drawStages(p, r) {
      const active = ACTIVE.includes((r || run).status);
      const stages = (p && p.stages ? p.stages : []).map((s) => (s.status === "running" && !active ? { ...s, status: "failed" } : s));
      fill(stagesSlot, stages.length ? tableWrap(t("log.stages"), [t("col.stage"), t("col.status"), t("col.started"), { label: t("col.duration"), num: true }, t("col.note")],
        stages.map((s) => h("tr", null, h("td", null, tCode("stage.", s.id), " ", h("span", { class: "s-layer small muted" }, STAGE_LAYER[s.id])),
          h("td", null, chip(tCode("stage_status.", s.status), { done: "ok", running: "info", failed: "danger", skipped: "" }[s.status] || "")),
          h("td", null, fmtTime(s.started_at, true)), h("td", { class: "num" }, s.started_at ? fmtDuration(elapsed(s.started_at, s.finished_at)) : "—"),
          h("td", null, h("span", { class: "small" }, s.note || "")))))
        : emptyState(t("stage.no_progress"), "clock"));
    }
    async function loadLogs() {
      try {
        const data = await api("GET", "/api/runs/" + enc(run.id) + "/log?tail=600");
        if (seq !== renderSeq) return;
        for (const [el, text] of [[progressLog, data.progress_log.join("\n")], [pipelineLog, data.pipeline_log], [runLog, data.run_log]]) {
          const atEnd = el.scrollTop + el.clientHeight >= el.scrollHeight - 8;
          el.textContent = text || t("log.empty");
          if (atEnd) el.scrollTop = el.scrollHeight;
        }
      } catch (e) { /* shown on the next poll */ }
    }
    drawStages(progress, run);
    loadLogs();
    panel.append(h("div", { class: "stack" },
      card(t("log.stages_label"), t("log.stages"), stagesSlot),
      run.argv && run.argv.length ? card(t("log.argv_label"), t("log.argv"), h("pre", { class: "log", tabindex: "0" }, run.argv.join(" "))) : null,
      card(t("log.progress_label"), t("log.progress"), progressLog),
      card(t("log.pipeline_label"), t("log.pipeline"), pipelineLog),
      card(t("log.run_label"), t("log.run"), runLog)));
    return (p, r) => { drawStages(p, r); loadLogs(); };
  }

  // ---------------------------------------------------------------- environment
  async function viewEnv(main, seq) {
    const [env, configs, jobs] = await Promise.all([loadEnv(true), loadConfigs(true), api("GET", "/api/jobs")]);
    if (seq !== renderSeq) return;
    const jobSlot = h("div");
    const running = (jobs.jobs || []).find((j) => j.status === "running");
    let watching = running ? running.id : (jobs.jobs || [])[0] ? jobs.jobs[0].id : null;

    async function drawJob() {
      if (!watching) { fill(jobSlot, h("p", { class: "muted small" }, t("env.job.none"))); return; }
      try {
        const data = await api("GET", "/api/jobs/" + enc(watching));
        if (seq !== renderSeq) return;
        const j = data.job;
        const cls = { running: "info", finished: "ok", failed: "danger", interrupted: "warn" }[j.status] || "";
        fill(jobSlot, h("div", { class: "stack" },
          h("div", { class: "row" }, chip(tCode("job.", j.kind)), chip(tCode("job_status.", j.status), cls), h("span", { class: "small muted" }, fmtTime(j.started_at, true)),
            j.exit_code !== null && j.exit_code !== undefined ? chip(t("env.job.exit", { code: j.exit_code })) : null),
          h("pre", { class: "log", tabindex: "0" }, j.argv.join(" ")), h("pre", { class: "log", tabindex: "0" }, j.log_tail || t("log.empty"))));
        if (j.status !== "running" && running && running.id === j.id) { state.env = null; render(false); }
      } catch (e) { fill(jobSlot, emptyState(tCode("error.", e.code), "alert")); }
    }
    async function startJob(body, confirmKey) {
      if (confirmKey && !window.confirm(t(confirmKey))) return;
      try {
        const data = await api("POST", "/api/jobs", body);
        watching = data.job.id;
        showOk(t("env.job.started", { job: tCode("job.", body.kind) }));
        render(false);
      } catch (e) { showError(e); }
    }
    if (running) every(RUN_POLL_MS, () => { if (seq === renderSeq) drawJob(); });

    const rows = env.tools.rows;
    const statusCls = { ok: "ok", missing: "warn", version_mismatch: "danger", unverified: "warn" };
    const scanners = rows.filter((r) => r.role !== "verifier");
    const missing = rows.filter((r) => r.status !== "ok").map((r) => r.name);
    const actions = env.actions || {};
    const busy = Boolean(running);
    const toolTable = tableWrap(t("env.tools.title"), [t("col.tool"), t("col.role"), t("col.locked"), t("col.installed"), t("col.verify"), t("col.dimensions"), t("col.status")],
      rows.map((r) => h("tr", null,
        h("td", null, h("div", { class: "t-title" }, r.name), h("div", { class: "t-sub" }, r.kind + (r.license ? " · " + r.license : ""))),
        h("td", null, tCode("tool_role.", r.role)),
        h("td", null, mono(r.locked_version)),
        h("td", null, mono(r.installed_version || "—")),
        h("td", null, h("div", null, r.verify_method), r.signature_verified === null ? null : h("div", { class: "t-sub" }, t(r.signature_verified ? "env.sig_ok" : "env.sig_no"))),
        h("td", null, (r.dimensions || []).map(dimLabel).join("、") || "—"),
        h("td", null, chip(tCode("tool_status.", r.status), statusCls[r.status] || "")))));
    const lockNote = env.tools.lock_matches_manifest === false ? h("div", { class: "gap-item" }, icon("alert", "sm"), h("span", null, t("env.lock_changed"))) : null;
    const platformNote = env.tools.locked_platform && env.tools.locked_platform.os && !String(env.tools.host_platform.os).startsWith(env.tools.locked_platform.os)
      ? h("div", { class: "gap-item" }, icon("alert", "sm"), h("span", null, t("env.platform", { os: env.tools.host_platform.os, locked: env.tools.locked_platform.os }))) : null;

    const wsCard = card(t("env.ws.label"), t("env.ws.title"), h("div", { class: "stack" }, kv([
      [t("env.ws.workspace"), mono(env.workspace)],
      [t("env.ws.out"), mono(env.out_dir)],
      [t("env.ws.tools"), mono(env.tools.tools_dir)],
      [t("env.ws.trivy"), mono(env.trivy_db.cache_dir)],
      [t("env.ws.python"), mono(env.python.version + " · " + env.python.executable)],
      [t("env.ws.platform"), mono(env.platform)],
      [t("env.ws.node"), env.node.path ? h("span", { class: "row" }, mono(env.node.version + " · " + env.node.path), env.node.ok ? null : chip(t("env.node_old"), "warn"))
        : chip(t("env.node_missing"), "warn")],
      [t("env.ws.version"), mono(env.version)],
    ]), h("div", null, h("div", { class: "card-label", style: { "margin-bottom": "8px" } }, t("env.ws.vars")),
      h("div", { class: "row" }, Object.entries(env.env_vars).map(([k, v]) => chip(k, v ? "ok" : "", t(v ? "env.var_set" : "env.var_unset")))))));

    const toolsCard = card(t("env.tools.label"), t("env.tools.title"), h("div", { class: "stack" },
      h("div", { class: "row" }, chip(t("env.tools.summary", { ok: scanners.filter((r) => r.status === "ok").length, total: scanners.length }),
        scanners.every((r) => r.status === "ok") ? "ok" : "warn"), h("span", { class: "spacer" }),
        btn(t("env.install_missing"), { small: true, icon: "download", disabled: busy || !actions.install_tools || !missing.length,
          onClick: () => startJob({ kind: "install_tools", only: missing }, "env.confirm_install") }),
        btn(t("env.install_all"), { small: true, kind: "primary", icon: "download", disabled: busy || !actions.install_tools,
          onClick: () => startJob({ kind: "install_tools" }, "env.confirm_install") })),
      lockNote, platformNote, toolTable, h("p", { class: "note" }, t("env.tools.note"))));

    const trivyCard = card(t("env.trivy.label"), t("env.trivy.title"), h("div", { class: "stack" },
      h("div", { class: "row" }, env.trivy_db.ok ? chip(t("env.trivy.ok"), "ok") : chip(t(env.trivy_db.present ? "env.trivy.bad" : "env.trivy.missing"), "warn"),
        chip(t("env.trivy.limit", { h: env.trivy_db.max_age_hours })), h("span", { class: "spacer" }),
        btn(t("env.trivy.check"), { small: true, icon: "search", disabled: busy || !actions.trivy_db_status, onClick: () => startJob({ kind: "trivy_db_status" }) }),
        btn(t("env.trivy.download"), { small: true, kind: "primary", icon: "database", disabled: busy || !actions.trivy_db_download,
          onClick: () => startJob({ kind: "trivy_db_download" }, "env.confirm_trivy") })),
      h("pre", { class: "log", tabindex: "0" }, (env.trivy_db.lines || []).join("\n"))));

    const jobCard = card(t("env.job.label"), t("env.job.title"), jobSlot);

    const cfgCards = configs.map((c) => {
      const passed = c.policies.filter((p) => p.passed).length;
      const body = c.structure_ok ? h("div", { class: "stack", style: { "margin-top": "14px" } },
        tableWrap(t("env.cfg.models"), [t("col.model_name"), t("col.family"), t("col.provider"), t("col.model"), t("col.residency"), t("col.credential")],
          c.models.map((m) => h("tr", null, h("td", null, mono(m.name)), h("td", null, m.family), h("td", null, tCode("provider.", m.provider)),
            h("td", null, mono(m.model), m.endpoint_host ? h("div", { class: "t-sub" }, m.endpoint_host) : null), h("td", null, tCode("residency.", m.data_residency)),
            h("td", null, m.credential.env ? chip(m.credential.env + " · " + t(m.credential.present ? "cred.present" : "cred.missing"), m.credential.present ? "ok" : "warn")
              : chip(t("cred.none")))))),
        h("div", { class: "row" }, ROLES.map((r) => {
          const v = c.roles[r];
          return chip(tCode("role.", r) + ": " + (Array.isArray(v) ? v.join(", ") : v || "—"));
        })),
        tableWrap(t("env.cfg.policies"), [t("col.policy"), t("col.status"), t("col.reason")], c.policies.map((p) => h("tr", null,
          h("td", null, h("div", { class: "t-title" }, p.id + " " + tCode("policy.", p.id)), h("div", { class: "t-sub" }, p.name)),
          h("td", null, chip(t(p.passed ? "policy.pass" : "policy.fail"), p.passed ? "ok" : "danger")), h("td", null, h("span", { class: "small" }, p.reason))))),
        h("div", { class: "row" }, h("span", { class: "spacer" }), btn(t("env.cfg.check"), { small: true, icon: "terminal", disabled: busy,
          onClick: () => startJob({ kind: "check_config", config: c.path }) })))
        : h("div", { class: "gap-item", style: { "margin-top": "12px" } }, icon("alert", "sm"), h("span", null, t("env.cfg.invalid"), " ", mono(c.error)));
      return h("details", { class: "card flat" }, h("summary", null, h("span", { class: "row", style: { display: "inline-flex" } }, mono(c.path),
        chip(c.provider_mode ? tCode("mode.", c.provider_mode) : t("env.cfg.invalid_short"), c.provider_mode === "live" ? "ok" : c.provider_mode === "mock" ? "info" : "warn"),
        c.structure_ok ? chip(t("new.policies", { passed, total: c.policies.length }), c.loadable ? "ok" : "danger") : null)), body);
    });

    const settings = (state.session && state.session.settings) || {};
    const langSel = h("select", { id: "s-lang" }, LANGS.map((l) => h("option", { value: l, selected: l === lang }, t("lang." + l))));
    const provSel = h("select", { id: "s-prov" }, ["mock", "live"].map((p) => h("option", { value: p, selected: (settings.default_provider || "mock") === p }, tCode("mode.", p))));
    const cfgSel = h("select", { id: "s-cfg" }, h("option", { value: "" }, t("settings.auto")),
      configs.filter((c) => c.structure_ok).map((c) => h("option", { value: c.path, selected: settings.default_config === c.path }, c.path)));
    const save = btn(t("settings.save"), { kind: "primary", small: true, onClick: async () => {
      try {
        const res = await api("PUT", "/api/settings", { language: langSel.value, default_provider: provSel.value, default_config: cfgSel.value });
        if (state.session) state.session.settings = res;
        setLang(res.language);
        showOk(t("settings.saved"));
      } catch (e) { showError(e); }
    } });
    const settingsCard = card(t("settings.label"), t("settings.title"), h("div", { class: "grid three" },
      h("div", { class: "field" }, h("label", { for: "s-lang" }, t("settings.language")), langSel),
      h("div", { class: "field" }, h("label", { for: "s-prov" }, t("settings.provider")), provSel),
      h("div", { class: "field" }, h("label", { for: "s-cfg" }, t("settings.config")), cfgSel)), { right: save });

    fill(main, h("div", { class: "stack" },
      pageHead(t("env.eyebrow"), t("env.heading"), t("env.sub")),
      h("div", { class: "grid halves" }, wsCard, h("div", { class: "stack" }, trivyCard, jobCard)),
      toolsCard,
      card(t("env.cfg.label"), t("env.cfg.title"), h("div", { class: "stack" }, h("p", { class: "small muted" }, t("env.cfg.note")), ...cfgCards)),
      settingsCard));
    drawJob();
  }

  // ---------------------------------------------------------------- boot
  function setLang(next) {
    if (!LANGS.includes(next) || next === lang) return;
    lang = next;
    store.set("mara.lang", lang);
    render(false);
  }

  async function startSession() {
    if (!TOKEN && !DEMO) { showLoggedOut(); return; }
    try {
      state.session = await api("GET", "/api/session");
      if (!store.get("mara.lang") && state.session.settings && LANGS.includes(state.session.settings.language)) lang = state.session.settings.language;
    } catch (e) {
      if (e.code !== "unauthenticated") showError(e);
      if (loggedOut) return;
    }
    await render(false);
  }

  async function boot() {
    applyStatic();
    document.getElementById("lang-toggle").addEventListener("click", () => setLang(lang === "zh-TW" ? "en" : "zh-TW"));
    document.getElementById("refresh").addEventListener("click", () => { state.env = null; state.configs = null; refreshRuns().then(() => render(false)).catch(showError); });
    document.getElementById("logout").addEventListener("click", () => {
      // this browser forgets the key; the server and any running review go on, and the printed URL still opens it
      store.remove(TOKEN_KEY);
      TOKEN = "";
      showLoggedOut();
    });
    window.addEventListener("hashchange", () => {
      if (takeToken()) { loggedOut = false; startSession(); return; }
      render(true);
    });
    if (DEMO) {
      // nothing to sign out of and nothing to poll: the data is a snapshot, and every change is refused
      document.getElementById("logout").remove();  // .btn would override the hidden attribute
      const area = document.getElementById("banner-area");
      area.before(h("aside", { class: "banner info demo", "aria-label": t("top.demo") }, icon("info"),
        h("div", null, h("strong", null, t("demo.title")), h("div", { class: "detail" }, t("demo.body", { when: fmtTime(DEMO.captured_at, true) })))));
      await startSession();
      return;
    }
    takeToken();
    await startSession();
    const pollList = async () => {
      if (!loggedOut) {
        try { await refreshRuns(); } catch (e) { /* the service dot shows it */ }
      }
      setTimeout(pollList, state.busy ? LIST_POLL_MS : IDLE_LIST_POLL_MS);
    };
    setTimeout(pollList, LIST_POLL_MS);
    setInterval(() => { if (!loggedOut) api("GET", "/api/health").catch(() => setService(false)); }, HEALTH_MS);
  }

  boot();
})();
