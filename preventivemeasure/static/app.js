"use strict";
// PreventiveMeasure: SPA sin dependencias. Todo el texto externo entra por textContent (nunca innerHTML).

const $ = (sel, root = document) => root.querySelector(sel);
const PRIO = { critical: "Crítica", high: "Alta", medium: "Media", low: "Baja" };
const STATUS = { open: "Abierto", acknowledged: "Reconocido", ignored: "Ignorado", resolved: "Resuelto" };
const CONF = { confirmed: "Confirmada", probable: "Probable (CNA)", possible: "Posible (sin analizar)" };
const KIND = { path: "Proyecto", url: "Web", system: "Equipo local", upload: "Fichero", agent: "Agente", manual: "Manual" };
const CHANNELS = {
  email: { title: "Email (SMTP)", fields: { host: "Servidor SMTP", port: "Puerto", security: "Seguridad (starttls / ssl / none)", user: "Usuario", password: "Contraseña", sender: "Remitente", to: "Destinatarios (coma)" } },
  telegram: { title: "Telegram", fields: { bot_token: "Token del bot (@BotFather)", chat_id: "Chat ID" } },
  whatsapp_twilio: { title: "WhatsApp (Twilio)", fields: { account_sid: "Account SID", auth_token: "Auth token", from: "Número origen (+34...)", to: "Número destino (+34...)" } },
  whatsapp_callmebot: { title: "WhatsApp (CallMeBot, gratis)", fields: { phone: "Tu número (+34...)", apikey: "API key de CallMeBot" } },
  discord: { title: "Discord", fields: { webhook_url: "Webhook URL" } },
  slack: { title: "Slack", fields: { webhook_url: "Incoming webhook URL" } },
  teams: { title: "Microsoft Teams", fields: { webhook_url: "Webhook URL" } },
  ntfy: { title: "ntfy (push al móvil)", fields: { server: "Servidor", topic: "Tema", token: "Token (opcional)" } },
  webhook: { title: "Webhook genérico (JSON + HMAC)", fields: { url: "URL", secret: "Secreto HMAC (opcional)" } },
};
const SECRET = new Set(["password", "bot_token", "auth_token", "apikey", "token", "secret", "webhook_url", "url", "topic"]);

let token = "";
try { token = sessionStorage.getItem("pm_token") || ""; } catch { /* almacenamiento bloqueado */ }
let status = null;

// --- DOM ------------------------------------------------------------------
function h(tag, attrs = {}, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (k === "href") el.setAttribute("href", safeHref(v));
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const kid of kids.flat()) {
    if (kid === null || kid === undefined || kid === false) continue;
    el.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  }
  return el;
}
function safeHref(u) {
  if (typeof u === "string" && (u.startsWith("#") || u.startsWith("/"))) return u;
  try { const p = new URL(u); return ["http:", "https:"].includes(p.protocol) ? p.href : "#"; } catch { return "#"; }
}
const ext = (url, text) => h("a", { href: url, target: "_blank", rel: "noopener noreferrer" }, text || url);
const sev = (p) => h("span", { class: `sev ${p || "low"}` }, PRIO[p] || p || "-");
const fmtDate = (ts) => ts ? new Date(ts * 1000).toLocaleString("es-ES", { dateStyle: "short", timeStyle: "short" }) : "nunca";
function ago(ts) {
  if (!ts) return "nunca";
  const s = Math.round(Date.now() / 1000 - ts);
  if (s < 60) return "hace un momento";
  if (s < 3600) return `hace ${Math.round(s / 60)} min`;
  if (s < 86400) return `hace ${Math.round(s / 3600)} h`;
  return `hace ${Math.round(s / 86400)} d`;
}
function toast(msg, bad = false) {
  const t = h("div", { class: `toast${bad ? " bad" : ""}`, role: bad ? "alert" : "status" }, msg);
  $("#toasts").append(t);
  setTimeout(() => t.remove(), 5000);
}
const empty = (title, text) => h("div", { class: "empty" }, h("b", {}, title), text);

// --- API ------------------------------------------------------------------
async function api(path, opts = {}) {
  const init = { method: opts.method || "GET", headers: { Authorization: `Bearer ${token}` } };
  if (opts.body !== undefined) {
    if (opts.raw) init.body = opts.body;
    else { init.body = JSON.stringify(opts.body); init.headers["Content-Type"] = "application/json"; }
  }
  const r = await fetch(path, init);
  if (r.status === 401) { showLogin("Token no válido o caducado"); throw new Error("401"); }
  if (!r.ok) {
    let detail = r.statusText;
    try { const j = await r.json(); detail = typeof j.detail === "string" ? j.detail : JSON.stringify(j.detail); } catch { /* sin cuerpo */ }
    throw new Error(detail);
  }
  return opts.blob ? r.blob() : r.json();
}
async function act(fn, ok) {
  try { await fn(); if (ok) toast(ok); return true; } catch (e) { if (e.message !== "401") toast(e.message, true); return false; }
}

// --- Sesión ---------------------------------------------------------------
function showLogin(msg = "") {
  $("#app").hidden = true; $("#login").hidden = false;
  $("#login-error").textContent = msg; $("#login-token").focus();
}
$("#login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  token = $("#login-token").value.trim();
  try { sessionStorage.setItem("pm_token", token); } catch { /* sin persistencia */ }
  start();
});
$("#logout").addEventListener("click", () => { token = ""; try { sessionStorage.removeItem("pm_token"); } catch { /* */ } showLogin(); });
$("#theme").addEventListener("click", () => {
  const cur = document.documentElement.dataset.theme || (matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark");
  const next = cur === "light" ? "dark" : "light";
  document.documentElement.dataset.theme = next;
  try { localStorage.setItem("pm_theme", next); } catch { /* */ }
});
try { const t = localStorage.getItem("pm_theme"); if (t) document.documentElement.dataset.theme = t; } catch { /* */ }

// --- Estado del ciclo -------------------------------------------------------
async function refreshStatus() {
  try { status = await api("/api/status"); } catch { return; }
  const c = $("#cycle");
  c.replaceChildren();
  if (status.running) {
    c.append(h("span", { class: "dot run" }), h("span", {}, `Comprobando: ${status.phase || "..."}`));
  } else {
    const next = status.next_run ? Math.max(0, Math.round((status.next_run - Date.now() / 1000) / 60)) : null;
    c.append(h("span", { class: `dot${status.last_error ? " err" : ""}` }),
      h("span", {}, `Última comprobación ${ago(status.last_run)}` + (next !== null ? ` · próxima en ${next} min` : "") +
        ` · cada ${status.interval_minutes} min` + (status.last_error ? ` · error: ${status.last_error}` : "")));
  }
  $("#scan-now").disabled = status.running;
  const urgent = (status.open.critical || 0) + (status.open.high || 0);
  $("#nav-count").textContent = urgent ? String(urgent) : "";
  document.title = urgent ? `(${urgent}) PreventiveMeasure` : "PreventiveMeasure";
}
$("#scan-now").addEventListener("click", () => act(() => api("/api/scan", { method: "POST" }), "Comprobación iniciada").then(refreshStatus));

// --- Router ---------------------------------------------------------------
const VIEWS = { panel: viewPanel, activos: viewTargets, hallazgos: viewFindings, noticias: viewNews, ajustes: viewSettings, registro: viewLog };
async function route() {
  const [name, arg] = (location.hash.replace(/^#\//, "").split("?")[0] || "panel").split("/");
  const view = VIEWS[name] ? name : "panel";
  document.querySelectorAll("nav a").forEach((a) => {
    if (a.dataset.view === view) a.setAttribute("aria-current", "page"); else a.removeAttribute("aria-current");
  });
  const main = $("#main");
  main.replaceChildren(h("p", { class: "muted" }, "Cargando..."));
  try { main.replaceChildren(await VIEWS[view](arg)); } catch (e) { if (e.message !== "401") main.replaceChildren(empty("No se pudo cargar", e.message)); }
}
window.addEventListener("hashchange", route);
const rerender = () => route();
const head = (title, sub, ...actions) => h("div", { class: "page-head" }, h("div", {}, h("h1", {}, title), sub ? h("p", { class: "muted" }, sub) : null), h("div", { class: "btns" }, ...actions));

// --- Panel ----------------------------------------------------------------
async function viewPanel() {
  await refreshStatus();
  const s = status;
  const top = await api("/api/findings?status=open&limit=8");
  const notices = [];
  if (!s.targets) notices.push(h("div", { class: "notice" }, h("span", {}, "Aún no monitorizas nada. Añade tu web, tu proyecto o este equipo."), h("a", { class: "btn primary small", href: "#/activos" }, "Añadir activo")));
  if (!s.channels.length) notices.push(h("div", { class: "notice bad" }, h("span", {}, "No hay ningún canal de aviso activo: los hallazgos solo se verán aquí."), h("a", { class: "btn small", href: "#/ajustes" }, "Configurar avisos")));
  if (s.nvd_pending && !s.nvd_key) notices.push(h("div", { class: "notice" }, h("span", {}, `${s.nvd_pending} productos pendientes de su primera consulta en NVD (25 por ciclo sin API key). Una API key gratuita lo acelera x10.`), h("a", { class: "btn small", href: "#/ajustes" }, "Añadir API key")));
  const kpi = (cls, n, label) => h("div", { class: `kpi ${cls}` }, h("b", {}, String(n || 0)), h("span", {}, label));
  const max = Math.max(1, ...s.trend.map((t) => t.n));
  const days = [...Array(30)].map((_, i) => { const d = new Date(Date.now() - (29 - i) * 864e5); return d.toISOString().slice(0, 10); });
  const byDay = Object.fromEntries(s.trend.map((t) => [t.day, t.n]));
  const bars = days.map((d) => { const n = byDay[d] || 0; const el = h("div", { title: `${d}: ${n} nuevos` }); el.style.height = `${(n / max) * 100}%`; return el; });
  return h("div", {},
    head("Panel", "Tu exposición actual a vulnerabilidades conocidas y noticias de seguridad."),
    ...notices,
    h("div", { class: "kpis" },
      kpi("critical", s.open.critical, "Críticas"), kpi("high", s.open.high, "Altas"),
      kpi("medium", s.open.medium, "Medias"), kpi("low", s.open.low, "Bajas"),
      kpi("kev", s.kev_open, "Explotadas activamente (KEV)"), kpi("", s.targets, "Activos"), kpi("", s.components, "Componentes")),
    h("div", { class: "grid two" },
      h("section", { class: "card" }, h("h3", {}, "Más urgente"),
        top.length ? findingsTable(top, true) : empty("Sin hallazgos abiertos", "Nada de lo que tienes instalado aparece en las bases de vulnerabilidades.")),
      h("section", { class: "card" }, h("h3", {}, "Nuevos hallazgos (30 días)"), h("div", { class: "trend", role: "img", "aria-label": "Hallazgos nuevos por día" }, bars),
        h("div", { class: "trend-axis" }, h("span", {}, days[0]), h("span", {}, "hoy")))));
}

// --- Activos --------------------------------------------------------------
async function viewTargets(arg) {
  if (arg) return viewComponents(Number(arg));
  const targets = await api("/api/targets");
  const settings = await api("/api/settings");
  return h("div", {},
    head("Activos", "Todo lo que PreventiveMeasure vigila: webs, proyectos, equipos, apps móviles y servidores remotos."),
    h("section", { class: "card" }, h("h2", {}, "Añadir activo"), addTargetForm(settings.agent_token)),
    h("h2", { class: "spaced" }, `Monitorizados (${targets.length})`),
    targets.length ? h("div", { class: "targets" }, targets.map(targetCard)) : empty("Sin activos", "Añade el primero con el formulario de arriba."));
}

function addTargetForm(agentToken) {
  const body = h("div");
  const tabs = {
    url: ["Web / app web", () => [
      field("Nombre", "t-name", "Mi web"), field("URL", "t-loc", "https://ejemplo.com", "url"),
      h("p", { class: "muted" }, "Detecta servidor, lenguaje, CMS, plugins y librerías JavaScript por cabeceras, HTML y scripts."),
      submit("url")]],
    path: ["Proyecto / código", () => [
      field("Nombre", "t-name", "Backend API"), field("Ruta en el servidor", "t-loc", "C:\\proyectos\\mi-app o /srv/app"),
      h("p", { class: "muted" }, "Lee lockfiles y manifiestos: npm, yarn, pnpm, pip, Poetry, uv, Composer, Bundler, Go, Cargo, Maven, Gradle, NuGet, Pub (Flutter), CocoaPods, SwiftPM, Hex, Dockerfile, SBOM CycloneDX/SPDX, APK e IPA."),
      submit("path")]],
    system: ["Este equipo", () => [
      field("Nombre", "t-name", "Servidor principal"),
      h("p", { class: "muted" }, "Inventaria el sistema donde corre PreventiveMeasure: programas instalados (Windows), paquetes dpkg/rpm/apk/pacman/snap (Linux), aplicaciones y Homebrew (macOS), kernel y runtimes."),
      submit("system")]],
    upload: ["Subir fichero", () => {
      const file = h("input", { id: "t-file", type: "file", accept: ".json,.lock,.txt,.xml,.toml,.yaml,.yml,.apk,.aab,.ipa,.gradle,.kts,.csproj,.resolved,Dockerfile" });
      return [field("Nombre", "t-name", "App Android v2.3"), h("label", { for: "t-file" }, "Fichero (lockfile, SBOM, APK, AAB o IPA)"), file,
        h("div", { class: "btns spaced" }, h("button", { class: "btn primary", type: "button", onclick: async (e) => {
          const f = file.files[0]; if (!f) return toast("Elige un fichero", true);
          e.target.disabled = true;
          const name = $("#t-name").value.trim() || f.name;
          await act(() => api(`/api/targets/upload?name=${encodeURIComponent(name)}&filename=${encodeURIComponent(f.name)}`, { method: "POST", body: f, raw: true }), "Fichero subido; analizando...");
          rerender();
        } }, "Subir y analizar"))];
    }],
    agent: ["Agente remoto", () => {
      const server = location.origin;
      return [h("p", {}, "Instala el agente en cualquier servidor, Mac o PC (solo necesita Python 3.11+, sin dependencias) y enviará su inventario cada 30 minutos."),
        h("label", {}, "Linux / macOS"), h("pre", { class: "cmd" }, `PM_AGENT_TOKEN=${agentToken} python3 -m preventivemeasure agent --server ${server} --every 30 --path /srv/mi-app`),
        h("label", {}, "Windows (PowerShell)"), h("pre", { class: "cmd" }, `$env:PM_AGENT_TOKEN="${agentToken}"; python -m preventivemeasure agent --server ${server} --every 30 --path C:\\apps\\mi-app`),
        h("p", { class: "muted" }, "El token va en variable de entorno para que no aparezca en la lista de procesos. Solo permite enviar inventario y puedes rotarlo en Ajustes. Para agentes fuera de esta máquina, publica el panel detrás de un proxy con TLS (https)."),
        location.protocol === "http:" && !["localhost", "127.0.0.1", "[::1]"].includes(location.hostname)
          ? h("p", { class: "error" }, "Este panel se sirve sin https: el token del agente viajaría en claro.") : null];
    }],
    manual: ["Manual", () => [
      field("Nombre", "t-name", "Router de la oficina"),
      h("p", { class: "muted" }, "Crea un activo vacío y añade componentes a mano (p. ej. firmware de un router, un NAS o una app sin manifiesto)."),
      submit("manual")]],
  };
  const bar = h("div", { class: "tabs", role: "tablist" });
  const select = (key) => {
    bar.querySelectorAll("button").forEach((b) => b.setAttribute("aria-selected", String(b.dataset.k === key)));
    body.replaceChildren(...tabs[key][1]());
  };
  for (const [k, [label]] of Object.entries(tabs)) bar.append(h("button", { type: "button", role: "tab", "data-k": k, onclick: () => select(k) }, label));
  select("url");
  return h("div", {}, bar, body);
}
function field(label, id, placeholder, type = "text", value = "") {
  return h("div", {}, h("label", { for: id }, label), h("input", { id, type, placeholder, value, spellcheck: "false", autocomplete: "off" }));
}
function submit(kind) {
  return h("div", { class: "btns spaced" }, h("button", { class: "btn primary", type: "button", onclick: async (e) => {
    const name = $("#t-name").value.trim(), loc = $("#t-loc") ? $("#t-loc").value.trim() : "";
    if (!name) return toast("Pon un nombre al activo", true);
    e.target.disabled = true;
    const ok = await act(() => api("/api/targets", { method: "POST", body: { name, kind, location: loc } }), kind === "manual" ? "Activo creado" : "Activo añadido; analizando...");
    if (ok) rerender(); else e.target.disabled = false;
  } }, "Añadir y analizar"));
}
function targetCard(t) {
  const worst = ["low", "medium", "high", "critical"][t.worst ?? -1];
  return h("article", { class: `card target${t.enabled ? "" : " off"}` },
    h("div", { class: "target-head" }, h("div", {}, h("b", {}, t.name), h("div", { class: "loc" }, t.location || "-")),
      h("div", { class: "btns" }, h("span", { class: "tag" }, KIND[t.kind] || t.kind), t.open_findings ? sev(worst) : h("span", { class: "sev ok" }, "Sin hallazgos"))),
    h("div", { class: "stats" }, h("span", {}, h("b", {}, String(t.components)), " componentes"),
      h("span", {}, h("b", {}, String(t.open_findings)), " hallazgos"), h("span", {}, "Analizado ", ago(t.last_scan))),
    t.last_error ? h("p", { class: "error trunc", title: t.last_error }, t.last_error) : null,
    h("div", { class: "btns" },
      h("button", { class: "btn small", type: "button", onclick: () => act(() => api(`/api/targets/${t.id}/scan`, { method: "POST" }), `Recomprobando ${t.name}`) }, "Recomprobar"),
      h("a", { class: "btn small", href: `#/activos/${t.id}` }, "Componentes"),
      h("a", { class: "btn small ghost", href: `#/hallazgos?target=${t.id}` }, "Hallazgos"),
      h("button", { class: "btn small ghost", type: "button", onclick: () => act(() => api(`/api/targets/${t.id}`, { method: "PATCH", body: { enabled: !t.enabled } })).then(rerender) }, t.enabled ? "Pausar" : "Reanudar"),
      h("button", { class: "btn small danger", type: "button", onclick: () => {
        if (confirm(`¿Eliminar "${t.name}" y todo su historial de hallazgos? No se puede deshacer.`)) act(() => api(`/api/targets/${t.id}`, { method: "DELETE" }), "Activo eliminado").then(rerender);
      } }, "Eliminar")));
}

async function viewComponents(tid) {
  const [targets, comps] = await Promise.all([api("/api/targets"), api(`/api/targets/${tid}/components`)]);
  const t = targets.find((x) => x.id === tid);
  if (!t) return empty("Activo no encontrado", "");
  const q = h("input", { type: "search", placeholder: "Filtrar componentes...", "aria-label": "Filtrar componentes" });
  const tbody = h("tbody");
  const draw = () => {
    const term = q.value.toLowerCase();
    tbody.replaceChildren(...comps.filter((c) => !term || `${c.name} ${c.ecosystem} ${c.product || ""}`.toLowerCase().includes(term)).slice(0, 1500).map((c) =>
      h("tr", {}, h("td", {}, h("span", { class: "tag" }, c.ecosystem)), h("td", {}, h("b", {}, c.name), c.product && c.ecosystem === "CPE" ? h("div", { class: "muted mono" }, `${c.vendor || "*"}:${c.product}`) : null),
        h("td", { class: "mono" }, c.version || "?"), h("td", { class: "num" }, c.open_findings ? String(c.open_findings) : "-"),
        h("td", { class: "trunc muted", title: c.source }, c.source),
        h("td", {}, h("div", { class: "btns" },
          h("button", { class: "btn small ghost", type: "button", onclick: () => cpeEdit(c) }, "CPE"),
          h("button", { class: "btn small ghost", type: "button", onclick: () => act(() => api(`/api/components/${c.id}`, { method: "PATCH", body: { ignored: !c.ignored } }), c.ignored ? "Vuelve a vigilarse" : "Componente ignorado").then(rerender) }, c.ignored ? "Vigilar" : "Ignorar"),
          c.manual ? h("button", { class: "btn small danger", type: "button", onclick: () => act(() => api(`/api/components/${c.id}`, { method: "DELETE" }), "Eliminado").then(rerender) }, "Quitar") : null)))));
  };
  q.addEventListener("input", draw);
  draw();
  const eco = h("select", { id: "c-eco" }, ["CPE", "npm", "PyPI", "Packagist", "Maven", "NuGet", "Go", "crates.io", "RubyGems", "Pub", "Hex", "SwiftURL"].map((e) => h("option", { value: e }, e === "CPE" ? "Software genérico (NVD/CPE)" : e)));
  return h("div", {},
    head(t.name, `${comps.length} componentes detectados · ${KIND[t.kind]} · ${t.location}`, h("a", { class: "btn", href: "#/activos" }, "Volver"),
      h("button", { class: "btn primary", type: "button", onclick: () => act(() => api(`/api/targets/${tid}/scan`, { method: "POST" }), "Recomprobando") }, "Recomprobar")),
    h("details", { class: "card spaced-b" }, h("summary", {}, "Añadir componente a mano"),
      h("div", { class: "row" }, h("div", {}, h("label", { for: "c-eco" }, "Tipo"), eco), field("Nombre / producto", "c-name", "nginx, openssl, lodash..."),
        field("Versión", "c-ver", "1.24.0"), field("Fabricante CPE (opcional)", "c-vendor", "f5")),
      h("div", { class: "btns spaced" }, h("button", { class: "btn primary", type: "button", onclick: async () => {
        const body = { ecosystem: eco.value, name: $("#c-name").value.trim(), version: $("#c-ver").value.trim(), vendor: $("#c-vendor").value.trim() || null };
        if (!body.name) return toast("Falta el nombre", true);
        if (await act(() => api(`/api/targets/${tid}/components`, { method: "POST", body }), "Componente añadido")) rerender();
      } }, "Añadir"))),
    h("div", { class: "filters" }, h("div", {}, q)),
    comps.length ? h("div", { class: "table-wrap" }, h("table", {}, h("thead", {}, h("tr", {}, ["Tipo", "Componente", "Versión", "Hallazgos", "Origen", ""].map((x) => h("th", {}, x)))), tbody))
      : empty("Sin componentes todavía", "Si acabas de añadirlo, el análisis está en marcha. Revisa el error del activo si persiste."));
}
function cpeEdit(c) {
  openDrawer(h("div", {},
    h("h2", { id: "drawer-title" }, `Identificación CPE de ${c.name}`),
    h("p", { class: "muted" }, "Si el nombre detectado no coincide con el de NVD, corrígelo. Busca el producto en nvd.nist.gov/products/cpe. La corrección se recuerda aunque cambie la versión."),
    field("Fabricante (vendor)", "cpe-v", "p. ej. f5", "text", c.vendor || ""), field("Producto", "cpe-p", "p. ej. nginx", "text", c.product || ""),
    h("div", { class: "btns spaced" }, h("button", { class: "btn primary", type: "button", onclick: async () => {
      const product = $("#cpe-p").value.trim(); if (!product) return toast("Falta el producto", true);
      if (await act(() => api(`/api/components/${c.id}`, { method: "PATCH", body: { vendor: $("#cpe-v").value.trim() || null, product } }), "Guardado; recomprobando")) { closeDrawer(); rerender(); }
    } }, "Guardar y recomprobar"))));
}

// --- Hallazgos ------------------------------------------------------------
function findingsTable(rows, compact = false) {
  const cols = compact ? ["Prioridad", "Vulnerabilidad", "Componente", "Activo"] : ["Prioridad", "Vulnerabilidad", "CVSS", "Componente", "Corregida en", "Activo", "Confianza", "Detectada"];
  return h("div", { class: "table-wrap" }, h("table", {},
    h("thead", {}, h("tr", {}, cols.map((c) => h("th", {}, c)))),
    h("tbody", {}, rows.map((r) => h("tr", { class: "click", tabindex: "0", onclick: () => openFinding(r.id), onkeydown: (e) => { if (e.key === "Enter") openFinding(r.id); } },
      h("td", {}, sev(r.priority)),
      h("td", {}, h("div", { class: "btns" }, h("b", { class: "mono" }, r.vuln_id), r.kev ? h("span", { class: "tag kev", title: "Explotación activa confirmada por CISA" }, "KEV") : null),
        h("div", { class: "trunc muted", title: r.summary }, r.summary)),
      compact ? null : h("td", { class: "num" }, r.cvss != null ? r.cvss.toFixed(1) : "-"),
      h("td", {}, h("b", {}, r.name), " ", h("span", { class: "mono muted" }, r.version || "?")),
      compact ? null : h("td", { class: "mono" }, r.fixed_version || "-"),
      h("td", {}, r.target),
      compact ? null : h("td", {}, h("span", { class: "tag" }, CONF[r.confidence] || r.confidence)),
      compact ? null : h("td", { class: "muted" }, ago(r.first_seen)))))));
}

async function viewFindings() {
  const params = new URLSearchParams(location.hash.split("?")[1] || "");
  const targets = await api("/api/targets");
  const st = h("select", { id: "f-status" }, Object.entries({ open: "Abiertos", acknowledged: "Reconocidos", ignored: "Ignorados", resolved: "Resueltos", all: "Todos" }).map(([v, l]) => h("option", { value: v }, l)));
  const pr = h("select", { id: "f-prio" }, h("option", { value: "" }, "Todas"), Object.entries(PRIO).reverse().map(([v, l]) => h("option", { value: v }, l)));
  const tg = h("select", { id: "f-target" }, h("option", { value: "" }, "Todos"), targets.map((t) => h("option", { value: String(t.id) }, t.name)));
  const q = h("input", { id: "f-q", type: "search", placeholder: "CVE, paquete, texto..." });
  if (params.get("target")) tg.value = params.get("target");
  const out = h("div");
  let rows = [];
  const load = async () => {
    out.replaceChildren(h("p", { class: "muted" }, "Cargando..."));
    rows = await api(`/api/findings?status=${st.value}` + (tg.value ? `&target_id=${tg.value}` : ""));
    draw();
  };
  const draw = () => {
    const term = q.value.toLowerCase();
    const list = rows.filter((r) => (!pr.value || r.priority === pr.value) &&
      (!term || `${r.vuln_id} ${r.aliases.join(" ")} ${r.name} ${r.summary} ${r.target}`.toLowerCase().includes(term)));
    out.replaceChildren(list.length ? findingsTable(list.slice(0, 1000)) : empty("Nada que mostrar", st.value === "open" ? "No hay hallazgos abiertos con estos filtros." : "Prueba con otros filtros."));
  };
  st.addEventListener("change", load); tg.addEventListener("change", load); pr.addEventListener("change", draw); q.addEventListener("input", draw);
  await load();
  const exportBtn = h("button", { class: "btn", type: "button", onclick: async () => {
    const blob = await api(`/api/export/findings.csv?status=${st.value}`, { blob: true });
    const a = h("a", { download: "preventivemeasure-hallazgos.csv" }); a.href = URL.createObjectURL(blob); a.click(); URL.revokeObjectURL(a.href);
  } }, "Exportar CSV");
  return h("div", {},
    head("Hallazgos", "Vulnerabilidades que afectan a lo que tienes instalado, ordenadas por urgencia real (CVSS + explotación activa + EPSS).", exportBtn),
    h("div", { class: "filters" },
      h("div", {}, h("label", { for: "f-q" }, "Buscar"), q), h("div", {}, h("label", { for: "f-status" }, "Estado"), st),
      h("div", {}, h("label", { for: "f-prio" }, "Prioridad"), pr), h("div", {}, h("label", { for: "f-target" }, "Activo"), tg)),
    out);
}

async function openFinding(id) {
  const f = await api(`/api/findings/${id}`);
  const setStatus = (s, msg) => act(() => api(`/api/findings/${id}`, { method: "PATCH", body: { status: s } }), msg).then(() => { closeDrawer(); rerender(); });
  const note = h("textarea", { id: "f-note", rows: "3" }); note.value = f.note || "";
  const rec = f.recommendation || {};
  openDrawer(h("div", {},
    h("div", { class: "btns" }, sev(f.priority), f.kev ? h("span", { class: "tag kev" }, "Explotada activamente") : null, h("span", { class: "tag" }, STATUS[f.status]), h("span", { class: "tag" }, CONF[f.confidence])),
    h("h2", { id: "drawer-title", class: "spaced" }, f.vuln_id, f.aliases.length ? h("span", { class: "muted" }, ` · ${f.aliases.slice(0, 3).join(", ")}`) : null),
    h("p", {}, f.summary),
    h("dl", { class: "meta" },
      h("dt", {}, "Componente"), h("dd", {}, `${f.name} ${f.version || "?"} (${f.ecosystem})`),
      h("dt", {}, "Activo"), h("dd", {}, f.target),
      h("dt", {}, "Origen"), h("dd", { class: "mono" }, f.source),
      h("dt", {}, "Versión corregida"), h("dd", { class: "mono" }, f.fixed_version || "Sin parche publicado"),
      h("dt", {}, "CVSS"), h("dd", {}, f.cvss != null ? `${f.cvss} (${f.severity})` : "Sin puntuar", f.vuln_vector ? h("div", { class: "mono muted" }, f.vuln_vector) : null),
      h("dt", {}, "EPSS"), h("dd", {}, f.epss != null ? `${(f.epss * 100).toFixed(1)} % de probabilidad de explotación en 30 días` : "n/d"),
      f.kev ? h("dt", {}, "CISA KEV") : null, f.kev ? h("dd", {}, `Añadida ${f.kev.added || "?"} · límite ${f.kev.due || "?"}` + (f.kev.ransomware === "Known" ? " · usada en ransomware" : "")) : null,
      h("dt", {}, "Debilidad"), h("dd", {}, f.cwes.join(", ") || "-"),
      h("dt", {}, "Publicada"), h("dd", {}, f.vuln_published ? new Date(f.vuln_published).toLocaleDateString("es-ES") : "-"),
      h("dt", {}, "Detectada"), h("dd", {}, fmtDate(f.first_seen)), h("dt", {}, "Vista por última vez"), h("dd", {}, fmtDate(f.last_seen))),
    h("h3", {}, "Qué hacer"),
    h("ol", { class: "steps" }, (rec.steps || []).map((s) => h("li", {}, s))),
    h("div", { class: "btns" },
      h("button", { class: "btn primary", type: "button", onclick: () => act(() => api(`/api/findings/${id}/recheck`, { method: "POST" }), "Recomprobando el activo...").then(closeDrawer) }, "Recomprobar ahora"),
      f.status !== "acknowledged" ? h("button", { class: "btn", type: "button", onclick: () => setStatus("acknowledged", "Marcado como reconocido") }, "Reconocer") : null,
      f.status !== "open" ? h("button", { class: "btn", type: "button", onclick: () => setStatus("open", "Reabierto") }, "Reabrir") : null,
      f.status !== "resolved" ? h("button", { class: "btn", type: "button", onclick: () => setStatus("resolved", "Marcado como resuelto") }, "Resuelto") : null,
      f.status !== "ignored" ? h("button", { class: "btn ghost", type: "button", onclick: () => setStatus("ignored", "Ignorado (no volverá a avisar)") }, "Ignorar") : null,
      h("button", { class: "btn ghost", type: "button", onclick: async () => {
        try { const r = await api(`/api/findings/${id}/notify`, { method: "POST" }); r.results.length ? r.results.forEach((x) => toast(`${x.channel}: ${x.ok ? "enviado" : x.error}`, !x.ok)) : toast("No hay canales activos", true); } catch (e) { toast(e.message, true); }
      } }, "Reenviar aviso")),
    h("h3", { class: "spaced" }, "Nota interna"), note,
    h("div", { class: "btns spaced" }, h("button", { class: "btn small", type: "button", onclick: () => act(() => api(`/api/findings/${id}`, { method: "PATCH", body: { note: note.value } }), "Nota guardada") }, "Guardar nota")),
    f.vuln_details ? h("div", {}, h("h3", { class: "spaced" }, "Detalle técnico"), h("div", { class: "details" }, f.vuln_details)) : null,
    h("h3", { class: "spaced" }, "Referencias"),
    h("ul", { class: "links" }, h("li", {}, ext(f.link)), (f.refs || []).slice(0, 15).map((u) => h("li", {}, ext(u))))));
}

// --- Drawer ---------------------------------------------------------------
let lastFocus = null;
function openDrawer(content) {
  lastFocus = document.activeElement;
  $("#drawer-body").replaceChildren(content);
  $("#drawer").hidden = false;
  $("#drawer-close").focus();
}
function closeDrawer() { $("#drawer").hidden = true; if (lastFocus) lastFocus.focus(); }
$("#drawer-close").addEventListener("click", closeDrawer);
$("#drawer").addEventListener("click", (e) => { if (e.target.id === "drawer") closeDrawer(); });
document.addEventListener("keydown", (e) => { if (e.key === "Escape" && !$("#drawer").hidden) closeDrawer(); });

// --- Noticias -------------------------------------------------------------
async function viewNews() {
  const only = h("input", { type: "checkbox", id: "n-only", checked: true });
  const list = h("div", { class: "news" });
  const load = async () => {
    const rows = await api(`/api/news?only_matched=${only.checked}`);
    list.replaceChildren(...(rows.length ? rows.map((n) => h("article", { class: "card news-item" },
      h("div", {}, ext(n.link, n.title), h("div", { class: "muted" }, `${new URL(n.feed).hostname} · ${n.published || fmtDate(n.fetched)}`)),
      h("div", { class: "btns" }, n.matched.map((m) => h("span", { class: "sev high" }, m))))) :
      [empty(only.checked ? "Ninguna noticia menciona tu inventario" : "Aún no hay noticias", "Los feeds se leen en cada ciclo. Puedes añadir más en Ajustes.")]));
  };
  only.addEventListener("change", load);
  await load();
  return h("div", {}, head("Noticias de ciberseguridad", "Aviso temprano: titulares que mencionan software que usas, a menudo antes de que exista CVE."),
    h("label", { class: "check", for: "n-only" }, only, "Solo las que mencionan mi inventario"), list);
}

// --- Ajustes --------------------------------------------------------------
async function viewSettings() {
  const s = await api("/api/settings");
  const inp = (id, value, attrs = {}) => { const el = h("input", { id, ...attrs }); el.value = value ?? ""; return el; };
  const interval = inp("s-interval", s.interval_minutes, { type: "number", min: "5", max: "1440" });
  const minp = h("select", { id: "s-minp" }, Object.entries(PRIO).reverse().map(([v, l]) => h("option", { value: v }, `${l} o superior`)));
  minp.value = s.notify_min_priority;
  const news = h("input", { type: "checkbox", id: "s-news", checked: s.notify_news });
  const nvd = inp("s-nvd", s.nvd_api_key, { type: "password", autocomplete: "off", placeholder: "Opcional" });
  const feeds = h("textarea", { id: "s-feeds", rows: "5" }); feeds.value = s.feeds.join("\n");
  const header = inp("s-header", s.notify_digest_header);
  const tpl = h("textarea", { id: "s-tpl", rows: "8" }); tpl.value = s.notify_template;
  const preview = h("div", { class: "preview", "aria-live": "polite" });
  let timer;
  const doPreview = () => { clearTimeout(timer); timer = setTimeout(async () => { try { preview.textContent = (await api("/api/settings/preview", { method: "POST", body: { template: tpl.value } })).text; } catch { /* */ } }, 300); };
  tpl.addEventListener("input", doPreview); doPreview();
  const chips = h("div", { class: "chips" }, s.variables.map((v) => h("button", { class: "chip", type: "button", onclick: () => {
    const pos = tpl.selectionStart ?? tpl.value.length;
    tpl.value = tpl.value.slice(0, pos) + `$${v}` + tpl.value.slice(tpl.selectionEnd ?? pos);
    tpl.focus(); doPreview();
  } }, `$${v}`)));

  const chInputs = {};
  const channelCards = Object.entries(CHANNELS).map(([name, def]) => {
    const cfg = s.channels[name] || {};
    const en = h("input", { type: "checkbox", id: `ch-${name}-en`, checked: !!cfg.enabled });
    chInputs[name] = { enabled: en };
    const fields = Object.entries(def.fields).map(([k, label]) => {
      const el = inp(`ch-${name}-${k}`, cfg[k], { type: SECRET.has(k) ? "password" : (k === "port" ? "number" : "text"), autocomplete: "off", spellcheck: "false" });
      chInputs[name][k] = el;
      return h("div", {}, h("label", { for: el.id }, label), el);
    });
    return h("section", { class: "card" },
      h("div", { class: "channel-head" }, h("h2", {}, def.title), h("label", { class: "check", for: en.id }, en, "Activo")),
      fields,
      h("div", { class: "btns spaced" }, h("button", { class: "btn small", type: "button", onclick: async () => {
        if (!(await save(true))) return;
        try { const r = await api(`/api/notify/test/${name}`, { method: "POST" }); r.results.forEach((x) => toast(`${def.title}: ${x.ok ? "mensaje de prueba enviado" : x.error}`, !x.ok)); } catch (e) { toast(e.message, true); }
      } }, "Guardar y enviar prueba")));
  });

  async function save(quiet = false) {
    const channels = {};
    for (const [name, els] of Object.entries(chInputs)) {
      channels[name] = {};
      for (const [k, el] of Object.entries(els)) channels[name][k] = el.type === "checkbox" ? el.checked : (k === "port" ? Number(el.value) || 0 : el.value.trim());
    }
    return act(() => api("/api/settings", { method: "PUT", body: {
      interval_minutes: Number(interval.value), notify_min_priority: minp.value, notify_news: news.checked,
      nvd_api_key: nvd.value.trim(), feeds: feeds.value.split("\n").map((x) => x.trim()).filter(Boolean),
      notify_digest_header: header.value, notify_template: tpl.value, channels,
    } }), quiet ? null : "Ajustes guardados");
  }

  const agentTok = h("code", {}, s.agent_token);
  return h("div", {},
    head("Ajustes", "Sondeo, mensajes y canales de aviso."),
    h("div", { class: "grid two" },
      h("section", { class: "card" }, h("h2", {}, "Sondeo"),
        h("label", { for: "s-interval" }, "Minutos entre comprobaciones (5 a 1440)"), interval,
        h("label", { for: "s-minp" }, "Avisar a partir de prioridad"), minp,
        h("label", { class: "check", for: "s-news" }, news, "Avisar también de noticias que mencionen mi inventario"),
        h("label", { for: "s-nvd" }, "API key de NVD (gratuita, acelera 10x)"), nvd,
        h("p", { class: "muted" }, "Solicítala en nvd.nist.gov/developers/request-an-api-key. Admite env:NOMBRE_VARIABLE para no guardarla en la base de datos."),
        h("label", { for: "s-feeds" }, "Feeds RSS de noticias (uno por línea)"), feeds),
      h("section", { class: "card" }, h("h2", {}, "Mensaje de aviso"),
        h("label", { for: "s-header" }, "Asunto / cabecera del resumen"), header,
        h("label", { for: "s-tpl" }, "Plantilla por vulnerabilidad"), tpl,
        h("p", { class: "muted" }, "Pulsa una variable para insertarla:"), chips,
        h("label", {}, "Vista previa"), preview)),
    h("h2", { class: "spaced" }, "Canales"),
    h("p", { class: "muted" }, "Los secretos se muestran como ******** y nunca salen del servidor. Puedes escribir env:NOMBRE para leerlos de una variable de entorno."),
    h("div", { class: "channels" }, channelCards),
    h("section", { class: "card spaced" }, h("h2", {}, "Agentes remotos"),
      h("p", {}, "Token de agente: ", agentTok),
      h("button", { class: "btn small danger", type: "button", onclick: () => {
        if (confirm("Los agentes con el token actual dejarán de poder enviar inventario. ¿Rotar?")) act(async () => { agentTok.textContent = (await api("/api/settings/rotate-agent-token", { method: "POST" })).agent_token; }, "Token rotado");
      } }, "Rotar token")),
    h("div", { class: "save-bar" }, h("button", { class: "btn primary", type: "button", onclick: () => save() }, "Guardar ajustes")));
}

// --- Registro -------------------------------------------------------------
async function viewLog() {
  const rows = await api("/api/events?limit=500");
  return h("div", {}, head("Registro", "Actividad del monitor: ciclos, fuentes, avisos enviados y errores.", h("button", { class: "btn", type: "button", onclick: rerender }, "Actualizar")),
    rows.length ? h("div", { class: "table-wrap" }, h("table", { class: "log" }, h("tbody", {}, rows.map((e) =>
      h("tr", {}, h("td", { class: "muted" }, fmtDate(e.ts)), h("td", { class: `lvl-${e.level}` }, e.level), h("td", {}, e.message)))))) : empty("Sin actividad", ""));
}

// --- Arranque -------------------------------------------------------------
let poll;
async function start() {
  if (!token) return showLogin();
  try { await api("/api/status"); } catch { return; }
  $("#login").hidden = true; $("#app").hidden = false;
  if (!location.hash) location.hash = "#/panel";
  await route();
  refreshStatus();
  clearInterval(poll);
  let wasRunning = false;
  poll = setInterval(async () => {
    await refreshStatus();
    // Solo vistas de lectura: re-renderizar un formulario borraría lo que se está escribiendo
    const readOnly = /^#\/(panel|hallazgos)?($|\?)/.test(location.hash) || /^#\/activos\/\d+/.test(location.hash);
    if (wasRunning && status && !status.running && $("#drawer").hidden && readOnly) route();
    wasRunning = !!(status && status.running);
  }, 5000);
}
start();
