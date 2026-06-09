"use strict";

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));

// 401 → редирект на /login, кроме двух случаев:
//  - вызов /api/login (сам этап аутентификации, 401 — ожидаемый ответ);
//  - пользователь сейчас в Router-секции (там правят креды; редирект только мешает —
//    криво введённый пароль не даст ничего поломать, страница пускай останется).
const _fetch = window.fetch.bind(window);
window.fetch = async (...args) => {
  const res = await _fetch(...args);
  if (res.status === 401) {
    const url = String(args[0] || "");
    const inRouter = !!document.querySelector('.view[data-view="router"]:not(.hidden)');
    if (!url.includes("api/login") && !inRouter) {
      const next = encodeURIComponent(location.pathname + location.search);
      location.replace("/login?next=" + next);
    }
  }
  return res;
};

const langSel = $("#lang");

// Разделы Settings и Router сохраняются независимо: каждый знает только о своих
// изменениях, и Save шлёт только свою секцию с частичной валидацией на бэке.
const dirty = { settings: false, router: false };
const anyDirty = () => Object.values(dirty).some(Boolean);
// Маппинг view → query-параметр section для /api/config.
const sectionOf = { settings: "service", router: "router" };
let currentMode = "server"; // активный режим, обновляется из /api/config и /api/status

const errSlots = () => $$(".error-slot");
const viewEl = (name) => $(`.view[data-view="${name}"]`);
function viewOf(input) {
  const v = input.closest(".view");
  return v ? v.dataset.view : null;
}

// ---- nested get/set by dotted path ----
function setByPath(obj, path, value) {
  const parts = path.split(".");
  let cur = obj;
  for (let i = 0; i < parts.length - 1; i++) {
    cur[parts[i]] ??= {};
    cur = cur[parts[i]];
  }
  cur[parts[parts.length - 1]] = value;
}
function getByPath(obj, path) {
  return path.split(".").reduce((o, k) => (o == null ? undefined : o[k]), obj);
}

// ---- form <-> object ----
function fillForm(cfg) {
  for (const input of $$("[data-key]")) {
    const v = getByPath(cfg, input.dataset.key);
    if (v === undefined || v === null) continue;
    if (input.type === "checkbox") { input.checked = !!v; continue; }
    if (input.tagName === "SELECT" && v !== "" &&
        !Array.from(input.options).some((o) => o.value === v)) {
      // У SELECT'а нет такой опции (роутер недоступен / интерфейс ещё не создан) —
      // добавляем текущим значением, чтобы не потерять его при сохранении.
      const opt = document.createElement("option");
      opt.value = v; opt.textContent = v;
      input.appendChild(opt);
    }
    input.value = v;
  }
}
function collectForm() {
  const cfg = {};
  for (const input of $$("[data-key]")) {
    let v;
    if (input.type === "checkbox") v = input.checked;
    else if (input.type === "number") v = input.value === "" ? 0 : Number(input.value);
    else v = input.value;
    setByPath(cfg, input.dataset.key, v);
  }
  return cfg;
}

// ---- messaging ----
// view=null — пишем во ВСЕ msg-слоты (например, после loadConfig).
function showMsg(text, kind, view) {
  const root = view ? viewEl(view) : document;
  if (!root) return;
  for (const m of root.querySelectorAll(".msg-slot")) {
    m.textContent = text;
    m.className = "bar-msg msg-slot" + (kind ? " " + kind : "");
  }
}
function showError(text, view) {
  const slots = view ? viewEl(view)?.querySelectorAll(".error-slot") || [] : errSlots();
  for (const e of slots) {
    if (!text) { e.classList.add("hidden"); continue; }
    e.textContent = text;
    e.classList.remove("hidden");
  }
}
function setDirty(view, on) {
  if (!(view in dirty)) return;
  dirty[view] = on;
  const v = viewEl(view);
  if (!v) return;
  for (const b of v.querySelectorAll(".save-btn")) b.disabled = !on;
  for (const d of v.querySelectorAll(".dirty-marker")) d.classList.toggle("hidden", !on);
  if (on) showMsg(t("msg.unsaved"), null, view);
  else showMsg("", null, view);
}
function clearAllDirty() {
  for (const v of Object.keys(dirty)) setDirty(v, false);
}

// ---- API ----
async function loadConfig() {
  showError(null);
  try {
    const res = await fetch("api/config");
    if (!res.ok) throw new Error((await res.json()).error || res.statusText);
    const cfg = await res.json();
    currentMode = cfg.mode || "server";
    await loadInterfaces(); // подгружаем варианты до fillForm, чтобы select получил value
    fillForm(cfg);
    splitPublicEndpoint();
    applyModeUI();
    applyRouterGate();
    clearAllDirty();
    showMsg(t("msg.loaded"), "ok");
  } catch (e) {
    showError(t("msg.loadFailed") + e.message);
  }
}

// Кеш ответа /api/net/auto — один запрос на жизнь страницы достаточно
// (адреса контейнера и шлюз не меняются на лету).
let netAutoCache = null;
async function getNetAuto() {
  if (netAutoCache) return netAutoCache;
  try {
    const res = await fetch("api/net/auto");
    if (res.ok) netAutoCache = await res.json();
  } catch { /* ignore */ }
  return netAutoCache || {};
}

// bindAutoDetect — вешает на .auto-btn клик «определить и подставить значение».
// data-auto: gateway | container_addr (из /api/net/auto) либо iface_listen_port
// (listen-port выбранного wg-интерфейса). Целевой инпут — ближайший [data-key]
// в том же .form-control.
function bindAutoDetect() {
  for (const btn of $$(".auto-btn[data-auto]")) {
    btn.addEventListener("click", async () => {
      const src = btn.dataset.auto;
      let val;
      if (src === "iface_listen_port") {
        const sel = $('[data-key="server.router.wg_iface"]');
        const it = sel ? ifacesCache.find((x) => x.name === sel.value) : null;
        val = it?.listen_port || "";
      } else {
        const info = await getNetAuto();
        val = info[src];
      }
      if (!val) return;
      const inp = btn.closest(".form-control")?.querySelector("[data-key]");
      if (!inp) return;
      inp.value = val;
      inp.dispatchEvent(new Event("input", { bubbles: true }));
    });
  }
}

// Кастомная выпадашка адресов роутера для поля Public endpoint host.
// Делаем стилизованной (`.menu`/`.menu-item`), нативный <datalist> не вписывается
// в тёмную тему и работает по-разному в браузерах.
let hostMenuEl = null;
function closeHostMenu() {
  if (hostMenuEl) { hostMenuEl.remove(); hostMenuEl = null; }
}
async function openHostMenu(anchor) {
  closeHostMenu();
  let list = [];
  try {
    const res = await fetch("api/router/addresses");
    if (res.ok) list = await res.json();
  } catch { /* ignore */ }
  list = (list || []).filter((a) => a && a.address);
  if (!list.length) return;
  const m = document.createElement("div");
  m.className = "menu";
  m.style.position = "fixed";
  m.style.maxHeight = "260px";
  m.style.overflowY = "auto";
  for (const a of list) {
    const ip = (a.address || "").split("/")[0];
    if (!ip) continue;
    const b = document.createElement("button");
    b.className = "menu-item host-menu-item";
    const main = document.createElement("span"); main.textContent = ip;
    const sub = document.createElement("span"); sub.className = "host-menu-iface"; sub.textContent = a.interface || "";
    b.append(main, sub);
    b.addEventListener("click", (e) => {
      e.stopPropagation();
      closeHostMenu();
      const host = $("#pe-host");
      if (!host) return;
      host.value = ip;
      host.dispatchEvent(new Event("input", { bubbles: true }));
    });
    m.appendChild(b);
  }
  document.body.appendChild(m);
  const r = anchor.getBoundingClientRect();
  m.style.top = r.bottom + 4 + "px";
  m.style.left = Math.max(8, r.left) + "px";
  hostMenuEl = m;
  // Один клик «вне» — закрываем; setTimeout, чтобы не словить событие открытия.
  setTimeout(() => document.addEventListener("click", closeHostMenu, { once: true }), 0);
}

// Кеш WG-интерфейсов: нужен, чтобы при смене выпадашки подставлять listen-port
// в server.remote_port (см. bindIfaceAutoPort).
let ifacesCache = [];

// loadInterfaces заполняет выпадашки WG-интерфейсов списком с роутера. Если роутер
// недоступен — оставляет селекты пустыми (fillForm затем добавит текущее значение
// как опцию-фолбэк).
async function loadInterfaces() {
  const selects = $$(".iface-select");
  if (!selects.length) return;
  let list = [];
  try {
    const res = await fetch("api/router/interfaces");
    if (res.ok) list = await res.json();
  } catch { /* ignore — оставим селект пустым */ }
  ifacesCache = list || [];
  for (const s of selects) {
    s.innerHTML = "";
    // Плейсхолдер для пустой / недоступной конфигурации, перетирается fillForm'ом.
    const ph = document.createElement("option");
    ph.value = ""; ph.textContent = "—"; ph.disabled = true;
    s.appendChild(ph);
    for (const it of list) {
      const opt = document.createElement("option");
      opt.value = it.name; opt.textContent = it.name;
      s.appendChild(opt);
    }
  }
}

// bindIfaceAutoPort: при смене WG-интерфейса в Settings (server-режим) автоматически
// подставляет его listen-port в server.remote_port. Ручная правка пользователя
// блокирует автоподстановку (помечаем «авто»-значение dataset.autoVal — любое
// расхождение = пользователь поправил, дальше не трогаем).
function bindIfaceAutoPort() {
  const sel = $('[data-key="server.router.wg_iface"]');
  const port = $('[data-key="server.remote_port"]');
  if (!sel || !port) return;
  port.addEventListener("input", () => {
    if (port.value !== port.dataset.autoVal) delete port.dataset.autoVal;
  });
  sel.addEventListener("change", () => {
    const it = ifacesCache.find((x) => x.name === sel.value);
    if (!it || !it.listen_port) return;
    // Пусто или ровно то, что мы сами вставили в прошлый раз → можно перезаписать.
    if (port.value !== "" && port.value !== port.dataset.autoVal) return;
    port.value = it.listen_port;
    port.dataset.autoVal = it.listen_port;
    port.dispatchEvent(new Event("input", { bubbles: true })); // dirty-маркер
    port.dataset.autoVal = it.listen_port; // input-handler мог снять — восстанавливаем
  });
}

// applyRouterGate блокирует разделы Peers и Settings, если адрес роутера активного
// режима не задан — без него остальные разделы бесполезны. Источник — текущее
// значение поля в форме (а не сохранённый конфиг), чтобы реагировать на правки.
function applyRouterGate() {
  const inp = $(`[data-key="${currentMode}.router.address"]`);
  const ok = !!inp && inp.value.trim() !== "";
  for (const nav of $$('.sidenav-item[data-view="peers"], .sidenav-item[data-view="settings"]')) {
    nav.classList.toggle("disabled", !ok);
    nav.title = ok ? "" : t("nav.lockedHint");
  }
}

// applyModeUI прячет/показывает блоки .mode-server / .mode-client по текущему режиму.
function applyModeUI() {
  for (const el of $$(".mode-server")) el.classList.toggle("hidden", currentMode !== "server");
  for (const el of $$(".mode-client")) el.classList.toggle("hidden", currentMode !== "client");
}
async function saveSection(view) {
  const section = sectionOf[view];
  if (!section) return;
  showError(null, view);
  const v = viewEl(view);
  for (const b of v.querySelectorAll(".save-btn")) b.disabled = true;
  try {
    const res = await fetch("api/config?section=" + encodeURIComponent(section), {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(collectForm()),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || res.statusText);
    // Файл записан целиком — оба раздела чистые.
    clearAllDirty();
    showMsg(t("msg.saved"), "ok", view);
    // Сохранили Router-секцию → пробуем авто-логин с введёнными кредами, чтобы
    // следующая операция не упёрлась в 401 и пользователя не редиректнуло.
    if (view === "router") autoLoginAfterRouterSave(view);
  } catch (e) {
    for (const b of v.querySelectorAll(".save-btn")) b.disabled = false;
    showError(t("msg.saveFailed") + e.message, view);
  }
}

// autoLoginAfterRouterSave — best-effort: пробуем установить сессию свежими
// кредами. Успех — без шума; провал — оставляем пользователя на странице
// с подсказкой (не редиректим, креды просто не подошли).
async function autoLoginAfterRouterSave(view) {
  const u = $(`[data-key="${currentMode}.router.user"]`);
  const p = $(`[data-key="${currentMode}.router.password"]`);
  if (!u || !p || !u.value || !p.value) return;
  try {
    const res = await fetch("api/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: u.value, password: p.value }),
    });
    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      showError("login: " + (data.error || res.statusText), view);
    }
  } catch { /* ignore */ }
}
async function loadVersion() {
  try {
    const v = await (await fetch("api/version")).json();
    $("#build-info").textContent = "v" + v.version + " · build " + v.build;
  } catch { /* ignore */ }
}
async function loadStatus() {
  try {
    const st = await (await fetch("api/status")).json();
    if (st.mode) { currentMode = st.mode; applyModeUI(); }
    const poll = $("#st-poll"), key = $("#st-key");
    poll.textContent = st.poll_ok ? t("val.ok") : t("val.waiting");
    poll.className = "stat-value " + (st.poll_ok ? "ok" : "bad");
    key.textContent = st.server_key ? t("val.ok") : "—";
    key.className = "stat-value " + (st.server_key ? "ok" : "bad");
    const clients = $("#st-clients");
    if (clients) { clients.textContent = st.clients; clients.className = "stat-value"; }
    const up = $("#st-upstream"), upAddr = $("#st-upstream-addr"), wgl = $("#st-wglisten");
    if (up) {
      up.textContent = st.upstream_ready ? (st.upstream_comment || t("val.ok")) : t("val.notReady");
      up.className = "stat-value " + (st.upstream_ready ? "ok" : "bad");
    }
    if (upAddr) upAddr.textContent = st.upstream_addr || "—";
    if (wgl) wgl.textContent = st.wg_listen_port || "—";
  } catch { /* ignore */ }
}

// ---- nav (views: status / router / peers / settings) ----
// Settings и Router редактируют один и тот же config — перечитывать при входе
// можно только если форма чистая, иначе потеряем несохранённые правки.
function switchView(name) {
  // Заблокированные пункты (нет адреса роутера) — отскок в Router.
  const btn = $(`.sidenav-item[data-view="${name}"]`);
  if (btn && btn.classList.contains("disabled")) {
    showMsg(t("nav.lockedHint"), null, "router");
    name = "router";
  }
  $$(".sidenav-item").forEach((b) => b.classList.toggle("active", b.dataset.view === name));
  $$(".view").forEach((v) => v.classList.toggle("hidden", v.dataset.view !== name));
  if (name === "status") loadStatus();
  else if (name === "peers") loadPeers();
  else if (name === "settings" || name === "router") {
    // Перечитываем конфиг только если ни в одном разделе нет несохранённых правок —
    // иначе перезатрём чужие изменения.
    if (!anyDirty()) loadConfig();
  }
}
$$(".sidenav-item").forEach((b) => b.addEventListener("click", () => switchView(b.dataset.view)));

// decorateNumberInputs скрывает кривые нативные спиннеры и рисует свои
// аккуратные ▲▼ в правом краю поля (видимые на hover/focus, как нативные).
function decorateNumberInputs() {
  for (const inp of $$('.form-control input[type="number"]')) {
    if (inp.dataset.numDecorated) continue;
    inp.dataset.numDecorated = "1";
    const wrap = document.createElement("span");
    wrap.className = "num-wrap";
    if (inp.classList.contains("w-port")) {
      wrap.classList.add("w-port");
      inp.classList.remove("w-port");
    }
    inp.parentNode.insertBefore(wrap, inp);
    wrap.appendChild(inp);
    const arrows = document.createElement("span");
    arrows.className = "num-arrows";
    const up = document.createElement("button");
    up.type = "button"; up.className = "num-arrow up"; up.tabIndex = -1;
    up.setAttribute("aria-label", "increment");
    up.addEventListener("click", () => stepInput(inp, 1));
    const down = document.createElement("button");
    down.type = "button"; down.className = "num-arrow down"; down.tabIndex = -1;
    down.setAttribute("aria-label", "decrement");
    down.addEventListener("click", () => stepInput(inp, -1));
    arrows.appendChild(up);
    arrows.appendChild(down);
    wrap.appendChild(arrows);
  }
}

// stepInput меняет числовое значение на ±step с учётом min/max и шлёт input-event
// (чтобы сработали dirty-маркер и applyRouterGate, если нужно).
function stepInput(inp, delta) {
  const step = Number(inp.step) || 1;
  const min = inp.min !== "" ? Number(inp.min) : -Infinity;
  const max = inp.max !== "" ? Number(inp.max) : Infinity;
  const cur = inp.value === "" ? 0 : Number(inp.value);
  let v = cur + delta * step;
  if (v < min) v = min;
  if (v > max) v = max;
  inp.value = v;
  inp.dispatchEvent(new Event("input", { bubbles: true }));
}

decorateNumberInputs();

// ---- wire up ----
// Любое поле помечает «грязным» свой view (settings или router).
$$("[data-key]").forEach((input) => {
  const v = viewOf(input);
  if (!v) return;
  const ev = input.tagName === "SELECT" || input.type === "checkbox" ? "change" : "input";
  input.addEventListener(ev, () => setDirty(v, true));
});
// Селектор режима: переключение секций без сохранения.
const modeSel = $("#mode-select");
if (modeSel) modeSel.addEventListener("change", () => { currentMode = modeSel.value; applyModeUI(); applyRouterGate(); });
// Любое изменение адреса роутера тут же перепроверяет gate (включает/гасит пункты).
for (const i of $$('[data-key$=".router.address"]')) {
  i.addEventListener("input", applyRouterGate);
}
// Каждая Save-кнопка знает свой view и шлёт только свою секцию.
for (const b of $$(".save-btn")) {
  const v = viewOf(b);
  if (v) b.addEventListener("click", () => saveSection(v));
}
bindIfaceAutoPort();
bindPublicEndpoint();
bindAutoDetect();

// splitPublicEndpoint распиливает скрытое значение "host:port" на видимые поля.
// Делает rsplit по последнему ":" — на случай хоста с двоеточием (IPv6 в нашем
// контексте маловероятен, но не ломаемся).
function splitPublicEndpoint() {
  const hidden = $('[data-key="server.public_endpoint"]');
  const host = $("#pe-host"), port = $("#pe-port");
  if (!hidden || !host || !port) return;
  const v = hidden.value || "";
  const i = v.lastIndexOf(":");
  if (i > 0) { host.value = v.slice(0, i); port.value = v.slice(i + 1); }
  else { host.value = v; port.value = ""; }
}

// bindPublicEndpoint склеивает host+port в скрытое поле data-key и диспатчит
// input — благодаря этому дефолтный dirty-маркер и save-флоу не меняются.
function bindPublicEndpoint() {
  const hidden = $('[data-key="server.public_endpoint"]');
  const host = $("#pe-host"), port = $("#pe-port");
  if (!hidden || !host || !port) return;
  const sync = () => {
    const h = host.value.trim(), p = port.value.trim();
    hidden.value = h && p ? h + ":" + p : (h || "");
    hidden.dispatchEvent(new Event("input", { bubbles: true }));
  };
  host.addEventListener("input", sync);
  port.addEventListener("input", sync);
}

// Кнопка ▾ рядом с pe-host открывает кастомную выпадашку адресов роутера.
$("#pe-host-pick")?.addEventListener("click", (e) => {
  e.stopPropagation();
  openHostMenu(e.currentTarget);
});

langSel.value = currentLang;
langSel.addEventListener("change", () => {
  setLang(langSel.value);
  loadStatus(); // перевести значения статуса
  if (!$('.view[data-view="peers"]').classList.contains("hidden")) loadPeers();
});

// Отключаем браузерные подсказки/автозаполнение и проверку орфографии.
for (const i of $$("input")) {
  i.setAttribute("autocomplete", i.type === "password" ? "new-password" : "off");
  i.setAttribute("autocapitalize", "off");
  i.setAttribute("autocorrect", "off");
  i.spellcheck = false;
}

async function doLogout() {
  await fetch("api/logout", { method: "POST" });
  location.replace("/login");
}
$("#logout-btn").addEventListener("click", doLogout);

// init — на старте интерфейс уже авторизован (статика гейтится на бэке).
// Кнопку «Выйти» показываем, только если авторизация в принципе требуется.
// Если роутер ещё не настроен — сразу везём в раздел Router, иначе на Status.
async function init() {
  applyI18n();
  loadVersion();
  let needsRouter = false;
  try {
    const auth = await (await fetch("api/auth")).json();
    $("#logout-btn").classList.toggle("hidden", !auth.required);
    // auth.required=false при незаданном/недоступном роутере. Если конфиг пустой,
    // ведём в Router. Иначе — на Status.
    needsRouter = !auth.required;
  } catch { /* ignore */ }
  // Загрузим конфиг один раз сразу — чтобы корректно показать currentMode и поля.
  await loadConfig();
  // Если роутер активного режима не указан — открыть раздел Router сразу.
  const addrKey = currentMode === "client" ? "client.router.address" : "server.router.address";
  const addrInput = $(`[data-key="${addrKey}"]`);
  const noRouter = !addrInput || !addrInput.value.trim();
  switchView(needsRouter && noRouter ? "router" : "status");
}

init();
