"use strict";

// Управление пирами WireGuard: список + редактор (как редактирование групп в референсе).

const peersListEl = $("#peers-list");
const peersEditorEl = $("#peers-editor");
const peerRows = $("#peers-rows");
const peersErr = $("#peers-error");
const peersEmpty = $("#peers-empty");
const peerEditorMsg = $("#peer-editor-msg");
const peerSearch = $("#peers-search");

let allPeers = [];
let editingId = null; // id редактируемого пира (null — создание нового)
let openMenuEl = null;
let currentFilter = "all"; // all | active | disabled
let ifaceCIDR = "";       // адрес активного WG-интерфейса роутера, напр. "10.0.0.1/24"

// ---- список ----
async function loadPeers() {
  showPeersList();
  peersErr.classList.add("hidden");
  loadIfaceContext(); // фоном: для подсказки адреса нового пира
  try {
    const res = await fetch("api/peers");
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || res.statusText);
    allPeers = data || [];
    renderPeers();
  } catch (e) {
    allPeers = [];
    peerRows.replaceChildren();
    peersEmpty.classList.add("hidden");
    showErr(peersErr, t("peers.loadFailed") + e.message);
  }
}

// loadIfaceContext — узнаёт CIDR активного WG-интерфейса роутера (для предложения
// свободного IP при создании пира). Best-effort: ошибки молча игнорируем.
async function loadIfaceContext() {
  try {
    const [cfgRes, ifsRes] = await Promise.all([fetch("api/config"), fetch("api/router/interfaces")]);
    if (!cfgRes.ok || !ifsRes.ok) return;
    const cfg = await cfgRes.json();
    const ifs = await ifsRes.json();
    const mode = cfg.mode || "server";
    const want = (mode === "client" ? cfg.client : cfg.server)?.router?.wg_iface || "";
    const it = (ifs || []).find((x) => x.name === want);
    ifaceCIDR = it?.address || "";
  } catch { /* ignore */ }
}

// suggestPeerAddress — следующий свободный IPv4 в подсети интерфейса в виде "x.x.x.x/32".
// Учитывает собственный адрес интерфейса и все занятые токены allowed_address.
// Возвращает "" если интерфейс не задан, не IPv4 или сеть исчерпана.
function suggestPeerAddress() {
  const m = /^(\d+)\.(\d+)\.(\d+)\.(\d+)\/(\d+)$/.exec(ifaceCIDR);
  if (!m) return "";
  const ifaceIP = (+m[1] * 16777216) + (+m[2] * 65536) + (+m[3] * 256) + (+m[4]);
  const prefix = +m[5];
  if (prefix < 8 || prefix > 30) return "";
  const mask = (0xFFFFFFFF << (32 - prefix)) >>> 0;
  const net = (ifaceIP & mask) >>> 0;
  const bcast = (net | (~mask >>> 0)) >>> 0;
  const used = new Set([ifaceIP]);
  for (const p of allPeers) {
    for (const tok of normAddrTokens(p.allowed_address)) {
      const mm = /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(tok);
      if (mm) used.add((+mm[1] * 16777216) + (+mm[2] * 65536) + (+mm[3] * 256) + (+mm[4]));
    }
  }
  for (let n = net + 1; n < bcast; n++) {
    if (!used.has(n)) {
      return `${(n >>> 24) & 255}.${(n >>> 16) & 255}.${(n >>> 8) & 255}.${n & 255}/32`;
    }
  }
  return "";
}

// peersVisible — открыт ли список пиров (не редактор, не меню, не модалка).
function peersVisible() {
  const sec = document.querySelector('.view[data-view="peers"]');
  return sec && !sec.classList.contains("hidden")
    && !peersListEl.classList.contains("hidden")
    && !openMenuEl
    && qrModal.classList.contains("hidden");
}

// refreshPeers — фоновое обновление списка (handshake/трафик/статус) без сброса вида.
async function refreshPeers() {
  if (!peersVisible()) return;
  try {
    const res = await fetch("api/peers");
    if (!res.ok) return;
    allPeers = (await res.json()) || [];
    renderPeers();
  } catch { /* ignore */ }
}

function renderPeers() {
  $("#count-all").textContent = allPeers.length;
  $("#count-active").textContent = allPeers.filter((p) => !p.disabled).length;
  $("#count-disabled").textContent = allPeers.filter((p) => p.disabled).length;

  let list = allPeers;
  if (currentFilter === "active") list = list.filter((p) => !p.disabled);
  else if (currentFilter === "disabled") list = list.filter((p) => p.disabled);

  const q = peerSearch.value.trim().toLowerCase();
  if (q) {
    list = list.filter((p) =>
      [p.name, p.comment, p.public_key, p.allowed_address].some((v) => (v || "").toLowerCase().includes(q)));
  }
  peerRows.replaceChildren();
  peersEmpty.classList.toggle("hidden", list.length > 0);
  for (const p of list) peerRows.appendChild(peerRow(p));
}

function peerRow(p) {
  const tr = document.createElement("div");
  tr.className = "tr" + (p.disabled ? " disabled" : "");

  // имя + публичный ключ
  const name = cell("td-name");
  const icon = document.createElement("span");
  icon.className = "row-icon";
  icon.textContent = "⊙";
  const wrap = document.createElement("div");
  wrap.className = "peer-name-wrap";
  const nm = document.createElement("span");
  nm.className = "peer-name";
  nm.textContent = p.name || p.comment || t("peers.unnamed");
  const sub = document.createElement("span");
  sub.className = "peer-sub";
  sub.textContent = p.public_key || "";
  wrap.append(nm, sub);
  // В client-режиме помеченные [awgproxy] пиры маркируются бейджем.
  if (isViaProxy(p)) {
    const badge = document.createElement("span");
    badge.className = "peer-badge";
    badge.textContent = t("peers.viaProxy");
    wrap.appendChild(badge);
  }
  name.append(icon, wrap);
  name.addEventListener("click", () => openEditor(p));
  tr.appendChild(name);

  tr.appendChild(cell("td-mono", p.allowed_address || "—"));
  tr.appendChild(cell("td-mono", p.last_handshake || "—"));

  // переключатель статуса
  const status = cell();
  status.appendChild(rowSwitch(!p.disabled, () => togglePeer(p)));
  tr.appendChild(status);

  // действия (kebab)
  const act = cell("td-actions");
  const kebab = document.createElement("button");
  kebab.className = "icon-btn";
  kebab.textContent = "⋯";
  kebab.addEventListener("click", (e) => {
    e.stopPropagation();
    const items = [];
    if (p.private_key) items.push({ label: t("peers.showConfig"), onClick: () => openConfigModal(p) });
    items.push({ label: t("peers.editBtn"), onClick: () => openEditor(p) });
    if (currentMode === "client") {
      items.push({
        label: isViaProxy(p) ? t("peers.viaProxy") + " ✓" : t("peers.viaProxy"),
        onClick: () => toggleViaProxy(p),
      });
    }
    items.push({ sep: true });
    items.push({ label: t("peers.delete"), danger: true, onClick: () => deletePeer(p) });
    openMenu(kebab, items);
  });
  act.appendChild(kebab);
  tr.appendChild(act);
  return tr;
}

function cell(cls, text) {
  const el = document.createElement("div");
  if (cls) el.className = cls;
  if (text !== undefined) el.textContent = text;
  return el;
}

function rowSwitch(on, onChange) {
  const label = document.createElement("label");
  label.className = "row-switch";
  const input = document.createElement("input");
  input.type = "checkbox";
  input.checked = on;
  input.addEventListener("change", (e) => { e.stopPropagation(); onChange(); });
  const track = document.createElement("span");
  track.className = "switch-track";
  const thumb = document.createElement("span");
  thumb.className = "switch-thumb";
  track.appendChild(thumb);
  label.append(input, track);
  label.addEventListener("click", (e) => e.stopPropagation());
  return label;
}

// ---- kebab-меню ----
function openMenu(anchor, items) {
  closeMenu();
  const m = document.createElement("div");
  m.className = "menu";
  m.style.position = "fixed";
  for (const it of items) {
    if (it.sep) { const s = document.createElement("div"); s.className = "menu-sep"; m.appendChild(s); continue; }
    const b = document.createElement("button");
    b.className = "menu-item" + (it.danger ? " danger" : "");
    b.textContent = it.label;
    b.addEventListener("click", (e) => { e.stopPropagation(); closeMenu(); it.onClick(); });
    m.appendChild(b);
  }
  document.body.appendChild(m);
  const r = anchor.getBoundingClientRect();
  m.style.top = r.bottom + 4 + "px";
  m.style.left = Math.max(8, r.right - m.offsetWidth) + "px";
  openMenuEl = m;
  setTimeout(() => document.addEventListener("click", closeMenu, { once: true }), 0);
}
function closeMenu() { if (openMenuEl) { openMenuEl.remove(); openMenuEl = null; } }

// ---- переключение список/редактор ----
function showPeersList() {
  peersEditorEl.classList.add("hidden");
  peersListEl.classList.remove("hidden");
}

function pkInputs() { return $$("#peers-editor [data-pk]"); }

function openEditor(peer) {
  editingId = peer ? peer.id : null;
  $("#peer-crumb").textContent = peer ? (peer.name || peer.comment || t("peers.unnamed")) : t("peers.add");
  $("#peer-delete").classList.toggle("hidden", !editingId);
  for (const input of pkInputs()) {
    const k = input.dataset.pk;
    if (input.type === "checkbox") input.checked = peer ? !peer.disabled : true; // enabled = !disabled
    else input.value = peer ? (peer[k] || "") : "";
  }
  // Новый пир: предлагаем следующий свободный IP из сети активного WG-интерфейса.
  if (!peer) {
    const addr = $('#peers-editor [data-pk="allowed_address"]');
    if (addr && !addr.value) addr.value = suggestPeerAddress();
  }
  // Приватный ключ из пира: показываем строку и кнопку QR, если он сохранён.
  const priv = peer ? (peer.private_key || "") : "";
  $("#peer-privkey").value = priv;
  $("#peer-privrow").classList.toggle("hidden", !priv);
  const qrBtn = $("#peer-qr");
  qrBtn.classList.toggle("hidden", !priv);
  qrBtn.title = t("peers.showConfig");
  peerEditorMsg.classList.add("hidden");
  peersListEl.classList.add("hidden");
  peersEditorEl.classList.remove("hidden");
  const scroll = document.querySelector('.view[data-view="peers"] .view-scroll');
  if (scroll) scroll.scrollTop = 0;
  applyI18n();
  $("#peer-name-input").focus();
}

// normAddrTokens — разбивает "10.0.0.2/32, 10.0.0.3" на нормализованные токены
// (lower-case, без пробелов и без trailing-маски /32 у IPv4 / /128 у IPv6 для
// сравнения «голый IP» и «IP/32» как одно и то же).
function normAddrTokens(s) {
  if (!s) return [];
  return s.split(",").map((x) => {
    const t = x.trim().toLowerCase();
    if (!t) return "";
    if (t.endsWith("/32") && !t.includes(":")) return t.slice(0, -3);
    if (t.endsWith("/128") && t.includes(":")) return t.slice(0, -4);
    return t;
  }).filter(Boolean);
}

// addressConflict — ищет пересечение токенов нового пира с allPeers
// (исключая редактируемого по id). Возвращает {token, peer} либо null.
function addressConflict(addr, selfId) {
  const mine = normAddrTokens(addr);
  if (!mine.length) return null;
  for (const other of allPeers) {
    if (selfId && other.id === selfId) continue;
    const theirs = normAddrTokens(other.allowed_address);
    for (const t of mine) {
      if (theirs.includes(t)) return { token: t, peer: other };
    }
  }
  return null;
}

function collectPeer() {
  const p = {};
  for (const input of pkInputs()) {
    const k = input.dataset.pk;
    if (k === "enabled") p.disabled = !input.checked;
    else if (input.type !== "checkbox") p[k] = input.value.trim();
  }
  // Приватный ключ храним в пире (если он есть) — чтобы перевыпускать QR.
  const priv = $("#peer-privkey").value.trim();
  if (priv) p.private_key = priv;
  return p;
}

async function savePeer() {
  const p = collectPeer();
  if (!p.public_key && !p.private_key) { showErr(peerEditorMsg, t("peers.needKey")); return; }
  const dup = addressConflict(p.allowed_address, editingId);
  if (dup) {
    showErr(peerEditorMsg, t("peers.addrTaken") + dup.token + " — " + (dup.peer.name || dup.peer.public_key));
    return;
  }
  const btn = $("#peer-save");
  btn.disabled = true;
  try {
    const url = editingId ? "api/peers/" + encodeURIComponent(editingId) : "api/peers";
    const res = await fetch(url, {
      method: editingId ? "PATCH" : "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(p),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || res.statusText);
    // Есть приватный ключ — после любого сохранения показываем конфиг/QR.
    if ($("#peer-privkey").value) { qrAfterSave = true; await openConfigModal(); }
    else loadPeers();
  } catch (e) {
    showErr(peerEditorMsg, t("peers.saveFailed") + e.message);
  } finally {
    btn.disabled = false;
  }
}

// ---- клиентский конфиг / QR ----
const qrModal = $("#qr-modal");
let lastConfig = "";
let lastName = "peer";
let qrAfterSave = false;

// openConfigModal: src — пир из списка; без него берёт поля из открытого редактора.
async function openConfigModal(src) {
  const priv = src ? (src.private_key || "") : $("#peer-privkey").value;
  const addr = src ? (src.allowed_address || "") : $('#peers-editor [data-pk="allowed_address"]').value.trim();
  const psk = src ? (src.preshared_key || "") : $('#peers-editor [data-pk="preshared_key"]').value.trim();
  lastName = (src ? src.name : $('#peers-editor [data-pk="name"]').value.trim()) || "peer";
  $("#qr-error").classList.add("hidden");
  try {
    const res = await fetch("api/peer-config", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ private_key: priv, address: addr, preshared_key: psk, name: lastName }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || res.statusText);
    lastConfig = data.config;
    $("#qr-img").src = data.qr;
    $("#qr-config").textContent = data.config;
    qrModal.classList.remove("hidden");
  } catch (e) {
    showErr($("#qr-error"), t("peers.saveFailed") + e.message);
    qrModal.classList.remove("hidden");
  }
}

function closeConfigModal() {
  qrModal.classList.add("hidden");
  if (qrAfterSave) { qrAfterSave = false; loadPeers(); }
}

function downloadConfig() {
  if (!lastConfig) return;
  const blob = new Blob([lastConfig], { type: "text/plain" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = lastName.replace(/[^\w.-]/g, "_") + ".conf";
  a.click();
  URL.revokeObjectURL(a.href);
}

async function togglePeer(p) {
  try {
    const res = await fetch("api/peers/" + encodeURIComponent(p.id), {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ...p, disabled: !p.disabled }),
    });
    if (!res.ok) throw new Error((await res.json()).error || res.statusText);
    loadPeers();
  } catch (e) {
    showErr(peersErr, t("peers.saveFailed") + e.message);
  }
}

// isViaProxy — peer помечен префиксом [awgproxy] в comment.
function isViaProxy(p) {
  return (p.comment || "").trimStart().startsWith("[awgproxy]");
}

// toggleViaProxy — добавляет/убирает префикс [awgproxy] в начале comment'а.
async function toggleViaProxy(p) {
  const cur = (p.comment || "").trimStart();
  let next;
  if (cur.startsWith("[awgproxy]")) {
    next = cur.slice("[awgproxy]".length).trimStart();
  } else {
    next = ("[awgproxy] " + cur).trimEnd();
  }
  try {
    const res = await fetch("api/peers/" + encodeURIComponent(p.id), {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ...p, comment: next }),
    });
    if (!res.ok) throw new Error((await res.json()).error || res.statusText);
    loadPeers();
  } catch (e) {
    showErr(peersErr, t("peers.saveFailed") + e.message);
  }
}

async function deletePeer(p) {
  if (!confirm(t("peers.confirmDelete") + (p.name || p.comment || p.public_key))) return;
  try {
    const res = await fetch("api/peers/" + encodeURIComponent(p.id), { method: "DELETE" });
    if (!res.ok) throw new Error((await res.json()).error || res.statusText);
    loadPeers();
  } catch (e) {
    showErr(peersErr, t("peers.saveFailed") + e.message);
  }
}

async function genKeypair() {
  try {
    const res = await fetch("api/keypair", { method: "POST" });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || res.statusText);
    $('#peers-editor [data-pk="public_key"]').value = data.public;
    $("#peer-privkey").value = data.private;
    $("#peer-privrow").classList.remove("hidden");
    $("#peer-qr").classList.remove("hidden");
  } catch (e) {
    showErr(peerEditorMsg, t("peers.saveFailed") + e.message);
  }
}

function showErr(el, text) {
  el.textContent = text;
  el.classList.remove("hidden");
}

// ---- импорт AmneziaWG-конфига (client-режим) ----
const importModal = $("#import-modal");
const importErr = $("#import-error");
const importText = $("#import-text");
const importFile = $("#import-file");
const importPreview = $("#import-preview");
const importApplyBtn = $("#import-apply");
let importParsed = null; // { iface, peer, suggestName }

// parseAwgConfig — лояльный INI-парсер под формат wg-quick/AmneziaWG.
function parseAwgConfig(text) {
  const out = { iface: {}, peer: {} };
  let section = null;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#") || line.startsWith(";")) continue;
    if (line.startsWith("[") && line.endsWith("]")) {
      section = line.slice(1, -1).trim().toLowerCase();
      continue;
    }
    const idx = line.indexOf("=");
    if (idx < 0) continue;
    const key = line.slice(0, idx).trim();
    const val = line.slice(idx + 1).trim();
    if (section === "interface") out.iface[key] = val;
    else if (section === "peer") out.peer[key] = val;
  }
  return out;
}

// splitEndpoint — "host:port" → [host, port] (поддержка IPv6 в [].)
function splitEndpoint(s) {
  if (!s) return ["", ""];
  const m = s.match(/^\[(.+)\]:(\d+)$/);
  if (m) return [m[1], m[2]];
  const i = s.lastIndexOf(":");
  if (i < 0) return [s, ""];
  return [s.slice(0, i), s.slice(i + 1)];
}

function previewImport(parsed) {
  const { iface, peer } = parsed;
  const [host, port] = splitEndpoint(peer.Endpoint || "");
  const rows = [
    ["Endpoint", host && port ? `${host}:${port}` : "—"],
    ["Peer public key", peer.PublicKey || "—"],
    ["Preshared key", peer.PresharedKey ? "set" : "—"],
    ["AllowedIPs", peer.AllowedIPs || "—"],
    ["Keepalive", peer.PersistentKeepalive || "—"],
    ["Obfuscation", ["Jc", "Jmin", "Jmax", "S1", "S2", "H1", "H2", "H3", "H4"]
      .map((k) => iface[k]).filter(Boolean).length + " of 9"],
    ["Iface PrivateKey", iface.PrivateKey ? "will be applied" : "—"],
    ["Iface Address", iface.Address || "—"],
  ];
  const dl = importPreview.querySelector("dl");
  dl.replaceChildren();
  for (const [k, v] of rows) {
    const dt = document.createElement("dt"); dt.textContent = k;
    const dd = document.createElement("dd"); dd.textContent = v;
    dl.append(dt, dd);
  }
  importPreview.classList.remove("hidden");
  importApplyBtn.disabled = !peer.PublicKey || !host || !port;
}

function clearImport() {
  importText.value = "";
  importFile.value = "";
  importErr.classList.add("hidden");
  importPreview.classList.add("hidden");
  importApplyBtn.disabled = true;
  importParsed = null;
}

async function readImportFile(file) {
  // image/* → пробуем BarcodeDetector; иначе читаем как текст.
  if (file.type.startsWith("image/")) {
    if (!("BarcodeDetector" in window)) {
      throw new Error(t("peers.importNoBarcode"));
    }
    try {
      const detector = new BarcodeDetector({ formats: ["qr_code"] });
      const bmp = await createImageBitmap(file);
      const codes = await detector.detect(bmp);
      if (!codes.length) throw new Error("no QR detected");
      return codes[0].rawValue;
    } catch (e) {
      throw new Error(t("peers.importQRFail") + e.message);
    }
  }
  return await file.text();
}

async function onImportFile() {
  const f = importFile.files[0];
  if (!f) return;
  importErr.classList.add("hidden");
  try {
    importText.value = await readImportFile(f);
    onImportTextChanged();
  } catch (e) {
    showErr(importErr, e.message);
  }
}

function onImportTextChanged() {
  importErr.classList.add("hidden");
  importPreview.classList.add("hidden");
  importApplyBtn.disabled = true;
  importParsed = null;
  const text = importText.value.trim();
  if (!text) return;
  try {
    const parsed = parseAwgConfig(text);
    if (!parsed.peer.PublicKey || !parsed.peer.Endpoint) {
      throw new Error("missing [Peer] PublicKey or Endpoint");
    }
    // Подсказка имени для пира — из имени файла или генерим.
    const fname = importFile.files[0]?.name || "";
    parsed.suggestName = fname.replace(/\.[^.]+$/, "") || "imported";
    importParsed = parsed;
    previewImport(parsed);
  } catch (e) {
    showErr(importErr, t("peers.importParseFail") + e.message);
  }
}

async function applyImport() {
  if (!importParsed) return;
  const { iface, peer, suggestName } = importParsed;
  const [host, port] = splitEndpoint(peer.Endpoint);
  importApplyBtn.disabled = true;
  importErr.classList.add("hidden");
  try {
    // 1) Сохраняем обфускацию в client-секцию.
    const cfgRes = await fetch("api/config");
    const cfg = await cfgRes.json();
    if (!cfgRes.ok) throw new Error(cfg.error || cfgRes.statusText);
    cfg.client = cfg.client || {};
    cfg.client.obfuscation = cfg.client.obfuscation || {};
    const o = cfg.client.obfuscation;
    const num = (v) => v == null || v === "" ? undefined : Number(v);
    for (const [k, dst] of [["Jc","jc"],["Jmin","jmin"],["Jmax","jmax"],["S1","s1"],["S2","s2"],["H1","h1"],["H2","h2"],["H3","h3"],["H4","h4"]]) {
      const n = num(iface[k]);
      if (n !== undefined && !Number.isNaN(n)) o[dst] = n;
    }
    const putRes = await fetch("api/config", {
      method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(cfg),
    });
    const putData = await putRes.json();
    if (!putRes.ok) throw new Error(putData.error || putRes.statusText);

    // 2) Применяем private-key/address к WG-интерфейсу на роутере.
    if (iface.PrivateKey || iface.Address) {
      const ifRes = await fetch("api/router/interface", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ private_key: iface.PrivateKey || "", address: iface.Address || "" }),
      });
      const ifData = await ifRes.json();
      if (!ifRes.ok) throw new Error(ifData.error || ifRes.statusText);
    }

    // 3) Создаём помеченного пира.
    const newPeer = {
      name: suggestName,
      comment: "[awgproxy] imported",
      public_key: peer.PublicKey,
      preshared_key: peer.PresharedKey || "",
      allowed_address: peer.AllowedIPs || "",
      endpoint_address: host,
      endpoint_port: port,
      persistent_keepalive: peer.PersistentKeepalive || "",
    };
    const peerRes = await fetch("api/peers", {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(newPeer),
    });
    const peerData = await peerRes.json();
    if (!peerRes.ok) throw new Error(peerData.error || peerRes.statusText);

    showMsg(t("peers.importDone"), "ok");
    closeImport();
    loadPeers();
  } catch (e) {
    showErr(importErr, t("peers.saveFailed") + e.message);
    importApplyBtn.disabled = false;
  }
}

function openImport() {
  clearImport();
  importModal.classList.remove("hidden");
  applyI18n();
}
function closeImport() { importModal.classList.add("hidden"); }

$("#peer-import").addEventListener("click", openImport);
$("#import-file").addEventListener("change", onImportFile);
$("#import-text").addEventListener("input", onImportTextChanged);
$("#import-clear").addEventListener("click", clearImport);
$("#import-apply").addEventListener("click", applyImport);
$("#import-close").addEventListener("click", closeImport);
importModal.addEventListener("click", (e) => { if (e.target === importModal) closeImport(); });

// ---- wire up ----
$("#peer-add").addEventListener("click", () => openEditor(null));
$("#peer-back").addEventListener("click", showPeersList);
$("#peer-save").addEventListener("click", savePeer);
$("#peer-delete").addEventListener("click", () => {
  const p = allPeers.find((x) => x.id === editingId);
  if (p) deletePeer(p);
});
$("#peer-genkey").addEventListener("click", genKeypair);
$("#peer-qr").addEventListener("click", () => openConfigModal());
$("#qr-download").addEventListener("click", downloadConfig);
$("#qr-close").addEventListener("click", closeConfigModal);
qrModal.addEventListener("click", (e) => { if (e.target === qrModal) closeConfigModal(); });
peerSearch.addEventListener("input", renderPeers);
$$(".filter-pills .pill").forEach((b) =>
  b.addEventListener("click", () => {
    currentFilter = b.dataset.filter;
    $$(".filter-pills .pill").forEach((x) => x.classList.toggle("active", x === b));
    renderPeers();
  }));

setInterval(refreshPeers, 10000);
