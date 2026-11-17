#!/usr/bin/env python3
# =============================================================================
#  BariStore — Single-Page App Store UI (HTML / CSS / JS, MIT)
# =============================================================================


def render_html(token, version):
    return _HTML_TEMPLATE.replace("__TOKEN__", token).replace("__VERSION__", version)


_HTML_TEMPLATE = """<!doctype html>
<html lang="en" data-theme="system">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no, viewport-fit=cover">
<link rel="icon" href="/__TOKEN__/icon.svg" type="image/svg+xml">
<title>BariStore</title>
<style>
:root {
  --bg: #f2f2f7;
  --card: #ffffff;
  --card2: #f9f9fb;
  --text: #111114;
  --sub: #6c6c70;
  --border: rgba(60,60,67,0.12);
  --accent: #007aff;
  --accent-soft: rgba(0,122,255,0.12);
  --green: #34c759;
  --orange: #ff9500;
  --red: #ff3b30;
  --purple: #af52de;
  --nav-bg: rgba(255,255,255,0.86);
  --shadow: 0 2px 14px rgba(0,0,0,0.06);
}
@media (prefers-color-scheme: dark) {
  html[data-theme="system"] {
    --bg: #000000;
    --card: #1c1c1e;
    --card2: #2c2c2e;
    --text: #f5f5f7;
    --sub: #98989f;
    --border: rgba(255,255,255,0.12);
    --accent: #0a84ff;
    --accent-soft: rgba(10,132,255,0.18);
    --nav-bg: rgba(28,28,30,0.86);
    --shadow: 0 2px 16px rgba(0,0,0,0.35);
  }
}
html[data-theme="dark"] {
  --bg: #000000;
  --card: #1c1c1e;
  --card2: #2c2c2e;
  --text: #f5f5f7;
  --sub: #98989f;
  --border: rgba(255,255,255,0.12);
  --accent: #0a84ff;
  --accent-soft: rgba(10,132,255,0.18);
  --nav-bg: rgba(28,28,30,0.86);
  --shadow: 0 2px 16px rgba(0,0,0,0.35);
}
* { box-sizing: border-box; -webkit-tap-highlight-color: transparent; }
body {
  margin: 0;
  background: var(--bg);
  color: var(--text);
  font: 15px/1.42 -apple-system, BlinkMacSystemFont, "SF Pro Text", "Segoe UI", sans-serif;
  padding: calc(0.75rem + env(safe-area-inset-top)) 0.9rem calc(5.5rem + env(safe-area-inset-bottom));
}
.container { max-width: 46rem; margin: 0 auto; }
header.topbar {
  display: flex; align-items: center; justify-content: space-between;
  gap: 0.75rem; margin-bottom: 1rem;
}
.brand { display: flex; align-items: center; gap: 0.65rem; }
.brand img { width: 38px; height: 38px; border-radius: 22%; box-shadow: var(--shadow); }
.brand h1 { font-size: 1.45rem; font-weight: 800; margin: 0; letter-spacing: -0.02em; }
.brand .ver { font-size: 0.75rem; color: var(--sub); font-weight: 600; }
.top-actions { display: flex; gap: 0.45rem; align-items: center; }

button, .btn {
  font: inherit; font-weight: 600; border: 0; border-radius: 0.7rem;
  padding: 0.55rem 0.95rem; cursor: pointer; background: var(--accent);
  color: #fff; display: inline-flex; align-items: center; justify-content: center;
  gap: 0.35rem; transition: opacity 0.15s, transform 0.1s; text-decoration: none;
}
button:active, .btn:active { opacity: 0.78; transform: scale(0.98); }
button.pill {
  border-radius: 999px; padding: 0.38rem 0.9rem; font-size: 0.85rem; font-weight: 700;
  background: var(--accent-soft); color: var(--accent);
}
button.secondary { background: var(--card2); color: var(--text); border: 1px solid var(--border); }
button.danger { background: rgba(255,59,48,0.14); color: var(--red); }
button.success { background: rgba(52,199,89,0.16); color: var(--green); }
button.full { width: 100%; padding: 0.78rem; font-size: 0.96rem; }

.card {
  background: var(--card); border-radius: 1rem; padding: 1rem;
  margin-bottom: 0.9rem; box-shadow: var(--shadow); border: 1px solid var(--border);
}
.card-title {
  font-size: 1.05rem; font-weight: 700; margin: 0 0 0.25rem;
  display: flex; align-items: center; justify-content: space-between;
}
.sub { color: var(--sub); font-size: 0.85rem; margin: 0; }
.sec-head {
  display: flex; align-items: baseline; justify-content: space-between;
  margin: 1.15rem 0 0.55rem;
}
.sec-head h2 { font-size: 1.15rem; font-weight: 800; margin: 0; letter-spacing: -0.01em; }

.search-bar {
  display: flex; gap: 0.5rem; margin-bottom: 0.9rem;
}
input[type="text"], input[type="password"], input[type="email"], input[type="url"], input[type="tel"], select {
  width: 100%; font: inherit; padding: 0.68rem 0.85rem;
  border-radius: 0.7rem; border: 1px solid var(--border);
  background: var(--card); color: var(--text); outline: none;
}
input:focus, select:focus { border-color: var(--accent); }

.app-grid {
  display: grid; grid-template-columns: repeat(auto-fill, minmax(19rem, 1fr));
  gap: 0.65rem;
}
.app-row {
  background: var(--card); border-radius: 0.95rem; padding: 0.75rem 0.85rem;
  display: flex; align-items: center; gap: 0.75rem;
  border: 1px solid var(--border); box-shadow: var(--shadow);
}
.app-icon {
  width: 52px; height: 52px; border-radius: 22.5%; flex-shrink: 0;
  object-fit: cover; background: var(--accent-soft);
  display: flex; align-items: center; justify-content: center;
  font-weight: 800; font-size: 1.2rem; color: var(--accent);
  border: 1px solid var(--border);
}
.app-meta { flex: 1; min-width: 0; cursor: pointer; }
.app-name {
  font-weight: 700; font-size: 0.96rem; white-space: nowrap;
  overflow: hidden; text-overflow: ellipsis;
}
.app-sub {
  color: var(--sub); font-size: 0.78rem; white-space: nowrap;
  overflow: hidden; text-overflow: ellipsis; margin-top: 0.1rem;
}
.badge {
  display: inline-block; padding: 0.12rem 0.45rem; border-radius: 0.4rem;
  font-size: 0.7rem; font-weight: 700; background: var(--accent-soft); color: var(--accent);
}
.badge.warn { background: rgba(255,149,0,0.16); color: var(--orange); }
.badge.ok { background: rgba(52,199,89,0.16); color: var(--green); }
.badge.purple { background: rgba(175,82,222,0.16); color: var(--purple); }

.pin-box {
  font-size: 2.8rem; font-weight: 800; letter-spacing: 0.35rem;
  text-align: center; padding: 0.75rem; margin: 0.65rem 0;
  background: var(--card2); border-radius: 0.9rem;
  font-variant-numeric: tabular-nums; border: 1px solid var(--border);
}
.progress-wrap {
  height: 0.48rem; background: var(--card2); border-radius: 99px;
  overflow: hidden; margin: 0.55rem 0;
}
.progress-bar {
  height: 100%; background: var(--accent); width: 0%;
  transition: width 0.3s ease;
}
.progress-bar.indeterminate {
  width: 35% !important;
  animation: slide 1.15s ease-in-out infinite alternate;
}
@keyframes slide { from { margin-left: 0%; } to { margin-left: 65%; } }

.banner {
  position: sticky; top: 0.4rem; z-index: 40;
  background: var(--card); border: 1.5px solid var(--accent);
  border-radius: 1rem; padding: 0.85rem 1rem; margin-bottom: 1rem;
  box-shadow: 0 6px 24px rgba(0,0,0,0.18);
}

.tabbar {
  position: fixed; left: 0; right: 0; bottom: 0; z-index: 50;
  background: var(--nav-bg); -webkit-backdrop-filter: blur(18px); backdrop-filter: blur(18px);
  border-top: 1px solid var(--border);
  display: flex; justify-content: space-around;
  padding: 0.4rem 0.5rem calc(0.45rem + env(safe-area-inset-bottom));
}
.tabbar button {
  background: transparent; color: var(--sub); flex: 1;
  flex-direction: column; gap: 0.15rem; padding: 0.25rem;
  font-size: 0.72rem; font-weight: 600; border-radius: 0.5rem;
}
.tabbar button.active { color: var(--accent); }
.tabbar svg { width: 22px; height: 22px; fill: currentColor; }

.modal-backdrop {
  position: fixed; inset: 0; z-index: 100;
  background: rgba(0,0,0,0.52); -webkit-backdrop-filter: blur(4px); backdrop-filter: blur(4px);
  display: none; align-items: center; justify-content: center; padding: 1rem;
}
.modal-backdrop.open { display: flex; }
.modal {
  background: var(--card); color: var(--text); width: 100%; max-width: 28rem;
  max-height: 86vh; overflow-y: auto; border-radius: 1.15rem;
  padding: 1.15rem; box-shadow: 0 12px 36px rgba(0,0,0,0.35);
  border: 1px solid var(--border);
}
.modal h3 { margin: 0 0 0.4rem; font-size: 1.15rem; }
.kv-row {
  display: flex; justify-content: space-between; align-items: center;
  padding: 0.5rem 0; border-bottom: 1px solid var(--border); font-size: 0.88rem;
}
.kv-row:last-child { border-bottom: 0; }
.step-pills {
  display: flex; gap: 0.4rem; flex-wrap: wrap; margin-bottom: 1rem;
}
.step-pill {
  padding: 0.28rem 0.68rem; border-radius: 99px; font-size: 0.78rem;
  font-weight: 700; background: var(--card2); color: var(--sub);
}
.step-pill.active { background: var(--accent); color: #fff; }
.step-pill.done { background: rgba(52,199,89,0.16); color: var(--green); }
.hidden { display: none !important; }
</style>
</head>
<body>
<div class="container">
  <header class="topbar">
    <div class="brand">
      <img src="/__TOKEN__/icon.svg" alt="BariStore">
      <div>
        <h1>BariStore</h1>
        <div class="ver">v__VERSION__ · On-Device Store</div>
      </div>
    </div>
    <div class="top-actions" id="topActions">
      <button class="pill" onclick="triggerCustomIpaPicker()">+ Custom IPA</button>
      <button class="pill" onclick="openSourcesModal()">Sources</button>
    </div>
  </header>

  <!-- Active Background Task Banner -->
  <div id="jobBanner" class="banner hidden">
    <div style="display:flex;justify-content:space-between;align-items:center;gap:0.5rem">
      <strong id="jobTitle">Working…</strong>
      <button class="danger" style="padding:0.25rem 0.65rem;font-size:0.78rem" onclick="cancelJob()">Cancel</button>
    </div>
    <div id="jobStep" class="sub" style="margin-top:0.25rem"></div>
    <div id="jobPinWrap" class="hidden">
      <div class="pin-box" id="jobPin">------</div>
      <div style="display:flex;gap:0.5rem;margin-bottom:0.4rem">
        <button class="secondary full" onclick="startPiPPin()">Float PIN over Settings (PiP)</button>
      </div>
    </div>
    <div class="progress-wrap"><div id="jobBar" class="progress-bar indeterminate"></div></div>
  </div>

  <!-- ONBOARDING VIEW -->
  <section id="viewOnboarding" class="hidden">
    <div class="card">
      <div class="card-title">Welcome to BariStore</div>
      <p class="sub" style="margin-bottom:0.85rem">One-time setup on this iPhone. After setup finishes, BariStore opens directly into the Store every time.</p>
      <div class="step-pills">
        <span class="step-pill" id="obPill1">1. LocalDevVPN</span>
        <span class="step-pill" id="obPill2">2. Pairing</span>
        <span class="step-pill" id="obPill3">3. Developer Mode</span>
        <span class="step-pill" id="obPill4">4. Apple ID</span>
      </div>
      <div id="obStepBody"></div>
    </div>
  </section>

  <!-- STORE: FEATURED TAB -->
  <section id="viewFeatured" class="hidden">
    <div class="search-bar">
      <input type="text" id="searchInput" placeholder="Search apps, emulators, utilities…" oninput="renderCatalog()">
      <select id="sourceFilter" style="max-width:11rem" onchange="renderCatalog()">
        <option value="">All Sources</option>
      </select>
    </div>

    <div id="storesSection">
      <div class="sec-head">
        <h2>Stores &amp; Containers</h2>
        <span class="sub">Auto-injects pairing file</span>
      </div>
      <div class="app-grid" id="storeVariantsGrid"></div>
    </div>

    <div class="sec-head">
      <h2 id="catalogHeading">Featured Apps</h2>
      <span class="sub" id="catalogCount"></span>
    </div>
    <div class="app-grid" id="catalogGrid"></div>
  </section>

  <!-- STORE: MY APPS TAB -->
  <section id="viewMyApps" class="hidden">
    <div class="sec-head" style="margin-top:0">
      <h2>My Apps</h2>
      <div style="display:flex;gap:0.4rem">
        <button class="pill" onclick="triggerCustomIpaPicker()">+ Install IPA</button>
        <button class="pill" onclick="refreshAllApps()">Refresh All</button>
      </div>
    </div>
    <div id="myAppsList"></div>
  </section>

  <!-- STORE: OPTIONS TAB -->
  <section id="viewOptions" class="hidden">
    <div class="card">
      <div class="card-title">
        <span>Apple ID &amp; Developer Portal</span>
        <span class="badge ok" id="optAccountBadge">Connected</span>
      </div>
      <div id="optAccountDetails" style="margin:0.6rem 0"></div>
      <div style="display:flex;gap:0.5rem;flex-wrap:wrap">
        <button class="secondary" onclick="openAppIdsModal()">App IDs &amp; Certificates</button>
        <button class="secondary" onclick="openLoginModal()">Switch / Re-login Apple ID</button>
      </div>
    </div>

    <div class="card">
      <div class="card-title">
        <span>Device &amp; Pairing</span>
        <span class="badge" id="optPairBadge">Paired</span>
      </div>
      <div id="optDeviceDetails" style="margin:0.6rem 0"></div>
      <div style="display:flex;gap:0.5rem;flex-wrap:wrap">
        <a class="btn secondary" href="/__TOKEN__/api/pair/export" download="ALTPairingFile.mobiledevicepairing">Export Pairing File</a>
        <button class="secondary" onclick="triggerPairingImport()">Import Pairing File</button>
        <button class="secondary" onclick="startPairing(true)">Re-Pair Device</button>
      </div>
    </div>

    <div class="card">
      <div class="card-title"><span>Appearance &amp; Anisette</span></div>
      <div class="kv-row">
        <span>Theme</span>
        <select id="themeSelect" style="width:auto" onchange="saveTheme(this.value)">
          <option value="system">System</option>
          <option value="light">Light</option>
          <option value="dark">Dark</option>
        </select>
      </div>
      <div style="margin-top:0.6rem">
        <label class="sub">Preferred Anisette Server</label>
        <div style="display:flex;gap:0.45rem;margin-top:0.3rem">
          <input type="url" id="anisetteInput" placeholder="https://mac-ani.jkcoxson.com">
          <button class="secondary" onclick="saveAnisetteUrl()">Save</button>
        </div>
      </div>
      <div style="margin-top:0.65rem">
        <button class="secondary full" onclick="runNetcheck()">Test Network &amp; Anisette Servers</button>
        <div id="netcheckOut" style="margin-top:0.5rem"></div>
      </div>
    </div>

    <div class="card">
      <div class="card-title"><span>System &amp; Maintenance</span></div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:0.5rem;margin-top:0.5rem">
        <button class="secondary" onclick="checkUpdates()">Check for Updates</button>
        <button class="secondary" onclick="clearCache()">Clear IPA Cache</button>
        <button class="secondary" onclick="openSetupWizard()">Run Setup Wizard</button>
        <button class="danger" onclick="resetBariStore()">Reset BariStore</button>
      </div>
      <div id="maintOut" class="sub" style="margin-top:0.55rem"></div>
    </div>

    <div class="card">
      <div class="card-title"><span>About BariStore</span></div>
      <p class="sub">BariStore v__VERSION__ — 100% On-Device iOS App Store, Signer, and StikDebug-style JIT Enabler running in a-Shell over LocalDevVPN. MIT Licensed.</p>
    </div>
  </section>
</div>

<!-- Bottom Navigation Tab Bar -->
<nav class="tabbar" id="bottomNav">
  <button id="tabBtnFeatured" class="active" onclick="switchTab('featured')">
    <svg viewBox="0 0 24 24"><path d="M12 2L15.09 8.26L22 9.27L17 14.14L18.18 21.02L12 17.77L5.82 21.02L7 14.14L2 9.27L8.91 8.26L12 2Z"/></svg>
    <span>Featured</span>
  </button>
  <button id="tabBtnMyApps" onclick="switchTab('myapps')">
    <svg viewBox="0 0 24 24"><path d="M4 4h6v6H4V4zm10 0h6v6h-6V4zM4 14h6v6H4v-6zm10 0h6v6h-6v-6z"/></svg>
    <span>My Apps</span>
  </button>
  <button id="tabBtnOptions" onclick="switchTab('options')">
    <svg viewBox="0 0 24 24"><path d="M19.14 12.94c.04-.3.06-.61.06-.94 0-.32-.02-.64-.07-.94l2.03-1.58a.49.49 0 0 0 .12-.61l-1.92-3.32a.49.49 0 0 0-.59-.22l-2.39.96c-.5-.38-1.03-.7-1.62-.94l-.36-2.54a.484.484 0 0 0-.48-.41h-3.84c-.24 0-.43.17-.47.41l-.36 2.54c-.59.24-1.13.57-1.62.94l-2.39-.96c-.22-.08-.47 0-.59.22L2.74 8.87c-.12.21-.08.47.12.61l2.03 1.58c-.05.3-.09.63-.09.94s.02.64.07.94l-2.03 1.58a.49.49 0 0 0-.12.61l1.92 3.32c.12.22.37.29.59.22l2.39-.96c.5.38 1.03.7 1.62.94l.36 2.54c.05.24.24.41.48.41h3.84c.24 0 .44-.17.47-.41l.36-2.54c.59-.24 1.13-.56 1.62-.94l2.39.96c.22.08.47 0 .59-.22l1.92-3.32c.12-.22.07-.47-.12-.61l-2.01-1.58zM12 15.6c-1.98 0-3.6-1.62-3.6-3.6s1.62-3.6 3.6-3.6 3.6 1.62 3.6 3.6-1.62 3.6-3.6 3.6z"/></svg>
    <span>Options</span>
  </button>
</nav>

<!-- Hidden File Inputs & Media Keep-Alive Elements -->
<input type="file" id="ipaFileInput" accept=".ipa,application/octet-stream" class="hidden" onchange="onCustomIpaSelected(this)">
<input type="file" id="pairFileInput" accept=".plist,.mobiledevicepairing,application/xml,application/x-plist" class="hidden" onchange="onPairFileSelected(this)">
<audio id="keepAliveAudio" loop playsinline class="hidden"></audio>
<canvas id="pipCanvas" width="480" height="270" class="hidden"></canvas>
<video id="pipVideo" muted playsinline style="position:fixed;width:1px;height:1px;opacity:0;pointer-events:none"></video>

<!-- Generic Modal Dialog -->
<div class="modal-backdrop" id="modalBackdrop" onclick="if(event.target===this)closeModal()">
  <div class="modal" id="modalContent"></div>
</div>

<script>
"use strict";
const TOKEN = "/__TOKEN__";
let APP = {
  onboarding_complete: false,
  obStep: 1,
  env: { vpn_connected: false, paired: false, udid: "", devmode_on: null },
  state: {},
  catalog: { sources: [], apps: [], store_variants: [] },
  installed_apps: [],
  job: { active: false },
  currentTab: "featured"
};

function esc(s) {
  return String(s ?? "").replace(/[&<>"]/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
}
function fmtBytes(b) {
  const n = Number(b || 0);
  if (!n) return "";
  return (n / 1048576).toFixed(1) + " MB";
}

async function apiGet(path) {
  const r = await fetch(TOKEN + path, { cache: "no-store" });
  return await r.json();
}
async function apiPost(path, body = {}) {
  const r = await fetch(TOKEN + path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
  });
  return await r.json();
}

/* --- Non-Zero Sub-Audible WAV Keep-Alive + Picture-in-Picture PIN --- */
let keepAliveActive = false;
function buildSubAudibleWavDataUri() {
  const sampleRate = 8000;
  const numSamples = 8000;
  const buffer = new ArrayBuffer(44 + numSamples * 2);
  const view = new DataView(buffer);
  const writeStr = (off, s) => { for (let i = 0; i < s.length; i++) view.setUint8(off + i, s.charCodeAt(i)); };
  writeStr(0, "RIFF");
  view.setUint32(4, 36 + numSamples * 2, true);
  writeStr(8, "WAVEfmt ");
  view.setUint32(16, 16, true);
  view.setUint16(20, 1, true);
  view.setUint16(22, 1, true);
  view.setUint32(24, sampleRate, true);
  view.setUint32(28, sampleRate * 2, true);
  view.setUint16(32, 2, true);
  view.setUint16(34, 16, true);
  writeStr(36, "data");
  view.setUint32(40, numSamples * 2, true);
  // 1-LSB oscillation (±1 out of 32767) prevents iOS hardware silence detection from suspending WebKit
  for (let i = 0; i < numSamples; i++) {
    view.setInt16(44 + i * 2, (i & 1) ? 1 : -1, true);
  }
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return "data:audio/wav;base64," + btoa(binary);
}

function startKeepAlive() {
  try {
    const audio = document.getElementById("keepAliveAudio");
    if (audio && !audio.src) audio.src = buildSubAudibleWavDataUri();
    if (audio && audio.paused) audio.play().catch(() => {});
    const AC = window.AudioContext || window.webkitAudioContext;
    if (AC) {
      if (!window.__ac) window.__ac = new AC();
      if (window.__ac.state === "suspended") window.__ac.resume();
      if (!window.__osc) {
        const osc = window.__ac.createOscillator();
        const gain = window.__ac.createGain();
        osc.frequency.value = 1;
        gain.gain.value = 0.0001;
        osc.connect(gain);
        gain.connect(window.__ac.destination);
        osc.start();
        window.__osc = osc;
      }
    }
    if ("wakeLock" in navigator && !window.__wl) {
      navigator.wakeLock.request("screen").then(w => {
        window.__wl = w;
        w.addEventListener("release", () => { window.__wl = null; });
      }).catch(() => {});
    }
    keepAliveActive = true;
  } catch (e) {}
}

function drawPiPFrame(pin) {
  const canvas = document.getElementById("pipCanvas");
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  ctx.fillStyle = "#111116";
  ctx.fillRect(0, 0, canvas.width, canvas.height);
  ctx.fillStyle = "#98989f";
  ctx.font = "bold 22px -apple-system, sans-serif";
  ctx.textAlign = "center";
  ctx.fillText("BariStore Pairing Code", canvas.width / 2, 65);
  ctx.fillStyle = "#ffffff";
  ctx.font = "800 76px -apple-system, monospace";
  ctx.fillText(String(pin || "------").split("").join(" "), canvas.width / 2, 165);
  ctx.fillStyle = "#0a84ff";
  ctx.font = "600 20px -apple-system, sans-serif";
  ctx.fillText("Settings > Developer > Paired Macs", canvas.width / 2, 228);
}

async function startPiPPin() {
  startKeepAlive();
  const pin = APP.job?.pin || "------";
  drawPiPFrame(pin);
  const canvas = document.getElementById("pipCanvas");
  const video = document.getElementById("pipVideo");
  try {
    if (!video.srcObject && canvas.captureStream) {
      video.srcObject = canvas.captureStream(5);
    }
    await video.play();
    if (video.requestPictureInPicture) {
      await video.requestPictureInPicture();
    } else if (video.webkitSetPresentationMode) {
      video.webkitSetPresentationMode("picture-in-picture");
    }
  } catch (e) {
    alert("Keep this PIN ready: " + pin + "\\nOpen Settings > Developer > Paired Macs > BariStore.");
  }
}

/* --- Modal Helpers --- */
function openModal(html) {
  document.getElementById("modalContent").innerHTML = html;
  document.getElementById("modalBackdrop").classList.add("open");
}
function closeModal() {
  document.getElementById("modalBackdrop").classList.remove("open");
}

/* --- Theme --- */
function applyTheme(theme) {
  const t = theme || "system";
  document.documentElement.setAttribute("data-theme", t);
  const sel = document.getElementById("themeSelect");
  if (sel) sel.value = t;
}
async function saveTheme(theme) {
  applyTheme(theme);
  APP.state.theme = theme;
  await apiPost("/api/settings", { theme });
}

/* --- Bootstrap & Navigation --- */
async function initApp() {
  const data = await apiGet("/api/bootstrap");
  if (!data.ok) return;
  APP.onboarding_complete = data.onboarding_complete;
  APP.state = data.state || {};
  APP.catalog = data.catalog || { sources: [], apps: [], store_variants: [] };
  APP.installed_apps = data.installed_apps || [];
  APP.job = data.job || { active: false };
  applyTheme(APP.state.theme);

  if (!APP.onboarding_complete) {
    await enterOnboarding();
  } else {
    showStoreUI();
    // Refresh sources in background without blocking UI
    apiGet("/api/sources").then(res => {
      if (res.ok && res.catalog) {
        APP.catalog = res.catalog;
        renderCatalog();
      }
    }).catch(() => {});
  }
  setInterval(pollStatus, 1200);
}

function showStoreUI() {
  document.getElementById("viewOnboarding").classList.add("hidden");
  document.getElementById("bottomNav").classList.remove("hidden");
  document.getElementById("topActions").classList.remove("hidden");
  switchTab(APP.currentTab || "featured");
  renderCatalog();
  renderMyApps();
  renderOptions();
}

function switchTab(tab) {
  APP.currentTab = tab;
  for (const [id, key] of [
    ["viewFeatured", "featured"],
    ["viewMyApps", "myapps"],
    ["viewOptions", "options"]
  ]) {
    document.getElementById(id).classList.toggle("hidden", tab !== key);
  }
  document.getElementById("tabBtnFeatured").classList.toggle("active", tab === "featured");
  document.getElementById("tabBtnMyApps").classList.toggle("active", tab === "myapps");
  document.getElementById("tabBtnOptions").classList.toggle("active", tab === "options");
  if (tab === "myapps") renderMyApps();
  if (tab === "options") renderOptions();
}

/* --- First-Time Onboarding Wizard --- */
async function enterOnboarding() {
  document.getElementById("viewOnboarding").classList.remove("hidden");
  document.getElementById("viewFeatured").classList.add("hidden");
  document.getElementById("viewMyApps").classList.add("hidden");
  document.getElementById("viewOptions").classList.add("hidden");
  document.getElementById("bottomNav").classList.add("hidden");
  document.getElementById("topActions").classList.add("hidden");

  const envRes = await apiGet("/api/check-env?tunnel=1");
  APP.env = envRes.env || {};

  if (!APP.env.vpn_connected) {
    APP.obStep = 1;
  } else if (!APP.env.paired) {
    APP.obStep = 2;
  } else if (!APP.env.devmode_on) {
    APP.obStep = 3;
  } else if (!APP.state.has_session) {
    APP.obStep = 4;
  } else {
    await completeOnboarding();
    return;
  }
  renderOnboardingStep();
}

function openSetupWizard() {
  APP.onboarding_complete = false;
  enterOnboarding();
}

function renderOnboardingStep() {
  for (let i = 1; i <= 4; i++) {
    const el = document.getElementById("obPill" + i);
    el.className = "step-pill" + (i === APP.obStep ? " active" : (i < APP.obStep ? " done" : ""));
  }
  const box = document.getElementById("obStepBody");
  if (APP.obStep === 1) {
    box.innerHTML = `
      <h3 style="margin:0 0 0.35rem">Step 1: Connect LocalDevVPN</h3>
      <p class="sub" style="margin-bottom:0.85rem">BariStore communicates with this iPhone over the LocalDevVPN loopback (10.7.0.1). Open <b>LocalDevVPN</b> from the App Store, turn the VPN switch ON, then tap Check Connection.</p>
      <div style="display:flex;gap:0.5rem;flex-wrap:wrap">
        <button class="full" onclick="checkObVpn()">Check Connection</button>
        <button class="secondary full" onclick="completeOnboarding()">Skip to Store (Browse Offline)</button>
      </div>
    `;
  } else if (APP.obStep === 2) {
    box.innerHTML = `
      <h3 style="margin:0 0 0.35rem">Step 2: Pair This iPhone</h3>
      <p class="sub" style="margin-bottom:0.85rem">Tap <b>Start Pairing</b> below. BariStore will immediately display a 6-digit PIN and keep a-Shell active in the background while you open <b>Settings &gt; Privacy &amp; Security &gt; Developer Mode &gt; Paired Macs</b> (or <b>Settings &gt; Developer &gt; Paired Macs</b>) and tap <b>BariStore</b>.</p>
      <div style="display:flex;gap:0.5rem;flex-wrap:wrap">
        <button class="full" onclick="startPairing(false)">Start Pairing</button>
        <button class="secondary full" onclick="triggerPairingImport()">Import Existing Pairing File</button>
      </div>
    `;
  } else if (APP.obStep === 3) {
    box.innerHTML = `
      <h3 style="margin:0 0 0.35rem">Step 3: Enable Developer Mode</h3>
      <p class="sub" style="margin-bottom:0.85rem">Developer Mode is required by iOS to launch sideloaded apps. BariStore can reveal the switch in Settings or turn it on right now (which restarts your iPhone; re-open BariStore after reboot).</p>
      <div id="obDevmodeMsg" class="sub" style="margin-bottom:0.65rem;color:var(--accent);font-weight:600"></div>
      <div style="display:flex;gap:0.5rem;flex-wrap:wrap">
        <button class="full" onclick="obDevmodeAction('on')">Enable &amp; Restart iPhone Now</button>
        <button class="secondary full" onclick="obDevmodeAction('show')">Reveal Developer Mode Switch in Settings</button>
        <button class="secondary full" onclick="obVerifyDevmode()">Verify Developer Mode is ON</button>
      </div>
    `;
  } else if (APP.obStep === 4) {
    box.innerHTML = `
      <h3 style="margin:0 0 0.35rem">Step 4: Sign In with Apple ID</h3>
      <p class="sub" style="margin-bottom:0.85rem">Sign in with your free Apple ID. Your password is used locally via SRP-6a zero-knowledge proof and is never stored; your session stays signed in for future installs and refreshes.</p>
      <div style="display:flex;flex-direction:column;gap:0.55rem">
        <input type="email" id="obEmail" placeholder="Apple ID (email)" value="${esc(APP.state.email || '')}" autocapitalize="off" autocorrect="off">
        <input type="password" id="obPassword" placeholder="Password">
        <div id="obLoginErr" class="sub" style="color:var(--red)"></div>
        <button class="full" id="obLoginBtn" onclick="submitObLogin()">Sign In &amp; Finish Setup</button>
      </div>
    `;
  }
}

async function checkObVpn() {
  startKeepAlive();
  const res = await apiGet("/api/check-env?tunnel=1");
  APP.env = res.env || {};
  if (!APP.env.vpn_connected) {
    alert("LocalDevVPN is not responding on 10.7.0.1 yet. Make sure LocalDevVPN is connected.");
    return;
  }
  if (!APP.env.paired) APP.obStep = 2;
  else if (!APP.env.devmode_on) APP.obStep = 3;
  else if (!APP.state.has_session) APP.obStep = 4;
  else { await completeOnboarding(); return; }
  renderOnboardingStep();
}

async function obDevmodeAction(action) {
  const msgEl = document.getElementById("obDevmodeMsg");
  if (msgEl) msgEl.textContent = "Contacting device over tunnel…";
  const res = await apiPost("/api/devmode", { action });
  if (!res.ok) {
    if (msgEl) msgEl.textContent = res.error || "Action failed.";
    return;
  }
  if (msgEl) msgEl.textContent = res.result?.message || "Done.";
}

async function obVerifyDevmode() {
  const res = await apiPost("/api/devmode", { action: "status" });
  if (res.ok && res.result?.devmode_on) {
    APP.env.devmode_on = true;
    APP.obStep = APP.state.has_session ? 5 : 4;
    if (APP.obStep === 5) await completeOnboarding();
    else renderOnboardingStep();
  } else {
    const msgEl = document.getElementById("obDevmodeMsg");
    if (msgEl) msgEl.textContent = "Developer Mode is still OFF. Enable it in Settings > Privacy & Security > Developer Mode.";
  }
}

async function submitObLogin() {
  const email = document.getElementById("obEmail").value.trim();
  const password = document.getElementById("obPassword").value;
  const errEl = document.getElementById("obLoginErr");
  const btn = document.getElementById("obLoginBtn");
  if (!email || !password) {
    errEl.textContent = "Please enter both your Apple ID and password.";
    return;
  }
  errEl.textContent = "Signing in with Apple (SRP-6a)…";
  btn.disabled = true;
  const res = await apiPost("/api/apple/login", { email, password });
  btn.disabled = false;
  if (!res.ok) {
    errEl.textContent = res.error || "Sign-in failed.";
    return;
  }
  if (res.result.status === "2fa_required") {
    open2FAModal(res.result.login_id, res.result.message, true);
  } else {
    APP.state.email = res.result.email;
    APP.state.team_id = res.result.team_id;
    APP.state.team_name = res.result.team_name;
    APP.state.has_session = true;
    await completeOnboarding();
  }
}

async function completeOnboarding() {
  await apiPost("/api/onboarding/complete", {});
  const data = await apiGet("/api/bootstrap");
  if (data.ok) {
    APP.onboarding_complete = true;
    APP.state = data.state || APP.state;
    APP.catalog = data.catalog || APP.catalog;
    APP.installed_apps = data.installed_apps || APP.installed_apps;
  }
  showStoreUI();
}

/* --- Apple ID Login & 2FA Modals --- */
function openLoginModal() {
  openModal(`
    <h3>Apple ID Sign-In</h3>
    <p class="sub" style="margin-bottom:0.75rem">Your session stays active so you never need to re-enter your password unless you switch accounts.</p>
    <div style="display:flex;flex-direction:column;gap:0.55rem">
      <input type="email" id="modEmail" placeholder="Apple ID (email)" value="${esc(APP.state.email || '')}" autocapitalize="off" autocorrect="off">
      <input type="password" id="modPassword" placeholder="Password">
      <div id="modLoginErr" class="sub" style="color:var(--red)"></div>
      <button class="full" id="modLoginBtn" onclick="submitModalLogin()">Sign In</button>
      <button class="secondary full" onclick="closeModal()">Cancel</button>
    </div>
  `);
}

async function submitModalLogin() {
  const email = document.getElementById("modEmail").value.trim();
  const password = document.getElementById("modPassword").value;
  const errEl = document.getElementById("modLoginErr");
  const btn = document.getElementById("modLoginBtn");
  if (!email || !password) {
    errEl.textContent = "Enter your Apple ID and password.";
    return;
  }
  errEl.textContent = "Authenticating with Apple…";
  btn.disabled = true;
  const res = await apiPost("/api/apple/login", { email, password });
  btn.disabled = false;
  if (!res.ok) {
    errEl.textContent = res.error || "Sign-in failed.";
    return;
  }
  if (res.result.status === "2fa_required") {
    open2FAModal(res.result.login_id, res.result.message, false);
  } else {
    APP.state.email = res.result.email;
    APP.state.team_id = res.result.team_id;
    APP.state.team_name = res.result.team_name;
    APP.state.has_session = true;
    closeModal();
    renderOptions();
  }
}

function open2FAModal(loginId, message, isOnboarding) {
  openModal(`
    <h3>Two-Factor Authentication</h3>
    <p class="sub" style="margin-bottom:0.75rem">${esc(message)}</p>
    <input type="tel" id="tfaCode" placeholder="6-digit code" maxlength="6" inputmode="numeric" autocomplete="one-time-code" style="font-size:1.4rem;text-align:center;letter-spacing:0.3rem;font-weight:700">
    <div id="tfaErr" class="sub" style="color:var(--red);margin-top:0.4rem"></div>
    <button class="full" style="margin-top:0.65rem" id="tfaBtn" onclick="submit2FA('${esc(loginId)}', ${Boolean(isOnboarding)})">Verify Code</button>
  `);
  setTimeout(() => document.getElementById("tfaCode")?.focus(), 100);
}

async function submit2FA(loginId, isOnboarding) {
  const code = document.getElementById("tfaCode").value.trim();
  const errEl = document.getElementById("tfaErr");
  const btn = document.getElementById("tfaBtn");
  errEl.textContent = "Verifying with Apple…";
  btn.disabled = true;
  const res = await apiPost("/api/apple/2fa", { login_id: loginId, code });
  btn.disabled = false;
  if (!res.ok) {
    errEl.textContent = res.error || "Invalid verification code.";
    return;
  }
  APP.state.email = res.result.email;
  APP.state.team_id = res.result.team_id;
  APP.state.team_name = res.result.team_name;
  APP.state.has_session = true;
  closeModal();
  if (isOnboarding) await completeOnboarding();
  else renderOptions();
}

/* --- Pairing & Job Polling --- */
async function startPairing(fresh) {
  startKeepAlive();
  const res = await apiPost("/api/pair/start", { fresh: Boolean(fresh) });
  if (!res.ok) {
    alert(res.error || "Could not start pairing.");
    return;
  }
  pollStatus();
}

function triggerPairingImport() {
  document.getElementById("pairFileInput").value = "";
  document.getElementById("pairFileInput").click();
}

function onPairFileSelected(input) {
  const file = input.files?.[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = async () => {
    const base64 = String(reader.result).split(",")[1] || "";
    const res = await apiPost("/api/pair/import", { data_base64: base64 });
    if (!res.ok) {
      alert(res.error || "Could not import pairing file.");
      return;
    }
    APP.state.paired = true;
    APP.state.udid = res.env?.udid || APP.state.udid;
    APP.state.devmode_on = res.env?.devmode_on;
    if (!APP.onboarding_complete) {
      APP.obStep = res.env?.devmode_on ? (APP.state.has_session ? 5 : 4) : 3;
      if (APP.obStep === 5) await completeOnboarding();
      else renderOnboardingStep();
    } else {
      renderOptions();
      alert("Pairing file imported! UDID: " + (APP.state.udid || "verified"));
    }
  };
  reader.readAsDataURL(file);
}

let lastHandledJobId = 0;
async function pollStatus() {
  try {
    const res = await apiGet("/api/status");
    if (!res.ok || !res.job) return;
    const job = res.job;
    APP.job = job;
    const banner = document.getElementById("jobBanner");
    if (job.active) {
      startKeepAlive();
      banner.classList.remove("hidden");
      document.getElementById("jobTitle").textContent = job.title || "Working…";
      document.getElementById("jobStep").textContent = job.step || "";
      const pinWrap = document.getElementById("jobPinWrap");
      if (job.pin) {
        pinWrap.classList.remove("hidden");
        document.getElementById("jobPin").textContent = job.pin;
        drawPiPFrame(job.pin);
      } else {
        pinWrap.classList.add("hidden");
      }
      const bar = document.getElementById("jobBar");
      if (typeof job.progress === "number") {
        bar.classList.remove("indeterminate");
        bar.style.width = job.progress + "%";
      } else {
        bar.classList.add("indeterminate");
      }
    } else {
      banner.classList.add("hidden");
      if (job.id && job.id !== lastHandledJobId) {
        lastHandledJobId = job.id;
        if (job.prompt) {
          handleJobPrompt(job.prompt);
        } else if (job.error) {
          alert(job.error);
        } else if (job.result) {
          await onJobFinished(job);
        }
      }
    }
  } catch (e) {}
}

async function onJobFinished(job) {
  const boot = await apiGet("/api/bootstrap");
  if (boot.ok) {
    APP.state = boot.state || APP.state;
    APP.installed_apps = boot.installed_apps || APP.installed_apps;
  }
  if (job.kind === "pair") {
    if (!APP.onboarding_complete) {
      APP.obStep = job.result?.devmode_on ? (APP.state.has_session ? 5 : 4) : 3;
      if (APP.obStep === 5) await completeOnboarding();
      else renderOnboardingStep();
    } else {
      renderOptions();
    }
  } else if (job.kind === "install" || job.kind === "refresh-all") {
    renderMyApps();
    renderCatalog();
  }
}

async function cancelJob() {
  await apiPost("/api/job/cancel", {});
  pollStatus();
}

/* --- Featured Catalog & Multi-Source Rendering --- */
function iconHtml(url, name) {
  const letter = esc((name || "?").trim()[0] || "?").toUpperCase();
  if (!url) return `<div class="app-icon">${letter}</div>`;
  return `<img class="app-icon" src="${esc(url)}" alt="" loading="lazy" onerror="this.outerHTML='<div class=\\'app-icon\\'>${letter}</div>'">`;
}

function renderCatalog() {
  const q = (document.getElementById("searchInput")?.value || "").trim().toLowerCase();
  const srcFilter = document.getElementById("sourceFilter")?.value || "";

  // Populate source filter dropdown
  const sel = document.getElementById("sourceFilter");
  if (sel) {
    const current = sel.value;
    const opts = ['<option value="">All Sources</option>'].concat(
      (APP.catalog.sources || []).map(s => `<option value="${esc(s.url)}">${esc(s.name)} (${s.app_count})</option>`)
    );
    sel.innerHTML = opts.join("");
    sel.value = current;
  }

  // Render built-in Store & Container variants
  const storesSec = document.getElementById("storesSection");
  const vGrid = document.getElementById("storeVariantsGrid");
  const variants = (APP.catalog.store_variants || []).filter(v =>
    !srcFilter && (!q || v.name.toLowerCase().includes(q) || v.subtitle.toLowerCase().includes(q))
  );
  if (variants.length) {
    storesSec.classList.remove("hidden");
    vGrid.innerHTML = variants.map(v => `
      <div class="app-row">
        ${iconHtml(v.icon_url, v.name)}
        <div class="app-meta" onclick="openVariantDetail('${esc(v.id)}')">
          <div class="app-name">${esc(v.name)}</div>
          <div class="app-sub">${esc(v.subtitle)}</div>
          ${v.warning ? '<span class="badge warn" style="margin-top:0.2rem">Nightly</span>' : '<span class="badge ok" style="margin-top:0.2rem">Auto-Pairing</span>'}
        </div>
        <button class="pill" onclick="installVariant('${esc(v.id)}')">GET</button>
      </div>
    `).join("");
  } else {
    storesSec.classList.add("hidden");
  }

  // Render AltSource apps
  const apps = (APP.catalog.apps || []).filter(a => {
    if (srcFilter && !a.offers.some(o => o.source_url === srcFilter)) return false;
    if (!q) return true;
    return (
      a.name.toLowerCase().includes(q) ||
      a.bundle_id.toLowerCase().includes(q) ||
      (a.developer || "").toLowerCase().includes(q) ||
      (a.subtitle || "").toLowerCase().includes(q)
    );
  });

  document.getElementById("catalogCount").textContent = apps.length + " apps";
  const grid = document.getElementById("catalogGrid");
  if (!apps.length) {
    grid.innerHTML = `<div class="card" style="grid-column:1/-1"><p class="sub">No matching apps found. Tap <b>Sources</b> at the top to refresh or add an AltSource.</p></div>`;
    return;
  }

  grid.innerHTML = apps.map(a => {
    const installed = APP.installed_apps.find(
      i => i.original_bundle_id === a.bundle_id || i.base_bundle_id === a.bundle_id
    );
    const btnLabel = installed ? "UPDATE" : "GET";
    const multiBadge = a.multi_source
      ? `<span class="badge purple">${a.source_count} Sources</span>`
      : `<span class="badge">${esc(a.source_name)}</span>`;
    return `
      <div class="app-row">
        ${iconHtml(a.icon_url, a.name)}
        <div class="app-meta" onclick="openAppDetail('${esc(a.bundle_id)}')">
          <div class="app-name">${esc(a.name)}</div>
          <div class="app-sub">v${esc(a.version)} · ${esc(a.developer)}${a.size ? ' · ' + fmtBytes(a.size) : ''}</div>
          <div style="margin-top:0.2rem">${multiBadge}</div>
        </div>
        <button class="pill" onclick="onTapGetApp('${esc(a.bundle_id)}')">${btnLabel}</button>
      </div>
    `;
  }).join("");
}

function openVariantDetail(variantId) {
  const v = (APP.catalog.store_variants || []).find(x => x.id === variantId);
  if (!v) return;
  openModal(`
    <div style="display:flex;align-items:center;gap:0.8rem;margin-bottom:0.75rem">
      ${iconHtml(v.icon_url, v.name)}
      <div>
        <h3 style="margin:0">${esc(v.name)}</h3>
        <div class="sub">${esc(v.subtitle)}</div>
      </div>
    </div>
    <p style="font-size:0.9rem">${esc(v.description || '')}</p>
    ${v.warning ? `<p class="sub" style="color:var(--orange)">⚠️ ${esc(v.warning)}</p>` : ''}
    <div class="kv-row"><span>Bundle ID</span><code>${esc(v.bundle_id)}</code></div>
    <div class="kv-row"><span>Pairing Injection</span><span class="badge ok">Automatic</span></div>
    <div style="display:flex;gap:0.5rem;margin-top:0.85rem">
      <button class="full" onclick="closeModal();installVariant('${esc(v.id)}')">Install Now</button>
      <button class="secondary" onclick="closeModal();openCustomInstallModal({kind:'variant',variant_id:'${esc(v.id)}',name:'${esc(v.name)}',bundle_id:'${esc(v.bundle_id)}',icon_url:'${esc(v.icon_url||'')}'})">Custom…</button>
    </div>
  `);
}

function installVariant(variantId) {
  const v = (APP.catalog.store_variants || []).find(x => x.id === variantId);
  if (!v) return;
  triggerInstall({
    kind: "variant",
    variant_id: v.id,
    name: v.name,
    bundle_id: v.bundle_id,
    icon_url: v.icon_url || ""
  });
}

function onTapGetApp(bundleId) {
  const app = (APP.catalog.apps || []).find(a => a.bundle_id === bundleId);
  if (!app) return;
  if (app.offers && app.offers.length > 1) {
    openSourcePickerModal(app);
    return;
  }
  const offer = (app.offers && app.offers[0]) || app;
  triggerInstall({
    kind: "altsource",
    name: app.name,
    bundle_id: app.bundle_id,
    version: offer.version,
    download_url: offer.download_url,
    size: offer.size,
    sha256: offer.sha256,
    icon_url: app.icon_url,
    source_name: offer.source_name
  });
}

function openSourcePickerModal(app) {
  openModal(`
    <h3>Choose Source for ${esc(app.name)}</h3>
    <p class="sub" style="margin-bottom:0.75rem">This app is available in ${app.offers.length} AltSources. Select which source to install from:</p>
    <div style="display:flex;flex-direction:column;gap:0.5rem">
      ${app.offers.map((o, idx) => `
        <div class="card" style="margin:0;padding:0.75rem;display:flex;justify-content:space-between;align-items:center">
          <div>
            <div style="font-weight:700">${esc(o.source_name)}</div>
            <div class="sub">v${esc(o.version)}${o.size ? ' · ' + fmtBytes(o.size) : ''}${o.date ? ' · ' + esc(String(o.date).slice(0,10)) : ''}</div>
          </div>
          <button class="pill" onclick="installFromOffer('${esc(app.bundle_id)}', ${idx})">Install</button>
        </div>
      `).join("")}
    </div>
    <button class="secondary full" style="margin-top:0.75rem" onclick="closeModal()">Cancel</button>
  `);
}

function installFromOffer(bundleId, offerIndex) {
  const app = (APP.catalog.apps || []).find(a => a.bundle_id === bundleId);
  if (!app || !app.offers[offerIndex]) return;
  const offer = app.offers[offerIndex];
  closeModal();
  triggerInstall({
    kind: "altsource",
    name: app.name,
    bundle_id: app.bundle_id,
    version: offer.version,
    download_url: offer.download_url,
    size: offer.size,
    sha256: offer.sha256,
    icon_url: app.icon_url,
    source_name: offer.source_name
  });
}

function openAppDetail(bundleId) {
  const app = (APP.catalog.apps || []).find(a => a.bundle_id === bundleId);
  if (!app) return;
  const offer = (app.offers && app.offers[0]) || app;
  openModal(`
    <div style="display:flex;align-items:center;gap:0.8rem;margin-bottom:0.75rem">
      ${iconHtml(app.icon_url, app.name)}
      <div>
        <h3 style="margin:0">${esc(app.name)}</h3>
        <div class="sub">${esc(app.developer)} · v${esc(app.version)}</div>
      </div>
    </div>
    <p style="font-size:0.88rem;max-height:10rem;overflow-y:auto;white-space:pre-line">${esc(app.description || app.subtitle || '')}</p>
    <div class="kv-row"><span>Bundle ID</span><code>${esc(app.bundle_id)}</code></div>
    <div class="kv-row"><span>Size</span><span>${fmtBytes(app.size) || 'Unknown'}</span></div>
    <div class="kv-row"><span>Available Sources</span><span>${app.offers.map(o => esc(o.source_name)).join(", ")}</span></div>
    <div style="display:flex;gap:0.5rem;margin-top:0.85rem">
      <button class="full" onclick="closeModal();onTapGetApp('${esc(app.bundle_id)}')">Install</button>
      <button class="secondary" onclick="closeModal();openCustomInstallModal({kind:'altsource',name:'${esc(app.name)}',bundle_id:'${esc(app.bundle_id)}',version:'${esc(offer.version)}',download_url:'${esc(offer.download_url)}',size:${Number(offer.size||0)},sha256:'${esc(offer.sha256||'')}',icon_url:'${esc(app.icon_url||'')}',source_name:'${esc(offer.source_name||'')}'})">Custom Install…</button>
    </div>
  `);
}

/* --- Custom Install & App ID Slot Saver Modal --- */
let pendingCustomParams = null;
function openCustomInstallModal(params, extensions = []) {
  pendingCustomParams = params;
  const extHtml = extensions.length ? `
    <div style="margin-top:0.65rem">
      <label class="sub" style="display:block;margin-bottom:0.3rem">App Extensions Found (${extensions.length}):</label>
      ${extensions.map(e => `
        <label style="display:flex;align-items:center;gap:0.5rem;font-size:0.85rem;padding:0.25rem 0">
          <input type="checkbox" class="ext-keep-cb" value="${esc(e.folder)}">
          <span>Keep <b>${esc(e.name)}</b> (<code>${esc(e.bundle_id)}</code>)</span>
        </label>
      `).join("")}
    </div>
  ` : "";

  openModal(`
    <h3>Custom Install · ${esc(params.name || 'App')}</h3>
    <p class="sub" style="margin-bottom:0.75rem">Customize display name, bundle identifier, or strip app extensions (.appex) to save your free Apple account's 10 App ID slots.</p>
    <div style="display:flex;flex-direction:column;gap:0.55rem">
      <div>
        <label class="sub">Display Name</label>
        <input type="text" id="custName" value="${esc(params.name || '')}">
      </div>
      <div>
        <label class="sub">Base Bundle Identifier</label>
        <input type="text" id="custBundleId" value="${esc(params.bundle_id || '')}" autocapitalize="off" autocorrect="off">
      </div>
      <label style="display:flex;align-items:center;gap:0.5rem;margin-top:0.25rem;font-weight:600">
        <input type="checkbox" id="custDropExt" checked>
        <span>Remove App Extensions (App ID Slot Saver)</span>
      </label>
      ${extHtml}
      <div style="display:flex;gap:0.5rem;margin-top:0.65rem">
        <button class="full" onclick="submitCustomInstall()">Install</button>
        <button class="secondary" onclick="closeModal()">Cancel</button>
      </div>
    </div>
  `);
}

function submitCustomInstall() {
  if (!pendingCustomParams) return;
  const params = Object.assign({}, pendingCustomParams);
  params.custom_name = document.getElementById("custName").value.trim();
  params.custom_bundle_id = document.getElementById("custBundleId").value.trim();
  params.drop_extensions = document.getElementById("custDropExt").checked;
  closeModal();
  triggerInstall(params);
}

async function triggerInstall(params) {
  startKeepAlive();
  const res = await apiPost("/api/install", params);
  if (!res.ok) {
    openModal(`
      <h3>Action Needed</h3>
      <p class="sub" style="margin:0.5rem 0 0.9rem;font-size:0.92rem;color:var(--text)">${esc(res.error || 'Could not start installation.')}</p>
      <div style="display:flex;gap:0.5rem">
        <button class="full" onclick="closeModal();triggerInstall(pendingRetryParams)" id="retryInstallBtn">Retry</button>
        <button class="secondary" onclick="closeModal()">Close</button>
      </div>
    `);
    window.pendingRetryParams = params;
    return;
  }
  pollStatus();
}

function handleJobPrompt(prompt) {
  window.pendingRetryParams = prompt.retry_params || {};
  if (prompt.type === "appid_limit") {
    const existing = prompt.existing_app_ids || [];
    openModal(`
      <h3>App ID Limit Reached (10/10)</h3>
      <p class="sub" style="margin-bottom:0.75rem">${esc(prompt.message)} Choose an existing registered App ID to reuse for this install (and strip app extensions):</p>
      <select id="reuseAppIdSelect" style="margin-bottom:0.75rem">
        ${existing.map(a => `<option value="${esc(a.identifier)}">${esc(a.name)} (${esc(a.identifier)})</option>`).join("")}
      </select>
      <div style="display:flex;gap:0.5rem">
        <button class="full" onclick="retryWithReusedAppId()">Reuse Selected App ID &amp; Install</button>
        <button class="secondary" onclick="closeModal()">Cancel</button>
      </div>
    `);
  } else if (prompt.type === "cert_limit") {
    const certs = prompt.certs || [];
    openModal(`
      <h3>Certificate Limit Reached</h3>
      <p class="sub" style="margin-bottom:0.75rem">Your Apple ID has reached the maximum number of development certificates. Select one to revoke and continue:</p>
      <select id="revokeCertSelect" style="margin-bottom:0.75rem">
        ${certs.map(c => `<option value="${esc(c.serial)}">${esc(c.name)} (${esc(c.machine)})</option>`).join("")}
      </select>
      <div style="display:flex;gap:0.5rem">
        <button class="danger full" onclick="retryWithRevokedCert()">Revoke &amp; Continue</button>
        <button class="secondary" onclick="closeModal()">Cancel</button>
      </div>
    `);
  }
}

function retryWithReusedAppId() {
  const sel = document.getElementById("reuseAppIdSelect");
  const params = Object.assign({}, window.pendingRetryParams || {});
  params.reuse_full_bundle_id = sel ? sel.value : "";
  params.drop_extensions = true;
  closeModal();
  triggerInstall(params);
}

function retryWithRevokedCert() {
  const sel = document.getElementById("revokeCertSelect");
  const params = Object.assign({}, window.pendingRetryParams || {});
  params.revoke_serial = sel ? sel.value : "";
  closeModal();
  triggerInstall(params);
}

/* --- Custom IPA File Picker --- */
function triggerCustomIpaPicker() {
  document.getElementById("ipaFileInput").value = "";
  document.getElementById("ipaFileInput").click();
}

function onCustomIpaSelected(input) {
  const file = input.files?.[0];
  if (!file) return;
  openModal(`<h3>Reading ${esc(file.name)}…</h3><p class="sub">Inspecting IPA bundle &amp; extensions…</p>`);
  const reader = new FileReader();
  reader.onload = async () => {
    const base64 = String(reader.result).split(",")[1] || "";
    const res = await apiPost("/api/ipa/upload", { filename: file.name, data_base64: base64 });
    if (!res.ok) {
      closeModal();
      alert(res.error || "Failed to read IPA.");
      return;
    }
    const ipa = res.ipa;
    openCustomInstallModal({
      kind: "custom",
      local_ipa: ipa.local_ipa,
      name: ipa.name,
      bundle_id: ipa.bundle_id,
      version: ipa.version,
      size: ipa.size,
      source_name: "Custom IPA"
    }, ipa.extensions || []);
  };
  reader.readAsDataURL(file);
}

/* --- Sources Modal --- */
function openSourcesModal() {
  const list = APP.catalog.sources || [];
  openModal(`
    <h3>AltSources (${list.length})</h3>
    <div style="display:flex;gap:0.45rem;margin:0.65rem 0">
      <input type="url" id="newSourceUrl" placeholder="https://example.com/apps.json" autocapitalize="off" autocorrect="off">
      <button onclick="addSourceFromModal()">Add</button>
    </div>
    <div id="sourceModalMsg" class="sub" style="margin-bottom:0.5rem"></div>
    <div style="max-height:18rem;overflow-y:auto">
      ${list.map(s => `
        <div class="kv-row">
          <div style="min-width:0;flex:1;padding-right:0.5rem">
            <div style="font-weight:700;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${esc(s.name)}</div>
            <div class="sub" style="font-size:0.75rem;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${esc(s.url)} · ${s.app_count} apps</div>
          </div>
          <button class="danger" style="padding:0.28rem 0.6rem;font-size:0.75rem" onclick="removeSource('${esc(s.url)}')">Remove</button>
        </div>
      `).join("")}
    </div>
    <div style="display:flex;gap:0.5rem;margin-top:0.85rem">
      <button class="secondary full" onclick="refreshSourcesNow()">Refresh All</button>
      <button class="secondary" onclick="resetDefaultSources()">Reset Defaults</button>
      <button class="secondary" onclick="closeModal()">Done</button>
    </div>
  `);
}

async function addSourceFromModal() {
  const url = document.getElementById("newSourceUrl").value.trim();
  const msg = document.getElementById("sourceModalMsg");
  if (!url) return;
  msg.textContent = "Fetching & verifying source…";
  const res = await apiPost("/api/sources/add", { url });
  if (!res.ok) {
    msg.textContent = res.error || "Could not add source.";
    return;
  }
  APP.catalog = res.catalog;
  renderCatalog();
  openSourcesModal();
}

async function removeSource(url) {
  const res = await apiPost("/api/sources/remove", { url });
  if (res.ok) {
    APP.catalog = res.catalog;
    renderCatalog();
    openSourcesModal();
  }
}

async function refreshSourcesNow() {
  const msg = document.getElementById("sourceModalMsg");
  if (msg) msg.textContent = "Refreshing all sources…";
  const res = await apiGet("/api/sources?refresh=1");
  if (res.ok) {
    APP.catalog = res.catalog;
    renderCatalog();
    openSourcesModal();
  }
}

async function resetDefaultSources() {
  const res = await apiPost("/api/sources/reset", {});
  if (res.ok) {
    APP.catalog = res.catalog;
    renderCatalog();
    openSourcesModal();
  }
}

/* --- My Apps Tab (Refresh, Delete, JIT Enabler, Pairing Injection, App Info) --- */
function daysLeftBadge(expiresAt) {
  if (!expiresAt) return '<span class="badge">7d</span>';
  const diff = Number(expiresAt) - Math.floor(Date.now() / 1000);
  const days = Math.max(0, Math.ceil(diff / 86400));
  if (days <= 0) return '<span class="badge warn">Expired</span>';
  if (days <= 2) return `<span class="badge warn">${days}d left</span>`;
  return `<span class="badge ok">${days}d left</span>`;
}

function renderMyApps() {
  const box = document.getElementById("myAppsList");
  const apps = APP.installed_apps || [];
  if (!apps.length) {
    box.innerHTML = `
      <div class="card">
        <div class="card-title">No Installed Apps Yet</div>
        <p class="sub">Install any app from the <b>Featured</b> tab or tap <b>+ Install IPA</b> to sideload your own .ipa file.</p>
      </div>
    `;
    return;
  }
  box.innerHTML = apps.map((a, idx) => `
    <div class="card" style="padding:0.85rem">
      <div style="display:flex;align-items:center;gap:0.75rem">
        ${iconHtml(a.icon_url, a.name)}
        <div style="flex:1;min-width:0">
          <div style="display:flex;align-items:center;gap:0.45rem">
            <span class="app-name">${esc(a.name)}</span>
            ${daysLeftBadge(a.expires_at)}
          </div>
          <div class="app-sub">v${esc(a.version || '1.0')} · <code>${esc(a.bundle_id)}</code></div>
        </div>
        <button class="pill" onclick="refreshSingleApp(${idx})">Refresh</button>
      </div>
      <div style="display:flex;gap:0.4rem;flex-wrap:wrap;margin-top:0.65rem;padding-top:0.6rem;border-top:1px solid var(--border)">
        <button class="secondary" style="padding:0.32rem 0.7rem;font-size:0.78rem" onclick="enableAppJit('${esc(a.bundle_id)}', '${esc(a.name)}')">⚡ Enable JIT</button>
        <button class="secondary" style="padding:0.32rem 0.7rem;font-size:0.78rem" onclick="injectAppPairing('${esc(a.bundle_id)}')">🔑 Inject Pairing</button>
        <button class="secondary" style="padding:0.32rem 0.7rem;font-size:0.78rem" onclick="showInstalledAppInfo(${idx})">ℹ️ App ID Info</button>
        <button class="danger" style="padding:0.32rem 0.7rem;font-size:0.78rem;margin-left:auto" onclick="deleteInstalledApp('${esc(a.bundle_id)}', '${esc(a.name)}')">Delete</button>
      </div>
    </div>
  `).join("");
}

function refreshSingleApp(idx) {
  const a = APP.installed_apps[idx];
  if (!a) return;
  triggerInstall({
    kind: "refresh",
    name: a.name,
    bundle_id: a.base_bundle_id || a.original_bundle_id || a.bundle_id,
    reuse_full_bundle_id: a.bundle_id,
    version: a.version,
    download_url: a.download_url || "",
    local_ipa: a.local_ipa || "",
    icon_url: a.icon_url || "",
    source_name: a.source_name || "BariStore",
    drop_extensions: Boolean(a.drop_extensions)
  });
}

async function refreshAllApps() {
  startKeepAlive();
  const res = await apiPost("/api/apps/refresh-all", {});
  if (!res.ok) {
    alert(res.error || "Could not start Refresh All.");
    return;
  }
  pollStatus();
}

async function enableAppJit(bundleId, name) {
  openModal(`<h3>Enabling JIT for ${esc(name)}…</h3><p class="sub">Connecting to debugproxy over loopback tunnel…</p>`);
  const res = await apiPost("/api/apps/jit", { bundle_id: bundleId });
  if (!res.ok) {
    openModal(`
      <h3>JIT Enable Notice</h3>
      <p class="sub" style="margin:0.5rem 0 0.9rem;color:var(--text)">${esc(res.error)}</p>
      <div style="display:flex;gap:0.5rem">
        <button class="full" onclick="enableAppJit('${esc(bundleId)}', '${esc(name)}')">Retry Enable JIT</button>
        <button class="secondary" onclick="closeModal()">Close</button>
      </div>
    `);
    return;
  }
  openModal(`
    <h3>⚡ JIT Enabled!</h3>
    <p class="sub" style="margin:0.5rem 0 0.9rem;color:var(--text)">Attached and detached cleanly via <code>debugproxy</code> for <b>${esc(name)}</b> (<code>${esc(res.result?.executable || bundleId)}</code>). You can switch back to the app now.</p>
    <button class="full" onclick="closeModal()">Done</button>
  `);
}

async function injectAppPairing(bundleId) {
  const res = await apiPost("/api/apps/inject-pairing", { bundle_id: bundleId });
  if (!res.ok) {
    alert(res.error || "Failed to inject pairing file.");
    return;
  }
  alert(res.message || "Pairing file injected!");
}

function showInstalledAppInfo(idx) {
  const a = APP.installed_apps[idx];
  if (!a) return;
  const exp = a.expires_at ? new Date(a.expires_at * 1000).toLocaleString() : "Unknown";
  openModal(`
    <h3>${esc(a.name)} · App Info</h3>
    <div class="kv-row"><span>Signed Bundle ID</span><code>${esc(a.bundle_id)}</code></div>
    <div class="kv-row"><span>Original Bundle ID</span><code>${esc(a.original_bundle_id || a.base_bundle_id || '')}</code></div>
    <div class="kv-row"><span>Team ID</span><code>${esc(a.team_id || APP.state.team_id || '')}</code></div>
    <div class="kv-row"><span>Version</span><span>${esc(a.version || '1.0')}</span></div>
    <div class="kv-row"><span>Source</span><span>${esc(a.source_name || 'Custom')}</span></div>
    <div class="kv-row"><span>Profile Expires</span><span>${esc(exp)}</span></div>
    <div class="kv-row"><span>Extensions Stripped</span><span>${a.drop_extensions ? 'Yes (1 App ID used)' : 'No'}</span></div>
    <button class="secondary full" style="margin-top:0.85rem" onclick="closeModal()">Close</button>
  `);
}

async function deleteInstalledApp(bundleId, name) {
  if (!confirm(`Uninstall "${name}" from this iPhone?`)) return;
  const res = await apiPost("/api/apps/delete", { bundle_id: bundleId });
  if (!res.ok) {
    alert(res.error || "Failed to uninstall app.");
    return;
  }
  APP.installed_apps = res.installed_apps || [];
  renderMyApps();
  renderCatalog();
}

/* --- Options Tab --- */
function renderOptions() {
  const st = APP.state || {};
  const accBadge = document.getElementById("optAccountBadge");
  accBadge.textContent = st.has_session ? "Signed In" : "Not Signed In";
  accBadge.className = "badge " + (st.has_session ? "ok" : "warn");

  document.getElementById("optAccountDetails").innerHTML = `
    <div class="kv-row"><span>Apple ID</span><b>${esc(st.email || 'Not signed in')}</b></div>
    <div class="kv-row"><span>Developer Team</span><span>${esc(st.team_name ? st.team_name + ' (' + st.team_id + ')' : (st.team_id || '—'))}</span></div>
  `;

  const pairBadge = document.getElementById("optPairBadge");
  pairBadge.textContent = st.paired ? "Paired" : "Not Paired";
  pairBadge.className = "badge " + (st.paired ? "ok" : "warn");

  document.getElementById("optDeviceDetails").innerHTML = `
    <div class="kv-row"><span>Device</span><span>${esc(st.peer_name || 'iPhone')} ${st.peer_model ? '(' + esc(st.peer_model) + ')' : ''}</span></div>
    <div class="kv-row"><span>UDID</span><code>${esc(st.udid || '—')}</code></div>
    <div class="kv-row"><span>Developer Mode</span><span>${st.devmode_on === true ? 'Enabled' : (st.devmode_on === false ? 'Disabled' : 'Verified on install')}</span></div>
  `;

  const aniInp = document.getElementById("anisetteInput");
  if (aniInp && !aniInp.value) aniInp.value = st.anisette_url || "";
}

async function openAppIdsModal() {
  openModal(`<h3>Loading Portal Data…</h3><p class="sub">Querying registered App IDs &amp; certificates…</p>`);
  const res = await apiGet("/api/apple/appids");
  if (!res.ok) {
    openModal(`<h3>Developer Portal</h3><p class="sub" style="color:var(--red)">${esc(res.error)}</p><button class="secondary full" onclick="closeModal()">Close</button>`);
    return;
  }
  openModal(`
    <h3>App IDs &amp; Certificates</h3>
    <div class="kv-row"><span>Available App ID Slots</span><span class="badge ok">${res.available ?? '?'} / ${res.max ?? 10} remaining</span></div>
    <h4 style="margin:0.75rem 0 0.35rem;font-size:0.9rem">Registered App IDs (${(res.app_ids||[]).length})</h4>
    <div style="max-height:11rem;overflow-y:auto;border:1px solid var(--border);border-radius:0.6rem;padding:0.4rem 0.6rem">
      ${(res.app_ids||[]).map(a => `
        <div class="kv-row">
          <div>
            <div style="font-weight:600">${esc(a.name)}</div>
            <code style="font-size:0.75rem;color:var(--sub)">${esc(a.identifier)}</code>
          </div>
        </div>
      `).join("") || '<div class="sub">None registered yet.</div>'}
    </div>
    <h4 style="margin:0.75rem 0 0.35rem;font-size:0.9rem">Development Certificates (${(res.certs||[]).length})</h4>
    <div style="max-height:8rem;overflow-y:auto;border:1px solid var(--border);border-radius:0.6rem;padding:0.4rem 0.6rem">
      ${(res.certs||[]).map(c => `
        <div class="kv-row">
          <div>
            <div style="font-weight:600">${esc(c.name)}</div>
            <div class="sub" style="font-size:0.75rem">Machine: ${esc(c.machine)} · Serial: ${esc(c.serial)}</div>
          </div>
        </div>
      `).join("") || '<div class="sub">None</div>'}
    </div>
    <button class="secondary full" style="margin-top:0.85rem" onclick="closeModal()">Close</button>
  `);
}

async function saveAnisetteUrl() {
  const url = document.getElementById("anisetteInput").value.trim();
  const res = await apiPost("/api/settings", { anisette_url: url });
  if (res.ok) {
    APP.state.anisette_url = url;
    alert("Preferred Anisette server saved.");
  }
}

async function runNetcheck() {
  const out = document.getElementById("netcheckOut");
  out.innerHTML = '<span class="sub">Testing DNS, TLS, and Anisette hosts…</span>';
  const res = await apiPost("/api/netcheck", {});
  if (!res.ok) {
    out.textContent = res.error || "Test failed.";
    return;
  }
  out.innerHTML = (res.results || []).map(r => `
    <div class="kv-row">
      <span>${esc(r.host)}</span>
      <span class="badge ${r.ok ? 'ok' : 'warn'}">${esc(r.detail)}</span>
    </div>
  `).join("");
}

async function checkUpdates() {
  const out = document.getElementById("maintOut");
  out.textContent = "Checking GitHub for BariStore updates…";
  const res = await apiPost("/api/update", {});
  out.textContent = res.ok ? res.message : (res.error || "Update failed.");
}

async function clearCache() {
  const out = document.getElementById("maintOut");
  const res = await apiPost("/api/cache/clear", {});
  out.textContent = res.ok ? res.message : (res.error || "Could not clear cache.");
}

async function resetBariStore() {
  if (!confirm("Reset BariStore and erase all saved Apple ID sessions, pairing files, and cached IPAs?")) return;
  const res = await apiPost("/api/reset", {});
  if (res.ok) location.reload();
}

window.addEventListener("DOMContentLoaded", initApp);
</script>
</body>
</html>
"""
