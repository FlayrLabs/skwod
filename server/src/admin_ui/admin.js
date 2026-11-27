"use strict";
const $ = (id) => document.getElementById(id);
let lastInvite = null;
let busy = false;

async function api(method, path, body) {
  const res = await fetch(path, {
    method,
    credentials: "same-origin",
    headers: { "x-skwod-admin": "1", ...(body ? { "content-type": "application/json" } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  let data = null;
  try { data = await res.json(); } catch (_) { /* empty body */ }
  return { ok: res.ok, status: res.status, data };
}

function show(id) {
  for (const s of ["login", "stopped", "running"]) $(s).hidden = s !== id;
}

function problem(text) {
  $("problem").hidden = !text;
  $("problem").textContent = text || "";
}

const INVITE_TEXT = {
  owner: ["Your invite", "Open this on your own phone first: the first person to join with it becomes the owner. After that, make invites for friends here or in the app."],
  friend: ["Invite a friend", "Send this to a friend. They ask to join, and you approve them in the app."],
  address: ["Server address", "This is your server's address. Press New invite to make a link a friend can ask to join with."],
};

// What to say for each reason the call server is not running. Fixed sentences: nothing the
// server says about itself is shown.
const VOICE_REASON = {
  ports: "a port it needs is taken",
  files: "its settings could not be written to the data folder",
  exec: "its program could not be started",
  exited: "it stopped by itself",
  no_answer: "it did not answer in time",
  storage: "its settings could not be saved",
  disabled: "turned off in this server's settings",
  no_call_server: "this server has no call server next to it",
};

function voiceText(st) {
  const why = VOICE_REASON[st.voice_reason];
  if (st.voice_status === "on") return st.voice_server ? "On, through " + st.voice_server + " (saved in the app)" : "On";
  if (st.voice_status === "starting") return "Starting…" + (why ? " (" + why + ", trying again)" : "");
  const retried = why && !["disabled", "no_call_server"].includes(st.voice_reason);
  return "Off" + (why ? ": " + why + (retried ? ". It is tried again by itself." : "") : "");
}

function render(st) {
  $("state").dataset.phase = st.phase;
  $("state").textContent = { running: "Running", starting: "Starting…", stopped: "Stopped" }[st.phase] || st.phase;
  $("version").textContent = "Skwod server " + st.version;
  $("logout").hidden = false;
  $("firewall-note").hidden = !navigator.userAgent.includes("Windows");
  // An invite with as many people waiting as it may have lets nobody else sign up: say so here,
  // where the host looks, instead of leaving friends with a refusal nobody can explain.
  const full = st.invites_full > 0
    ? (st.invites_full === 1 ? "One invite has " : st.invites_full + " invites each have ") + st.invite_waiting_cap +
      " people waiting to be let in, so nobody else can join with it. Open the Skwod app to approve them, or revoke the invite and share a new one."
    : "";
  problem(st.problem || full);
  if (st.phase !== "running") { show("stopped"); $("start").disabled = st.phase === "starting" || busy; return; }
  show("running");
  $("members").textContent = st.members;
  $("online").textContent = st.online;
  $("voice").textContent = voiceText(st);
  $("p2p").textContent = st.p2p ? (st.public_fallback ? "Yes" : "Yes (direct only)") : "No";
  if (!busy) $("lan").checked = !!st.local_discovery;
  $("lan").disabled = !st.p2p || busy;
  const inv = st.invite;
  $("invite-block").hidden = !inv && !st.needs_new_code && !st.setup_code_hidden;
  if (inv) {
    const [title, help] = INVITE_TEXT[inv.kind];
    $("invite-title").textContent = title;
    $("invite-help").textContent = help;
    $("invite").textContent = inv.link;
    $("invite-expiry").textContent = inv.expires_at ? "Expires " + new Date(inv.expires_at).toLocaleDateString() + "." : "";
    if (inv.link !== lastInvite) { $("qr").src = "/admin/api/qr.svg?" + Date.now(); lastInvite = inv.link; }
    $("qr").hidden = false; $("copy").hidden = false; $("invite").hidden = false;
  } else if (st.setup_code_hidden) {
    $("invite-title").textContent = "Your invite";
    $("invite-help").textContent = "Nobody has claimed this server yet. The owner invite is only shown on the computer that runs the server, because this page is not encrypted: open http://127.0.0.1:3477 there (or through an SSH tunnel).";
    $("qr").hidden = true; $("copy").hidden = true; $("invite").hidden = true; $("invite-expiry").textContent = "";
  } else if (st.needs_new_code) {
    $("invite-title").textContent = "Your invite";
    $("invite-help").textContent = "Nobody has claimed this server yet, and the first invite is only shown once. Press New invite to make another.";
    $("qr").hidden = true; $("copy").hidden = true; $("invite").hidden = true; $("invite-expiry").textContent = "";
  }
}

async function refresh() {
  const r = await api("GET", "/admin/api/status").catch(() => null);
  if (!r) { problem("Cannot reach the server."); return; }
  if (r.status === 401) { show("login"); $("state").textContent = "Locked"; $("logout").hidden = true; return; }
  if (r.ok) render(r.data);
}

async function act(button, path) {
  busy = true; button.disabled = true;
  const r = await api("POST", path).catch(() => null);
  busy = false; button.disabled = false;
  if (!r || !r.ok) problem((r && r.data && r.data.error) || "That did not work. Try again.");
  await refresh();
}

async function signIn(token) {
  const r = await api("POST", "/admin/api/login", { token }).catch(() => null);
  if (r && r.ok) { problem(""); await refresh(); return true; }
  problem((r && r.data && r.data.error) || "Could not sign in.");
  return false;
}

$("login-form").addEventListener("submit", async (e) => { e.preventDefault(); if (await signIn($("token").value)) $("token").value = ""; });
$("start").addEventListener("click", () => act($("start"), "/admin/api/start"));
$("restart").addEventListener("click", () => act($("restart"), "/admin/api/restart"));
$("new-invite").addEventListener("click", () => act($("new-invite"), "/admin/api/invite"));
$("stop").addEventListener("click", () => { if (confirm("Stop the server? Everyone will be disconnected until you start it again.")) act($("stop"), "/admin/api/stop"); });
$("lan").addEventListener("change", async () => {
  busy = true; $("lan").disabled = true;
  const r = await api("POST", "/admin/api/local-discovery", { enabled: $("lan").checked }).catch(() => null);
  busy = false;
  if (!r || !r.ok) problem((r && r.data && r.data.error) || "That did not work. Try again.");
  await refresh();
});
$("logout").addEventListener("click", async (e) => { e.preventDefault(); await api("POST", "/admin/api/logout"); await refresh(); });
$("copy").addEventListener("click", async () => {
  const text = $("invite").textContent;
  try { await navigator.clipboard.writeText(text); }
  catch (_) {
    // Plain-http LAN pages have no Clipboard API: select the text so Ctrl/Cmd+C works.
    const range = document.createRange(); range.selectNodeContents($("invite"));
    const sel = getSelection(); sel.removeAllRanges(); sel.addRange(range);
    try { document.execCommand("copy"); } catch (_e) { /* user copies by hand */ }
  }
  $("copy").textContent = "Copied"; setTimeout(() => { $("copy").textContent = "Copy invite"; }, 1500);
});

(async () => {
  // The desktop host app opens the page with a launch key in the fragment (never sent to a server).
  const m = location.hash.match(/^#k=([0-9a-f]{16,128})$/);
  if (m) { history.replaceState(null, "", location.pathname); await signIn(m[1]); }
  await refresh();
  setInterval(refresh, 4000);
})();
