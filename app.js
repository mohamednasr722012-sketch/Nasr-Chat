'use strict';
const $ = (s) => document.querySelector(s);
let me = null;
let socket = null;
let current = null; // كود الطرف التاني في المحادثة المفتوحة
let mode = 'login';
let convs = [];
const unread = new Map();

/* ---------- أدوات ---------- */
async function api(url, opts = {}) {
  const init = { method: opts.method || 'GET', credentials: 'same-origin', headers: {} };
  if (opts.body instanceof FormData) {
    init.body = opts.body;
  } else if (opts.body) {
    init.headers['Content-Type'] = 'application/json';
    init.body = JSON.stringify(opts.body);
  }
  const res = await fetch(url, init);
  let data = null;
  try { data = await res.json(); } catch { /* مفيش JSON */ }
  if (!res.ok) {
    const err = new Error((data && data.error) || 'حصل خطأ');
    err.status = res.status;
    throw err;
  }
  return data;
}
const fmtTime = (t) => new Date(t).toLocaleTimeString('ar-EG', { hour: '2-digit', minute: '2-digit' });
const show = (el, on) => el.classList.toggle('hidden', !on);

/* ---------- الدخول والتسجيل ---------- */
function setMode(m) {
  mode = m;
  $('#tab-login').classList.toggle('active', m === 'login');
  $('#tab-register').classList.toggle('active', m === 'register');
  show($('#name-wrap'), m === 'register');
  $('#f-name').required = m === 'register';
  $('#f-pass').autocomplete = m === 'register' ? 'new-password' : 'current-password';
  $('#auth-submit').textContent = m === 'register' ? 'إنشاء الحساب' : 'دخول';
  $('#auth-error').textContent = '';
}
$('#tab-login').onclick = () => setMode('login');
$('#tab-register').onclick = () => setMode('register');

$('#auth-form').onsubmit = async (e) => {
  e.preventDefault();
  $('#auth-error').textContent = '';
  const body = { code: $('#f-code').value.trim(), password: $('#f-pass').value };
  if (mode === 'register') body.name = $('#f-name').value;
  try {
    await api(mode === 'register' ? '/api/register' : '/api/login', { method: 'POST', body });
    $('#f-pass').value = '';
    await start();
  } catch (err) {
    $('#auth-error').textContent = err.message;
  }
};

async function start() {
  try {
    me = await api('/api/me');
  } catch {
    show($('#auth'), true);
    show($('#app'), false);
    return;
  }
  show($('#auth'), false);
  show($('#app'), true);
  $('#me-name').textContent = me.name;
  $('#me-code').textContent = me.code;
  connectSocket();
  await loadConvs();
}

function connectSocket() {
  if (socket) socket.disconnect();
  socket = io({ withCredentials: true });
  socket.on('message', onIncoming);
  socket.on('connect_error', () => {});
  socket.on('disconnect', (reason) => {
    if (reason === 'io server disconnect') location.reload(); // السيرفر قفل الجلسة
  });
}

/* ---------- قائمة المحادثات ---------- */
async function loadConvs() {
  convs = await api('/api/conversations');
  renderConvs();
}
function preview(m) {
  if (!m) return '';
  const who = m.from === me.code ? 'أنت: ' : '';
  if (m.mediaType && !m.text) return who + (m.mediaType === 'video' ? '🎬 فيديو' : '🖼️ صورة');
  return who + (m.mediaType ? (m.mediaType === 'video' ? '🎬 ' : '🖼️ ') : '') + m.text;
}
function renderConvs() {
  const ul = $('#convs');
  ul.replaceChildren();
  for (const c of convs) {
    const li = document.createElement('li');
    if (c.code === current) li.classList.add('active');
    const row = document.createElement('div');
    row.className = 'row';
    const name = document.createElement('strong');
    name.textContent = `${c.name} (${c.code})`;
    row.append(name);
    const n = unread.get(c.code);
    if (n) {
      const dot = document.createElement('span');
      dot.className = 'dot';
      dot.textContent = n;
      row.append(dot);
    }
    const last = document.createElement('div');
    last.className = 'last';
    last.textContent = preview(c.last);
    li.append(row, last);
    li.onclick = () => openChat(c.code);
    ul.append(li);
  }
}

$('#new-chat').onsubmit = async (e) => {
  e.preventDefault();
  $('#new-error').textContent = '';
  const code = $('#new-code').value.trim();
  if (!/^[1-9][0-9]{0,29}$/.test(code)) {
    $('#new-error').textContent = 'اكتب كود صحيح (رقم موجب)';
    return;
  }
  if (code === me.code) {
    $('#new-error').textContent = 'ده كودك انت 🙂';
    return;
  }
  try {
    await openChat(code);
    $('#new-code').value = '';
  } catch (err) {
    $('#new-error').textContent = err.message;
  }
};

/* ---------- المحادثة ---------- */
async function openChat(code) {
  const peer = await api('/api/users/' + code);
  const msgs = await api('/api/messages/' + code);
  current = code;
  unread.delete(code);
  $('#peer-name').textContent = peer.name;
  $('#peer-code').textContent = peer.code;
  show($('#empty'), false);
  show($('#chat-box'), true);
  $('#app').classList.add('in-chat');
  $('#msgs').replaceChildren();
  msgs.forEach(appendMsg);
  scrollDown();
  $('#send-error').textContent = '';
  renderConvs();
  $('#text').focus();
}
$('#btn-back').onclick = () => {
  current = null;
  $('#app').classList.remove('in-chat');
  show($('#chat-box'), false);
  show($('#empty'), true);
  renderConvs();
};

function appendMsg(m) {
  const d = document.createElement('div');
  d.className = 'msg' + (m.from === me.code ? ' mine' : '');
  d.dataset.id = m.id;
  if (m.mediaUrl) {
    const el = document.createElement(m.mediaType === 'video' ? 'video' : 'img');
    el.src = m.mediaUrl;
    if (m.mediaType === 'video') { el.controls = true; el.preload = 'metadata'; }
    else { el.alt = 'صورة'; el.loading = 'lazy'; el.onload = scrollDown; }
    d.append(el);
  }
  if (m.text) {
    const t = document.createElement('span');
    t.textContent = m.text; // textContent = حماية من XSS
    d.append(t);
  }
  const tm = document.createElement('time');
  tm.textContent = fmtTime(m.at);
  d.append(tm);
  $('#msgs').append(d);
}
function scrollDown() {
  const box = $('#msgs');
  box.scrollTop = box.scrollHeight;
}

function onIncoming(m) {
  const peer = m.from === me.code ? m.to : m.from;
  if (current === peer) {
    if (!document.querySelector(`.msg[data-id="${m.id}"]`)) {
      appendMsg(m);
      scrollDown();
    }
  } else if (m.from !== me.code) {
    unread.set(peer, (unread.get(peer) || 0) + 1);
  }
  loadConvs().catch(() => {});
}

/* ---------- الإرسال ---------- */
const fileInput = $('#file');
fileInput.onchange = () => {
  const f = fileInput.files[0];
  $('#send-error').textContent = '';
  if (f && f.size > 50 * 1024 * 1024) {
    $('#send-error').textContent = 'الملف أكبر من 50 ميجا';
    fileInput.value = '';
    return;
  }
  $('#file-name').textContent = f ? f.name : '';
  show($('#file-chip'), !!f);
};
$('#file-clear').onclick = () => {
  fileInput.value = '';
  show($('#file-chip'), false);
};

$('#send-form').onsubmit = async (e) => {
  e.preventDefault();
  if (!current) return;
  const text = $('#text').value.trim();
  const file = fileInput.files[0];
  if (!text && !file) return;
  const fd = new FormData();
  fd.append('text', text);
  if (file) fd.append('file', file);
  const btn = e.submitter;
  btn.disabled = true;
  $('#send-error').textContent = file ? 'جاري الرفع...' : '';
  try {
    await api('/api/messages/' + current, { method: 'POST', body: fd });
    $('#text').value = '';
    fileInput.value = '';
    show($('#file-chip'), false);
    $('#send-error').textContent = '';
  } catch (err) {
    $('#send-error').textContent = err.message;
  } finally {
    btn.disabled = false;
  }
};

/* ---------- الإعدادات ---------- */
const dlg = $('#settings');
$('#btn-settings').onclick = () => {
  $('#s-name').value = me.name;
  $('#s-cur').value = $('#s-new').value = '';
  $('#s-msg').textContent = '';
  dlg.showModal();
};
$('#btn-close').onclick = () => dlg.close();
$('#btn-rename').onclick = async () => {
  try {
    const r = await api('/api/rename', { method: 'POST', body: { name: $('#s-name').value } });
    me.name = r.name;
    $('#me-name').textContent = r.name;
    $('#s-msg').textContent = 'تم حفظ الاسم ✔️';
  } catch (err) { $('#s-msg').textContent = err.message; }
};
$('#btn-pw').onclick = async () => {
  try {
    await api('/api/change-password', { method: 'POST', body: { current: $('#s-cur').value, next: $('#s-new').value } });
    $('#s-cur').value = $('#s-new').value = '';
    $('#s-msg').textContent = 'تم تغيير كلمة السر، وتم تسجيل خروجك من الأجهزة التانية ✔️';
    connectSocket();
  } catch (err) { $('#s-msg').textContent = err.message; }
};
async function logout(all) {
  await api('/api/logout', { method: 'POST', body: { all } }).catch(() => {});
  location.reload();
}
$('#btn-logout').onclick = () => logout(false);
$('#btn-logout-all').onclick = () => logout(true);

setMode('login');
start();
