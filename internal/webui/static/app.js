const loginEl = document.getElementById('login');
const filesEl = document.getElementById('files');
const loginErr = document.getElementById('loginErr');
const filesErr = document.getElementById('filesErr');
const logoutBtn = document.getElementById('logout');

const tbody = document.getElementById('tbody');
const cwdEl = document.getElementById('cwd');
const crumbsEl = document.getElementById('crumbs');

let cwd = '/';

function fmtBytes(n) {
  if (n == null) return '';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  let x = Number(n);
  while (x >= 1024 && i < units.length - 1) {
    x /= 1024;
    i++;
  }
  return `${x.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}

function setErr(el, msg) {
  el.textContent = msg || '';
}

async function api(path, opts) {
  const res = await fetch(path, { credentials: 'include', ...opts });
  if (!res.ok) {
    let msg = `HTTP ${res.status}`;
    try {
      const j = await res.json();
      if (j && j.error) msg = j.error;
    } catch (_) {}
    throw new Error(msg);
  }
  const ct = res.headers.get('content-type') || '';
  if (ct.includes('application/json')) return res.json();
  return res;
}

function joinPath(base, name) {
  if (base.endsWith('/')) return base + name;
  return base + '/' + name;
}

function parentPath(p) {
  if (p === '/' || p === '') return '/';
  const parts = p.split('/').filter(Boolean);
  parts.pop();
  return '/' + parts.join('/');
}

function renderCrumbs() {
  crumbsEl.innerHTML = '';
  const parts = cwd.split('/').filter(Boolean);
  const rootBtn = document.createElement('button');
  rootBtn.className = 'crumb';
  rootBtn.textContent = '/';
  rootBtn.onclick = () => { cwd = '/'; refresh(); };
  crumbsEl.appendChild(rootBtn);

  let acc = '';
  for (const part of parts) {
    acc += '/' + part;
    const sep = document.createElement('span');
    sep.textContent = ' / ';
    sep.style.color = '#6b6259';
    crumbsEl.appendChild(sep);

    const btn = document.createElement('button');
    btn.className = 'crumb';
    btn.textContent = part;
    btn.onclick = () => { cwd = acc; refresh(); };
    crumbsEl.appendChild(btn);
  }
}

async function refresh() {
  setErr(filesErr, '');
  cwdEl.textContent = cwd;
  renderCrumbs();
  tbody.innerHTML = '';
  try {
    const data = await api(`/api/files?path=${encodeURIComponent(cwd)}`);
    const entries = data.entries || [];
    if (cwd !== '/') {
      const tr = document.createElement('tr');
      tr.innerHTML = `<td><span class="name"><span class="tag">..</span></span></td><td></td><td></td><td></td>`;
      tr.onclick = () => { cwd = parentPath(cwd); refresh(); };
      tbody.appendChild(tr);
    }
    for (const e of entries) {
      const tr = document.createElement('tr');
      const tag = e.is_dir ? '<span class="tag">dir</span>' : '';
      const name = e.name;
      const size = e.is_dir ? '' : fmtBytes(e.size);
      const mod = e.mod_time ? new Date(e.mod_time * 1000).toLocaleString() : '';
      const actions = e.is_dir
        ? `<button class="btn ghost" data-act="open">Open</button> <button class="btn ghost" data-act="del">Delete</button>`
        : `<a class="btn ghost" href="/api/download?path=${encodeURIComponent(joinPath(cwd, name))}">Download</a> <button class="btn ghost" data-act="del">Delete</button>`;

      tr.innerHTML = `<td><span class="name">${tag}<span>${name}</span></span></td><td>${size}</td><td>${mod}</td><td>${actions}</td>`;
      tr.addEventListener('click', (ev) => {
        const btn = ev.target && ev.target.dataset && ev.target.dataset.act;
        if (!btn) return;
        ev.preventDefault();
        ev.stopPropagation();
      });
      tr.querySelectorAll('[data-act="open"]').forEach((b) => {
        b.onclick = () => { cwd = joinPath(cwd, name); refresh(); };
      });
      tr.querySelectorAll('[data-act="del"]').forEach((b) => {
        b.onclick = async () => {
          if (!confirm(`Delete ${name}?`)) return;
          try {
            await api(`/api/files?path=${encodeURIComponent(joinPath(cwd, name))}`, { method: 'DELETE' });
            refresh();
          } catch (e) {
            setErr(filesErr, e.message);
          }
        };
      });
      tbody.appendChild(tr);
    }
  } catch (e) {
    setErr(filesErr, e.message);
  }
}

document.getElementById('loginForm').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  setErr(loginErr, '');
  const username = document.getElementById('username').value;
  const password = document.getElementById('password').value;
  try {
    await api('/api/login', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ username, password }),
    });
    loginEl.hidden = true;
    filesEl.hidden = false;
    logoutBtn.hidden = false;
    cwd = '/';
    refresh();
  } catch (e) {
    setErr(loginErr, e.message);
  }
});

document.getElementById('refresh').addEventListener('click', refresh);

document.getElementById('upload').addEventListener('change', async (ev) => {
  setErr(filesErr, '');
  const files = ev.target.files;
  if (!files || files.length === 0) return;
  try {
    for (const f of files) {
      const form = new FormData();
      form.append('file', f, f.name);
      await api(`/api/upload?path=${encodeURIComponent(cwd)}`, { method: 'POST', body: form });
    }
    ev.target.value = '';
    refresh();
  } catch (e) {
    setErr(filesErr, e.message);
  }
});

logoutBtn.addEventListener('click', async () => {
  try {
    await api('/api/logout', { method: 'POST' });
  } catch (_) {}
  loginEl.hidden = false;
  filesEl.hidden = true;
  logoutBtn.hidden = true;
  setErr(loginErr, '');
});
