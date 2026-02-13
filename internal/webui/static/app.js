const loginEl = document.getElementById('login');
const filesEl = document.getElementById('files');
const loginErr = document.getElementById('loginErr');
const filesErr = document.getElementById('filesErr');
const logoutBtn = document.getElementById('logout');

const newFolderBtn = document.getElementById('newFolder');
const downloadFolderEl = document.getElementById('downloadFolder');

const tbody = document.getElementById('tbody');
const cwdEl = document.getElementById('cwd');
const crumbsEl = document.getElementById('crumbs');

const uploadsEl = document.getElementById('uploads');
const uploadsListEl = document.getElementById('uploadsList');
const uploadsSummaryEl = document.getElementById('uploadsSummary');

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

function setUploadsVisible(v) {
  uploadsEl.hidden = !v;
  if (!v) {
    uploadsListEl.innerHTML = '';
    uploadsSummaryEl.textContent = '';
  }
}

function makeUploadRow(file) {
  const row = document.createElement('div');
  row.className = 'uploadRow';

  const name = document.createElement('div');
  name.className = 'uploadName';
  name.textContent = file.name;

  const meta = document.createElement('div');
  meta.className = 'uploadMeta';
  meta.textContent = `0% (${fmtBytes(0)} / ${fmtBytes(file.size)})`;

  const bar = document.createElement('div');
  bar.className = 'bar';
  const fill = document.createElement('div');
  fill.className = 'barFill';
  bar.appendChild(fill);

  row.appendChild(name);
  row.appendChild(meta);
  row.appendChild(bar);

  return { row, fill, meta };
}

function uploadWithProgress(file, destPath, onProgress) {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open('POST', `/api/upload?path=${encodeURIComponent(destPath)}`, true);
    xhr.withCredentials = true;

    xhr.upload.onprogress = (ev) => {
      if (!ev.lengthComputable) return;
      onProgress(ev.loaded, ev.total);
    };

    xhr.onerror = () => reject(new Error('upload failed'));
    xhr.onabort = () => reject(new Error('upload aborted'));

    xhr.onload = () => {
      if (xhr.status >= 200 && xhr.status < 300) {
        resolve();
        return;
      }
      try {
        const j = JSON.parse(xhr.responseText || '{}');
        if (j?.error) {
          reject(new Error(j.error));
          return;
        }
      } catch (_) { /* JSON parse error is expected for non-JSON responses */ }
      reject(new Error(`HTTP ${xhr.status}`));
    };

    const form = new FormData();
    form.append('file', file, file.name);
    xhr.send(form);
  });
}

async function api(path, opts) {
  const res = await fetch(path, { credentials: 'include', ...opts });
  if (!res.ok) {
    let msg = `HTTP ${res.status}`;
    try {
      const j = await res.json();
      if (j?.error) msg = j.error;
    } catch (_) { /* JSON parse error is expected for non-JSON responses */ }
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

function isValidFolderName(name) {
  const n = String(name || '').trim();
  if (!n) return false;
  if (n === '.' || n === '..') return false;
  if (n.includes('/') || n.includes('\\')) return false;
  return true;
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
  downloadFolderEl.href = `/api/download?path=${encodeURIComponent(cwd)}`;
  tbody.innerHTML = '';
  try {
    const data = await api(`/api/files?path=${encodeURIComponent(cwd)}`);
    const entries = data.entries || [];
    if (cwd !== '/') {
      const tr = document.createElement('tr');
      const td = document.createElement('td');
      const wrap = document.createElement('span');
      wrap.className = 'name';
      const tag = document.createElement('span');
      tag.className = 'tag';
      tag.textContent = '..';
      wrap.appendChild(tag);
      td.appendChild(wrap);
      tr.appendChild(td);
      tr.appendChild(document.createElement('td'));
      tr.appendChild(document.createElement('td'));
      tr.appendChild(document.createElement('td'));
      tr.onclick = () => { cwd = parentPath(cwd); refresh(); };
      tbody.appendChild(tr);
    }
    for (const e of entries) {
      const tr = document.createElement('tr');
      const name = e.name;
      const size = e.is_dir ? '' : fmtBytes(e.size);
      const mod = e.mod_time ? new Date(e.mod_time * 1000).toLocaleString() : '';

      // Avoid innerHTML with untrusted filename.
      const tdName = document.createElement('td');
      const nameWrap = document.createElement('span');
      nameWrap.className = 'name';
      if (e.is_dir) {
        const t = document.createElement('span');
        t.className = 'tag';
        t.textContent = 'dir';
        nameWrap.appendChild(t);
      }
      const nameText = document.createElement('span');
      nameText.textContent = name;
      nameWrap.appendChild(nameText);
      tdName.appendChild(nameWrap);

      const tdSize = document.createElement('td');
      tdSize.textContent = size;
      const tdMod = document.createElement('td');
      tdMod.textContent = mod;
      const tdAct = document.createElement('td');

      const renameBtn = document.createElement('button');
      renameBtn.className = 'btn ghost';
      renameBtn.textContent = 'Rename';
      renameBtn.dataset.act = 'rename';
      renameBtn.onclick = async () => {
        const newName = prompt('New name', name);
        if (newName == null || newName === name) return;
        if (!isValidFolderName(newName)) {
          setErr(filesErr, 'invalid name');
          return;
        }
        try {
          await api(`/api/files?path=${encodeURIComponent(joinPath(cwd, name))}`, {
            method: 'PATCH',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ name: newName.trim() }),
          });
          refresh();
        } catch (e) {
          setErr(filesErr, e.message);
        }
      };

      if (e.is_dir) {
        const openBtn = document.createElement('button');
        openBtn.className = 'btn ghost';
        openBtn.textContent = 'Open';
        openBtn.dataset.act = 'open';
        openBtn.onclick = () => { cwd = joinPath(cwd, name); refresh(); };

        const zipBtn = document.createElement('a');
        zipBtn.className = 'btn ghost';
        zipBtn.textContent = 'Zip';
        zipBtn.href = `/api/download?path=${encodeURIComponent(joinPath(cwd, name))}`;

        const delBtn = document.createElement('button');
        delBtn.className = 'btn ghost';
        delBtn.textContent = 'Delete';
        delBtn.dataset.act = 'del';
        delBtn.onclick = async () => {
          if (!confirm(`Delete folder "${name}" and all contents?`)) return;
          try {
            await api(`/api/files?path=${encodeURIComponent(joinPath(cwd, name))}`, { method: 'DELETE' });
            refresh();
          } catch (e) {
            setErr(filesErr, e.message);
          }
        };

        tdAct.appendChild(openBtn);
        tdAct.appendChild(document.createTextNode(' '));
        tdAct.appendChild(zipBtn);
        tdAct.appendChild(document.createTextNode(' '));
        tdAct.appendChild(renameBtn);
        tdAct.appendChild(document.createTextNode(' '));
        tdAct.appendChild(delBtn);
      } else {
        const dl = document.createElement('a');
        dl.className = 'btn ghost';
        dl.textContent = 'Download';
        dl.href = `/api/download?path=${encodeURIComponent(joinPath(cwd, name))}`;

        const delBtn = document.createElement('button');
        delBtn.className = 'btn ghost';
        delBtn.textContent = 'Delete';
        delBtn.dataset.act = 'del';
        delBtn.onclick = async () => {
          if (!confirm(`Delete ${name}?`)) return;
          try {
            await api(`/api/files?path=${encodeURIComponent(joinPath(cwd, name))}`, { method: 'DELETE' });
            refresh();
          } catch (e) {
            setErr(filesErr, e.message);
          }
        };

        tdAct.appendChild(dl);
        tdAct.appendChild(document.createTextNode(' '));
        tdAct.appendChild(renameBtn);
        tdAct.appendChild(document.createTextNode(' '));
        tdAct.appendChild(delBtn);
      }

      tr.appendChild(tdName);
      tr.appendChild(tdSize);
      tr.appendChild(tdMod);
      tr.appendChild(tdAct);
      tr.addEventListener('click', (ev) => {
        const btn = ev.target?.dataset?.act;
        if (!btn) return;
        ev.preventDefault();
        ev.stopPropagation();
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

newFolderBtn.addEventListener('click', async () => {
  setErr(filesErr, '');
  const name = prompt('New folder name');
  if (name == null) return;
  if (!isValidFolderName(name)) {
    setErr(filesErr, 'invalid folder name');
    return;
  }
  try {
    await api(`/api/files?path=${encodeURIComponent(joinPath(cwd, String(name).trim()))}`, { method: 'POST' });
    refresh();
  } catch (e) {
    setErr(filesErr, e.message);
  }
});

document.getElementById('upload').addEventListener('change', async (ev) => {
  setErr(filesErr, '');
  const files = ev.target.files;
  if (!files || files.length === 0) return;
  try {
    setUploadsVisible(true);
    uploadsListEl.innerHTML = '';

    const list = Array.from(files);
    const totalBytes = list.reduce((acc, f) => acc + (f.size || 0), 0);
    let doneBytes = 0;
    let okCount = 0;
    let failCount = 0;

    const updateSummary = (activeName, activePct) => {
      const overall = totalBytes > 0 ? Math.min(100, Math.round(((doneBytes) / totalBytes) * 100)) : 0;
      const active = activeName ? `Uploading ${activeName} (${activePct}%)` : 'Uploads complete';
      uploadsSummaryEl.textContent = `${active} · ${overall}% overall · ${okCount} ok · ${failCount} failed`;
    };

    for (const f of list) {
      const ui = makeUploadRow(f);
      uploadsListEl.appendChild(ui.row);
      updateSummary(f.name, 0);

      let lastLoaded = 0;
      try {
        await uploadWithProgress(f, cwd, (loaded, total) => {
          lastLoaded = loaded;
          const pct = total > 0 ? Math.min(100, Math.round((loaded / total) * 100)) : 0;
          ui.fill.style.width = `${pct}%`;
          ui.meta.textContent = `${pct}% (${fmtBytes(loaded)} / ${fmtBytes(total)})`;
          updateSummary(f.name, pct);
        });
        doneBytes += f.size || lastLoaded || 0;
        okCount += 1;
        ui.row.classList.add('done');
        ui.fill.style.width = '100%';
        ui.meta.textContent = `100% (${fmtBytes(f.size)} / ${fmtBytes(f.size)})`;
      } catch (e) {
        doneBytes += f.size || lastLoaded || 0;
        failCount += 1;
        ui.row.classList.add('fail');
        ui.meta.textContent = `failed (${e.message})`;
      }
    }

    updateSummary(null, 100);
    ev.target.value = '';
    refresh();
  } catch (e) {
    setErr(filesErr, e.message);
  }
});

logoutBtn.addEventListener('click', async () => {
  try {
    await api('/api/logout', { method: 'POST' });
  } catch (_) { /* Logout failure is non-critical; proceed to clear UI */ }
  loginEl.hidden = false;
  filesEl.hidden = true;
  logoutBtn.hidden = true;
  setErr(loginErr, '');
});
