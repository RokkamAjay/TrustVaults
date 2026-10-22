(() => {
  const csrf = document.querySelector('meta[name="csrf-token"]')?.content || '';
  let me = null;
  const $ = (id) => document.getElementById(id);
  const escapeHtml = (value) => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const dateText = (v) => { try { return new Date(v).toLocaleString(); } catch { return '—'; } };
  async function api(url, options = {}) {
    const headers = new Headers(options.headers || {});
    headers.set('X-CSRFToken', csrf);
    if (options.body && !(options.body instanceof FormData) && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json');
    const response = await fetch(url, {...options, headers, credentials: 'same-origin'});
    if (response.status === 401) { location.href = '/login'; throw new Error('Your session has expired.'); }
    const type = response.headers.get('content-type') || '';
    const data = type.includes('application/json') ? await response.json() : null;
    if (!response.ok) throw new Error(data?.message || `Request failed (${response.status}).`);
    return {response, data};
  }
  function notice(message, isError = false) {
    const n = $('notice'); n.textContent = message; n.className = `alert ${isError ? 'alert-danger' : 'alert-success'}`;
    window.scrollTo({top:0, behavior:'smooth'});
    setTimeout(() => n.classList.add('d-none'), 5500);
  }
  async function loadMe() {
    const {data} = await api('/api/me'); me = data;
    $('identity').textContent = `${data.name} · ${data.role}`;
    if (['owner','admin'].includes(data.role)) $('upload-area').classList.remove('d-none');
    if (data.role === 'admin') { $('admin-panel').classList.remove('d-none'); loadAudit(); }
  }
  async function loadDocuments() {
    const params = new URLSearchParams();
    if ($('search').value.trim()) params.set('q', $('search').value.trim());
    if ($('category-filter').value.trim()) params.set('category', $('category-filter').value.trim());
    if ($('owner-filter').value.trim()) params.set('owner', $('owner-filter').value.trim());
    const body = $('documents'); body.innerHTML = '<tr><td colspan="5" class="text-center py-5 muted">Loading…</td></tr>';
    try {
      const {data} = await api(`/api/documents?${params.toString()}`);
      if (!data.documents.length) { body.innerHTML = '<tr><td colspan="5" class="text-center py-5 muted">No documents found for this account.</td></tr>'; return; }
      body.innerHTML = data.documents.map(d => `<tr><td><div class="doc-name">${escapeHtml(d.name)}</div><div class="doc-meta">${(d.size_bytes/1024).toFixed(1)} KB · ${escapeHtml(d.content_type)}</div></td><td>${escapeHtml(d.owner_name)}</td><td><span class="badge rounded-pill text-bg-light">${escapeHtml(d.category)}</span></td><td>${escapeHtml(dateText(d.updated_at))}</td><td class="text-end text-nowrap">${d.can_download ? `<button class="btn btn-sm btn-outline-primary action-btn" data-download="${d.id}">Download</button>` : '<span class="muted small">Metadata only</span>'}${d.can_edit ? ` <button class="btn btn-sm btn-outline-secondary action-btn" data-edit="${d.id}" data-name="${escapeHtml(d.name)}" data-category="${escapeHtml(d.category)}">Edit</button>` : ''}${d.can_manage_access ? ` <button class="btn btn-sm btn-outline-secondary action-btn" data-share="${d.id}" data-name="${escapeHtml(d.name)}">Access</button>` : ''}${d.can_edit ? ` <button class="btn btn-sm btn-outline-danger action-btn" data-delete="${d.id}">Delete</button>` : ''}</td></tr>`).join('');
    } catch (e) { body.innerHTML = `<tr><td colspan="5" class="text-danger p-3">${escapeHtml(e.message)}</td></tr>`; }
  }
  async function loadAudit() {
    try {
      const {data} = await api('/api/audit?limit=30');
      $('audit-status').textContent = `Hash-chain check: ${data.chain_valid ? 'valid' : 'FAILED'} · Showing up to 30 recent events.`;
      $('audit-rows').innerHTML = data.events.map(e => `<tr><td>${escapeHtml(dateText(e.occurred_at))}</td><td>${escapeHtml(e.actor_email)}</td><td>${escapeHtml(e.action)}</td><td>${e.document_id ?? '—'}</td><td><span class="badge ${e.outcome==='success'?'text-bg-success':e.outcome==='denied'?'text-bg-danger':'text-bg-secondary'}">${escapeHtml(e.outcome)}</span></td></tr>`).join('') || '<tr><td colspan="5" class="p-3 muted">No events yet.</td></tr>';
    } catch (e) { $('audit-rows').innerHTML = `<tr><td colspan="5" class="p-3 text-danger">${escapeHtml(e.message)}</td></tr>`; }
  }
  $('search-btn').addEventListener('click', loadDocuments);
  ['search','category-filter','owner-filter'].forEach(id => $(id).addEventListener('keydown', e => { if (e.key === 'Enter') loadDocuments(); }));
  $('documents').addEventListener('click', async e => {
    const download = e.target.closest('[data-download]');
    const share = e.target.closest('[data-share]');
    const edit = e.target.closest('[data-edit]');
    const del = e.target.closest('[data-delete]');
    try {
      if (download) {
        const response = await fetch(`/api/documents/${download.dataset.download}/download`, {headers:{'X-CSRFToken':csrf}, credentials:'same-origin'});
        if (!response.ok) { const d = await response.json().catch(()=>({})); throw new Error(d.message || `Download failed (${response.status}).`); }
        const blob = await response.blob(); const url = URL.createObjectURL(blob); const a = document.createElement('a');
        a.href = url; a.download = 'trustvault-document'; document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url);
        notice('Download request completed.');
      } else if (share) {
        $('share-doc-id').value = share.dataset.share; $('shareTitle').textContent = `Access · ${share.dataset.name}`;
        $('share-email').value = ''; $('current-grants').textContent = 'Loading current permissions…';
        bootstrap.Modal.getOrCreateInstance($('shareModal')).show();
        const {data} = await api(`/api/documents/${share.dataset.share}/permissions`);
        $('current-grants').innerHTML = '<strong>Current grants</strong>' + (data.permissions.length ? data.permissions.map(p => `<div class="d-flex justify-content-between align-items-center border-top py-2"><span>${escapeHtml(p.email)} <span class="badge ${p.permission==='edit'?'badge-edit':'badge-read'}">${escapeHtml(p.permission)}</span></span><button class="btn btn-sm btn-outline-danger" data-revoke="${p.user_id}">Revoke</button></div>`).join('') : '<p class="muted mt-2 mb-0">No users have been granted access.</p>');
      } else if (edit) {
        const nextName = prompt('Document name:', edit.dataset.name); if (nextName === null) return;
        const nextCategory = prompt('Category:', edit.dataset.category); if (nextCategory === null) return;
        await api(`/api/documents/${edit.dataset.edit}`, {method:'PATCH', body:JSON.stringify({name:nextName, category:nextCategory})});
        notice('Document details updated.'); await loadDocuments();
      } else if (del && confirm('Delete this document? It will be soft-deleted and no longer accessible.')) {
        await api(`/api/documents/${del.dataset.delete}`, {method:'DELETE'}); notice('Document deleted.'); await loadDocuments();
      }
    } catch (err) { notice(err.message, true); }
  });
  $('current-grants').addEventListener('click', async e => {
    const btn = e.target.closest('[data-revoke]'); if (!btn) return;
    try { await api(`/api/documents/${$('share-doc-id').value}/permissions/${btn.dataset.revoke}`, {method:'DELETE'}); notice('Access revoked.'); const {data}=await api(`/api/documents/${$('share-doc-id').value}/permissions`); $('current-grants').innerHTML = '<strong>Current grants</strong>' + (data.permissions.length ? data.permissions.map(p => `<div class="d-flex justify-content-between align-items-center border-top py-2"><span>${escapeHtml(p.email)} <span class="badge ${p.permission==='edit'?'badge-edit':'badge-read'}">${escapeHtml(p.permission)}</span></span><button class="btn btn-sm btn-outline-danger" data-revoke="${p.user_id}">Revoke</button></div>`).join('') : '<p class="muted mt-2 mb-0">No users have been granted access.</p>'); await loadDocuments(); } catch(err) { notice(err.message, true); }
  });
  $('share-form').addEventListener('submit', async e => {
    e.preventDefault();
    try { await api(`/api/documents/${$('share-doc-id').value}/permissions`, {method:'POST', body:JSON.stringify({email:$('share-email').value, permission:$('share-permission').value})}); notice('Permission saved.'); const {data}=await api(`/api/documents/${$('share-doc-id').value}/permissions`); $('current-grants').innerHTML = '<strong>Current grants</strong>' + data.permissions.map(p => `<div class="d-flex justify-content-between align-items-center border-top py-2"><span>${escapeHtml(p.email)} <span class="badge ${p.permission==='edit'?'badge-edit':'badge-read'}">${escapeHtml(p.permission)}</span></span><button class="btn btn-sm btn-outline-danger" data-revoke="${p.user_id}">Revoke</button></div>`).join(''); await loadDocuments(); } catch(err) { notice(err.message, true); }
  });
  $('upload-form').addEventListener('submit', async e => {
    e.preventDefault(); const form = new FormData(); form.append('file', $('file').files[0]); form.append('name', $('doc-name').value); form.append('category', $('doc-category').value);
    try { await api('/api/documents', {method:'POST', body:form}); bootstrap.Modal.getOrCreateInstance($('uploadModal')).hide(); $('upload-form').reset(); notice('Document uploaded securely.'); await loadDocuments(); } catch(err) { notice(err.message, true); }
  });
  $('verify-audit').addEventListener('click', async () => { try { const {data}=await api('/api/audit/verify'); $('audit-status').textContent = data.valid ? 'Audit hash chain verified.' : 'AUDIT CHAIN INVALID.'; await loadAudit(); } catch(err) { notice(err.message, true); } });
  (async () => { try { await loadMe(); await loadDocuments(); } catch (e) { notice(e.message, true); } })();
})();
