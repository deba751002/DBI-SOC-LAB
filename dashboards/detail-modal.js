(function () {
  function escapeHtml(s) {
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  function flattenForDisplay(obj, prefix) {
    prefix = prefix || '';
    const out = [];
    if (obj === null || obj === undefined) return out;
    for (const [k, v] of Object.entries(obj)) {
      const key = prefix ? `${prefix}.${k}` : k;
      if (v && typeof v === 'object' && !Array.isArray(v)) out.push(...flattenForDisplay(v, key));
      else out.push([key, Array.isArray(v) ? v.join(', ') : String(v)]);
    }
    return out;
  }

  function ensureModal() {
    if (document.getElementById('detail-modal')) return;
    const div = document.createElement('div');
    div.id = 'detail-modal';
    div.style.cssText = 'display:none;position:fixed;inset:0;background:rgba(0,0,0,0.6);z-index:1000;align-items:center;justify-content:center;';
    div.innerHTML = `
      <div style="background:var(--bg-surface,#1a1f2e);border:1px solid var(--border,#333);border-radius:8px;max-width:720px;width:90%;max-height:80vh;overflow-y:auto;padding:20px;">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;">
          <span id="detail-modal-title" style="font-size:15px;font-weight:600;color:var(--text-primary,#eee)">Details</span>
          <button onclick="closeDetailModal()" style="background:none;border:none;color:var(--text-muted,#94a3b8);font-size:20px;cursor:pointer;line-height:1">&times;</button>
        </div>
        <div id="detail-modal-body" style="font-size:12px;color:var(--text-secondary,#cbd5e1);"></div>
      </div>`;
    document.body.appendChild(div);
    div.addEventListener('click', (e) => { if (e.target.id === 'detail-modal') closeDetailModal(); });
    document.addEventListener('keydown', (e) => { if (e.key === 'Escape') closeDetailModal(); });
  }

  window.openDetailModal = function (obj, title) {
    ensureModal();
    document.getElementById('detail-modal-title').textContent = title || 'Details';
    const rows = flattenForDisplay(obj).map(([k, v]) =>
      `<tr><td style="padding:4px 10px 4px 0;color:var(--text-muted,#94a3b8);white-space:nowrap;vertical-align:top">${escapeHtml(k)}</td><td style="padding:4px 0;word-break:break-all">${escapeHtml(v)}</td></tr>`
    ).join('');
    document.getElementById('detail-modal-body').innerHTML = rows
      ? `<table style="width:100%;border-collapse:collapse">${rows}</table>`
      : '<div style="color:var(--text-muted,#94a3b8)">No details available.</div>';
    document.getElementById('detail-modal').style.display = 'flex';
  };

  window.closeDetailModal = function () {
    const m = document.getElementById('detail-modal');
    if (m) m.style.display = 'none';
  };
})();
