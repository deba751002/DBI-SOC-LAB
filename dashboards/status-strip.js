(function () {
  const API_BASE = `${location.protocol}//${location.hostname}:8766`;
  const ICONS = {
    opensearch: '🔍', suricata: '🚨', zeek: '🌐', wazuh: '🐺',
    misp: '🌍', iris: '📋', ai_agents: '🤖', ollama: '🧠', caldera: '🎯',
    velociraptor: '🦖', stackstorm: '⚡',
  };

  function renderFull(container, services) {
    container.innerHTML = services.map(s => `
      <span class="status-strip-item" title="${s.name}: ${s.online ? 'online' : 'offline'}">
        <span class="status-strip-icon">${ICONS[s.key] || '⚙️'}</span>
        <span class="status-dot ${s.online ? 'green' : 'red'}"></span>
        <span class="status-strip-label">${s.name}</span>
      </span>
    `).join('');
  }

  function renderSummary(container, services) {
    const up = services.filter(s => s.online).length;
    const down = services.length - up;
    container.innerHTML = `
      <span class="status-strip-summary" title="${up} of ${services.length} monitored services online">
        <span class="status-dot green"></span><span>${up} running</span>
        <span class="status-dot red"></span><span>${down} offline</span>
      </span>
    `;
  }

  async function refresh() {
    const container = document.getElementById('global-status-strip');
    let services = [];
    try {
      const res = await fetch(`${API_BASE}/api/services/status`);
      const d = await res.json();
      services = d.services || [];
    } catch (e) {
      services = [];
    }

    if (container) {
      if (!services.length) {
        container.innerHTML = '<span class="status-strip-item" style="color:var(--text-muted)">Status unreachable</span>';
      } else if (container.dataset.mode === 'summary') {
        renderSummary(container, services);
      } else {
        renderFull(container, services);
      }
    }

    document.dispatchEvent(new CustomEvent('soc-status-update', { detail: { services } }));
  }

  document.addEventListener('DOMContentLoaded', () => {
    refresh();
    setInterval(refresh, 15000);
  });

  const style = document.createElement('style');
  style.textContent = `
    #global-status-strip { display:flex; align-items:center; gap:10px; flex-wrap:wrap; }
    .status-strip-item { display:inline-flex; align-items:center; gap:4px; font-size:11px; color:var(--text-secondary,#94a3b8); }
    .status-strip-icon { font-size:11px; }
    .status-strip-summary { display:inline-flex; align-items:center; gap:6px; font-size:12px; color:var(--text-secondary,#94a3b8); font-family:var(--font-mono,monospace); }
    .status-strip-summary .status-dot { margin-left:4px; }
    .status-strip-summary .status-dot:first-child { margin-left:0; }
  `;
  document.head.appendChild(style);
})();
