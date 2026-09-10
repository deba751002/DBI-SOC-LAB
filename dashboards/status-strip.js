/**
 * Shared "live services" status strip. Include this script on any
 * dashboard page and add a container element with id="global-status-strip"
 * (usually in the topbar) - it polls ws-streamer's real /api/services/status
 * endpoint (which checks OpenSearch cluster health, whether Zeek/Suricata/
 * Wazuh have shipped a real event in the last 5 minutes, and pings MISP/
 * DFIR-IRIS/AI Agents/Ollama/Caldera directly) and renders one dot+label
 * per service. Never invents a status - a service that can't be reached
 * shows red/OFFLINE, not a guess.
 */
(function () {
  const API_BASE = `${location.protocol}//${location.hostname}:8766`;
  const ICONS = {
    opensearch: '🔍', suricata: '🚨', zeek: '🌐', wazuh: '🐺',
    misp: '🌍', iris: '📋', ai_agents: '🤖', ollama: '🧠', caldera: '🎯',
  };

  function render(container, services) {
    container.innerHTML = services.map(s => `
      <span class="status-strip-item" title="${s.name}: ${s.online ? 'online' : 'offline'}">
        <span class="status-strip-icon">${ICONS[s.key] || '⚙️'}</span>
        <span class="status-dot ${s.online ? 'green' : 'red'}"></span>
        <span class="status-strip-label">${s.name}</span>
      </span>
    `).join('');
  }

  async function refresh() {
    const container = document.getElementById('global-status-strip');
    if (!container) return;
    try {
      const res = await fetch(`${API_BASE}/api/services/status`);
      const d = await res.json();
      render(container, d.services || []);
    } catch (e) {
      container.innerHTML = '<span class="status-strip-item" style="color:var(--text-muted)">Status unreachable</span>';
    }
  }

  // Inject minimal styling once, so every page including this script
  // looks the same without needing to touch each page's own <style>.
  const style = document.createElement('style');
  style.textContent = `
    #global-status-strip { display:flex; align-items:center; gap:10px; flex-wrap:wrap; }
    .status-strip-item { display:inline-flex; align-items:center; gap:4px; font-size:11px; color:var(--text-secondary,#94a3b8); }
    .status-strip-icon { font-size:11px; }
  `;
  document.head.appendChild(style);

  document.addEventListener('DOMContentLoaded', () => {
    refresh();
    setInterval(refresh, 15000);
  });
})();
