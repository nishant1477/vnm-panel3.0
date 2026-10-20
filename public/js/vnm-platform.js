/* =====================================================================
   VNM Platform runtime (Round 5)
   ---------------------------------------------------------------------
   - VNMCharts: dependency-free canvas area/sparkline charts (DPR-aware)
   - Command palette (Ctrl+K / Cmd+K) with global search
   - Collapsible sidebar (persisted)
   - Live polling helper (pauses when the tab is hidden)
   - Formatters (bytes, uptime, relative time)
   - Bulk-action helpers used by the VM list pages
   All motion respects prefers-reduced-motion via CSS.
   ===================================================================== */
(function () {
  'use strict';
  window.VNM = window.VNM || {};

  /* ==================== Formatters ==================== */
  const fmt = {
    bytes(v, digits) {
      const n = Number(v);
      if (!Number.isFinite(n)) return '—';
      if (n === 0) return '0 B';
      const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
      const i = Math.min(Math.floor(Math.log(Math.abs(n)) / Math.log(1024)), units.length - 1);
      return (n / Math.pow(1024, i)).toFixed(digits === undefined ? (i === 0 ? 0 : 1) : digits) + ' ' + units[i];
    },
    pct(v) { return v == null ? '—' : Number(v).toFixed(1) + '%'; },
    uptime(sec) {
      const s = Number(sec) || 0;
      if (s < 60) return s + 's';
      if (s < 3600) return Math.floor(s / 60) + 'm ' + (s % 60) + 's';
      if (s < 86400) return Math.floor(s / 3600) + 'h ' + Math.floor((s % 3600) / 60) + 'm';
      return Math.floor(s / 86400) + 'd ' + Math.floor((s % 86400) / 3600) + 'h';
    },
    rel(ts) {
      if (!ts) return '—';
      const d = new Date(String(ts).replace(' ', 'T') + (String(ts).includes('Z') ? '' : 'Z'));
      if (isNaN(d)) return String(ts);
      const diff = (Date.now() - d.getTime()) / 1000;
      if (diff < 5) return 'just now';
      if (diff < 60) return Math.floor(diff) + 's ago';
      if (diff < 3600) return Math.floor(diff / 60) + 'm ago';
      if (diff < 86400) return Math.floor(diff / 3600) + 'h ago';
      return Math.floor(diff / 86400) + 'd ago';
    },
    when(ts) {
      if (!ts) return '—';
      const d = new Date(String(ts).replace(' ', 'T') + (String(ts).includes('Z') ? '' : 'Z'));
      if (isNaN(d)) return String(ts);
      return d.toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
    },
  };
  VNM.fmt = fmt;

  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  }
  VNM.esc = esc;

  /* ==================== Charts (canvas, no deps) ==================== */
  const PALETTE = ['#22d3ee', '#818cf8', '#c084fc', '#34d399', '#fbbf24', '#f87171'];

  function setupCanvas(canvas) {
    const dpr = window.devicePixelRatio || 1;
    const rect = canvas.getBoundingClientRect();
    const w = Math.max(rect.width, 10), h = Math.max(rect.height, 10);
    canvas.width = Math.round(w * dpr);
    canvas.height = Math.round(h * dpr);
    const ctx = canvas.getContext('2d');
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    return { ctx, w, h };
  }

  // series: [{ name, color?, data: [numbers] }]; opts: { max, unit, labelFn, showNow }
  function areaChart(canvas, series, opts) {
    opts = opts || {};
    if (!canvas || !canvas.getContext) return;
    const { ctx, w, h } = setupCanvas(canvas);
    ctx.clearRect(0, 0, w, h);
    const data = series.filter((s) => s.data && s.data.length);
    if (!data.length) {
      ctx.fillStyle = 'rgba(148,163,184,.55)';
      ctx.font = '12px inherit';
      ctx.textAlign = 'center';
      ctx.fillText('No samples yet — collector starts within seconds', w / 2, h / 2);
      return;
    }
    const pad = { l: 34, r: 10, t: 12, b: 20 };
    const cw = w - pad.l - pad.r, ch = h - pad.t - pad.b;
    let max = opts.max;
    if (max == null) {
      max = 0;
      data.forEach((s) => s.data.forEach((v) => { if (Number.isFinite(v) && v > max) max = v; }));
      max = max <= 0 ? 1 : max * 1.15;
    }
    const gridColor = 'rgba(148,163,184,.12)';
    const labelColor = 'rgba(148,163,184,.55)';
    // Grid + Y labels
    ctx.font = '10px inherit';
    ctx.textAlign = 'right';
    ctx.textBaseline = 'middle';
    const lines = 4;
    for (let i = 0; i <= lines; i++) {
      const y = pad.t + (ch * i) / lines;
      ctx.strokeStyle = gridColor;
      ctx.lineWidth = 1;
      ctx.beginPath(); ctx.moveTo(pad.l, y); ctx.lineTo(w - pad.r, y); ctx.stroke();
      const val = max - (max * i) / lines;
      ctx.fillStyle = labelColor;
      ctx.fillText(opts.unit === '%' ? Math.round(val) + '%' : fmt.bytes(val, 0), pad.l - 6, y);
    }
    // Series
    data.forEach((s, si) => {
      const color = s.color || PALETTE[si % PALETTE.length];
      const n = s.data.length;
      const x = (i) => pad.l + (n === 1 ? cw / 2 : (cw * i) / (n - 1));
      const y = (v) => pad.t + ch - (Math.max(0, Math.min(v, max)) / max) * ch;
      // Fill
      const grad = ctx.createLinearGradient(0, pad.t, 0, pad.t + ch);
      grad.addColorStop(0, color + '3d');
      grad.addColorStop(1, color + '02');
      ctx.beginPath();
      ctx.moveTo(x(0), pad.t + ch);
      s.data.forEach((v, i) => ctx.lineTo(x(i), y(v)));
      ctx.lineTo(x(n - 1), pad.t + ch);
      ctx.closePath();
      ctx.fillStyle = grad;
      ctx.fill();
      // Line (smooth via midpoints)
      ctx.beginPath();
      if (n === 1) { ctx.arc(x(0), y(s.data[0]), 2.5, 0, Math.PI * 2); }
      else {
        ctx.moveTo(x(0), y(s.data[0]));
        for (let i = 1; i < n; i++) {
          const mx = (x(i - 1) + x(i)) / 2;
          const my = (y(s.data[i - 1]) + y(s.data[i])) / 2;
          ctx.quadraticCurveTo(x(i - 1), y(s.data[i - 1]), mx, my);
        }
        ctx.lineTo(x(n - 1), y(s.data[n - 1]));
      }
      ctx.strokeStyle = color;
      ctx.lineWidth = 2;
      ctx.lineJoin = 'round';
      ctx.lineCap = 'round';
      ctx.stroke();
      // Last-point dot
      const lastV = s.data[n - 1];
      ctx.beginPath();
      ctx.arc(x(n - 1), y(lastV), 3.2, 0, Math.PI * 2);
      ctx.fillStyle = color;
      ctx.fill();
      ctx.beginPath();
      ctx.arc(x(n - 1), y(lastV), 6.5, 0, Math.PI * 2);
      ctx.strokeStyle = color + '55';
      ctx.lineWidth = 1.5;
      ctx.stroke();
    });
    // X labels
    ctx.textAlign = 'left';
    ctx.fillStyle = labelColor;
    if (opts.xLabels && opts.xLabels.length) {
      ctx.textAlign = 'center';
      const xl = opts.xLabels;
      const step = Math.ceil(xl.length / 6);
      xl.forEach((lab, i) => {
        if (i % step !== 0 && i !== xl.length - 1) return;
        const xi = pad.l + (xl.length === 1 ? cw / 2 : (cw * i) / (xl.length - 1));
        ctx.fillText(lab, xi, h - 6);
      });
    }
  }

  function sparkline(canvas, values, color) {
    if (!canvas || !canvas.getContext) return;
    const { ctx, w, h } = setupCanvas(canvas);
    ctx.clearRect(0, 0, w, h);
    if (!values || values.length < 2) return;
    const c = color || '#22d3ee';
    let max = Math.max(...values, 1);
    const x = (i) => (w * i) / (values.length - 1);
    const y = (v) => h - 3 - ((Math.max(0, v) / max) * (h - 6));
    const grad = ctx.createLinearGradient(0, 0, 0, h);
    grad.addColorStop(0, c + '38');
    grad.addColorStop(1, c + '02');
    ctx.beginPath();
    ctx.moveTo(0, h);
    values.forEach((v, i) => ctx.lineTo(x(i), y(v)));
    ctx.lineTo(w, h);
    ctx.fillStyle = grad;
    ctx.fill();
    ctx.beginPath();
    ctx.moveTo(x(0), y(values[0]));
    values.forEach((v, i) => ctx.lineTo(x(i), y(v)));
    ctx.strokeStyle = c;
    ctx.lineWidth = 1.6;
    ctx.stroke();
  }

  // Auto-draw any <canvas data-vnm-spark='1,2,3'>
  function drawSparks(root) {
    (root || document).querySelectorAll('canvas[data-vnm-spark]').forEach((c) => {
      try { sparkline(c, c.dataset.vnmSpark.split(',').map(Number), c.dataset.vnmColor); } catch (e) {}
    });
  }

  const charts = {
    area: areaChart,
    sparkline,
    drawSparks,
    // Redraw-once fonts are ready
    redrawOnFonts(canvas, fn) {
      if (document.fonts && document.fonts.ready) document.fonts.ready.then(() => fn());
    },
  };
  VNM.charts = charts;

  /* ==================== Polling helper ==================== */
  function poll(fn, intervalMs, immediate) {
    let alive = true;
    const run = async () => {
      if (!alive || document.visibilityState !== 'visible') return;
      try { await fn(); } catch (e) { /* transient */ }
    };
    if (immediate !== false) setTimeout(run, 0);
    const t = setInterval(run, intervalMs);
    document.addEventListener('visibilitychange', () => {
      if (document.visibilityState === 'visible') run();
    });
    return () => { alive = false; clearInterval(t); };
  }
  VNM.poll = poll;

  /* ==================== Sidebar collapse ==================== */
  function initSidebarCollapse() {
    const KEY = 'vnm-sidebar-collapsed';
    if (localStorage.getItem(KEY) === '1') document.body.classList.add('sidebar-collapsed');
    document.querySelectorAll('[data-sidebar-collapse]').forEach((btn) => {
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        document.body.classList.toggle('sidebar-collapsed');
        localStorage.setItem(KEY, document.body.classList.contains('sidebar-collapsed') ? '1' : '0');
        // Redraw any visible charts after the layout settles
        setTimeout(() => window.dispatchEvent(new Event('resize')), 320);
      });
    });
  }

  /* ==================== Command palette ==================== */
  const PALETTE_ACTIONS = [
    { title: 'Create VM', sub: 'Provision a new virtual machine', href: '/admin/vm-create', icon: 'M12 5v14M5 12h14' },
    { title: 'All VMs', sub: 'Browse and manage virtual machines', href: '/admin/vms', icon: 'M2 4h20v16H2zM8 20h8M12 16v4' },
    { title: 'Monitoring & Alerts', sub: 'Live metrics, history, alert rules', href: '/admin/monitoring', icon: 'M22 12h-4l-3 9L9 3l-3 9H2' },
    { title: 'Task Automation', sub: 'Job queue, schedules, history', href: '/admin/tasks', icon: 'M12 8v4l3 3M12 3a9 9 0 100 18 9 9 0 000-18z' },
    { title: 'Backup Center', sub: 'Backups, snapshots, recovery tests', href: '/admin/backups', icon: 'M19 21H5a2 2 0 01-2-2V5a2 2 0 012-2h11l5 5v11a2 2 0 01-2 2zM17 21v-8H7v8M7 3v5h8' },
    { title: 'Storage Pools', sub: 'Disk usage across nodes', href: '/admin/storage', icon: 'M3 7h18v4H3zM5 11v8M19 11v8M3 19h18' },
    { title: 'Network Center', sub: 'IPs, port forwards, firewall', href: '/admin/network', icon: 'M12 3v18M5 8c0 4 14 4 14 8M19 8c0-4-14-4-14-8' },
    { title: 'API Keys', sub: 'Scoped programmatic access', href: '/admin/api-keys', icon: 'M21 2l-2 2m-7.6 7.6a5.5 5.5 0 11-7.8 7.8 5.5 5.5 0 017.8-7.8zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3' },
    { title: 'Audit Log', sub: 'Security-sensitive action history', href: '/admin/audit', icon: 'M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8zM14 2v6h6M16 13H8M16 17H8M10 9H8' },
    { title: 'Nodes', sub: 'Fleet infrastructure and agents', href: '/admin/nodes', icon: 'M2 2h20v8H2zM2 14h20v8H2zM6 6h.01M6 18h.01' },
    { title: 'Users', sub: 'Accounts, roles, quotas', href: '/admin/users', icon: 'M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2M9 3a4 4 0 100 8 4 4 0 000-8z' },
    { title: 'OS Templates', sub: 'Cloud images and ISO library', href: '/admin/templates', icon: 'M21 16V8l-9-5-9 5v8l9 5zM3.3 7L12 12l8.7-5M12 22V12' },
    { title: 'Settings', sub: 'Panel configuration', href: '/admin/settings', icon: 'M12 15a3 3 0 100-6 3 3 0 000 6z' },
    { title: 'My Panel (user view)', sub: 'Switch to the user dashboard', href: '/dashboard', icon: 'M3 9l9-7 9 7v11a2 2 0 01-2 2H5a2 2 0 01-2-2z' },
    { title: 'My Monitoring', sub: 'Your VMs live metrics', href: '/monitoring', icon: 'M22 12h-4l-3 9L9 3l-3 9H2' },
    { title: 'My Tasks', sub: 'Your backup and automation jobs', href: '/tasks', icon: 'M12 8v4l3 3M12 3a9 9 0 100 18 9 9 0 000-18z' },
  ];

  let cpState = { open: false, items: [], selected: 0 };

  function ensurePaletteDom() {
    if (document.getElementById('vnmPalette')) return;
    const overlay = document.createElement('div');
    overlay.id = 'vnmPalette';
    overlay.className = 'cp-overlay';
    overlay.innerHTML = `
      <div class="cp-panel" role="dialog" aria-label="Command palette">
        <div class="cp-input-row">
          <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>
          <input class="cp-input" id="vnmPaletteInput" placeholder="Search VMs, nodes, users, or jump anywhere..." autocomplete="off" spellcheck="false">
          <span class="cp-kbd">ESC</span>
        </div>
        <div class="cp-results" id="vnmPaletteResults"></div>
        <div class="cp-footer">
          <span><kbd>↑↓</kbd> navigate</span><span><kbd>↵</kbd> open</span><span><kbd>esc</kbd> close</span>
          <span style="margin-left:auto;">VNM Command Center</span>
        </div>
      </div>`;
    document.body.appendChild(overlay);
    const input = overlay.querySelector('#vnmPaletteInput');
    overlay.addEventListener('mousedown', (e) => { if (e.target === overlay) closePalette(); });
    input.addEventListener('input', () => scheduleSearch(input.value));
    input.addEventListener('keydown', (e) => {
      if (e.key === 'ArrowDown') { e.preventDefault(); moveSel(1); }
      else if (e.key === 'ArrowUp') { e.preventDefault(); moveSel(-1); }
      else if (e.key === 'Enter') { e.preventDefault(); openSelected(); }
      else if (e.key === 'Escape') { e.preventDefault(); closePalette(); }
    });
  }

  function paletteItemsFor(q) {
    const query = q.trim().toLowerCase();
    if (query.length < 2) return [{ section: 'Quick jump' }, ...PALETTE_ACTIONS.map((a) => ({ kind: 'action', ...a }))].slice(0, 12);
    const acts = PALETTE_ACTIONS.filter((a) => a.title.toLowerCase().includes(query) || a.sub.toLowerCase().includes(query)).slice(0, 5)
      .map((a) => ({ kind: 'action', ...a }));
    return [{ section: 'Search results' }, ...acts]; // remote results are appended async
  }

  let searchTimer = null;
  function scheduleSearch(q) {
    renderPalette(paletteItemsFor(q), q);
    clearTimeout(searchTimer);
    if (q.trim().length < 2) return;
    searchTimer = setTimeout(async () => {
      try {
        const res = await fetch('/api/search?q=' + encodeURIComponent(q.trim()));
        if (!res.ok) return;
        const data = await res.json();
        const items = [];
        (data.vms || []).forEach((v) => items.push({ kind: 'link', title: v.vm_name, sub: 'VM #' + v.vm_id + ' · ' + (v.status || '') + (v.os_type ? ' · ' + v.os_type : ''), href: (window.location.pathname.startsWith('/admin') ? '/admin/vm/' : '/vm/') + v.vm_id, icon: 'M2 4h20v16H2zM8 20h8M12 16v4' }));
        (data.nodes || []).forEach((n) => items.push({ kind: 'link', title: n.name, sub: 'Node · ' + n.mode + (n.maintenance_mode ? ' · maintenance' : ' · ' + n.status), href: '/admin/nodes', icon: 'M2 2h20v8H2zM2 14h20v8H2z' }));
        (data.users || []).forEach((u) => items.push({ kind: 'link', title: u.username, sub: 'User · ' + u.role, href: '/admin/users/' + u.id + '/edit', icon: 'M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2M9 3a4 4 0 100 8 4 4 0 000-8z' }));
        (data.templates || []).forEach((t) => items.push({ kind: 'link', title: t.template_name, sub: 'OS template', href: '/admin/templates', icon: 'M21 16V8l-9-5-9 5v8l9 5z' }));
        // Only rerender if the query hasn't changed while fetching
        if (document.getElementById('vnmPaletteInput') && document.getElementById('vnmPaletteInput').value.trim() === q.trim()) {
          const base = paletteItemsFor(q);
          renderPalette(base.concat(items.length ? items : []), q);
        }
      } catch (e) { /* offline */ }
    }, 220);
  }

  function renderPalette(items, q) {
    const box = document.getElementById('vnmPaletteResults');
    if (!box) return;
    cpState.items = items.filter((i) => !i.section);
    cpState.selected = 0;
    if (!cpState.items.length) {
      box.innerHTML = '<div class="cp-empty">No matches for "' + esc(q) + '"</div>';
      return;
    }
    let idx = -1;
    box.innerHTML = items.map((it) => {
      if (it.section) return '<div class="cp-section">' + esc(it.section) + '</div>';
      idx++;
      const sel = idx === cpState.selected ? ' selected' : '';
      return `<div class="cp-item${sel}" data-idx="${idx}">
        <span class="cp-item-icon"><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="${esc(it.icon || 'M12 5v14M5 12h14')}"/></svg></span>
        <span style="min-width:0"><div class="cp-item-title">${esc(it.title)}</div><div class="cp-item-sub">${esc(it.sub || '')}</div></span>
        <span class="cp-item-arrow">↵</span>
      </div>`;
    }).join('');
    box.querySelectorAll('.cp-item').forEach((el) => {
      el.addEventListener('click', () => { cpState.selected = +el.dataset.idx; openSelected(); });
      el.addEventListener('mousemove', () => {
        if (cpState.selected !== +el.dataset.idx) {
          cpState.selected = +el.dataset.idx;
          box.querySelectorAll('.cp-item').forEach((x) => x.classList.toggle('selected', +x.dataset.idx === cpState.selected));
        }
      });
    });
  }

  function moveSel(d) {
    const box = document.getElementById('vnmPaletteResults');
    cpState.selected = (cpState.selected + d + cpState.items.length) % Math.max(cpState.items.length, 1);
    box.querySelectorAll('.cp-item').forEach((x) => x.classList.toggle('selected', +x.dataset.idx === cpState.selected));
    const sel = box.querySelector('.cp-item.selected');
    if (sel) sel.scrollIntoView({ block: 'nearest' });
  }

  function openSelected() {
    const it = cpState.items[cpState.selected];
    if (!it) return;
    closePalette();
    if (it.href) window.location.href = it.href;
  }

  function openPalette() {
    ensurePaletteDom();
    document.getElementById('vnmPalette').classList.add('show');
    const input = document.getElementById('vnmPaletteInput');
    input.value = '';
    input.focus();
    renderPalette(paletteItemsFor(''), '');
    cpState.open = true;
  }
  function closePalette() {
    const el = document.getElementById('vnmPalette');
    if (el) el.classList.remove('show');
    cpState.open = false;
  }

  function initPalette() {
    document.addEventListener('keydown', (e) => {
      if ((e.ctrlKey || e.metaKey) && (e.key === 'k' || e.key === 'K')) {
        e.preventDefault();
        cpState.open ? closePalette() : openPalette();
      } else if (e.key === 'Escape' && cpState.open) {
        closePalette();
      }
    });
    document.querySelectorAll('[data-open-palette]').forEach((el) => {
      el.addEventListener('click', (e) => { e.preventDefault(); openPalette(); });
    });
    const gs = document.getElementById('globalSearch');
    if (gs) {
      gs.addEventListener('focus', () => { openPalette(); gs.blur(); });
    }
  }
  VNM.openPalette = openPalette;

  /* ==================== Bulk actions ==================== */
  // Wire: VNM.bulk({ checkboxSelector: '.vm-select', barId: 'bulkBar', actions: {...}, rowId: cb => cb.dataset.vmId })
  function bulk({ checkboxSelector, barId, onRun, rowId }) {
    const bar = document.getElementById(barId);
    if (!bar) return;
    const boxes = () => [...document.querySelectorAll(checkboxSelector + ':checked')];
    const refresh = () => {
      const sel = boxes();
      bar.classList.toggle('show', sel.length > 0);
      const cnt = bar.querySelector('.bulk-count');
      if (cnt) cnt.textContent = sel.length + ' selected';
    };
    document.addEventListener('change', (e) => {
      if (e.target.matches && e.target.matches(checkboxSelector)) refresh();
      if (e.target.id === 'bulkSelectAll') {
        document.querySelectorAll(checkboxSelector).forEach((cb) => { cb.checked = e.target.checked; });
        refresh();
      }
    });
    bar.querySelectorAll('[data-bulk-action]').forEach((btn) => {
      btn.addEventListener('click', async () => {
        const action = btn.dataset.bulkAction;
        const sel = boxes();
        if (!sel.length) return;
        const ids = sel.map((cb) => (rowId ? rowId(cb) : cb.value)).filter(Boolean);
        if (!ids.length) return;
        btn.disabled = true;
        try { await onRun(action, ids, btn); }
        finally { btn.disabled = false; }
      });
    });
  }
  VNM.bulk = bulk;

  /* ==================== Toast (light helper for platform pages) ==================== */
  function toast(msg, type) {
    let host = document.getElementById('vnmToastHost');
    if (!host) {
      host = document.createElement('div');
      host.id = 'vnmToastHost';
      host.style.cssText = 'position:fixed;bottom:22px;right:22px;z-index:950;display:flex;flex-direction:column;gap:9px;';
      document.body.appendChild(host);
    }
    const el = document.createElement('div');
    const color = type === 'error' ? '#f87171' : type === 'success' ? '#34d399' : '#22d3ee';
    el.style.cssText = `max-width:380px;padding:11px 16px;border-radius:12px;font-size:13px;font-family:inherit;
      color:#e2e8f0;background:rgba(13,18,32,.92);backdrop-filter:blur(14px);
      border:1px solid ${color}44;box-shadow:0 10px 34px rgba(0,0,0,.4), 0 0 18px ${color}22;
      animation:toastIn .3s cubic-bezier(.22,1,.36,1) both;`;
    el.innerHTML = (type === 'error' ? '⚠ ' : type === 'success' ? '✓ ' : '') + esc(msg);
    host.appendChild(el);
    setTimeout(() => {
      el.style.transition = 'opacity .4s ease, transform .4s ease';
      el.style.opacity = '0'; el.style.transform = 'translateY(8px)';
      setTimeout(() => el.remove(), 420);
    }, 4200);
  }
  VNM.toast = toast;

  /* keyframes for toast injected once */
  if (!document.getElementById('vnmToastKeyframes')) {
    const st = document.createElement('style');
    st.id = 'vnmToastKeyframes';
    st.textContent = '@keyframes toastIn{from{opacity:0;transform:translateY(12px)}to{opacity:1;transform:none}}';
    document.head.appendChild(st);
  }

  /* ==================== Boot ==================== */
  function boot() {
    initSidebarCollapse();
    initPalette();
    drawSparks();
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
  else boot();
})();
