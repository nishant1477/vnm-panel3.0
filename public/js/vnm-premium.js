/**
 * VNM Premium — client runtime
 * ---------------------------------------------------------------------
 * Loaded on every authenticated page (via the shared footer partial).
 *
 * Responsibilities:
 *  - caches /api/premium/status on load
 *  - patches fetch(): any 402 { premium_required } response pops the
 *    license modal for that feature, so even pages that forgot to
 *    pre-check show the unlock flow
 *  - VNM.premium.ensure(featureId, cb) — gate any UI action
 *  - injects the PRO chip in the header + body.premium-on class
 *  - owns the license modal (enter key -> activate -> refresh locks)
 *
 * The license key is only ever sent to POST /api/premium/activate over
 * the same origin; it is never stored client-side.
 */
(function () {
  'use strict';
  if (window.VNM && window.VNM.premium) return; // double-load guard

  const VNM = (window.VNM = window.VNM || {});
  const GOLD = 'linear-gradient(135deg,#fbbf24,#f59e0b)';

  // ---------- state ----------
  const state = {
    on: false,
    status: null,          // last /api/premium/status payload
    modalFor: null,        // feature id the modal is currently pitching
    pending: {},           // featureId -> callback to run after unlock
  };

  // ---------- tiny helpers ----------
  const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const fmtBytes = (n) => { // only used in manage view
    if (n == null) return '—';
    const u = ['B', 'KB', 'MB', 'GB']; let i = 0; while (n >= 1024 && i < 3) { n /= 1024; i++; }
    return n.toFixed(n >= 100 || i === 0 ? 0 : 1) + ' ' + u[i];
  };
  VNM.fmt = VNM.fmt || {}; VNM.fmt.bytes = VNM.fmt.bytes || fmtBytes;

  // ---------- CSS (injected once) ----------
  function injectCss() {
    if (document.getElementById('vnm-premium-css')) return;
    const st = document.createElement('style');
    st.id = 'vnm-premium-css';
    st.textContent = `
.prem-pro-chip{display:inline-flex;align-items:center;gap:5px;margin-left:9px;padding:2px 9px;border-radius:99px;font-size:10px;font-weight:800;letter-spacing:.8px;color:#1a1206;background:${GOLD};border:1px solid rgba(251,191,36,.55);box-shadow:0 2px 10px rgba(245,158,11,.28);animation:premPop .45s cubic-bezier(.22,1,.36,1) both}
.prem-pro-chip svg{width:11px;height:11px}
@keyframes premPop{from{opacity:0;transform:scale(.6)}to{opacity:1;transform:scale(1)}}
.prem-feature-chip{display:inline-flex;align-items:center;gap:5px;font-size:9.5px;font-weight:800;letter-spacing:.7px;text-transform:uppercase;padding:2px 8px;border-radius:99px;color:#fcd34d;background:rgba(245,158,11,.1);border:1px solid rgba(245,158,11,.32);flex-shrink:0}
.prem-feature-chip svg{width:10px;height:10px}
.prem-locked-card{position:relative}
.prem-locked-card>.prem-veil{position:absolute;inset:0;z-index:5;border-radius:inherit;background:rgba(8,11,20,.66);backdrop-filter:blur(7px);cursor:pointer;transition:background .2s ease}
.prem-locked-card>.prem-veil:hover{background:rgba(8,11,20,.78)}
/* standalone (in-flow) veil — used when the locked content is hidden entirely */
.prem-veil{display:flex;flex-direction:column;align-items:center;justify-content:center;gap:10px;text-align:center;padding:30px 18px;border-radius:inherit}
.prem-veil .prem-veil-title{font-size:14px;font-weight:750;color:#fde68a;display:flex;align-items:center;gap:8px}
.prem-veil .prem-veil-sub{font-size:11.5px;color:var(--text-muted,#94a3b8);max-width:340px;line-height:1.55}
.prem-veil .prem-veil-btn{margin-top:2px;display:inline-flex;align-items:center;gap:7px;padding:8px 16px;border-radius:10px;font-size:12px;font-weight:750;font-family:inherit;color:#1a1206;background:${GOLD};border:1px solid rgba(251,191,36,.6);cursor:pointer;box-shadow:0 6px 22px rgba(245,158,11,.3);transition:transform .18s ease,box-shadow .18s ease}
.prem-veil .prem-veil-btn:hover{transform:translateY(-1px);box-shadow:0 10px 30px rgba(245,158,11,.4)}
.prem-veil .prem-veil-btn svg{width:13px;height:13px}
/* ---- license modal ---- */
.prem-overlay{position:fixed;inset:0;z-index:1100;background:rgba(2,4,10,.66);backdrop-filter:blur(7px) saturate(1.25);display:none;align-items:center;justify-content:center;padding:18px}
.prem-overlay.show{display:flex;animation:premFade .2s ease both}
@keyframes premFade{from{opacity:0}to{opacity:1}}
.prem-panel{width:min(460px,calc(100vw - 28px));border-radius:18px;overflow:hidden;position:relative;background:#0b101d;border:1px solid rgba(251,191,36,.28);box-shadow:0 30px 90px rgba(0,0,0,.6),0 0 50px rgba(245,158,11,.1);animation:premPanelIn .3s cubic-bezier(.22,1,.36,1) both}
@keyframes premPanelIn{from{opacity:0;transform:translateY(-16px) scale(.97)}to{opacity:1;transform:none}}
.prem-panel::before{content:'';position:absolute;top:0;left:0;right:0;height:2.5px;background:${GOLD}}
.prem-head{display:flex;align-items:center;gap:13px;padding:17px 20px 13px;border-bottom:1px solid rgba(148,163,184,.12)}
.prem-head-icon{width:42px;height:42px;border-radius:13px;display:flex;align-items:center;justify-content:center;background:rgba(245,158,11,.12);border:1px solid rgba(245,158,11,.3);color:#fcd34d;flex-shrink:0}
.prem-head-icon svg{width:21px;height:21px}
.prem-head-title{font-size:16.5px;font-weight:800;color:#fde68a;letter-spacing:-.2px}
.prem-head-sub{font-size:11.5px;color:var(--text-muted,#94a3b8);margin-top:2px}
.prem-x{margin-left:auto;width:30px;height:30px;border-radius:9px;display:flex;align-items:center;justify-content:center;background:transparent;border:1px solid rgba(148,163,184,.18);color:var(--text-muted,#94a3b8);cursor:pointer;transition:all .18s ease;flex-shrink:0}
.prem-x:hover{color:#fca5a5;border-color:rgba(239,68,68,.4)}
.prem-x svg{width:13px;height:13px}
.prem-body{padding:17px 20px}
.prem-feature-box{display:flex;gap:11px;align-items:flex-start;padding:12px 14px;border-radius:12px;background:rgba(245,158,11,.06);border:1px solid rgba(245,158,11,.22);margin-bottom:14px}
.prem-feature-box .fb-icon{width:34px;height:34px;border-radius:10px;flex-shrink:0;display:flex;align-items:center;justify-content:center;background:rgba(245,158,11,.13);border:1px solid rgba(245,158,11,.3);color:#fcd34d}
.prem-feature-box .fb-icon svg{width:16px;height:16px}
.prem-feature-box .fb-name{font-size:13.5px;font-weight:750;color:#fde68a}
.prem-feature-box .fb-desc{font-size:11.5px;color:var(--text-secondary,#cbd5e1);margin-top:3px;line-height:1.5}
.prem-list{margin:0 0 14px;padding:0;list-style:none;display:flex;flex-direction:column;gap:7px}
.prem-list li{display:flex;align-items:center;gap:9px;font-size:12px;color:var(--text-secondary,#cbd5e1)}
.prem-list li svg{width:13px;height:13px;color:#fcd34d;flex-shrink:0}
.prem-label{font-size:10.5px;font-weight:800;text-transform:uppercase;letter-spacing:.9px;color:var(--text-muted,#94a3b8);margin-bottom:7px}
.prem-input{width:100%;padding:11px 14px;border-radius:11px;background:rgba(8,12,22,.72);border:1px solid rgba(251,191,36,.3);color:#fde68a;font-family:'Sarasa Mono SC',ui-monospace,Menlo,monospace;font-size:14px;letter-spacing:1.5px;text-align:center;outline:none;transition:border-color .18s ease,box-shadow .18s ease;text-transform:uppercase}
.prem-input::placeholder{color:rgba(148,163,184,.5);letter-spacing:.4px;text-transform:none;font-family:inherit}
.prem-input:focus{border-color:rgba(251,191,36,.65);box-shadow:0 0 0 4px rgba(245,158,11,.12)}
.prem-input.prem-err{border-color:rgba(239,68,68,.65);animation:premShake .4s ease}
@keyframes premShake{0%,100%{transform:translateX(0)}25%{transform:translateX(-7px)}75%{transform:translateX(7px)}}
.prem-msg{min-height:18px;font-size:12px;margin-top:9px;color:#fca5a5;display:flex;align-items:center;gap:7px}
.prem-msg.ok{color:#6ee7b7}
.prem-actions{display:flex;gap:9px;margin-top:13px}
.prem-btn{flex:1;display:inline-flex;align-items:center;justify-content:center;gap:8px;padding:11px 16px;border-radius:11px;font-size:13px;font-weight:800;font-family:inherit;cursor:pointer;transition:transform .18s ease,box-shadow .18s ease;border:1px solid transparent}
.prem-btn svg{width:14px;height:14px}
.prem-btn-gold{color:#1a1206;background:${GOLD};border-color:rgba(251,191,36,.6);box-shadow:0 8px 26px rgba(245,158,11,.32)}
.prem-btn-gold:hover{transform:translateY(-1px);box-shadow:0 12px 34px rgba(245,158,11,.42)}
.prem-btn-ghost{background:transparent;color:var(--text-secondary,#cbd5e1);border-color:rgba(148,163,184,.22)}
.prem-btn-ghost:hover{color:var(--text-primary,#f1f5f9);border-color:rgba(148,163,184,.4)}
.prem-btn:disabled{opacity:.55;cursor:wait;transform:none}
.prem-foot{display:flex;gap:12px;align-items:center;padding:11px 20px;border-top:1px solid rgba(148,163,184,.12);font-size:10.5px;color:var(--text-muted,#94a3b8)}
.prem-foot .prem-dot{width:7px;height:7px;border-radius:50%;background:${GOLD};box-shadow:0 0 10px rgba(245,158,11,.8)}
.prem-manage{padding:15px 20px;border-top:1px solid rgba(148,163,184,.12);display:flex;align-items:center;gap:11px}
.prem-manage .pm-avatar{width:38px;height:38px;border-radius:12px;display:flex;align-items:center;justify-content:center;background:${GOLD};color:#1a1206;flex-shrink:0}
.prem-manage .pm-avatar svg{width:19px;height:19px}
.prem-manage .pm-name{font-size:13.5px;font-weight:800;color:#fde68a}
.prem-manage .pm-sub{font-size:11px;color:var(--text-muted,#94a3b8);margin-top:2px}
.prem-manage button{margin-left:auto}
@media (prefers-reduced-motion:reduce){.prem-panel,.prem-overlay.show,.prem-pro-chip,.prem-input.prem-err{animation:none!important}}
`;
    document.head.appendChild(st);
  }

  // ---------- icons ----------
  const IC = {
    crown: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 17l2-9 4 5 3-7 3 7 4-5 2 9H3z"/><path d="M5 21h14"/></svg>',
    lock: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="11" width="16" height="10" rx="2.5"/><path d="M8 11V7a4 4 0 018 0v4"/></svg>',
    check: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>',
    x: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>',
    key: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 11-7.778 7.778 5.5 5.5 0 017.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/></svg>',
    bolt: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>',
    shield: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>',
    globe: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 014 10 15.3 15.3 0 01-4 10 15.3 15.3 0 01-4-10 15.3 15.3 0 014-10z"/></svg>',
    cam: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M23 19a2 2 0 01-2 2H3a2 2 0 01-2-2V8a2 2 0 012-2h4l2-3h6l2 3h4a2 2 0 012 2z"/><circle cx="12" cy="13" r="4"/></svg>',
    power: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18.36 6.64a9 9 0 11-12.73 0"/><line x1="12" y1="2" x2="12" y2="12"/></svg>',
  };
  const FEATURE_ICON = {
    auto_backup: IC.cam, live_migration: IC.globe, alert_rules: IC.shield, scheduled_power: IC.power,
  };

  // ---------- modal ----------
  let overlay = null;
  function ensureOverlay() {
    if (overlay) return overlay;
    injectCss();
    overlay = document.createElement('div');
    overlay.className = 'prem-overlay';
    overlay.id = 'vnmPremiumModal';
    overlay.addEventListener('click', (e) => { if (e.target === overlay) hideModal(); });
    document.body.appendChild(overlay);
    document.addEventListener('keydown', (e) => { if (e.key === 'Escape' && overlay.classList.contains('show')) hideModal(); });
    return overlay;
  }

  function hideModal() { if (overlay) overlay.classList.remove('show'); }

  function renderModal(featureId, opts = {}) {
    const o = ensureOverlay();
    const f = (state.status && state.status.features.find((x) => x.id === featureId)) || { id: featureId, label: featureId, desc: '' };
    const others = (state.status ? state.status.features : []).filter((x) => x.id !== featureId).slice(0, 3);
    const showManage = state.on && opts.manageable;
    o.innerHTML = `
      <div class="prem-panel" role="dialog" aria-modal="true" aria-label="VNM Premium">
        <div class="prem-head">
          <div class="prem-head-icon">${IC.crown}</div>
          <div>
            <div class="prem-head-title">VNM Premium</div>
            <div class="prem-head-sub">${state.on ? 'Premium is active on this panel' : 'Unlock the full platform with a license key'}</div>
          </div>
          <button class="prem-x" aria-label="Close">${IC.x}</button>
        </div>
        ${showManage ? `
        <div class="prem-manage">
          <div class="pm-avatar">${IC.crown}</div>
          <div>
            <div class="pm-name">Premium active</div>
            <div class="pm-sub">Unlocked ${esc(whenStr())}${state.status && state.status.key_tail ? ' · key ****' + esc(state.status.key_tail) : ''}</div>
          </div>
          <button class="prem-btn prem-btn-ghost" style="flex:0 0 auto;padding:8px 13px;font-size:11.5px" id="premDeactivate">Deactivate</button>
        </div>` : `
        <div class="prem-body">
          <div class="prem-feature-box">
            <div class="fb-icon">${FEATURE_ICON[f.id] || IC.bolt}</div>
            <div>
              <div class="fb-name">${esc(f.label)} ${''}</div>
              <div class="fb-desc">${esc(f.desc)}</div>
            </div>
          </div>
          <ul class="prem-list">
            ${others.map((x) => `<li>${IC.check}<span>${esc(x.label)}</span><span style="color:var(--text-muted,#94a3b8)">included in the same key</span></li>`).join('')}
            <li>${IC.check}<span>Priority support &amp; early features</span></li>
          </ul>
          <div class="prem-label">License key</div>
          <input class="prem-input" id="premKeyInput" placeholder="XXXX-XXXXXX-XXXX" autocomplete="off" spellcheck="false" maxlength="64">
          <div class="prem-msg" id="premMsg"></div>
          <div class="prem-actions">
            <button class="prem-btn prem-btn-gold" id="premActivate">${IC.key} Unlock Premium</button>
            <button class="prem-btn prem-btn-ghost" id="premCancel">Not now</button>
          </div>
        </div>`}
        <div class="prem-foot"><span class="prem-dot"></span><span>VNM Panel Premium · one key unlocks everything</span></div>
      </div>`;
    o.querySelector('.prem-x').onclick = hideModal;
    const cancel = o.querySelector('#premCancel'); if (cancel) cancel.onclick = hideModal;
    const act = o.querySelector('#premActivate');
    const input = o.querySelector('#premKeyInput');
    const msg = o.querySelector('#premMsg');
    if (act) {
      act.onclick = async () => {
        const key = input.value.trim();
        if (!key) { input.classList.add('prem-err'); setTimeout(() => input.classList.remove('prem-err'), 450); msg.className = 'prem-msg'; msg.textContent = 'Enter your license key first.'; return; }
        act.disabled = true; act.textContent = 'Checking…';
        try {
          const res = await fetch('/api/premium/activate', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ key }),
          });
          const d = await res.json().catch(() => ({}));
          if (res.ok && d.success) {
            msg.className = 'prem-msg ok'; msg.textContent = d.message || 'Premium unlocked.';
            input.value = '';
            await refresh(true);
            setTimeout(() => { hideModal(); runPending(f.id); }, 700);
          } else {
            input.classList.add('prem-err'); setTimeout(() => input.classList.remove('prem-err'), 450);
            msg.className = 'prem-msg'; msg.textContent = d.error || d.message || 'That license key is not valid.';
          }
        } catch (e) {
          msg.className = 'prem-msg'; msg.textContent = 'Could not reach the panel: ' + e.message;
        } finally { act.disabled = false; act.innerHTML = IC.key + ' Unlock Premium'; }
      };
      input.addEventListener('keydown', (e) => { if (e.key === 'Enter') act.click(); });
    }
    const deact = o.querySelector('#premDeactivate');
    if (deact) deact.onclick = async () => {
      if (!confirm('Deactivate Premium on this panel? Premium features lock again.')) return;
      try {
        const res = await fetch('/api/premium/deactivate', { method: 'POST' });
        if (res.ok) { await refresh(true); hideModal(); if (VNM.toast) VNM.toast('Premium deactivated', 'info'); }
      } catch (e) { /* ignore */ }
    };
    o.classList.add('show');
    if (input) setTimeout(() => input.focus(), 80);
  }

  function whenStr() {
    if (!state.status || !state.status.activated_at) return '';
    try {
      const d = new Date(state.status.activated_at);
      const ago = Math.floor((Date.now() - d.getTime()) / 86400000);
      return ago <= 0 ? 'today' : ago + (ago === 1 ? ' day ago' : ' days ago');
    } catch (e) { return ''; }
  }

  function runPending(featureId) {
    const cb = state.pending[featureId];
    if (cb) { delete state.pending[featureId]; try { cb(); } catch (e) { console.error('[Premium] pending callback failed', e); } }
  }

  // ---------- header chip + body class ----------
  function applyChrome() {
    document.body.classList.toggle('premium-on', state.on);
    const name = document.getElementById('headerUsername');
    if (name && !document.getElementById('premProChip')) {
      if (state.on) {
        const chip = document.createElement('span');
        chip.id = 'premProChip'; chip.className = 'prem-pro-chip';
        chip.innerHTML = IC.crown + 'PRO';
        name.appendChild(chip);
      }
    } else if (name) {
      const chip = document.getElementById('premProChip');
      if (chip && !state.on) chip.remove();
      else if (state.on && !chip) { /* re-added after nav */ }
    }
    // dropdown menu entry (license manager)
    const menu = document.getElementById('userMenu');
    if (menu && !document.getElementById('premMenuEntry')) {
      const a = document.createElement('button');
      a.className = 'dropdown-item'; a.id = 'premMenuEntry';
      a.innerHTML = IC.crown.replace('<svg', '<svg width="14" height="14"') + ' License';
      a.onclick = () => { renderModal(null, { manageable: true }); };
      const settings = menu.querySelector('a[href$="/settings"]');
      if (settings && settings.parentNode) settings.parentNode.insertBefore(a, settings);
      else menu.appendChild(a);
    }
  }

  // ---------- fetch patch: catch 402 premium_required anywhere ----------
  const origFetch = window.fetch;
  window.fetch = function patchedFetch(input, init) {
    return origFetch.apply(this, arguments).then((res) => {
      if (res.status === 402) {
        const clone = res.clone();
        clone.json().then((d) => {
          if (d && d.premium_required) {
            if (state.on) refresh(true); // stale cache — re-sync then retry via toast
            else { state.pending[d.premium_required] = state.pending[d.premium_required] || null; renderModal(d.premium_required); }
          }
        }).catch(() => {});
      }
      return res;
    });
  };

  // ---------- public API ----------
  async function refresh(force) {
    try {
      const res = await origFetch('/api/premium/status', { headers: { Accept: 'application/json' } });
      if (!res.ok) return;
      const d = await res.json();
      state.status = d;
      state.on = !!d.premium;
      applyChrome();
      document.dispatchEvent(new CustomEvent('vnm:premium', { detail: { on: state.on, status: d } }));
    } catch (e) { /* offline — keep last state */ }
  }

  VNM.premium = {
    isOn: () => state.on,
    featureOn: (id) => state.on, // single tier: one key unlocks all features
    ensure(featureId, cb) {
      if (state.on) { if (cb) try { cb(); } catch (e) { console.error(e); } return true; }
      if (cb) state.pending[featureId] = cb;
      renderModal(featureId);
      return false;
    },
    openModal: (featureId) => renderModal(featureId),
    openManage: () => renderModal(null, { manageable: true }),
    refresh,
    status: () => state.status,
  };

  // boot
  injectCss();
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', () => refresh());
  else refresh();
})();
