/* ═══════════════════════════════════════════════════════════════════════════
   VNM PANEL — MOTION RUNTIME (v2.0 "Aurora")
   Progressive enhancement layer: ripples, count-up numbers, scroll reveal,
   page-exit transitions, subtle card tilt. Zero dependencies; every feature
   degrades gracefully and respects prefers-reduced-motion.
   ═══════════════════════════════════════════════════════════════════════════ */
(function () {
  'use strict';

  var REDUCED = window.matchMedia &&
    window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  /* ── 1. RIPPLE — material-style ink on every .btn ─────────────────────── */
  document.addEventListener('pointerdown', function (e) {
    if (REDUCED) return;
    var btn = e.target.closest && e.target.closest('.btn, .header-btn, .theme-btn, .page-btn');
    if (!btn || btn.disabled) return;
    var rect = btn.getBoundingClientRect();
    var size = Math.max(rect.width, rect.height) * 1.6;
    var ink = document.createElement('span');
    ink.className = 'ripple-ink';
    ink.style.width = ink.style.height = size + 'px';
    ink.style.left = (e.clientX - rect.left - size / 2) + 'px';
    ink.style.top = (e.clientY - rect.top - size / 2) + 'px';
    if (getComputedStyle(btn).position === 'static') btn.style.position = 'relative';
    btn.appendChild(ink);
    setTimeout(function () { ink.remove(); }, 600);
  }, { passive: true });

  /* ── 2. COUNT-UP — animate numeric stat values once on first sight ────── */
  function countUp(el) {
    var raw = el.getAttribute('data-count-original') || el.textContent;
    el.setAttribute('data-count-original', raw);
    var m = String(raw).trim().match(/^([\d,.\s]+)(.*)$/);
    if (!m) return;
    var numStr = m[1].replace(/,/g, '');
    var target = parseFloat(numStr);
    if (isNaN(target)) return;
    var suffix = m[2] || '';
    var decimals = (numStr.split('.')[1] || '').length;
    var start = null, DUR = REDUCED ? 1 : 900;
    el.classList.add('count-up', 'flashing');
    function frame(ts) {
      if (!start) start = ts;
      var p = Math.min((ts - start) / DUR, 1);
      var eased = 1 - Math.pow(1 - p, 3); /* easeOutCubic */
      var val = target * eased;
      el.textContent = (decimals ? val.toFixed(decimals) : Math.round(val).toLocaleString()) + suffix;
      if (p < 1) requestAnimationFrame(frame);
      else { el.textContent = raw; setTimeout(function(){ el.classList.remove('flashing'); }, 420); }
    }
    requestAnimationFrame(frame);
  }

  var countables = document.querySelectorAll(
    '.stat-value, .stat-card .stat-value, .stat-card-enhanced .stat-number, .resource-ring-value'
  );
  if ('IntersectionObserver' in window && countables.length) {
    var seen = new WeakSet();
    var cObs = new IntersectionObserver(function (entries) {
      entries.forEach(function (en) {
        if (en.isIntersecting && !seen.has(en.target)) {
          seen.add(en.target);
          countUp(en.target);
          cObs.unobserve(en.target);
        }
      });
    }, { threshold: 0.4 });
    countables.forEach(function (el) { cObs.observe(el); });
  }

  /* ── 3. SCROLL REVEAL — below-the-fold cards rise in ──────────────────── */
  if (!REDUCED && 'IntersectionObserver' in window) {
    var revealables = document.querySelectorAll(
      '.admin-content .card, .admin-content .table-container, ' +
      '.admin-content .settings-section, .admin-content .vm-card'
    );
    /* Only apply to elements NOT already animated by the CSS entrance
       stagger — detect via viewport position (below the fold). */
    var rObs = new IntersectionObserver(function (entries) {
      entries.forEach(function (en) {
        if (en.isIntersecting) {
          en.target.classList.add('revealed');
          rObs.unobserve(en.target);
        }
      });
    }, { rootMargin: '0px 0px -40px 0px' });
    requestAnimationFrame(function () {
      revealables.forEach(function (el) {
        var rect = el.getBoundingClientRect();
        if (rect.top > window.innerHeight * 0.92) {
          el.classList.add('reveal');
          rObs.observe(el);
        }
      });
    });
  }

  /* ── 4. CARD TILT — subtle 3D parallax on stat cards ──────────────────── */
  if (!REDUCED && window.matchMedia('(hover: hover)').matches) {
    var TILT_SEL = '.stat-card, .stat-card-enhanced, .vm-card, .template-card';
    var MAX_TILT = 3.2; /* degrees — deliberately subtle */
    document.addEventListener('pointermove', function (e) {
      var card = e.target.closest && e.target.closest(TILT_SEL);
      if (!card) return;
      var r = card.getBoundingClientRect();
      var px = (e.clientX - r.left) / r.width - 0.5;
      var py = (e.clientY - r.top) / r.height - 0.5;
      card.style.transform =
        'perspective(900px) rotateX(' + (-py * MAX_TILT).toFixed(2) + 'deg) rotateY(' +
        (px * MAX_TILT).toFixed(2) + 'deg) translateY(-3px)';
      card.style.transition = 'transform 80ms linear';
    }, { passive: true });
    document.addEventListener('pointerout', function (e) {
      var card = e.target.closest && e.target.closest(TILT_SEL);
      if (card) {
        card.style.transition = 'transform 420ms cubic-bezier(0.22,1,0.36,1)';
        card.style.transform = '';
      }
    }, { passive: true });
  }

  /* ── 5. PAGE-EXIT TRANSITION — content dips before navigating ─────────── */
  if (!REDUCED) {
    document.addEventListener('click', function (e) {
      var a = e.target.closest && e.target.closest('a[href]');
      if (!a) return;
      var href = a.getAttribute('href') || '';
      if (a.target === '_blank' || a.hasAttribute('download')) return;
      if (href.charAt(0) === '#') return;
      var sameOrigin = href.charAt(0) === '/' ||
        href.indexOf(window.location.origin) === 0;
      if (!sameOrigin) return;
      if (e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
      document.body.classList.add('page-exiting');
      /* Safety: never block navigation for longer than needed. */
      setTimeout(function () { document.body.classList.remove('page-exiting'); }, 400);
    }, { passive: true });
  }

  /* ── 6. DYNAMIC CARD STAGGER — MutationObserver animates injected cards ── */
  if (!REDUCED && 'MutationObserver' in window) {
    var staggerHosts = document.querySelectorAll('.vm-list, .stats-grid, .stats-enhanced, .template-grid');
    var mObs = new MutationObserver(function (muts) {
      muts.forEach(function (m) {
        Array.prototype.forEach.call(m.addedNodes, function (n) {
          if (n.nodeType !== 1) return;
          var cards = n.matches && (n.matches('.vm-card, .stat-card, .template-card, .card'))
            ? [n] : (n.querySelectorAll ? n.querySelectorAll('.vm-card, .stat-card, .template-card') : []);
          Array.prototype.forEach.call(cards, function (c, i) {
            c.style.animation = 'sectionRise 480ms cubic-bezier(0.22,1,0.36,1) ' +
              Math.min(i * 70, 420) + 'ms backwards';
          });
        });
      });
    });
    staggerHosts.forEach(function (h) { mObs.observe(h, { childList: true, subtree: true }); });
  }

  /* ── 7. TOAST LIFETIME SYNC — feed real duration into the progress bar ── */
  var toastHost = document.getElementById('toastContainer');
  if (toastHost && 'MutationObserver' in window) {
    var tObs = new MutationObserver(function (muts) {
      muts.forEach(function (m) {
        Array.prototype.forEach.call(m.addedNodes, function (n) {
          if (n.nodeType === 1 && n.classList && n.classList.contains('toast')) {
            if (!n.style.getPropertyValue('--toast-life')) {
              n.style.setProperty('--toast-life', '4s');
            }
          }
        });
      });
    });
    tObs.observe(toastHost, { childList: true });
  }

  /* ── 8. SMOOTH ANCHOR SCROLLING ────────────────────────────────────────── */
  document.addEventListener('click', function (e) {
    var a = e.target.closest && e.target.closest('a[href^="#"]');
    if (!a) return;
    var id = a.getAttribute('href').slice(1);
    if (!id) return;
    var el = document.getElementById(id);
    if (el) {
      e.preventDefault();
      el.scrollIntoView({ behavior: REDUCED ? 'auto' : 'smooth', block: 'start' });
    }
  });
})();
