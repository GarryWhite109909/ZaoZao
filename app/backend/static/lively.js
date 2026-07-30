/* ======================================================================
   lively.js — 灵动交互驱动（3D 倾斜 / 磁吸 / 避开 / 去同步悬浮）
   依赖 lively.css。仅在支持 hover 的指针设备上启用倾斜/磁吸/避开；
   尊重 prefers-reduced-motion。
   ====================================================================== */
(function () {
  'use strict';

  var prefersReduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  if (prefersReduced) return; // CSS 已禁用动画，JS 不再介入

  var hasHover = window.matchMedia('(hover: hover) and (pointer: fine)').matches;

  var TILT_SEL =
    'article.glass-card:not(.result-card), .kpi-card, .bento-card, .cwe-card, .chart-card, ' +
    '.score-card, .stats-card, .posture-header, .remediation-table tbody tr, .results-panel > *:not(.result-card)';
  var MAG_SEL =
    'button, .filter-chip, .view-detail, nav[aria-label="主导航"] a, a[id^="cta-quick-"]';
  var DODGE_SEL =
    '.icon-box > svg, .kpi-card svg, nav[aria-label="主导航"] svg';

  function rand(min, max) { return min + Math.random() * (max - min); }

  /* ---- 给元素打标记 + 随机化浮动节奏（避免整齐划一） ---- */
  function decorate() {
    var els = document.querySelectorAll(TILT_SEL);
    for (var i = 0; i < els.length; i++) {
      var el = els[i];
      if (el.dataset.lvTilt) continue;
      el.dataset.lvTilt = '1';
      el.classList.add('lv-tilt');
      el.style.setProperty('--fd', rand(4.6, 6.8).toFixed(2) + 's');
      el.style.setProperty('--fdelay', rand(0, 3.2).toFixed(2) + 's');
    }
    els = document.querySelectorAll(MAG_SEL);
    for (i = 0; i < els.length; i++) {
      el = els[i];
      if (el.dataset.lvMag) continue;
      el.dataset.lvMag = '1';
      el.classList.add('lv-magnetic');
    }
    els = document.querySelectorAll(DODGE_SEL);
    for (i = 0; i < els.length; i++) {
      el = els[i];
      if (el.dataset.lvDodge) continue;
      el.dataset.lvDodge = '1';
      el.classList.add('lv-dodge');
    }
  }

  decorate();
  setInterval(decorate, 2500); // 兜底：捕获动态注入的卡片

  // 监听 DOM 变化（扫描结果/CWE 筛选动态渲染），防抖刷新
  var debounceTimer = null;
  if (window.MutationObserver) {
    new MutationObserver(function () {
      if (debounceTimer) return;
      debounceTimer = setTimeout(function () { debounceTimer = null; decorate(); }, 300);
    }).observe(document.body, { childList: true, subtree: true });
  }

  if (!hasHover) return; // 触屏设备：保留 CSS 悬浮/入场，不启用倾斜/磁吸/避开

  /* ---- 缓存避开元素列表 ---- */
  var dodgeEls = [];
  function refreshDodge() { dodgeEls = Array.prototype.slice.call(document.querySelectorAll('.lv-dodge')); }
  refreshDodge();
  setInterval(refreshDodge, 2500);

  var tiltEl = null, magEl = null;
  var px = -9999, py = -9999, pTarget = null, ticking = false;

  function climbTo(node, cls) {
    while (node && node !== document) {
      if (node.classList && node.classList.contains(cls)) return node;
      node = node.parentNode;
    }
    return null;
  }

  function onMove(e) {
    px = e.clientX; py = e.clientY; pTarget = e.target;
    if (!ticking) { ticking = true; requestAnimationFrame(tick); }
  }

  function tick() {
    ticking = false;
    var root = pTarget || document.body;

    /* 1) 3D 倾斜 */
    var tEl = climbTo(root, 'lv-tilt');
    if (tEl !== tiltEl) {
      if (tiltEl) {
        tiltEl.style.setProperty('--rx', '0deg');
        tiltEl.style.setProperty('--ry', '0deg');
      }
      tiltEl = tEl;
    }
    if (tiltEl) {
      var r = tiltEl.getBoundingClientRect();
      if (r.width) {
        var dx = (px - (r.left + r.width / 2)) / (r.width / 2);
        var dy = (py - (r.top + r.height / 2)) / (r.height / 2);
        dx = Math.max(-1, Math.min(1, dx));
        dy = Math.max(-1, Math.min(1, dy));
        tiltEl.style.setProperty('--ry', (dx * 7).toFixed(2) + 'deg');
        tiltEl.style.setProperty('--rx', (-dy * 7).toFixed(2) + 'deg');
      }
    }

    /* 2) 磁吸 */
    var mEl = climbTo(root, 'lv-magnetic');
    if (mEl !== magEl) {
      if (magEl) {
        magEl.style.setProperty('--mx', '0px');
        magEl.style.setProperty('--my', '0px');
      }
      magEl = mEl;
    }
    if (magEl) {
      var mr = magEl.getBoundingClientRect();
      if (mr.width) {
        magEl.style.setProperty('--mx', ((px - (mr.left + mr.width / 2)) * 0.28).toFixed(2) + 'px');
        magEl.style.setProperty('--my', ((py - (mr.top + mr.height / 2)) * 0.28).toFixed(2) + 'px');
      }
    }

    /* 3) 避开：图标在光标靠近时被推开 + 轻微放大 */
    for (var i = 0; i < dodgeEls.length; i++) {
      var el = dodgeEls[i];
      var er = el.getBoundingClientRect();
      if (!er.width) continue;
      var ddx = (er.left + er.width / 2) - px;
      var ddy = (er.top + er.height / 2) - py;
      var dist = Math.sqrt(ddx * ddx + ddy * ddy);
      var RADIUS = 95;
      if (dist < RADIUS && dist > 0.5) {
        var force = 1 - dist / RADIUS;
        var push = force * 16;
        el.style.setProperty('--dx', ((ddx / dist) * push).toFixed(2) + 'px');
        el.style.setProperty('--dy', ((ddy / dist) * push).toFixed(2) + 'px');
        el.style.setProperty('--ds', (1 + force * 0.28).toFixed(3));
      } else if (el.style.getPropertyValue('--dx') !== '0px') {
        el.style.setProperty('--dx', '0px');
        el.style.setProperty('--dy', '0px');
        el.style.setProperty('--ds', '1');
      }
    }
  }

  function resetAll() {
    if (tiltEl) { tiltEl.style.setProperty('--rx', '0deg'); tiltEl.style.setProperty('--ry', '0deg'); tiltEl = null; }
    if (magEl) { magEl.style.setProperty('--mx', '0px'); magEl.style.setProperty('--my', '0px'); magEl = null; }
    for (var i = 0; i < dodgeEls.length; i++) {
      dodgeEls[i].style.setProperty('--dx', '0px');
      dodgeEls[i].style.setProperty('--dy', '0px');
      dodgeEls[i].style.setProperty('--ds', '1');
    }
  }

  window.addEventListener('pointermove', onMove, { passive: true });
  document.addEventListener('pointerleave', resetAll);
  window.addEventListener('blur', resetAll);
  window.addEventListener('scroll', function () {
    if (tiltEl) { tiltEl.style.setProperty('--rx', '0deg'); tiltEl.style.setProperty('--ry', '0deg'); tiltEl = null; }
  }, { passive: true });
})();
