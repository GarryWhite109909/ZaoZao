/* ======================================================================
   theme.js — Nivis 深浅主题切换（统一版）
   - 默认浅色（首次访问无偏好时；见 resolveInitial）
   - localStorage 持久化（key: vuln-theme）
   - 跨标签页/窗口实时同步（storage 事件）
   - 图标随主题切换（月/日），即时更新
   - 统一管理右上角按钮和设置抽屉里的 [data-theme-btn] 选项
   - FOUC 防护由各 HTML <head> 内联脚本完成
   ====================================================================== */
(function () {
  'use strict';

  var STORAGE_KEY = 'vuln-theme';
  var DARK = 'dark';
  var LIGHT = 'light';

  /* ---- 工具 ---- */
  function getStored() {
    try { return localStorage.getItem(STORAGE_KEY); } catch (e) { return null; }
  }
  function setStored(v) {
    try { localStorage.setItem(STORAGE_KEY, v); } catch (e) {}
  }
  function applyTheme(theme) {
    var root = document.documentElement;
    root.classList.remove(LIGHT, DARK);
    root.classList.add(theme);
  }
  function currentTheme() {
    return document.documentElement.classList.contains(DARK) ? DARK : LIGHT;
  }
  function resolveInitial() {
    var s = getStored();
    if (s === DARK || s === LIGHT) return s;
    return LIGHT;
  }

  /* ---- 图标 ---- */
  var ICON_SUN =
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
    '<circle cx="12" cy="12" r="4"/>' +
    '<path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M6.34 17.66l-1.41 1.41M19.07 4.93l-1.41 1.41"/>' +
    '</svg>';
  var ICON_MOON =
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
    '<path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/>' +
    '</svg>';

  function btnIcon(theme) {
    return theme === DARK ? ICON_SUN : ICON_MOON; // 深色时显示太阳（点击转浅）
  }
  function btnLabel(theme) {
    return theme === DARK ? '切换到浅色模式' : '切换到深色模式';
  }

  /* ---- 防重入锁：过渡进行中忽略新点击 ---- */
  var _inTransition = false;

  /* ---- 统一主题切换入口 ---- */
  function switchTheme(next) {
    if (_inTransition) return;              /* 过渡中：忽略 */
    if (next === currentTheme()) return;    /* 相同主题：不重复切换 */

    _inTransition = true;
    document.body.classList.add('theme-transitioning');

    function done() {
      setTimeout(function () {
        document.body.classList.remove('theme-transitioning');
        _inTransition = false;
      }, 350);
    }

    function doSwitch() {
      applyTheme(next);
      setStored(next);
      syncButton();
      syncDrawerOpts();
    }

    if (document.startViewTransition) {
      var transition = document.startViewTransition(doSwitch);
      if (transition && transition.finished) {
        transition.finished.then(done, done);
      } else {
        done();
      }
    } else {
      doSwitch();
      done();
    }
  }

  /* ---- 同步右上角按钮 ---- */
  function syncButton() {
    var btn = document.getElementById('theme-toggle');
    if (!btn) return;
    var t = currentTheme();
    btn.innerHTML = btnIcon(t);
    btn.setAttribute('aria-label', btnLabel(t));
    btn.title = btnLabel(t);
  }

  /* ---- 绑定右上角按钮（document 级事件委托） ---- */
  var _toggleDelegated = false;
  function bindButton() {
    if (_toggleDelegated) return;
    _toggleDelegated = true;
    document.addEventListener('click', function (e) {
      var btn = e.target.closest('#theme-toggle');
      if (!btn) return;
      switchTheme(currentTheme() === DARK ? LIGHT : DARK);
    });
  }

  /* ---- 同步设置抽屉里的主题选项（暴露为全局，供 nivis-common.js 调用） ---- */
  function syncDrawerOpts() {
    var isDark = currentTheme() === DARK;
    document.querySelectorAll('[data-theme-btn]').forEach(function (b) {
      var v = b.getAttribute('data-theme-btn');
      var active = (v === DARK && isDark) || (v === LIGHT && !isDark);
      b.style.background = active ? 'var(--vuln-brand)' : 'transparent';
      b.style.color = active ? 'var(--vuln-brand-ink)' : 'var(--vuln-ink-2)';
    });
  }
  window.syncDrawerOpts = syncDrawerOpts;

  /* ---- 绑定设置抽屉主题选项（事件委托） ---- */
  var _drawerDelegated = false;
  function bindDrawerOpts() {
    if (_drawerDelegated) return;
    _drawerDelegated = true;
    document.addEventListener('click', function (e) {
      var b = e.target.closest('[data-theme-btn]');
      if (!b) return;
      var v = b.getAttribute('data-theme-btn');
      switchTheme(v === DARK ? DARK : LIGHT);
    });
  }

  /* ---- 初始化 ---- */
  function init() {
    bindButton();
    syncButton();
    bindDrawerOpts();
    syncDrawerOpts();
  }

  /* ---- 跨标签页同步 ---- */
  window.addEventListener('storage', function (e) {
    if (e.key === STORAGE_KEY && (e.newValue === DARK || e.newValue === LIGHT)) {
      applyTheme(e.newValue);
      syncButton();
      syncDrawerOpts();
    }
  });

  /* ---- 系统主题变化：仅当用户未显式设置时跟随 ---- */
  if (window.matchMedia) {
    window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', function () {
      if (!getStored()) {
        applyTheme(resolveInitial());
        syncButton();
        syncDrawerOpts();
      }
    });
  }

  /* ---- DOM 就绪后绑定 ---- */
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
