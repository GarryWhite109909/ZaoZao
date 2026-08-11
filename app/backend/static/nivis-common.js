/* ======================================================================
   nivis-common.js — Nivis 全站共享逻辑（4 个页面统一引用）
   内容：
     1. 工具函数：escapeHtml / normalizeRisk / riskWeight / riskBadge / relativeTime / setText / formatNumber
     2. 统一安全评分算法：calcSecurityScore（扣分制，0-100，全站唯一 score 来源）
     3. 后端健康检查：checkHealth（两步 /api/health/live → /api/health）
     4. 设置抽屉：injectSettingsDrawer + initSettingsDrawer（注入 HTML + 绑定事件）
   使用方式：在各页面 <body> 末尾引入 <script src="./nivis-common.js"></script>
   ====================================================================== */
(function () {
  'use strict';

  var HISTORY_KEY = 'vuln_scan_history';
  // 历史条数上限：默认只留 7 条会导致「累计分析文件/漏洞待修复」等 KPI 只统计最近 7 次扫描，
  // 与"累计"语义不符。放宽到 1000 条，让仪表盘累计统计覆盖全部历史（趋势图另行按近 7 天过滤）。
  var MAX_HISTORY = 1000;

  /* ====== 1. 工具函数 ====== */
  window.NivisUtil = {
    HISTORY_KEY: HISTORY_KEY,
    MAX_HISTORY: MAX_HISTORY,

    escapeHtml: function (str) {
      if (str === null || str === undefined) return '';
      return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
    },

    setText: function (id, val) {
      var el = document.getElementById(id);
      if (el) el.textContent = val;
    },

    formatNumber: function (n) {
      return String(n).replace(/\B(?=(\d{3})+(?!\d))/g, ',');
    },

    normalizeRisk: function (level) {
      if (!level) return 'info';
      var s = String(level).toLowerCase().trim();
      if (s === 'critical' || s === '严重' || s === '危急' || s.indexOf('crit') !== -1) return 'critical';
      if (s === 'high' || s === '高危' || s === '高' || s.indexOf('high') !== -1) return 'high';
      if (s === 'medium' || s === '中危' || s === '中' || s === 'moderate' || s.indexOf('med') !== -1) return 'medium';
      if (s === 'low' || s === '低危' || s === '低' || s.indexOf('low') !== -1) return 'low';
      return 'info';
    },

    riskWeight: function (lvl) {
      if (lvl === 'critical') return 10;
      if (lvl === 'high') return 7;
      if (lvl === 'medium') return 5;
      if (lvl === 'low') return 2;
      return 1;
    },

    riskBadge: function (lvl) {
      if (lvl === 'critical') return { label: '严重', color: 'var(--vuln-state-error)' };
      if (lvl === 'high') return { label: '高危', color: 'var(--vuln-state-error)' };
      if (lvl === 'medium') return { label: '中危', color: 'var(--vuln-state-warning)' };
      if (lvl === 'low') return { label: '低危', color: 'var(--vuln-state-success)' };
      return { label: '信息', color: 'var(--vuln-state-info)' };
    },

    relativeTime: function (ts) {
      if (!ts) return '';
      var d = new Date(ts);
      if (isNaN(d.getTime())) return '';
      var diff = Date.now() - d.getTime();
      if (diff < 0) diff = 0;
      var sec = Math.floor(diff / 1000);
      if (sec < 60) return sec + ' 秒前';
      var min = Math.floor(sec / 60);
      if (min < 60) return min + ' 分钟前';
      var hr = Math.floor(min / 60);
      if (hr < 24) return hr + ' 小时前';
      var day = Math.floor(hr / 24);
      if (day < 30) return day + ' 天前';
      return d.toLocaleDateString('zh-CN');
    },

    getHistory: function () {
      try {
        var raw = localStorage.getItem(HISTORY_KEY);
        if (!raw) return [];
        var arr = JSON.parse(raw);
        return Array.isArray(arr) ? arr : [];
      } catch (e) { return []; }
    },

    saveHistory: function (entry) {
      var hist = this.getHistory();
      hist.push(entry);
      hist.sort(function (a, b) { return new Date(a.date).getTime() - new Date(b.date).getTime(); });
      if (hist.length > MAX_HISTORY) hist = hist.slice(hist.length - MAX_HISTORY);
      try { localStorage.setItem(HISTORY_KEY, JSON.stringify(hist)); } catch (e) {}
    },

    /* 统计漏洞等级分布 */
    aggregateResults: function (results) {
      var counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
      if (!Array.isArray(results)) return counts;
      for (var i = 0; i < results.length; i++) {
        var r = results[i];
        if (!r || r.has_vulnerability !== true) continue;
        var lvl = this.normalizeRisk(r.risk_level);
        if (lvl === 'critical') counts.critical++;
        else if (lvl === 'high') counts.high++;
        else if (lvl === 'medium') counts.medium++;
        else if (lvl === 'low') counts.low++;
        else counts.info++;
      }
      return counts;
    },

    /* 趋势图交互：鼠标移动时显示平行于 y 轴的虚线，靠近数据点时吸附。
       config: { svg, points: [{x,y,data}], left, right, top, bottom, formatTip: fn(data)->string } */
    attachTrendHover: function (config) {
      var svg = config.svg;
      if (!svg || svg.__nivisHoverBound) return;
      svg.__nivisHoverBound = true;
      var SVG_NS = 'http://www.w3.org/2000/svg';
      var points = config.points || [];
      var left = config.left, right = config.right, top = config.top, bottom = config.bottom;
      var formatTip = config.formatTip || function (d) { return ''; };

      // 创建交互层（一个 <g> 容器，pointer-events: none，不干扰已有元素）
      var layer = document.createElementNS(SVG_NS, 'g');
      layer.setAttribute('pointer-events', 'none');
      layer.style.pointerEvents = 'none';

      var guideLine = document.createElementNS(SVG_NS, 'line');
      guideLine.setAttribute('stroke', 'var(--vuln-ink-3)');
      guideLine.setAttribute('stroke-width', '1.5');
      guideLine.setAttribute('stroke-dasharray', '4 4');
      guideLine.setAttribute('opacity', '0');
      guideLine.setAttribute('y1', top);
      guideLine.setAttribute('y2', bottom);
      layer.appendChild(guideLine);

      var tipRect = document.createElementNS(SVG_NS, 'rect');
      tipRect.setAttribute('fill', 'var(--vuln-surface)');
      tipRect.setAttribute('stroke', 'var(--vuln-line)');
      tipRect.setAttribute('rx', '6');
      tipRect.setAttribute('opacity', '0');
      layer.appendChild(tipRect);

      var tipText = document.createElementNS(SVG_NS, 'text');
      tipText.setAttribute('fill', 'var(--vuln-ink)');
      tipText.setAttribute('font-size', '12');
      tipText.setAttribute('opacity', '0');
      layer.appendChild(tipText);

      svg.appendChild(layer);

      // 用 createSVGPoint + getScreenCTM 做坐标转换，Chrome/Firefox/Safari 都可靠
      function clientToSvgX(clientX) {
        var pt = svg.createSVGPoint();
        pt.x = clientX;
        pt.y = 0;
        var ctm = svg.getScreenCTM();
        if (!ctm) {
          // 回退：用 viewBox 比例计算
          var rect = svg.getBoundingClientRect();
          var vb = svg.viewBox.baseVal;
          if (!vb || vb.width === 0) return clientX - rect.left;
          return (clientX - rect.left) / rect.width * vb.width;
        }
        var svgPt = pt.matrixTransform(ctm.inverse());
        return svgPt.x;
      }

      function showTip(x, content) {
        tipText.textContent = content;
        tipText.setAttribute('opacity', '1');
        tipText.setAttribute('text-anchor', 'middle');
        // 估算文字宽度（中文约 12px/字，英文约 7px/字，取折中）
        var tw = content.length * 9 + 16;
        tipRect.setAttribute('width', tw);
        tipRect.setAttribute('height', '22');
        tipRect.setAttribute('x', x - tw / 2);
        tipRect.setAttribute('y', top - 26);
        tipRect.setAttribute('opacity', '1');
        tipText.setAttribute('x', x);
        tipText.setAttribute('y', top - 11);
      }
      function hideAll() {
        guideLine.setAttribute('opacity', '0');
        tipRect.setAttribute('opacity', '0');
        tipText.setAttribute('opacity', '0');
      }

      svg.addEventListener('mousemove', function (e) {
        var mx = clientToSvgX(e.clientX);
        if (mx < left || mx > right) { hideAll(); return; }
        // 找最近的数据点（X 方向），仅在非常接近时吸附，避免点稀疏时全屏瞬移
        var nearest = null, minDist = Infinity;
        for (var i = 0; i < points.length; i++) {
          if (points[i] == null) continue;
          var d = Math.abs(points[i].x - mx);
          if (d < minDist) { minDist = d; nearest = points[i]; }
        }
        var stepX = points.length > 1 ? (right - left) / (points.length - 1) : 0;
        // 吸附阈值上限 30 SVG 单位：点稀疏时虚线仍能跟随鼠标，点密集时按 stepX*0.4 吸附
        var snapDist = Math.min(stepX * 0.4, 30);
        var snapX;
        if (nearest && minDist < snapDist) {
          snapX = nearest.x;
        } else {
          snapX = Math.max(left, Math.min(right, mx));
        }
        guideLine.setAttribute('x1', snapX);
        guideLine.setAttribute('x2', snapX);
        guideLine.setAttribute('opacity', '0.7');
        if (nearest && minDist < snapDist) {
          showTip(snapX, formatTip(nearest.data));
        } else {
          tipRect.setAttribute('opacity', '0');
          tipText.setAttribute('opacity', '0');
        }
      });
      svg.addEventListener('mouseleave', hideAll);
    }
  };

  /* ====== 2. 统一安全评分算法（扣分制，0-100） ====== */
  /* 全站唯一 score 计算入口：scan.html 和 posture.html 共用。
     语义：100 = 无漏洞（满分安全），每发现一个漏洞按等级扣分。
     取代 scan.html 旧有的风险密度算法（sum/total × 10）。 */
  window.calcSecurityScore = function (counts) {
    var score = 100;
    score -= (counts.critical + counts.high) * 8;
    score -= counts.medium * 4;
    score -= counts.low * 2;
    score -= counts.info * 0.5;
    return Math.max(0, Math.min(100, Math.round(score)));
  };

  /* ====== 3. 后端健康检查（两步：/api/health/live → /api/health） ====== */
  /* 用法：NivisHealth.check(function(level, label){ ... })
     level: ok / warn / err / loading
     返回 AbortController 供页面切换时中止。 */
  window.NivisHealth = {
    _ctrl: null,

    check: function (onUpdate) {
      var self = this;
      var set = function (level, text) {
        var el = document.getElementById('health-indicator');
        if (!el) return;
        el.innerHTML = '<span class="health-dot is-' + level + '"></span><span class="health-text">' + window.NivisUtil.escapeHtml(text) + '</span>';
        if (onUpdate) onUpdate(level, text);
      };
      var isJson = function (r) {
        var ct = r.headers.get('content-type') || '';
        return r.ok && ct.indexOf('application/json') !== -1;
      };

      if (self._ctrl) { try { self._ctrl.abort(); } catch (e) {} }
      self._ctrl = new AbortController();
      var signal = self._ctrl.signal;
      set('loading', '检测中');

      fetch('/api/health/live', { signal: signal })
        .then(function (rl) { return isJson(rl) ? rl.json() : null; })
        .then(function (live) {
          if (!live || !live.status) throw new Error('响应无效');
          set('loading', '后端已连接 · 检测引擎…');
          return fetch('/api/health', { signal: signal })
            .then(function (rh) { return isJson(rh) ? rh.json() : null; })
            .then(function (h) {
              if (!h) { set('warn', '后端已连接 · 引擎检测失败'); return; }
              if (h.ollama_connected || h.vllm_connected) {
                var m = h.model || (h.vllm_connected ? 'vLLM' : 'unknown');
                set('ok', '后端已连接 · 引擎就绪 · ' + m);
              } else {
                set('warn', '后端已连接 · 引擎未就绪');
              }
            });
        })
        .catch(function (e) {
          if (e && e.name === 'AbortError') return;
          set('err', '后端未连接 · 请启动后端脚本');
        });

      return self._ctrl;
    },

    abort: function () {
      if (this._ctrl) { try { this._ctrl.abort(); } catch (e) {} this._ctrl = null; }
    }
  };

  /* ====== 3.5 模型管理（拉取 / 删除 / 切换） ====== */
  /* 设置抽屉「模型管理」区的数据源与交互。
     仅允许操作 /api/models/* 端点登记的模型（garrywhite109909 命名空间）。 */
  window.NivisModels = {
    _registry: null,
    _installed: null,
    _active: '',
    _mgmtSupported: true, /* 进程内后端（transformers/llamacpp）不支持模型管理 */
    _mgmtBackend: '',
    _localResources: null, /* 进程内后端的本地资源（基座/adapter/GGUF） */
    _dlProgress: {},     /* resourceId -> {pct, status, error}（本地资源下载进度） */
    _dlPulling: {},      /* resourceId -> true（下载进行中） */
    _pulling: {},        /* model -> true（拉取进行中） */
    _pullProgress: {},   /* model -> {pct, status, error}（拉取进度状态） */
    _abort: null,

    esc: function (s) { return window.NivisUtil.escapeHtml(s); },

    formatSize: function (bytes) {
      if (!bytes || bytes <= 0) return '';
      var gb = bytes / (1024 * 1024 * 1024);
      if (gb >= 1) return gb.toFixed(2) + ' GB';
      var mb = bytes / (1024 * 1024);
      return mb.toFixed(1) + ' MB';
    },

    /* 加载注册表 + 已安装列表，并渲染 */
    load: function () {
      var self = this;
      if (this._abort) { try { this._abort.abort(); } catch (e) {} }
      this._abort = new AbortController();
      var signal = this._abort.signal;
      Promise.all([
        fetch('/api/models/registry', { signal: signal }).then(function (r) { return r.json(); }),
        fetch('/api/models/installed', { signal: signal }).then(function (r) { return r.json(); }),
      ]).then(function (results) {
        self._registry = (results[0] && results[0].models) || [];
        self._installed = (results[1] && results[1].installed) || [];
        self._active = (results[1] && results[1].active_model) || '';
        self._mgmtSupported = results[1] ? results[1].management_supported !== false : true;
        self._mgmtBackend = (results[1] && results[1].backend) || '';
        /* 进程内后端：加载本地资源（基座/adapter/GGUF）状态 */
        if (!self._mgmtSupported) {
          return fetch('/api/models/local-resources', { signal: signal })
            .then(function (r) { return r.json(); })
            .then(function (d) {
              self._localResources = d.resources || [];
              self.render();
            });
        }
        self._localResources = null;
        self.render();
      }).catch(function (e) {
        if (e && e.name === 'AbortError') return;
        var an = document.getElementById('model-active-name');
        if (an) an.textContent = '加载失败';
        var el = document.getElementById('model-installed-list');
        if (el) el.innerHTML = '<div class="text-xs p-3 rounded-lg" style="background: var(--vuln-surface-2); color: var(--vuln-state-error)">加载失败，请确认后端已启动</div>';
        var el2 = document.getElementById('model-available-list');
        if (el2) el2.innerHTML = '';
      });
    },

    render: function () {
      var self = this;

      /* 进程内 / 独立服务后端（transformers/llamacpp/vllm）：渲染本地资源（基座/adapter/GGUF/vLLM 服务）及下载按钮 */
      if (!this._mgmtSupported) {
        var resources = this._localResources || [];
        /* 当前模型 = 实际基座模型（transformers 的 model_id / llamacpp 的 GGUF 路径 / vLLM 服务地址）+ adapter，而非 Ollama 的 v9max */
        var an0 = document.getElementById('model-active-name');
        var anLabel = document.getElementById('model-active-label');
        var baseRes = resources.filter(function (r) { return r.type === 'huggingface' || r.type === 'gguf' || r.type === 'vllm_server'; })[0];
        var adapterRes = resources.filter(function (r) { return r.type === 'adapter'; })[0];
        if (anLabel) anLabel.textContent = '当前基座模型';
        if (an0) {
          if (baseRes) {
            an0.textContent = baseRes.type === 'huggingface' ? baseRes.name : (baseRes.type === 'vllm_server' ? baseRes.path || '—' : (adapterRes && adapterRes.path ? baseRes.path.split(/[\\/]/).pop() : baseRes.path || '—'));
            an0.title = (baseRes.path || baseRes.name || '');
          } else {
            an0.textContent = '—';
          }
        }
        /* 标题改为「本地资源」，隐藏「可拉取」section */
        var instTitle = document.getElementById('model-installed-title');
        if (instTitle) instTitle.textContent = '本地资源';
        var availSection = document.getElementById('model-available-section');
        if (availSection) availSection.style.display = 'none';
        var instEl0 = document.getElementById('model-installed-list');
        if (instEl0) {
          if (resources.length === 0) {
            instEl0.innerHTML = '<div class="text-xs p-3 rounded-lg" style="background: var(--vuln-surface-2); color: var(--vuln-ink-3)">加载中…</div>';
          } else {
            instEl0.innerHTML = resources.map(function (r) { return self.renderResourceRow(r); }).join('');
          }
        }
        this.bindResourceEvents();
        return;
      }

      /* Ollama 后端：恢复标题与「可拉取」section 显示 */
      var instTitleOllama = document.getElementById('model-installed-title');
      if (instTitleOllama) instTitleOllama.textContent = '已安装';
      var anLabelOllama = document.getElementById('model-active-label');
      if (anLabelOllama) anLabelOllama.textContent = '当前活动模型';
      var availSectionOllama = document.getElementById('model-available-section');
      if (availSectionOllama) availSectionOllama.style.display = '';

      var registry = this._registry || [];
      var installed = this._installed || [];
      var active = this._active || '';
      var installedSet = {};
      installed.forEach(function (m) { installedSet[m.full_name] = m; });

      var an = document.getElementById('model-active-name');
      if (an) {
        var info = installed.filter(function (m) { return m.full_name === active; })[0];
        an.textContent = info ? info.display_name : (active || '未设置');
      }

      var instEl = document.getElementById('model-installed-list');
      if (instEl) {
        if (installed.length === 0) {
          instEl.innerHTML = '<div class="text-xs p-3 rounded-lg" style="background: var(--vuln-surface-2); color: var(--vuln-ink-3)">暂无已安装模型，请在下方拉取</div>';
        } else {
          instEl.innerHTML = installed.map(function (m) { return self.renderInstalledRow(m, active); }).join('');
        }
      }

      var availEl = document.getElementById('model-available-list');
      if (availEl) {
        var avail = registry.filter(function (m) { return !installedSet[m.full_name]; });
        if (avail.length === 0) {
          availEl.innerHTML = '<div class="text-xs p-3 rounded-lg" style="background: var(--vuln-surface-2); color: var(--vuln-ink-3)">所有可用模型均已安装</div>';
        } else {
          availEl.innerHTML = avail.map(function (m) { return self.renderAvailableRow(m); }).join('');
        }
      }

      this.bindRowEvents();
    },

    renderInstalledRow: function (m, active) {
      var isActive = m.full_name === active;
      var sizeStr = m.size_bytes ? this.formatSize(m.size_bytes) : '';
      var activeBadge = isActive ? '<span class="text-[10px] px-1.5 py-0.5 rounded ml-1.5" style="background: color-mix(in srgb, var(--vuln-state-success) 15%, transparent); color: var(--vuln-state-success)">使用中</span>' : '';
      var depBadge = m.deprecated ? '<span class="text-[10px] px-1.5 py-0.5 rounded ml-1.5" style="background: color-mix(in srgb, var(--vuln-state-warning) 15%, transparent); color: var(--vuln-state-warning)">已过时</span>' : '';
      var actions = isActive
        ? '<span class="text-xs" style="color: var(--vuln-ink-3)">—</span>'
        : '<button data-model-activate="' + this.esc(m.full_name) + '" class="text-xs px-2.5 py-1 rounded-md transition-colors hover:opacity-80" style="background: var(--vuln-surface-3); color: var(--vuln-ink-2)">切换</button>' +
          '<button data-model-delete="' + this.esc(m.full_name) + '" class="text-xs px-2.5 py-1 rounded-md transition-colors hover:opacity-80" style="background: color-mix(in srgb, var(--vuln-state-error) 10%, transparent); color: var(--vuln-state-error)">删除</button>';
      return '<div class="p-3 rounded-lg" style="background: var(--vuln-surface-2);">' +
        '<div class="flex items-start justify-between gap-2">' +
          '<div class="min-w-0">' +
            '<div class="text-sm font-medium" style="color: var(--vuln-ink)">' + this.esc(m.display_name) + activeBadge + depBadge + '</div>' +
            '<div class="text-[11px] mt-0.5 font-mono" style="color: var(--vuln-ink-3)">' + this.esc(m.full_name) + '</div>' +
            (sizeStr ? '<div class="text-[11px] mt-0.5" style="color: var(--vuln-ink-3)">' + sizeStr + '</div>' : '') +
          '</div>' +
          '<div class="flex items-center gap-1.5 flex-shrink-0">' + actions + '</div>' +
        '</div>' +
      '</div>';
    },

    renderAvailableRow: function (m) {
      var depBadge = m.deprecated ? '<span class="text-[10px] px-1.5 py-0.5 rounded ml-1.5" style="background: color-mix(in srgb, var(--vuln-state-warning) 15%, transparent); color: var(--vuln-state-warning)">已过时</span>' : '';
      var defaultTag = m.is_default ? '<span class="text-[10px] px-1.5 py-0.5 rounded ml-1.5" style="background: color-mix(in srgb, var(--vuln-brand) 12%, transparent); color: var(--vuln-brand)">推荐</span>' : '';
      var prog = this._pullProgress[m.full_name];
      var isPulling = !!this._pulling[m.full_name];
      var btnArea;
      if (isPulling) {
        var p = prog || { pct: 0, status: '准备拉取…' };
        btnArea = this.renderProgress(p.pct, p.status, false);
      } else if (prog && prog.error) {
        btnArea = '<button data-model-pull="' + this.esc(m.full_name) + '" class="text-xs px-2.5 py-1 rounded-md transition-colors hover:opacity-80" style="background: var(--vuln-brand); color: #fff">重试</button>';
      } else {
        btnArea = '<button data-model-pull="' + this.esc(m.full_name) + '" class="text-xs px-2.5 py-1 rounded-md transition-colors hover:opacity-80" style="background: var(--vuln-brand); color: #fff">拉取</button>';
      }
      return '<div class="p-3 rounded-lg" style="background: var(--vuln-surface-2);">' +
        '<div class="flex items-start justify-between gap-2">' +
          '<div class="min-w-0 flex-1">' +
            '<div class="text-sm font-medium" style="color: var(--vuln-ink)">' + this.esc(m.display_name) + defaultTag + depBadge + '</div>' +
            (m.description ? '<div class="text-[11px] mt-0.5" style="color: var(--vuln-ink-3)">' + this.esc(m.description) + '</div>' : '') +
            '<div class="text-[11px] mt-0.5 font-mono" style="color: var(--vuln-ink-3)">' + this.esc(m.full_name) + '</div>' +
            (prog && prog.error ? '<div class="text-[11px] mt-1" style="color: var(--vuln-state-error)">' + this.esc(prog.error) + '</div>' : '') +
          '</div>' +
          '<div class="flex-shrink-0 w-[120px] flex items-start justify-end">' + btnArea + '</div>' +
        '</div>' +
      '</div>';
    },

    renderProgress: function (pct, status, isError) {
      return '<div class="w-full">' +
        '<div class="flex items-center justify-between mb-1">' +
          '<span class="text-[11px] truncate" style="color: ' + (isError ? 'var(--vuln-state-error)' : 'var(--vuln-ink-2)') + '">' + this.esc(status || (isError ? '失败' : '拉取中')) + '</span>' +
          (pct > 0 && !isError ? '<span class="text-[11px] font-mono ml-1 flex-shrink-0" style="color: var(--vuln-ink-3)">' + pct + '%</span>' : '') +
        '</div>' +
        '<div class="w-full h-1.5 rounded-full overflow-hidden" style="background: var(--vuln-surface-3)">' +
          '<div style="width: ' + (isError ? 100 : pct) + '%; height: 100%; background: ' + (isError ? 'var(--vuln-state-error)' : 'var(--vuln-brand)') + '; transition: width 200ms ease;"></div>' +
        '</div>' +
      '</div>';
    },

    /* ====== 本地资源渲染（transformers 基座 / adapter / GGUF / vLLM 服务） ====== */
    renderResourceRow: function (r) {
      var rid = (r.type === 'huggingface' ? 'hf:' + r.id : r.type === 'gguf' ? 'gguf:' + (r.path || 'gguf') : r.type === 'vllm_server' ? 'vllm:' + (r.path || 'vllm') : 'adapter:' + (r.path || 'adapter'));
      var available = r.available === true;
      var statusBadge;
      if (available) {
        statusBadge = '<span class="text-[10px] px-1.5 py-0.5 rounded ml-1.5" style="background: color-mix(in srgb, var(--vuln-state-success) 15%, transparent); color: var(--vuln-state-success)">就绪</span>';
      } else if (r.available === false) {
        statusBadge = '<span class="text-[10px] px-1.5 py-0.5 rounded ml-1.5" style="background: color-mix(in srgb, var(--vuln-state-warning) 15%, transparent); color: var(--vuln-state-warning)">未就绪</span>';
      } else {
        statusBadge = '<span class="text-[10px] px-1.5 py-0.5 rounded ml-1.5" style="background: var(--vuln-surface-3); color: var(--vuln-ink-3)">未知</span>';
      }

      var title = r.type === 'huggingface' ? '基座模型' : r.type === 'gguf' ? 'GGUF 基座' : r.type === 'vllm_server' ? 'vLLM 服务' : 'LoRA Adapter';
      var nameLine = r.type === 'huggingface' ? this.esc(r.id || '') : (r.path ? this.esc(r.path) : '未配置');
      var desc = r.description || '';
      var hintLine = r.hint ? '<div class="text-[11px] mt-0.5" style="color: var(--vuln-state-warning)">' + this.esc(r.hint) + '</div>' : '';
      var statusLine = r.status ? '<div class="text-[11px] mt-0.5" style="color: var(--vuln-ink-2)">' + this.esc(r.status) + '</div>' : '';

      /* 下载按钮区：huggingface / gguf / vllm_server（有 download_endpoint）且未就绪时显示下载按钮；adapter 不可下载 */
      var btnArea;
      var prog = this._dlProgress[rid];
      var isPulling = !!this._dlPulling[rid];
      if (r.type === 'adapter') {
        btnArea = available
          ? '<span class="text-xs" style="color: var(--vuln-ink-3)">训练产物</span>'
          : '<span class="text-xs" style="color: var(--vuln-state-warning)">未找到</span>';
      } else if (r.type === 'vllm_server') {
        if (available) {
          btnArea = '<span class="text-xs" style="color: var(--vuln-state-success)">✓ 已连接</span>';
        } else if (isPulling) {
          var p2 = prog || { pct: 0, status: '准备下载…' };
          btnArea = this.renderProgress(p2.pct, p2.status, false);
        } else if (prog && prog.error) {
          btnArea = '<button data-dl-retry="' + this.esc(rid) + '" class="text-xs px-2.5 py-1 rounded-md transition-colors hover:opacity-80" style="background: var(--vuln-brand); color: #fff">重试</button>';
        } else if (r.download_endpoint) {
          btnArea = '<button data-dl-start="' + this.esc(rid) + '" class="text-xs px-2.5 py-1 rounded-md transition-colors hover:opacity-80" style="background: var(--vuln-brand); color: #fff">下载基座</button>';
        } else {
          btnArea = '<span class="text-xs" style="color: var(--vuln-state-warning)">未连接</span>';
        }
      } else if (available) {
        btnArea = '<span class="text-xs" style="color: var(--vuln-state-success)">✓ 已就绪</span>';
      } else if (isPulling) {
        var p = prog || { pct: 0, status: '准备下载…' };
        btnArea = this.renderProgress(p.pct, p.status, false);
      } else if (prog && prog.error) {
        btnArea = '<button data-dl-retry="' + this.esc(rid) + '" class="text-xs px-2.5 py-1 rounded-md transition-colors hover:opacity-80" style="background: var(--vuln-brand); color: #fff">重试</button>';
      } else if (r.type === 'gguf' && r.download_endpoint) {
        /* 与 transformers 后端对齐：llamacpp 只能下载固定基座（官方 Qwen3-8B-GGUF 未合并基座），
           不再提供自由 URL 输入，杜绝把已合并 LoRA 的发布 GGUF 当基座导致二次叠加 */
        var ggufUrl = r.default_url || '';
        btnArea = '<div class="flex flex-col items-end gap-1.5">' +
          '<div class="w-full max-w-[220px] text-[11px] px-2 py-1 rounded-md font-mono truncate" style="background: var(--vuln-surface); border: 1px solid var(--vuln-line); color: var(--vuln-ink-2);" title="' + this.esc(ggufUrl) + '">' + this.esc(ggufUrl) + '</div>' +
          '<button data-dl-start="' + this.esc(rid) + '" class="text-xs px-2.5 py-1 rounded-md transition-colors hover:opacity-80 whitespace-nowrap" style="background: var(--vuln-brand); color: #fff">下载基座 GGUF</button>' +
        '</div>';
      } else {
        btnArea = '<button data-dl-start="' + this.esc(rid) + '" class="text-xs px-2.5 py-1 rounded-md transition-colors hover:opacity-80" style="background: var(--vuln-brand); color: #fff">下载</button>';
      }

      /* 下载目标路径：告诉用户模型会下载到哪里 */
      var dlPath = r.download_path ? '<div class="text-[11px] mt-0.5 font-mono" style="color: var(--vuln-ink-3)">下载到: ' + this.esc(r.download_path) + '</div>' : '';
      var mirrorTag = r.mirror ? '<div class="text-[11px] mt-0.5" style="color: var(--vuln-ink-3)">镜像: ' + this.esc(r.mirror) + '</div>' : '';
      var errLine = (prog && prog.error) ? '<div class="text-[11px] mt-1" style="color: var(--vuln-state-error)">' + this.esc(prog.error) + '</div>' : '';
      var actionsWidth = r.type === 'gguf' ? 'w-[240px]' : 'w-[120px]';

      return '<div class="p-3 rounded-lg" style="background: var(--vuln-surface-2);">' +
        '<div class="flex items-start justify-between gap-2">' +
          '<div class="min-w-0 flex-1">' +
            '<div class="text-sm font-medium" style="color: var(--vuln-ink)">' + this.esc(title) + statusBadge + '</div>' +
            '<div class="text-[11px] mt-0.5 font-mono" style="color: var(--vuln-ink-3)">' + nameLine + '</div>' +
            (desc ? '<div class="text-[11px] mt-0.5" style="color: var(--vuln-ink-3)">' + this.esc(desc) + '</div>' : '') +
            hintLine + statusLine + dlPath + mirrorTag + errLine +
          '</div>' +
          '<div class="flex-shrink-0 ' + actionsWidth + ' flex items-start justify-end">' + btnArea + '</div>' +
        '</div>' +
      '</div>';
    },

    bindResourceEvents: function () {
      var self = this;
      var drawer = document.getElementById('settings-drawer');
      if (!drawer) return;
      drawer.querySelectorAll('[data-dl-start]').forEach(function (btn) {
        if (btn.__nivisBound) return; btn.__nivisBound = true;
        btn.addEventListener('click', function () { self.startResourceDownload(btn.getAttribute('data-dl-start')); });
      });
      drawer.querySelectorAll('[data-dl-retry]').forEach(function (btn) {
        if (btn.__nivisBound) return; btn.__nivisBound = true;
        btn.addEventListener('click', function () { self.startResourceDownload(btn.getAttribute('data-dl-retry')); });
      });
    },

    /* 解析 rid（hf:model_id / gguf:path），找到对应资源并启动下载 */
    startResourceDownload: function (rid) {
      var self = this;
      var resources = this._localResources || [];
      var res = null;
      if (rid.indexOf('hf:') === 0) {
        var id = rid.slice(3);
        res = resources.filter(function (r) { return r.type === 'huggingface' && r.id === id; })[0];
      } else if (rid.indexOf('gguf:') === 0) {
        res = resources.filter(function (r) { return r.type === 'gguf'; })[0];
      } else if (rid.indexOf('vllm:') === 0) {
        res = resources.filter(function (r) { return r.type === 'vllm_server'; })[0];
      }
      if (!res) { this.toast('未找到对应资源', true); return; }

      if (res.type === 'huggingface') {
        this.streamDownload(rid, '/api/models/download-hf', { model_id: res.id, backend: 'transformers' });
      } else if (res.type === 'vllm_server') {
        /* vLLM 基座：下载 AWQ 量化模型到项目 models/vllm/ */
        var mid = res.default_model_id || res.id || 'Qwen/Qwen3-8B-AWQ';
        this.streamDownload(rid, '/api/models/download-hf', { model_id: mid, backend: 'vllm' });
      } else if (res.type === 'gguf') {
        /* GGUF 固定下载后端配置的官方未合并基座（default_url），
           不再提供自由 URL 输入；default_url 缺失时才提示用户手动输入 */
        var url = res.default_url || '';
        if (!url) {
          /* 用 prompt 让用户输入 GGUF 下载 URL */
          url = window.prompt('请输入 GGUF 下载 URL（GitHub 链接将自动加 ghproxy 镜像）：', '');
          if (!url) return;
        }
        var filename = url.split('/').pop() || (res.id || 'model') + '.gguf';
        /* 去除查询参数 */
        filename = filename.split('?')[0].split('#')[0];
        this.streamDownload(rid, '/api/models/download-gguf', { url: url, filename: filename });
      }
    },

    /* 通用流式下载（NDJSON 进度），与 pull() 结构对齐 */
    streamDownload: function (rid, endpoint, body) {
      var self = this;
      if (this._dlPulling[rid]) return;
      this._dlPulling[rid] = true;
      this._dlProgress[rid] = { pct: 0, status: '准备下载…' };
      this.render();
      fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      }).then(function (resp) {
        if (!resp.body || !resp.body.getReader) {
          return resp.json().then(function (d) {
            delete self._dlPulling[rid];
            if (d && !d.error) { delete self._dlProgress[rid]; self.load(); self.toast('下载完成'); }
            else { self._dlProgress[rid] = { error: (d && d.error) || '下载失败' }; self.render(); }
          });
        }
        var reader = resp.body.getReader();
        var decoder = new TextDecoder('utf-8');
        var buf = '';
        var lastMessage = '';
        function pump() {
          reader.read().then(function (chunk) {
            if (chunk.done) {
              delete self._dlPulling[rid];
              delete self._dlProgress[rid];
              self.load();
              self.toast(lastMessage || '下载完成');
              return;
            }
            buf += decoder.decode(chunk.value, { stream: true });
            var lines = buf.split('\n');
            buf = lines.pop();
            var hadError = null;
            for (var i = 0; i < lines.length; i++) {
              if (!lines[i].trim()) continue;
              try { var obj = JSON.parse(lines[i]); } catch (e) { continue; }
              if (obj.error) { hadError = obj.error; break; }
              if (obj.pct != null) {
                var cur = self._dlProgress[rid] || {};
                cur.pct = obj.pct;
                if (obj.status) cur.status = obj.status;
                if (obj.current_file) cur.status = '下载: ' + obj.current_file;
                if (obj.completed != null && obj.total) cur.status = '已完成 ' + obj.completed + '/' + obj.total + ' 文件';
                self._dlProgress[rid] = cur;
              }
              if (obj.completed === true && obj.status === 'success') {
                cur.pct = 100; cur.status = '完成';
              }
              if (obj.message) {
                lastMessage = obj.message;
                var cur = self._dlProgress[rid] || {};
                cur.status = obj.message;
                self._dlProgress[rid] = cur;
              }
            }
            if (hadError) {
              delete self._dlPulling[rid];
              self._dlProgress[rid] = { error: hadError };
              self.render();
              self.toast(hadError, true);
              return;
            }
            self.render();
            pump();
          }).catch(function () {
            delete self._dlPulling[rid];
            self._dlProgress[rid] = { error: '连接中断' };
            self.render();
          });
        }
        pump();
      }).catch(function () {
        delete self._dlPulling[rid];
        self._dlProgress[rid] = { error: '网络错误' };
        self.render();
      });
    },

    bindRowEvents: function () {
      var self = this;
      var drawer = document.getElementById('settings-drawer');
      if (!drawer) return;
      drawer.querySelectorAll('[data-model-activate]').forEach(function (btn) {
        if (btn.__nivisBound) return; btn.__nivisBound = true;
        btn.addEventListener('click', function () { self.activate(btn.getAttribute('data-model-activate')); });
      });
      drawer.querySelectorAll('[data-model-delete]').forEach(function (btn) {
        if (btn.__nivisBound) return; btn.__nivisBound = true;
        btn.addEventListener('click', function () { self.del(btn.getAttribute('data-model-delete')); });
      });
      drawer.querySelectorAll('[data-model-pull]').forEach(function (btn) {
        if (btn.__nivisBound) return; btn.__nivisBound = true;
        btn.addEventListener('click', function () { self.pull(btn.getAttribute('data-model-pull')); });
      });
    },

    activate: function (model) {
      var self = this;
      fetch('/api/models/activate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ model: model }),
      }).then(function (r) { return r.json(); }).then(function (d) {
        if (d.activated) { self.load(); self.toast('已切换为 ' + model); }
        else { self.toast(d.error || '切换失败', true); }
      }).catch(function () { self.toast('网络错误', true); });
    },

    del: function (model) {
      var self = this;
      if (!window.confirm('确认删除模型？\n' + model + '\n\n将从模型存储目录（默认项目 models/ollama）彻底删除模型文件，释放磁盘空间。')) return;
      fetch('/api/models/' + encodeURIComponent(model), { method: 'DELETE' })
        .then(function (r) { return r.json(); })
        .then(function (d) {
          if (d.deleted) { self.load(); self.toast('已删除 ' + model); }
          else { self.toast(d.error || '删除失败', true); }
        })
        .catch(function () { self.toast('网络错误', true); });
    },

    /* 流式拉取：解析 NDJSON 进度，实时更新进度条 */
    pull: function (model) {
      var self = this;
      if (this._pulling[model]) return;
      this._pulling[model] = true;
      this._pullProgress[model] = { pct: 0, status: '准备拉取…' };
      this.render();
      fetch('/api/models/pull', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ model: model }),
      }).then(function (resp) {
        if (!resp.body || !resp.body.getReader) {
          // 流式不可用，退化为整体等待
          return resp.json().then(function (d) {
            delete self._pulling[model];
            if (d && !d.error) { delete self._pullProgress[model]; self.load(); self.toast('拉取完成'); }
            else { self._pullProgress[model] = { error: (d && d.error) || '拉取失败' }; self.render(); }
          });
        }
        var reader = resp.body.getReader();
        var decoder = new TextDecoder('utf-8');
        var buf = '';
        function pump() {
          reader.read().then(function (chunk) {
            if (chunk.done) {
              delete self._pulling[model];
              delete self._pullProgress[model];
              self.load();
              self.toast('拉取完成');
              return;
            }
            buf += decoder.decode(chunk.value, { stream: true });
            var lines = buf.split('\n');
            buf = lines.pop();
            var lastPct = null, lastStatus = '', hadError = null;
            for (var i = 0; i < lines.length; i++) {
              if (!lines[i].trim()) continue;
              try { var obj = JSON.parse(lines[i]); } catch (e) { continue; }
              if (obj.error) { hadError = obj.error; break; }
              if (obj.completed && obj.total) {
                lastPct = Math.round(obj.completed / obj.total * 100);
              }
              if (obj.status) lastStatus = obj.status;
              if (obj.completed === true && obj.status === 'success') {
                lastPct = 100; lastStatus = '完成';
              }
            }
            if (hadError) {
              delete self._pulling[model];
              self._pullProgress[model] = { error: hadError };
              self.render();
              self.toast(hadError, true);
              return;
            }
            var cur = self._pullProgress[model] || {};
            if (lastPct !== null) cur.pct = lastPct;
            if (lastStatus) cur.status = lastStatus;
            self._pullProgress[model] = cur;
            self.render();
            pump();
          }).catch(function () {
            delete self._pulling[model];
            self._pullProgress[model] = { error: '连接中断' };
            self.render();
          });
        }
        pump();
      }).catch(function () {
        delete self._pulling[model];
        self._pullProgress[model] = { error: '网络错误' };
        self.render();
      });
    },

    toast: function (msg, isErr) {
      var t = document.getElementById('model-toast');
      if (!t) {
        t = document.createElement('div');
        t.id = 'model-toast';
        t.style.cssText = 'position:fixed;bottom:24px;left:50%;transform:translateX(-50%);z-index:9999;padding:8px 16px;border-radius:8px;font-size:13px;box-shadow:0 4px 12px rgba(0,0,0,0.15);transition:opacity 300ms;opacity:0;max-width:80vw;';
        document.body.appendChild(t);
      }
      t.textContent = msg;
      t.style.background = isErr ? 'var(--vuln-state-error)' : 'var(--vuln-ink)';
      t.style.color = isErr ? '#fff' : 'var(--vuln-surface)';
      t.style.opacity = '1';
      clearTimeout(t.__timer);
      t.__timer = setTimeout(function () { t.style.opacity = '0'; }, 2400);
    }
  };

  /* ====== 3.6 推理后端信息（设置抽屉「推理后端」区） ====== */
  /* 从 /api/backend/info 获取当前推理后端精度/流程信息，渲染到设置抽屉。 */
  window.NivisBackendInfo = {
    esc: function (s) { return window.NivisUtil.escapeHtml(s); },

    load: function () {
      var el = document.getElementById('backend-info-list');
      if (!el) return;
      fetch('/api/backend/info', { cache: 'no-store' })
        .then(function (r) { return r.json(); })
        .then(function (info) { el.innerHTML = window.NivisBackendInfo.render(info); })
        .catch(function () {
          el.innerHTML = '<div class="text-xs p-3 rounded-lg" style="background: var(--vuln-surface-2); color: var(--vuln-state-error)">无法获取后端信息，请确认后端已启动</div>';
        });
    },

    render: function (info) {
      var b = (info.backend || 'unknown').toLowerCase();
      var labels = { ollama: 'Ollama', transformers: 'Transformers', llamacpp: 'LlamaCPP', vllm: 'vLLM' };
      var name = labels[b] || info.backend || '未知';

      var modelOk = info.model_available;
      var statusBadge;
      if (modelOk === true) {
        statusBadge = '<span class="text-[10px] px-1.5 py-0.5 rounded" style="background: color-mix(in srgb, var(--vuln-state-success) 15%, transparent); color: var(--vuln-state-success)">就绪</span>';
      } else if (modelOk === false) {
        statusBadge = '<span class="text-[10px] px-1.5 py-0.5 rounded" style="background: color-mix(in srgb, var(--vuln-state-warning) 15%, transparent); color: var(--vuln-state-warning)">未就绪</span>';
      } else {
        statusBadge = '<span class="text-[10px] px-1.5 py-0.5 rounded" style="background: var(--vuln-surface-3); color: var(--vuln-ink-3)">未知</span>';
      }

      var rows = [];
      rows.push(this.row('后端', name));
      if (info.model) rows.push(this.row('模型', info.model));
      if (info.model_status) rows.push(this.row('模型状态', info.model_status));
      if (info.detection_method) rows.push(this.paraRow('检测逻辑', info.detection_method));
      if (info.download_method) rows.push(this.paraRow('模型获取', info.download_method));
      if (info.model_store) rows.push(this.paraRow('存储位置', info.model_store));
      if (info.base_quantization) rows.push(this.row('基座量化', info.base_quantization));
      if (info.lora_precision) rows.push(this.row('LoRA 精度', info.lora_precision));
      if (info.compute_dtype) rows.push(this.row('计算精度', String(info.compute_dtype).toUpperCase()));
      if (info.device_type) rows.push(this.row('运行设备', info.device_type));
      if (info.num_ctx) rows.push(this.row('上下文长度', String(info.num_ctx)));
      if (info.server_url) rows.push(this.row('服务地址', info.server_url));
      if (info.num_gpu_layers != null) rows.push(this.row('GPU 层数', String(info.num_gpu_layers)));
      if (info.gguf_path) rows.push(this.row('GGUF 路径', info.gguf_path));
      if (info.adapter_path) rows.push(this.row('LoRA 路径', info.adapter_path));

      var alert = '';
      if (modelOk === false && info.download_hint) {
        alert = '<div class="text-xs p-2.5 rounded-lg mt-2" style="background: color-mix(in srgb, var(--vuln-state-warning) 10%, transparent); border: 1px solid color-mix(in srgb, var(--vuln-state-warning) 30%, var(--vuln-line)); color: var(--vuln-state-warning)">' + this.esc(info.download_hint).replace(/\n/g, '<br>') + '</div>';
      }

      var note = '';
      if (info.precision_note) {
        note = '<div class="text-xs mt-2" style="color: var(--vuln-ink-3)">' + this.esc(info.precision_note).replace(/\n/g, '<br>') + '</div>';
      }

      return '<div class="p-3 rounded-lg" style="background: var(--vuln-surface-2);">' +
        '<div class="flex items-center justify-between mb-2">' +
          '<span class="text-sm font-medium" style="color: var(--vuln-ink)">' + this.esc(name) + '</span>' +
          statusBadge +
        '</div>' +
        '<div class="space-y-1">' + rows.join('') + '</div>' +
        alert + note +
      '</div>';
    },

    row: function (k, v) {
      return '<div class="flex justify-between gap-3 text-xs"><span style="color: var(--vuln-ink-3)">' + this.esc(k) + '</span><span class="text-right" style="color: var(--vuln-ink-2); word-break: break-all">' + this.esc(String(v)) + '</span></div>';
    },

    paraRow: function (k, v) {
      return '<div class="text-xs"><div style="color: var(--vuln-ink-3); margin-bottom: 2px;">' + this.esc(k) + '</div><div style="color: var(--vuln-ink-2); word-break: break-all; white-space: pre-wrap; line-height: 1.6;">' + this.esc(String(v)) + '</div></div>';
    }
  };

  /* ====== 4. 设置抽屉（注入 HTML + 绑定事件） ====== */
  /* 各页面只需在 <body> 中保留 <button id="settings-open">，
     nivis-common.js 会自动注入抽屉 HTML 并绑定所有事件。 */

  var DRAWER_HTML = '\
    <div id="settings-overlay" class="fixed inset-0 z-[60] hidden" style="background: rgba(0,0,0,0.4); backdrop-filter: blur(2px);">\
      <aside id="settings-drawer" class="absolute right-0 top-0 bottom-0 w-full sm:w-[400px] flex flex-col" style="background: var(--vuln-surface); border-left: 1px solid var(--vuln-line); transform: translateX(100%); transition: transform 300ms cubic-bezier(0.4,0,0.2,1);">\
        <div class="flex items-center justify-between px-6 py-4 border-b" style="border-color: var(--vuln-line);">\
          <h2 class="text-base font-semibold" style="color: var(--vuln-ink)">设置</h2>\
          <button id="settings-close" class="inline-flex items-center justify-center w-8 h-8 rounded-md hover:bg-[var(--vuln-surface-2)] text-muted-foreground hover:text-foreground transition-colors" aria-label="关闭">\
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 6 6 18"/><path d="m6 6 12 12"/></svg>\
          </button>\
        </div>\
        <div class="flex-1 overflow-y-auto px-6 py-5 space-y-8">\
          <section>\
            <h3 class="text-xs font-semibold uppercase tracking-wider mb-3" style="color: var(--vuln-ink-3)">外观</h3>\
            <div class="space-y-2">\
              <div class="flex items-center justify-between p-3 rounded-lg" style="background: var(--vuln-surface-2);">\
                <div>\
                  <div class="text-sm font-medium" style="color: var(--vuln-ink)">主题模式</div>\
                  <div class="text-xs mt-0.5" style="color: var(--vuln-ink-3)">选择界面配色</div>\
                </div>\
                <div class="flex gap-1 p-1 rounded-md" style="background: var(--vuln-bg); border: 1px solid var(--vuln-line);">\
                  <button data-theme-btn="light" class="theme-opt px-3 py-1 text-xs rounded transition-colors">浅色</button>\
                  <button data-theme-btn="dark" class="theme-opt px-3 py-1 text-xs rounded transition-colors">深色</button>\
                </div>\
              </div>\
            </div>\
          </section>\
          <section>\
            <h3 class="text-xs font-semibold uppercase tracking-wider mb-3" style="color: var(--vuln-ink-3)">推理后端</h3>\
            <div id="backend-info-list" class="space-y-2">\
              <div class="text-xs p-3 rounded-lg" style="background: var(--vuln-surface-2); color: var(--vuln-ink-3)">加载中…</div>\
            </div>\
          </section>\
          <section>\
            <h3 class="text-xs font-semibold uppercase tracking-wider mb-3" style="color: var(--vuln-ink-3)">模型管理</h3>\
            <div class="space-y-3">\
              <div class="flex items-center justify-between p-3 rounded-lg" style="background: color-mix(in srgb, var(--vuln-brand) 6%, transparent); border: 1px solid color-mix(in srgb, var(--vuln-brand) 18%, var(--vuln-line));">\
                <div class="min-w-0">\
                  <div id="model-active-label" class="text-xs" style="color: var(--vuln-ink-3)">当前活动模型</div>\
                  <div id="model-active-name" class="text-sm font-medium mt-0.5 truncate" style="color: var(--vuln-ink)">加载中…</div>\
                </div>\
                <button id="model-refresh-btn" class="flex-shrink-0 inline-flex items-center justify-center w-8 h-8 rounded-md hover:bg-[var(--vuln-surface-2)] transition-colors" aria-label="刷新模型列表" title="刷新模型列表">\
                  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="color: var(--vuln-ink-2)"><path d="M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8"/><path d="M21 3v5h-5"/><path d="M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16"/><path d="M8 16H3v5"/></svg>\
                </button>\
              </div>\
              <div>\
                <div id="model-installed-title" class="text-xs font-medium mb-2" style="color: var(--vuln-ink-2)">已安装</div>\
                <div id="model-installed-list" class="space-y-2"><div class="text-xs p-3 rounded-lg" style="background: var(--vuln-surface-2); color: var(--vuln-ink-3)">加载中…</div></div>\
              </div>\
              <div id="model-available-section">\
                <div id="model-available-title" class="text-xs font-medium mb-2" style="color: var(--vuln-ink-2)">可拉取</div>\
                <div id="model-available-list" class="space-y-2"><div class="text-xs p-3 rounded-lg" style="background: var(--vuln-surface-2); color: var(--vuln-ink-3)">加载中…</div></div>\
              </div>\
            </div>\
          </section>\
          <section>\
            <h3 class="text-xs font-semibold uppercase tracking-wider mb-3" style="color: var(--vuln-ink-3)">关于 Nivis</h3>\
            <div class="flex items-center gap-3 mb-4 p-3 rounded-lg" style="background: color-mix(in srgb, var(--vuln-brand) 6%, transparent); border: 1px solid color-mix(in srgb, var(--vuln-brand) 15%, var(--vuln-line));">\
              <span class="nivis-logo" aria-hidden="true">\
                <img src="./logo/图标logo.png" class="logo-light" alt="" width="36" height="36">\
                <img src="./logo/图标logo深色版.png" class="logo-dark" alt="" width="36" height="36">\
              </span>\
              <div>\
                <div class="text-base font-semibold" style="color: var(--vuln-ink)">Nivis</div>\
                <div class="text-xs" style="color: var(--vuln-ink-3)">版本 2.0.0</div>\
              </div>\
            </div>\
            <p class="text-sm leading-relaxed mb-4" style="color: var(--vuln-ink-2)">\
              Nivis 是一款本地部署的 AI 代码漏洞静态分析平台。基于 <span class="font-mono text-xs px-1 py-0.5 rounded" style="background: var(--vuln-surface-2); color: var(--vuln-brand)">Qwen3-8B</span> 多轮微调的安全分析模型，结合静态规则引擎，识别 SQL 注入、XSS、命令注入、路径穿越、反序列化等常见安全漏洞。所有分析在本地完成，代码不上传云端。\
            </p>\
            <div class="space-y-2">\
              <div class="text-xs font-semibold mb-2" style="color: var(--vuln-ink)">使用指南</div>\
              <ol class="space-y-2 text-sm" style="color: var(--vuln-ink-2)">\
                <li class="flex gap-2.5"><span class="flex-shrink-0 w-5 h-5 inline-flex items-center justify-center rounded-full text-[10px] font-bold" style="background: color-mix(in srgb, var(--vuln-brand) 12%, transparent); color: var(--vuln-brand)">1</span>在「扫描工作台」选择输入方式：粘贴代码片段、上传文件或接入仓库</li>\
                <li class="flex gap-2.5"><span class="flex-shrink-0 w-5 h-5 inline-flex items-center justify-center rounded-full text-[10px] font-bold" style="background: color-mix(in srgb, var(--vuln-brand) 12%, transparent); color: var(--vuln-brand)">2</span>点击「开始扫描」，等待 AI 分析完成</li>\
                <li class="flex gap-2.5"><span class="flex-shrink-0 w-5 h-5 inline-flex items-center justify-center rounded-full text-[10px] font-bold" style="background: color-mix(in srgb, var(--vuln-brand) 12%, transparent); color: var(--vuln-brand)">3</span>查看漏洞详情、风险等级与修复建议</li>\
                <li class="flex gap-2.5"><span class="flex-shrink-0 w-5 h-5 inline-flex items-center justify-center rounded-full text-[10px] font-bold" style="background: color-mix(in srgb, var(--vuln-brand) 12%, transparent); color: var(--vuln-brand)">4</span>在「仪表盘」追踪扫描活动趋势，在「安全态势」查看整体评分</li>\
              </ol>\
            </div>\
          </section>\
        </div>\
        <div class="px-6 py-3 border-t text-xs text-center" style="border-color: var(--vuln-line); color: var(--vuln-ink-3)">\
          2.0.0 · 本地优先 · 数据不出境\
        </div>\
      </aside>\
    </div>';

  window.NivisSettings = {
    _bound: false,

    /* 注入抽屉 HTML（若页面已有则跳过） */
    inject: function () {
      if (document.getElementById('settings-overlay')) return;
      var div = document.createElement('div');
      div.innerHTML = DRAWER_HTML;
      var overlay = div.firstElementChild;
      if (overlay) document.body.appendChild(overlay);
    },

    /* 绑定 open/close/escape/save 事件（仅一次） */
    init: function () {
      if (this._bound) return;
      this._bound = true;
      var self = this;
      var overlay, drawer, btnOpen, btnClose;
      var opened = false;
      var closeTimer = null;   /* 保存 close 的隐藏延时句柄，open 时清掉，避免"关→快开"被残留定时器隐藏 */

      function ensureRefs() {
        overlay = document.getElementById('settings-overlay');
        drawer = document.getElementById('settings-drawer');
        btnOpen = document.getElementById('settings-open');
        btnClose = document.getElementById('settings-close');
      }

      function open() {
        ensureRefs();
        if (!overlay || opened) return;
        opened = true;
        if (closeTimer) { clearTimeout(closeTimer); closeTimer = null; }  /* 取消尚未执行的隐藏 */
        overlay.classList.remove('hidden');
        // 主题选项的高亮由 theme.js 的 syncDrawerOpts() 负责，这里不重复同步
        if (window.syncDrawerOpts) window.syncDrawerOpts();
        requestAnimationFrame(function () { if (drawer) drawer.style.transform = 'translateX(0)'; });
        document.body.style.overflow = 'hidden';
        // 每次打开抽屉时刷新推理后端信息与模型管理列表
        if (window.NivisBackendInfo) window.NivisBackendInfo.load();
        if (window.NivisModels) window.NivisModels.load();
      }

      function close() {
        ensureRefs();
        if (!overlay || !opened) return;
        opened = false;
        if (drawer) drawer.style.transform = 'translateX(100%)';
        document.body.style.overflow = '';
        if (closeTimer) clearTimeout(closeTimer);
        closeTimer = setTimeout(function () {
          overlay.classList.add('hidden');
          closeTimer = null;
        }, 300);
      }

      /* 延迟绑定：等 DOM 中存在按钮后再绑 */
      function tryBind() {
        ensureRefs();
        if (btnOpen && !btnOpen.__nivisSettingsBound) {
          btnOpen.__nivisSettingsBound = true;
          btnOpen.addEventListener('click', open);
        }
        if (btnClose && !btnClose.__nivisSettingsBound) {
          btnClose.__nivisSettingsBound = true;
          btnClose.addEventListener('click', close);
        }
        if (overlay && !overlay.__nivisSettingsBound) {
          overlay.__nivisSettingsBound = true;
          overlay.addEventListener('click', function (e) { if (e.target === overlay) close(); });
        }
        /* 模型管理刷新按钮 */
        var btnRefresh = document.getElementById('model-refresh-btn');
        if (btnRefresh && !btnRefresh.__nivisSettingsBound) {
          btnRefresh.__nivisSettingsBound = true;
          btnRefresh.addEventListener('click', function () {
            if (window.NivisModels) window.NivisModels.load();
          });
        }
      }

      /* 保存按钮逻辑已移除：后端地址与模型由启动器配置，前端 localStorage 中的值不会被任何代码读取 */

      document.addEventListener('keydown', function (e) { if (e.key === 'Escape') close(); });

      /* 立即尝试绑定，同时监听 DOM 变化 */
      tryBind();
      if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', tryBind);
      }

      /* 暴露 open/close 供外部调用 */
      self.open = open;
      self.close = close;
    }
  };

  /* 自动注入 + 初始化 */
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function () {
      window.NivisSettings.inject();
      window.NivisSettings.init();
    });
  } else {
    window.NivisSettings.inject();
    window.NivisSettings.init();
  }
})();
