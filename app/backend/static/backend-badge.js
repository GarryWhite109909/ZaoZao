/**
 * 导航栏推理后端 / 模型精度徽标
 * 所有带主导航的静态页面统一引入本脚本，自动调用 /api/backend/info。
 */
(function () {
  'use strict';

  function initBackendBadge() {
    var nav = document.querySelector('nav[aria-label="主导航"]');
    if (!nav) return;
    var target = nav.querySelector('.flex.items-center.gap-2');
    if (!target) return;

    // 注入样式（仅一次）
    if (!document.getElementById('backend-badge-styles')) {
      var style = document.createElement('style');
      style.id = 'backend-badge-styles';
      style.textContent = [
        '.backend-badge-wrap { position: relative; display: inline-flex; align-items: center; }',
        '.backend-badge { display: inline-flex; align-items: center; gap: 6px; padding: 4px 10px; border-radius: 999px; font-size: 12px; line-height: 1.4; font-weight: 500; cursor: help; white-space: nowrap; border: 1px solid var(--vuln-line); background: var(--vuln-surface); color: var(--vuln-ink-2); transition: opacity .2s ease; }',
        '.backend-badge:hover { opacity: .85; }',
        '.backend-badge-dot { width: 7px; height: 7px; border-radius: 50%; flex-shrink: 0; }',
        '.backend-badge-dot.ollama { background: #3b82f6; box-shadow: 0 0 6px rgba(59,130,246,.45); }',
        '.backend-badge-dot.transformers { background: #10b981; box-shadow: 0 0 6px rgba(16,185,129,.45); }',
        '.backend-badge-dot.llamacpp { background: #f59e0b; box-shadow: 0 0 6px rgba(245,158,11,.45); }',
        '.backend-badge-dot.vllm { background: #8b5cf6; box-shadow: 0 0 6px rgba(139,92,246,.45); }',
        '.backend-badge-dot.unknown { background: #9ca3af; }',
        '.backend-tooltip { position: absolute; top: calc(100% + 10px); right: 0; width: 320px; max-width: calc(100vw - 24px); padding: 12px 14px; border-radius: 10px; border: 1px solid var(--vuln-line); background: var(--vuln-card); color: var(--vuln-ink); box-shadow: var(--vuln-shadow-3); font-size: 12px; line-height: 1.6; z-index: 60; opacity: 0; visibility: hidden; transform: translateY(-4px); transition: opacity .2s ease, transform .2s ease, visibility .2s; }',
        '.backend-badge-wrap:hover .backend-tooltip, .backend-badge-wrap.active .backend-tooltip { opacity: 1; visibility: visible; transform: translateY(0); }',
        '.backend-tooltip h4 { margin: 0 0 6px; font-size: 13px; font-weight: 600; color: var(--vuln-ink); }',
        '.backend-tooltip .kv { display: flex; justify-content: space-between; gap: 12px; margin: 3px 0; }',
        '.backend-tooltip .kv .k { color: var(--vuln-ink-2); }',
        '.backend-tooltip .kv .v { color: var(--vuln-ink); text-align: right; word-break: break-all; }',
        '.backend-tooltip .note { margin-top: 8px; padding-top: 8px; border-top: 1px solid var(--vuln-line); color: var(--vuln-ink-2); font-size: 11.5px; }',
        '.backend-tooltip .note.warn { color: #ef4444; }',
        '.backend-tooltip .note.alert { margin-top: 8px; padding: 8px 10px; border-radius: 6px; border: 1px solid #f59e0b; background: rgba(245,158,11,.1); color: #b45309; font-size: 11.5px; border-top: 1px solid #f59e0b; }',
        '.backend-tooltip .backend-tag { display: inline-block; padding: 1px 6px; border-radius: 4px; background: var(--vuln-surface-2); font-size: 11px; }',
        '.backend-tooltip .rpt-header { margin: 6px 0 8px; }',
        '.backend-tooltip .rpt-status { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; }',
        '.backend-tooltip .rpt-ok { background: rgba(16,185,129,.15); color: #059669; }',
        '.backend-tooltip .rpt-warn { background: rgba(245,158,11,.15); color: #b45309; }',
        '.backend-tooltip .rpt-unknown { background: var(--vuln-surface-2); color: var(--vuln-ink-3); }'
      ].join('\n');
      document.head.appendChild(style);
    }

    var wrap = document.createElement('div');
    wrap.className = 'backend-badge-wrap mr-2 hidden md:inline-flex';
    wrap.innerHTML = '<span class="backend-badge" id="backend-badge" title="正在检测推理后端…"><span class="backend-badge-dot unknown"></span><span class="backend-badge-text">检测中…</span></span><div class="backend-tooltip" id="backend-tooltip"></div>';
    target.insertBefore(wrap, target.firstChild);

    fetch('/api/backend/info', { cache: 'no-store' })
      .then(function (r) { return r.json(); })
      .then(function (info) { render(info); })
      .catch(function (err) {
        render({ backend: 'unknown', model: '未连接', base_quantization: '—', precision_note: '无法获取后端信息：' + err.message });
      });

    function render(info) {
      var backend = (info.backend || 'unknown').toLowerCase();
      var short = shortLabel(info);
      var badge = document.getElementById('backend-badge');
      var tooltip = document.getElementById('backend-tooltip');
      if (!badge || !tooltip) return;

      // 模型未下载时 badge 显示警告色
      var modelOk = info.model_available;
      var dotClass = backend;
      if (modelOk === false) dotClass = 'unknown';
      badge.className = 'backend-badge backend-badge-' + backend;
      var statusIcon = modelOk === false ? '⚠ ' : (modelOk === true ? '✓ ' : '');
      badge.innerHTML = '<span class="backend-badge-dot ' + dotClass + '"></span><span class="backend-badge-text">' + statusIcon + escapeHtml(short) + '</span>';
      badge.title = modelOk === false ? '模型未下载，点击查看详情' : '点击/悬停查看推理精度检测报告';

      tooltip.innerHTML = buildTooltip(info);

      // 移动端点击切换 tooltip 显隐
      badge.addEventListener('click', function (e) {
        e.stopPropagation();
        wrap.classList.toggle('active');
      });
      document.addEventListener('click', function () { wrap.classList.remove('active'); });
    }

    function shortLabel(info) {
      var map = {
        ollama: 'Ollama',
        transformers: 'Transformers',
        llamacpp: 'LlamaCPP',
        vllm: 'vLLM'
      };
      var name = map[(info.backend || '').toLowerCase()] || info.backend || '未知';
      var q = info.base_quantization || '';
      // 简短化
      if (q.indexOf('Q4_K_M') >= 0) q = 'Q4_K_M';
      else if (q.indexOf('NF4') >= 0) q = 'NF4';
      else if (q.indexOf('GGUF Q4') >= 0) q = 'Q4';
      else q = ''; // 描述式文案不再提取简短标签
      return name + (q ? ' · ' + q : '');
    }

    function buildTooltip(info) {
      var b = (info.backend || 'unknown').toLowerCase();
      var title = {
        ollama: 'Ollama 托管推理',
        transformers: 'Transformers 进程内推理',
        llamacpp: 'llama.cpp 进程内推理',
        vllm: 'vLLM 独立服务推理'
      }[b] || '推理后端';

      // 检测报告头部：模型下载状态
      var modelOk = info.model_available;
      var statusBadge;
      if (modelOk === true) {
        statusBadge = '<span class="rpt-status rpt-ok">✓ 模型就绪</span>';
      } else if (modelOk === false) {
        statusBadge = '<span class="rpt-status rpt-warn">⚠ 模型未就绪</span>';
      } else {
        statusBadge = '<span class="rpt-status rpt-unknown">? 未知</span>';
      }

      var rows = [];
      rows.push(row('后端', '<span class="backend-tag">' + escapeHtml(info.backend || '未知') + '</span>'));
      if (info.model) rows.push(row('模型', escapeHtml(String(info.model))));
      if (info.model_status) rows.push(row('模型状态', escapeHtml(info.model_status)));
      if (info.base_quantization) rows.push(row('基座量化', escapeHtml(info.base_quantization)));
      if (info.compute_dtype) rows.push(row('计算精度', escapeHtml(info.compute_dtype.toUpperCase())));
      if (info.device_type) rows.push(row('运行设备', escapeHtml(info.device_type)));
      if (info.num_ctx) rows.push(row('上下文长度', escapeHtml(String(info.num_ctx))));
      if (info.num_gpu_layers != null) rows.push(row('GPU 层数', escapeHtml(String(info.num_gpu_layers))));
      if (info.adapter_path) rows.push(row('LoRA 路径', escapeHtml(info.adapter_path)));
      if (info.gguf_path) rows.push(row('GGUF 路径', escapeHtml(info.gguf_path)));
      if (info.server_url) rows.push(row('服务地址', escapeHtml(info.server_url)));
      if (info.model_store) rows.push(row('存储位置', escapeHtml(info.model_store)));

      var noteClass = 'note';
      var note = info.precision_note || '';
      if (info.lora_quantized) {
        noteClass = 'note warn';
        note = '⚠ ' + note;
      }

      var methodBlocks = '';
      if (info.detection_method) {
        methodBlocks += '<div class="note"><b>检测逻辑</b><br>' + escapeHtml(info.detection_method).replace(/\n/g, '<br>') + '</div>';
      }
      if (info.download_method) {
        methodBlocks += '<div class="note"><b>模型获取</b><br>' + escapeHtml(info.download_method).replace(/\n/g, '<br>') + '</div>';
      }

      // 模型未下载时追加醒目提醒
      var downloadAlert = '';
      if (modelOk === false && info.download_hint) {
        downloadAlert = '<div class="note alert">' + escapeHtml(info.download_hint).replace(/\n/g, '<br>') + '</div>';
      }

      return '<h4>' + escapeHtml(title) + ' 检测报告</h4>' +
        '<div class="rpt-header">' + statusBadge + '</div>' +
        rows.join('') +
        methodBlocks +
        downloadAlert +
        '<div class="' + noteClass + '">' + escapeHtml(note).replace(/\n/g, '<br>') + '</div>';
    }

    function row(k, v) {
      return '<div class="kv"><span class="k">' + escapeHtml(k) + '</span><span class="v">' + v + '</span></div>';
    }

    function escapeHtml(s) {
      return String(s).replace(/[&<>"']/g, function (c) {
        return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
      });
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initBackendBadge);
  } else {
    initBackendBadge();
  }
})();
