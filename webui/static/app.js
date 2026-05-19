(function () {
  'use strict';

  const REFRESH_MS = 10000;
  const MAX_PROMPT_CHARS = 100;
  const STORAGE_KEY = 'ai-scan-filters-v3';

  let allEntries = [];
  let refreshTimer = null;
  let knownServices = new Set();
  let pendingServiceRestore = null;

  // --- DOM refs ---
  const tbody       = document.getElementById('log-tbody');
  const emptyState  = document.getElementById('empty-state');
  const countBadge  = document.getElementById('count-badge');
  const statusDot   = document.getElementById('status-dot');
  const lastUpdated = document.getElementById('last-updated');
  const svcSelect      = document.getElementById('svc-select');
  const sevSelect      = document.getElementById('sev-select');
  const alertOnly      = document.getElementById('alert-only');
  const searchInput    = document.getElementById('search-input');
  const excludeSvcInput = document.getElementById('exclude-svc-input');
  const overlay     = document.getElementById('modal-overlay');
  const modalClose  = document.getElementById('modal-close');
  const modalBody   = document.getElementById('modal-body');

  // --- Fetch logs ---
  async function fetchLogs() {
    statusDot.classList.add('loading');
    try {
      const params = new URLSearchParams();
      const svc = svcSelect.value;
      const sev = sevSelect.value;
      const triggered = alertOnly.checked;
      const q = searchInput.value.trim();
      const excl = excludeSvcInput.value.trim();
      if (svc) params.set('service', svc);
      if (sev) params.set('severity', sev);
      if (triggered) params.set('triggered', 'true');
      if (q) params.set('q', q);
      if (excl) params.set('exclude_service', excl);

      const res = await fetch('/api/logs?' + params.toString());
      if (!res.ok) throw new Error('HTTP ' + res.status);
      allEntries = await res.json();

      updateServiceDropdown(allEntries);
      renderTable(allEntries);
      lastUpdated.textContent = '最終更新: ' + new Date().toLocaleTimeString('ja-JP');
    } catch (err) {
      console.error('fetch error:', err);
      lastUpdated.textContent = 'エラー: ' + err.message;
    } finally {
      statusDot.classList.remove('loading');
    }
  }

  function updateServiceDropdown(entries) {
    const current = svcSelect.value;
    entries.forEach(e => {
      if (e.service && !knownServices.has(e.service)) {
        knownServices.add(e.service);
        const opt = document.createElement('option');
        opt.value = e.service;
        opt.textContent = e.service;
        svcSelect.appendChild(opt);
      }
    });
    if (pendingServiceRestore) {
      svcSelect.value = pendingServiceRestore;
      if (svcSelect.value === pendingServiceRestore) pendingServiceRestore = null;
    } else if (current) {
      svcSelect.value = current;
    }
  }

  // --- Filter persistence ---
  function saveFilters() {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify({
        service:        svcSelect.value,
        severity:       sevSelect.value,
        alertOnly:      alertOnly.checked,
        search:         searchInput.value,
        excludeService: excludeSvcInput.value,
      }));
    } catch (e) {}
  }

  function loadFilters() {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (!raw) return;
      const s = JSON.parse(raw);
      if (s.severity)       sevSelect.value      = s.severity;
      if (s.alertOnly)      alertOnly.checked    = s.alertOnly;
      if (s.search)         searchInput.value    = s.search;
      if (s.excludeService) excludeSvcInput.value = s.excludeService;
      if (s.service) pendingServiceRestore = s.service;
    } catch (e) {}
  }

  // --- Action badge ---
  const ACTION_LABEL = {
    blocked:   'ブロック',
    masked:    'マスク',
    warned:    '警告',
    monitored: '監視',
    passed:    'スルー',
  };

  function actionBadge(action) {
    const span = document.createElement('span');
    span.className = 'action-badge act-' + (action || 'passed');
    span.textContent = ACTION_LABEL[action] || (action || 'スルー');
    return span;
  }

  // --- Render table ---
  function renderTable(entries) {
    tbody.textContent = '';

    if (!entries || entries.length === 0) {
      emptyState.style.display = 'block';
      countBadge.textContent = '0 件';
      return;
    }
    emptyState.style.display = 'none';
    countBadge.textContent = entries.length + ' 件';

    entries.forEach((e) => {
      const tr = document.createElement('tr');
      if (e.triggered) tr.classList.add('triggered-row');
      tr.addEventListener('click', () => openModal(e));

      // Timestamp
      const ts = e.timestamp ? new Date(e.timestamp).toLocaleString('ja-JP') : '';
      tr.appendChild(td(ts, 'ts'));

      // Service
      tr.appendChild(td(e.service || '', 'service'));

      // Severity badge
      const sevTd = document.createElement('td');
      sevTd.appendChild(severityBadge(e.severity));
      tr.appendChild(sevTd);

      // Action badge
      const actionTd = document.createElement('td');
      actionTd.appendChild(actionBadge(e.action));
      tr.appendChild(actionTd);

      // Client IP / User ID
      const ipText = e.user_id ? e.user_id : (e.client_ip || '');
      tr.appendChild(td(ipText, 'client-ip'));

      // Prompt (truncated)
      const promptTd = document.createElement('td');
      promptTd.className = 'prompt-cell';
      const promptDiv = document.createElement('div');
      promptDiv.className = 'prompt-text';
      const raw = e.prompt || '';
      promptDiv.textContent = raw.length > MAX_PROMPT_CHARS
        ? raw.slice(0, MAX_PROMPT_CHARS) + '…'
        : raw;
      promptTd.appendChild(promptDiv);
      tr.appendChild(promptTd);

      // Rule IDs
      const ruleTd = document.createElement('td');
      ruleTd.className = 'rule-ids';
      if (e.rule_ids && e.rule_ids.length > 0) {
        e.rule_ids.forEach(rid => {
          const span = document.createElement('span');
          span.className = 'rule-id-tag';
          span.textContent = rid;
          ruleTd.appendChild(span);
        });
      }
      tr.appendChild(ruleTd);

      tbody.appendChild(tr);
    });
  }

  function td(text, className) {
    const el = document.createElement('td');
    if (className) el.className = className;
    el.textContent = text;
    return el;
  }

  function severityBadge(sev) {
    const span = document.createElement('span');
    span.className = 'severity-badge';
    if (!sev) {
      span.classList.add('sev-none');
      span.textContent = 'none';
    } else {
      span.classList.add('sev-' + sev.toLowerCase());
      span.textContent = sev;
    }
    return span;
  }

  // --- Modal ---
  function openModal(e) {
    modalBody.textContent = '';

    addDetailRow(modalBody, 'タイムスタンプ', e.timestamp ? new Date(e.timestamp).toLocaleString('ja-JP') : '');
    addDetailRow(modalBody, 'サービス', e.service || '');
    addDetailRow(modalBody, 'ホスト', e.host || '');
    addDetailRow(modalBody, 'パス', e.path || '');
    addDetailRow(modalBody, 'クライアントIP', e.client_ip || '');
    if (e.user_id) addDetailRow(modalBody, 'ユーザーID', e.user_id);

    // Severity
    const sevRow = document.createElement('div');
    sevRow.className = 'detail-row';
    const sevLabel = document.createElement('div');
    sevLabel.className = 'detail-label';
    sevLabel.textContent = '重大度';
    sevRow.appendChild(sevLabel);
    const sevVal = document.createElement('div');
    sevVal.className = 'detail-value';
    sevVal.appendChild(severityBadge(e.severity));
    sevRow.appendChild(sevVal);
    modalBody.appendChild(sevRow);

    // Action
    const actRow = document.createElement('div');
    actRow.className = 'detail-row';
    const actLabel = document.createElement('div');
    actLabel.className = 'detail-label';
    actLabel.textContent = 'アクション';
    actRow.appendChild(actLabel);
    const actVal = document.createElement('div');
    actVal.className = 'detail-value';
    actVal.appendChild(actionBadge(e.action));
    actRow.appendChild(actVal);
    modalBody.appendChild(actRow);

    if (e.rule_ids && e.rule_ids.length > 0) {
      addDetailRow(modalBody, 'ルールID', e.rule_ids.join('\n'));
    }

    // Full prompt
    const promptRow = document.createElement('div');
    promptRow.className = 'detail-row';
    const promptLabel = document.createElement('div');
    promptLabel.className = 'detail-label';
    promptLabel.textContent = 'プロンプト';
    promptRow.appendChild(promptLabel);
    const promptPre = document.createElement('pre');
    promptPre.className = 'prompt-full';
    promptPre.textContent = e.prompt || '(なし)';
    promptRow.appendChild(promptPre);
    modalBody.appendChild(promptRow);

    overlay.classList.add('open');
  }

  function addDetailRow(parent, label, value) {
    const row = document.createElement('div');
    row.className = 'detail-row';
    const lbl = document.createElement('div');
    lbl.className = 'detail-label';
    lbl.textContent = label;
    const val = document.createElement('div');
    val.className = 'detail-value';
    val.textContent = value;
    row.appendChild(lbl);
    row.appendChild(val);
    parent.appendChild(row);
  }

  function closeModal() { overlay.classList.remove('open'); }

  modalClose.addEventListener('click', closeModal);
  overlay.addEventListener('click', function (e) {
    if (e.target === overlay) closeModal();
  });
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') {
      closeModal();
      settingsOverlay.classList.remove('open');
    }
  });

  // --- Filter controls ---
  function onFilterChange() {
    saveFilters();
    clearTimeout(refreshTimer);
    fetchLogs().finally(scheduleRefresh);
  }

  svcSelect.addEventListener('change', onFilterChange);
  sevSelect.addEventListener('change', onFilterChange);
  alertOnly.addEventListener('change', onFilterChange);

  let searchDebounce = null;
  searchInput.addEventListener('input', function () {
    clearTimeout(searchDebounce);
    searchDebounce = setTimeout(onFilterChange, 300);
  });
  excludeSvcInput.addEventListener('input', function () {
    clearTimeout(searchDebounce);
    searchDebounce = setTimeout(onFilterChange, 300);
  });

  function scheduleRefresh() {
    clearTimeout(refreshTimer);
    refreshTimer = setTimeout(function () {
      fetchLogs().finally(scheduleRefresh);
    }, REFRESH_MS);
  }

  // --- Filter reset ---
  document.getElementById('reset-filters-btn').addEventListener('click', function () {
    localStorage.removeItem(STORAGE_KEY);
    svcSelect.value = '';
    sevSelect.value = '';
    alertOnly.checked = false;
    searchInput.value = '';
    excludeSvcInput.value = '';
    clearTimeout(refreshTimer);
    fetchLogs().finally(scheduleRefresh);
  });

  // --- Init (called externally after auth check) ---
  window._initLogs = function() {
    loadFilters();
    fetchLogs().finally(scheduleRefresh);
  };
})();

// ---- Settings Panel ----
const settingsOverlay = document.getElementById('settings-overlay');
const settingsBtn = document.getElementById('settings-btn');
const settingsClose = document.getElementById('settings-close');
const settingsCancel = document.getElementById('settings-cancel');
const settingsSave = document.getElementById('settings-save');
const globalModeSelect = document.getElementById('global-mode-select');
const serviceModesListEl = document.getElementById('service-modes-list');
const addServiceBtn = document.getElementById('add-service-btn');
const settingsMsg = document.getElementById('settings-msg');

const SERVICES = ['Claude','Claude-API','Claude-Web','ChatGPT','ChatGPT-Web','Gemini','Gemini-Web','GitHub-Copilot','Azure-OpenAI'];
const MODE_LABELS = { monitor:'Monitor', warn:'Warn', block:'Block', mask:'Mask' };

let currentServiceModes = {};

function openSettings() {
  fetch('/api/policy')
    .then(r => r.json())
    .then(p => {
      globalModeSelect.value = p.global_mode || 'monitor';
      currentServiceModes = p.service_modes || {};
      renderServiceModes();
      settingsOverlay.classList.add('open');
      loadRules();
    })
    .catch(() => { settingsOverlay.classList.add('open'); loadRules(); });

  // Admin-only sections
  if (currentUser && currentUser.role === 'admin') {
    retentionSection.style.display = '';
    loadRetentionSettings();
    notificationSection.style.display = '';
    loadNotificationSettings();
  } else {
    retentionSection.style.display = 'none';
    notificationSection.style.display = 'none';
  }
}

function renderServiceModes() {
  serviceModesListEl.innerHTML = '';
  Object.entries(currentServiceModes).forEach(([svc, mode]) => {
    serviceModesListEl.appendChild(makeServiceRow(svc, mode));
  });
}

function makeServiceRow(svc, mode) {
  const row = document.createElement('div');
  row.style.cssText = 'display:flex;gap:8px;align-items:center;margin-top:6px';

  const svcSel = document.createElement('select');
  svcSel.style.cssText = 'background:#0f1117;border:1px solid #2d3148;color:#e2e8f0;border-radius:6px;padding:4px 8px;font-size:12px;flex:1';
  SERVICES.forEach(s => {
    const o = document.createElement('option');
    o.value = s; o.textContent = s;
    if (s === svc) o.selected = true;
    svcSel.appendChild(o);
  });

  const modeSel = document.createElement('select');
  modeSel.style.cssText = 'background:#0f1117;border:1px solid #2d3148;color:#e2e8f0;border-radius:6px;padding:4px 8px;font-size:12px;width:110px';
  ['monitor','warn','block','mask'].forEach(m => {
    const o = document.createElement('option');
    o.value = m; o.textContent = MODE_LABELS[m];
    if (m === mode) o.selected = true;
    modeSel.appendChild(o);
  });

  const del = document.createElement('button');
  del.textContent = '✕';
  del.style.cssText = 'background:none;border:none;color:#64748b;cursor:pointer;font-size:14px;padding:2px 6px';
  del.onclick = () => row.remove();

  row.appendChild(svcSel);
  row.appendChild(modeSel);
  row.appendChild(del);
  return row;
}

addServiceBtn.addEventListener('click', () => {
  serviceModesListEl.appendChild(makeServiceRow(SERVICES[0], 'block'));
});

settingsBtn.addEventListener('click', openSettings);
settingsClose.addEventListener('click', () => settingsOverlay.classList.remove('open'));
settingsCancel.addEventListener('click', () => settingsOverlay.classList.remove('open'));
settingsOverlay.addEventListener('click', e => { if (e.target === settingsOverlay) settingsOverlay.classList.remove('open'); });

settingsSave.addEventListener('click', () => {
  const serviceModes = {};
  serviceModesListEl.querySelectorAll('div').forEach(row => {
    const sels = row.querySelectorAll('select');
    if (sels.length === 2) serviceModes[sels[0].value] = sels[1].value;
  });
  const payload = { global_mode: globalModeSelect.value, service_modes: serviceModes };

  settingsSave.disabled = true;
  fetch('/api/policy', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  })
    .then(r => {
      if (r.ok) {
        settingsMsg.textContent = '✓ 保存しました';
        settingsMsg.style.color = '#22c55e';
        setTimeout(() => { settingsOverlay.classList.remove('open'); settingsMsg.textContent = ''; }, 1000);
      } else {
        settingsMsg.textContent = '保存に失敗しました';
        settingsMsg.style.color = '#ef4444';
      }
    })
    .catch(() => { settingsMsg.textContent = 'ネットワークエラー'; settingsMsg.style.color = '#ef4444'; })
    .finally(() => { settingsSave.disabled = false; });
});

// ---- Unified Rules Management ----
const rulesTableBody    = document.getElementById('rules-tbody');
const rulesEmpty        = document.getElementById('rules-empty');
const addRuleBtn        = document.getElementById('add-rule-btn');
const resetRulesBtn     = document.getElementById('reset-rules-btn');
const ruleForm          = document.getElementById('rule-form');
const ruleIdInput       = document.getElementById('rule-id');
const ruleSeverityInput = document.getElementById('rule-severity');
const ruleDescInput     = document.getElementById('rule-description');
const rulePatternInput  = document.getElementById('rule-pattern');
const ruleMaskBody      = document.getElementById('rule-mask-body');
const ruleFormMsg       = document.getElementById('rule-form-msg');
const ruleCancelBtn     = document.getElementById('rule-cancel-btn');
const ruleAddBtn        = document.getElementById('rule-add-btn');

const SEV_STYLES = {
  critical: 'background:#7f1d1d;color:#fca5a5',
  high:     'background:#7c2d12;color:#fdba74',
  medium:   'background:#713f12;color:#fde68a',
  low:      'background:#1e3a5f;color:#93c5fd',
};

function loadRules() {
  fetch('/api/rules')
    .then(r => r.json())
    .then(rules => renderRules(rules))
    .catch(() => { rulesEmpty.style.display = 'block'; rulesTableBody.innerHTML = ''; });
}

function renderRules(rules) {
  rulesTableBody.innerHTML = '';
  if (!rules || rules.length === 0) {
    rulesEmpty.style.display = 'block';
    return;
  }
  rulesEmpty.style.display = 'none';
  rules.forEach(rule => appendRuleRow(rule));
}

function appendRuleRow(rule) {
  const tr = document.createElement('tr');
  tr.id = 'rule-row-' + rule.id.replace(/[^a-zA-Z0-9-_]/g, '_');
  tr.style.cssText = 'border-bottom:1px solid #1e2130';

  // enabled toggle
  const enabledTd = document.createElement('td');
  enabledTd.style.cssText = 'padding:5px 6px;text-align:center';
  const toggle = document.createElement('input');
  toggle.type = 'checkbox';
  toggle.checked = rule.enabled;
  toggle.style.cssText = 'accent-color:#2563eb;width:14px;height:14px;cursor:pointer';
  toggle.title = rule.enabled ? '有効（クリックで無効化）' : '無効（クリックで有効化）';
  toggle.addEventListener('change', () => toggleRule(rule, toggle.checked, tr));
  enabledTd.appendChild(toggle);
  tr.appendChild(enabledTd);

  // source badge
  const srcTd = document.createElement('td');
  srcTd.style.cssText = 'padding:5px 6px';
  const srcSpan = document.createElement('span');
  const isBuiltin = rule.source === 'builtin';
  srcSpan.style.cssText = isBuiltin
    ? 'display:inline-block;padding:1px 6px;border-radius:3px;font-size:10px;font-weight:600;background:#172554;color:#60a5fa'
    : 'display:inline-block;padding:1px 6px;border-radius:3px;font-size:10px;font-weight:600;background:#052e16;color:#86efac';
  srcSpan.textContent = isBuiltin ? 'builtin' : 'custom';
  srcTd.appendChild(srcSpan);
  tr.appendChild(srcTd);

  // ID
  const idTd = document.createElement('td');
  idTd.style.cssText = 'padding:5px 6px;font-family:monospace;color:#60a5fa;font-size:11px;white-space:nowrap';
  idTd.textContent = rule.id;
  tr.appendChild(idTd);

  // severity
  const sevTd = document.createElement('td');
  sevTd.style.cssText = 'padding:5px 6px';
  const sevStyle = SEV_STYLES[rule.severity] || 'background:#1e2130;color:#64748b';
  const sevSpan = document.createElement('span');
  sevSpan.style.cssText = 'display:inline-block;padding:1px 7px;border-radius:3px;font-size:10px;font-weight:600;text-transform:uppercase;' + sevStyle;
  sevSpan.textContent = rule.severity || '-';
  sevTd.appendChild(sevSpan);
  tr.appendChild(sevTd);

  // description
  const descTd = document.createElement('td');
  descTd.style.cssText = 'padding:5px 6px;color:#cbd5e1;font-size:12px';
  descTd.textContent = rule.description;
  tr.appendChild(descTd);

  // pattern (truncated, full on hover)
  const patTd = document.createElement('td');
  patTd.style.cssText = 'padding:5px 6px;font-family:monospace;color:#94a3b8;font-size:11px;max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap';
  patTd.title = rule.pattern;
  patTd.textContent = rule.pattern;
  tr.appendChild(patTd);

  // mask body
  const maskTd = document.createElement('td');
  maskTd.style.cssText = 'padding:5px 6px;text-align:center;color:#22c55e;font-size:13px';
  maskTd.textContent = rule.mask_body ? '✓' : '';
  maskTd.title = rule.mask_body ? 'マスク有効' : '';
  tr.appendChild(maskTd);

  // actions
  const actTd = document.createElement('td');
  actTd.style.cssText = 'padding:5px 6px;text-align:right;white-space:nowrap';

  const editBtn = document.createElement('button');
  editBtn.textContent = '編集';
  editBtn.style.cssText = 'background:#2d3148;border:1px solid #1e40af;color:#60a5fa;border-radius:4px;padding:2px 8px;font-size:11px;cursor:pointer;margin-right:4px';
  editBtn.addEventListener('click', () => showEditRow(rule, tr));

  const delBtn = document.createElement('button');
  delBtn.textContent = '削除';
  delBtn.style.cssText = 'background:none;border:none;color:#64748b;cursor:pointer;font-size:11px;padding:2px 6px;border-radius:4px';
  delBtn.addEventListener('click', () => deleteRule(rule.id));

  actTd.appendChild(editBtn);
  actTd.appendChild(delBtn);
  tr.appendChild(actTd);

  rulesTableBody.appendChild(tr);
}

function showEditRow(rule, origRow) {
  // Remove any existing inline edit row
  const existing = document.getElementById('rule-edit-inline');
  if (existing) existing.remove();

  const editTr = document.createElement('tr');
  editTr.id = 'rule-edit-inline';
  editTr.style.cssText = 'background:#0d1021;border-bottom:2px solid #1e40af';

  const td = document.createElement('td');
  td.colSpan = 8;
  td.style.cssText = 'padding:10px 12px';

  // Build form via innerHTML (controlled values use esc())
  td.innerHTML =
    '<div style="display:grid;grid-template-columns:120px 1fr 2fr;gap:8px;align-items:end">' +
      '<div>' +
        '<label style="font-size:11px;color:#64748b;display:block;margin-bottom:3px">重大度</label>' +
        '<select id="ei-severity" style="width:100%;background:#1a1d27;border:1px solid #2d3148;color:#e2e8f0;border-radius:6px;padding:5px 8px;font-size:12px">' +
          ['critical','high','medium','low'].map(v =>
            '<option value="' + v + '"' + (rule.severity === v ? ' selected' : '') + '>' + v + '</option>'
          ).join('') +
        '</select>' +
      '</div>' +
      '<div>' +
        '<label style="font-size:11px;color:#64748b;display:block;margin-bottom:3px">説明</label>' +
        '<input id="ei-description" type="text" value="' + esc(rule.description) + '" style="width:100%;background:#1a1d27;border:1px solid #2d3148;color:#e2e8f0;border-radius:6px;padding:5px 8px;font-size:12px;outline:none">' +
      '</div>' +
      '<div>' +
        '<label style="font-size:11px;color:#64748b;display:block;margin-bottom:3px">パターン（正規表現）</label>' +
        '<input id="ei-pattern" type="text" value="' + esc(rule.pattern) + '" style="width:100%;background:#1a1d27;border:1px solid #2d3148;color:#e2e8f0;border-radius:6px;padding:5px 8px;font-size:12px;font-family:monospace;outline:none">' +
      '</div>' +
    '</div>' +
    '<div style="display:flex;align-items:center;justify-content:space-between;margin-top:8px">' +
      '<label style="font-size:12px;color:#cbd5e1;display:flex;align-items:center;gap:6px;cursor:pointer">' +
        '<input id="ei-mask-body" type="checkbox"' + (rule.mask_body ? ' checked' : '') + ' style="accent-color:#2563eb;width:13px;height:13px">' +
        '本文中のマッチ箇所をマスクする' +
      '</label>' +
      '<div style="display:flex;gap:8px;align-items:center">' +
        '<span id="ei-msg" style="font-size:11px;color:#ef4444"></span>' +
        '<button id="ei-cancel" style="background:#2d3148;border:none;color:#94a3b8;border-radius:6px;padding:5px 14px;font-size:12px;cursor:pointer">キャンセル</button>' +
        '<button id="ei-save" style="background:#2563eb;border:none;color:#fff;border-radius:6px;padding:5px 14px;font-size:12px;cursor:pointer;font-weight:600">保存</button>' +
      '</div>' +
    '</div>';

  editTr.appendChild(td);
  origRow.insertAdjacentElement('afterend', editTr);

  document.getElementById('ei-cancel').addEventListener('click', () => editTr.remove());
  document.getElementById('ei-save').addEventListener('click', () => {
    const pattern = document.getElementById('ei-pattern').value.trim();
    const msgEl = document.getElementById('ei-msg');
    if (!pattern) { msgEl.textContent = 'パターンを入力してください'; return; }

    const updated = {
      id:               rule.id,
      source:           rule.source,
      enabled:          rule.enabled,
      severity:         document.getElementById('ei-severity').value,
      description:      document.getElementById('ei-description').value.trim(),
      pattern:          pattern,
      mask_body:        document.getElementById('ei-mask-body').checked,
      negative_context: rule.negative_context || [],
    };

    const saveBtn = document.getElementById('ei-save');
    saveBtn.disabled = true;
    fetch('/api/rules/' + encodeURIComponent(rule.id), {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(updated),
    })
      .then(r => {
        if (r.ok || r.status === 204) {
          editTr.remove();
          loadRules();
        } else {
          return r.text().then(t => {
            const el = document.getElementById('ei-msg');
            if (el) el.textContent = t || '保存に失敗しました';
          });
        }
      })
      .catch(() => {
        const el = document.getElementById('ei-msg');
        if (el) el.textContent = 'ネットワークエラー';
      })
      .finally(() => {
        const btn = document.getElementById('ei-save');
        if (btn) btn.disabled = false;
      });
  });
}

function toggleRule(rule, enabled, tr) {
  const updated = {
    id:               rule.id,
    source:           rule.source,
    enabled:          enabled,
    severity:         rule.severity,
    description:      rule.description,
    pattern:          rule.pattern,
    mask_body:        rule.mask_body,
    negative_context: rule.negative_context || [],
  };
  tr.style.opacity = '0.5';
  fetch('/api/rules/' + encodeURIComponent(rule.id), {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(updated),
  })
    .then(r => {
      tr.style.opacity = '';
      if (!r.ok && r.status !== 204) loadRules();
      else rule.enabled = enabled;
    })
    .catch(() => { tr.style.opacity = ''; loadRules(); });
}

function deleteRule(id) {
  if (!confirm('ルール ' + id + ' を削除しますか？')) return;
  fetch('/api/rules/' + encodeURIComponent(id), { method: 'DELETE' })
    .then(r => { if (r.ok || r.status === 204) loadRules(); })
    .catch(() => {});
}

function resetRules() {
  if (!confirm('すべてのルールをデフォルトに戻しますか？\nカスタムルールはすべて削除されます。')) return;
  fetch('/api/rules/reset', { method: 'POST' })
    .then(r => { if (r.ok || r.status === 204) loadRules(); })
    .catch(() => {});
}

function addRule() {
  ruleFormMsg.textContent = '';
  const rule = {
    id:          ruleIdInput.value.trim(),
    severity:    ruleSeverityInput.value,
    description: ruleDescInput.value.trim(),
    pattern:     rulePatternInput.value.trim(),
    mask_body:   ruleMaskBody.checked,
  };
  if (!rule.id)      { ruleFormMsg.textContent = 'IDを入力してください'; return; }
  if (!rule.pattern) { ruleFormMsg.textContent = 'パターンを入力してください'; return; }

  ruleAddBtn.disabled = true;
  fetch('/api/rules', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(rule),
  })
    .then(r => {
      if (r.ok) {
        ruleForm.style.display = 'none';
        resetRuleForm();
        loadRules();
      } else {
        return r.text().then(t => { ruleFormMsg.textContent = t || '追加に失敗しました'; });
      }
    })
    .catch(() => { ruleFormMsg.textContent = 'ネットワークエラー'; })
    .finally(() => { ruleAddBtn.disabled = false; });
}

function resetRuleForm() {
  ruleIdInput.value = '';
  ruleSeverityInput.value = 'medium';
  ruleDescInput.value = '';
  rulePatternInput.value = '';
  ruleMaskBody.checked = false;
  ruleFormMsg.textContent = '';
}

addRuleBtn.addEventListener('click', () => {
  ruleForm.style.display = ruleForm.style.display === 'none' ? 'block' : 'none';
  ruleFormMsg.textContent = '';
});
ruleCancelBtn.addEventListener('click', () => {
  ruleForm.style.display = 'none';
  resetRuleForm();
});
ruleAddBtn.addEventListener('click', addRule);
resetRulesBtn.addEventListener('click', resetRules);

// ---- Authentication & User management ----

let currentUser = null;

const userBadge    = document.getElementById('user-badge');
const userNameEl   = document.getElementById('user-name');
const userRoleTag  = document.getElementById('user-role-tag');
const logoutBtn    = document.getElementById('logout-btn');
const usersBtn     = document.getElementById('users-btn');
const usersModal   = document.getElementById('users-overlay');
const usersClose   = document.getElementById('users-modal-close');
const usersTbody   = document.getElementById('users-tbody');
const addUserBtn   = document.getElementById('add-user-btn');
const addUserForm  = document.getElementById('add-user-form');
const addUserCancel = document.getElementById('add-user-cancel');
const addUserSave  = document.getElementById('add-user-save');
const addUserMsg   = document.getElementById('add-user-msg');
const usersMsg     = document.getElementById('users-msg');

async function checkAuth() {
  try {
    const res = await fetch('/api/auth/me');
    if (res.status === 401) {
      window.location.replace('/login.html');
      return;
    }
    currentUser = await res.json();
    userNameEl.textContent = currentUser.username;
    userRoleTag.textContent = currentUser.role;
    userRoleTag.className = 'role-tag' + (currentUser.role === 'admin' ? ' admin' : '');
    userBadge.style.display = 'flex';
    logoutBtn.style.display = '';
    if (currentUser.role === 'admin') {
      usersBtn.style.display = '';
    }
  } catch {
    window.location.replace('/login.html');
  }
}

logoutBtn.addEventListener('click', async () => {
  await fetch('/api/auth/logout', { method: 'POST' });
  window.location.replace('/login.html');
});

usersBtn.addEventListener('click', () => {
  usersModal.classList.add('open');
  loadUsers();
});
usersClose.addEventListener('click', () => {
  usersModal.classList.remove('open');
  addUserForm.style.display = 'none';
  addUserMsg.textContent = '';
  usersMsg.textContent = '';
});
usersModal.addEventListener('click', e => {
  if (e.target === usersModal) {
    usersModal.classList.remove('open');
    addUserForm.style.display = 'none';
  }
});

async function loadUsers() {
  usersTbody.innerHTML = '';
  usersMsg.textContent = '';
  try {
    const res = await fetch('/api/users');
    if (!res.ok) { usersMsg.textContent = 'ユーザー一覧の取得に失敗しました'; return; }
    const users = await res.json();
    users.sort((a, b) => a.username.localeCompare(b.username));
    for (const u of users) {
      const tr = document.createElement('tr');
      const isSelf = currentUser && u.id === currentUser.id;
      tr.innerHTML = `
        <td style="padding:6px 8px;border-bottom:1px solid #1e2235">${esc(u.username)}${isSelf ? ' <span style="color:#64748b;font-size:11px">(自分)</span>' : ''}</td>
        <td style="padding:6px 8px;border-bottom:1px solid #1e2235">
          <span class="role-tag${u.role === 'admin' ? ' admin' : ''}">${esc(u.role)}</span>
        </td>
        <td style="padding:6px 8px;border-bottom:1px solid #1e2235;color:#64748b;font-size:12px">${new Date(u.created_at).toLocaleDateString('ja-JP')}</td>
        <td style="padding:6px 8px;border-bottom:1px solid #1e2235;text-align:right;display:flex;gap:6px;justify-content:flex-end">
          <button data-uid="${esc(u.id)}" data-uname="${esc(u.username)}" class="unlock-user-btn" style="background:none;border:1px solid #1d4ed8;color:#60a5fa;border-radius:4px;padding:2px 8px;font-size:11px;cursor:pointer">解除</button>
          ${!isSelf ? `<button data-uid="${esc(u.id)}" data-uname="${esc(u.username)}" class="del-user-btn" style="background:none;border:1px solid #4b5563;color:#94a3b8;border-radius:4px;padding:2px 8px;font-size:11px;cursor:pointer">削除</button>` : ''}
        </td>`;
      usersTbody.appendChild(tr);
    }
    usersTbody.querySelectorAll('.del-user-btn').forEach(btn => {
      btn.addEventListener('click', () => deleteUser(btn.dataset.uid, btn.dataset.uname));
    });
    usersTbody.querySelectorAll('.unlock-user-btn').forEach(btn => {
      btn.addEventListener('click', () => unlockUser(btn.dataset.uid, btn.dataset.uname));
    });
  } catch {
    usersMsg.textContent = '通信エラーが発生しました';
  }
}

async function deleteUser(id, name) {
  if (!confirm(`ユーザー「${name}」を削除しますか？`)) return;
  const res = await fetch(`/api/users/${encodeURIComponent(id)}`, { method: 'DELETE' });
  if (res.ok) {
    loadUsers();
  } else {
    const text = await res.text();
    usersMsg.textContent = text || '削除に失敗しました';
  }
}

async function unlockUser(id, name) {
  const res = await fetch(`/api/users/${encodeURIComponent(id)}/unlock`, { method: 'POST' });
  if (res.ok) {
    usersMsg.textContent = `✓ ${name} のロックを解除しました`;
    usersMsg.style.color = '#22c55e';
    setTimeout(() => { usersMsg.textContent = ''; usersMsg.style.color = ''; }, 3000);
  } else {
    const text = await res.text();
    usersMsg.textContent = text || 'ロック解除に失敗しました';
    usersMsg.style.color = '#ef4444';
  }
}

addUserBtn.addEventListener('click', () => {
  addUserForm.style.display = addUserForm.style.display === 'none' ? 'block' : 'none';
  addUserMsg.textContent = '';
});
addUserCancel.addEventListener('click', () => {
  addUserForm.style.display = 'none';
  addUserMsg.textContent = '';
});

addUserSave.addEventListener('click', async () => {
  addUserMsg.textContent = '';
  const username = document.getElementById('new-username').value.trim();
  const password = document.getElementById('new-password').value;
  const role     = document.getElementById('new-role').value;
  if (!username || !password) { addUserMsg.textContent = 'ユーザー名とパスワードを入力してください'; return; }
  addUserSave.disabled = true;
  try {
    const res = await fetch('/api/users', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password, role }),
    });
    if (res.ok) {
      document.getElementById('new-username').value = '';
      document.getElementById('new-password').value = '';
      addUserForm.style.display = 'none';
      loadUsers();
    } else {
      const text = await res.text();
      addUserMsg.textContent = text || '作成に失敗しました';
    }
  } catch {
    addUserMsg.textContent = '通信エラーが発生しました';
  } finally {
    addUserSave.disabled = false;
  }
});

function esc(s) {
  return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

// ---- Log Retention Settings (admin only) ----

const retentionSection  = document.getElementById('log-retention-section');
const retentionDaysInput = document.getElementById('retention-days-input');
const retentionSaveBtn  = document.getElementById('retention-save-btn');
const retentionMsg      = document.getElementById('retention-msg');

function loadRetentionSettings() {
  fetch('/api/settings')
    .then(r => r.json())
    .then(s => { retentionDaysInput.value = s.retention_days || 30; })
    .catch(() => {});
}

if (retentionSaveBtn) {
  retentionSaveBtn.addEventListener('click', async () => {
    const days = parseInt(retentionDaysInput.value, 10);
    if (isNaN(days) || days < 1 || days > 3650) {
      retentionMsg.textContent = '1〜3650の範囲で入力してください';
      retentionMsg.style.color = '#ef4444';
      return;
    }
    retentionSaveBtn.disabled = true;
    try {
      const res = await fetch('/api/settings', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ retention_days: days }),
      });
      if (res.ok || res.status === 204) {
        retentionMsg.textContent = '✓ 保存しました';
        retentionMsg.style.color = '#22c55e';
        setTimeout(() => { retentionMsg.textContent = ''; }, 3000);
      } else {
        retentionMsg.textContent = '保存に失敗しました';
        retentionMsg.style.color = '#ef4444';
      }
    } catch {
      retentionMsg.textContent = '通信エラー';
      retentionMsg.style.color = '#ef4444';
    } finally {
      retentionSaveBtn.disabled = false;
    }
  });
}

// ---- Notification Settings (admin only) ----

const notificationSection = document.getElementById('notification-section');
const notifSlackUrl   = document.getElementById('notif-slack-url');
const notifSmtpHost   = document.getElementById('notif-smtp-host');
const notifSmtpPort   = document.getElementById('notif-smtp-port');
const notifSmtpUser   = document.getElementById('notif-smtp-user');
const notifSmtpPass   = document.getElementById('notif-smtp-pass');
const notifSmtpFrom   = document.getElementById('notif-smtp-from');
const notifEmailTo    = document.getElementById('notif-email-to');
const notifSaveBtn    = document.getElementById('notif-save-btn');
const notifMsg        = document.getElementById('notif-msg');

function loadNotificationSettings() {
  fetch('/api/notification')
    .then(r => r.json())
    .then(s => {
      notifSlackUrl.value  = s.slack_webhook_url || '';
      notifSmtpHost.value  = s.smtp_host || '';
      notifSmtpPort.value  = s.smtp_port || '587';
      notifSmtpUser.value  = s.smtp_user || '';
      notifSmtpPass.value  = '';  // never prefill password
      notifSmtpFrom.value  = s.smtp_from || '';
      notifEmailTo.value   = (s.alert_email_to || []).join(', ');
    })
    .catch(() => {});
}

if (notifSaveBtn) {
  notifSaveBtn.addEventListener('click', async () => {
    const toRaw = notifEmailTo.value.trim();
    const alertTo = toRaw ? toRaw.split(',').map(s => s.trim()).filter(Boolean) : [];
    const pass = notifSmtpPass.value;

    const payload = {
      slack_webhook_url: notifSlackUrl.value.trim(),
      smtp_host:   notifSmtpHost.value.trim(),
      smtp_port:   notifSmtpPort.value.trim() || '587',
      smtp_user:   notifSmtpUser.value.trim(),
      smtp_pass:   pass === '' ? '***' : pass,  // '***' = keep existing
      smtp_from:   notifSmtpFrom.value.trim(),
      alert_email_to: alertTo,
    };

    notifSaveBtn.disabled = true;
    try {
      const res = await fetch('/api/notification', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      if (res.ok || res.status === 204) {
        notifMsg.textContent = '✓ 保存しました';
        notifMsg.style.color = '#22c55e';
        setTimeout(() => { notifMsg.textContent = ''; }, 3000);
      } else {
        notifMsg.textContent = '保存に失敗しました';
        notifMsg.style.color = '#ef4444';
      }
    } catch {
      notifMsg.textContent = '通信エラー';
      notifMsg.style.color = '#ef4444';
    } finally {
      notifSaveBtn.disabled = false;
    }
  });
}

// Run auth check before starting the dashboard.
checkAuth().then(() => {
  window._initLogs();
});
