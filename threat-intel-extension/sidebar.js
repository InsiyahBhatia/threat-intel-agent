(function () {
  'use strict';

  var API = 'http://localhost:8000';
  var $ = function (id) { return document.getElementById(id); };
  var searchInput = $('search-input');
  var searchBtn = $('search-btn');
  var messages = $('messages');
  var welcome = $('welcome');

  chrome.storage.sync.get({ apiBase: API }, function (items) {
    API = items.apiBase;
    init();
  });

  function init() {
    bindEvents();
    checkHealth();
    connectBackground();
    setInterval(checkHealth, 30000);
    renderSamples();
    fetchLiveBuffer();
  }

  function renderSamples() {
    var container = $('sampleIocs');
    if (!container) return;
    var samples = ['185.220.101.1', '8.8.8.8', 'malware-c2.ru'];
    samples.forEach(function (s) {
      var el = document.createElement('button');
      el.className = 'sample-chip';
      el.textContent = s;
      container.appendChild(el);
    });
  }

  function bindEvents() {
    searchInput.addEventListener('keydown', function (e) {
      if (e.key === 'Enter') send();
    });
    searchInput.addEventListener('input', function () {
      searchBtn.disabled = searchInput.value.trim().length === 0;
    });
    searchBtn.addEventListener('click', send);

    document.getElementById('clearBtn').addEventListener('click', function () {
      messages.innerHTML = '';
      welcome.style.display = '';
      messages.appendChild(welcome);
    });

    document.addEventListener('click', function (e) {
      var el = e.target;
      while (el && el !== document) {
        if (el.classList && el.classList.contains('copy-btn')) {
          copyText(el.dataset.copy || '', el);
          return;
        }
        if (el.classList && el.classList.contains('sample-chip')) {
          searchInput.value = el.textContent.trim();
          searchBtn.disabled = false;
          send();
          return;
        }
        if (el.classList && el.classList.contains('explain-btn') && !el.disabled) {
          toggleExplain(el);
          return;
        }
        el = el.parentElement;
      }
    });
  }

  function connectBackground() {
    try {
      var port = chrome.runtime.connect({ name: 'sidebar' });
      port.onMessage.addListener(function (msg) {
        if (msg.type === 'page-investigation' && msg.ioc && msg.result) {
          welcome.style.display = 'none';
          renderAgentResponse(msg.ioc, msg.result.summary || '');
        }
        if (msg.type === 'new-detection' && msg.event) {
          addLiveDetection(msg.event);
        }
        if (msg.type === 'alerts-update' && msg.alertCount != null) {
          var el = $('live-count');
          if (el) el.textContent = msg.alertCount;
        }
      });
    } catch (e) {}
  }

  function send() {
    var text = searchInput.value.trim();
    if (!text) return;
    searchInput.value = '';
    searchBtn.disabled = true;

    welcome.style.display = 'none';
    showThinking();

    var controller = new AbortController();
    var timeout = setTimeout(function () { controller.abort(); }, 20000);

    fetch(API + '/api/chat', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message: text }),
      signal: controller.signal
    })
      .then(function (r) {
        clearTimeout(timeout);
        if (!r.ok) throw new Error(r.status === 404 ? 'API not found' : 'Error ' + r.status);
        return r.json();
      })
      .then(function (data) {
        hideThinking();
        renderAgentResponse(text, data.response || '');
      })
      .catch(function (err) {
        clearTimeout(timeout);
        hideThinking();
        showError(err.name === 'AbortError' ? 'Request timed out. Check your API server.' : err.message);
      });
  }

  function renderAgentResponse(ioc, raw) {
    var verdict = extractJson(raw, 'VERDICT');

    if (verdict) {
      if (verdict.severity && (verdict.severity === 'CRITICAL' || verdict.severity === 'HIGH')) {
        sendBg({ type: 'mark-malicious', severity: verdict.severity });
      }
      renderVerdict(ioc, verdict, raw);
    } else {
      showRawResponse(raw);
    }
  }

  function renderVerdict(ioc, verdict, raw) {
    var sev = (verdict.severity || 'UNKNOWN').toUpperCase();
    var conf = verdict.confidence || 0;
    var cat = verdict.threat_category || 'Unknown';
    var techs = verdict.mitre_techniques || [];
    var riskScore = verdict.risk_score !== undefined ? verdict.risk_score : null;
    var sourceCount = verdict.source_count || verdict.reported_by || null;
    var mlConf = verdict.ml_confidence || null;
    var findings = verdict.findings || [];
    var summary = verdict.summary || '';

    conf = Math.min(100, Math.max(0, conf));
    var riskPct = riskScore !== null ? Math.round(riskScore * 100) : (mlConf !== null ? Math.round(mlConf) : null);

    var badgeLabel = sev;
    if (sev === 'CRITICAL') badgeLabel = 'MALICIOUS';
    else if (sev === 'MEDIUM') badgeLabel = 'SUSPICIOUS';

    var confColor = conf >= 70 ? 'var(--success)' : conf >= 40 ? 'var(--warning)' : 'var(--danger)';

    var riskLabel = riskScore !== null
      ? (riskScore < 0.3 ? 'LOW' : riskScore < 0.6 ? 'MEDIUM' : riskScore < 0.8 ? 'HIGH' : 'CRITICAL')
      : (sev === 'CRITICAL' ? 'CRITICAL' : sev === 'HIGH' ? 'HIGH' : sev === 'MEDIUM' ? 'MEDIUM' : sev === 'LOW' || sev === 'CLEAN' ? 'LOW' : 'UNKNOWN');

    if (!findings.length) {
      findings = generateFindings(sev, cat, ioc);
    }

    var card = document.createElement('div');
    card.className = 'verdict-card';

    var section1 = document.createElement('div');
    section1.className = 'verdict-section';
    section1.innerHTML =
      '<div class="v-header">' +
        '<div class="v-ioc">' + esc(ioc) + '</div>' +
        '<div class="v-actions">' +
          '<button class="copy-btn" data-copy="' + escAttr(ioc) + '">' +
            '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>' +
            'Copy' +
          '</button>' +
        '</div>' +
      '</div>' +
      '<div class="v-badge-row">' +
        '<span class="v-badge ' + badgeLabel + '"><span class="dot"></span>' + badgeLabel + '</span>' +
      '</div>';
    card.appendChild(section1);

    var section2 = document.createElement('div');
    section2.className = 'verdict-section';
    section2.innerHTML =
      '<div class="conf-section">' +
        '<span class="conf-label">Confidence</span>' +
        '<div class="conf-bar-wrap"><div class="conf-bar-fill" style="width:' + conf + '%;background:' + confColor + '"></div></div>' +
        '<span class="conf-pct" style="color:' + confColor + '">' + Math.round(conf) + '%</span>' +
      '</div>';
    card.appendChild(section2);

    var section3 = document.createElement('div');
    section3.className = 'verdict-section';
    section3.innerHTML =
      '<div class="v-grid">' +
        '<div class="v-grid-item"><div class="v-grid-label">Risk Level</div><div class="v-grid-value">' + esc(riskLabel) + '</div></div>' +
        '<div class="v-grid-item"><div class="v-grid-label">Category</div><div class="v-grid-value">' + esc(cat) + '</div></div>' +
        (sourceCount !== null ? '<div class="v-grid-item"><div class="v-grid-label">Source Count</div><div class="v-grid-value">' + sourceCount + '</div></div>' : '') +
        (riskPct !== null ? '<div class="v-grid-item"><div class="v-grid-label">Threat Score</div><div class="v-grid-value">' + riskPct + '/100</div></div>' : '') +
      '</div>';
    card.appendChild(section3);

    if (findings.length > 0) {
      var section4 = document.createElement('div');
      section4.className = 'verdict-section';
      var fhtml = '<div class="section-title">Key Findings</div><div class="findings-list">';
      findings.forEach(function (f) {
        var isBad = String(f).match(/malicious|suspicious|blacklist|block|C2|phishing|threat|attack|compromise/i);
        fhtml += '<div class="finding ' + (isBad ? 'bad' : 'good') + '">' +
          '<span class="check">' +
            (isBad
              ? '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>'
              : '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>') +
          '</span>' +
          '<span>' + esc(f) + '</span>' +
        '</div>';
      });
      fhtml += '</div>';
      section4.innerHTML = fhtml;
      card.appendChild(section4);
    }

    if (techs.length > 0) {
      var secTech = document.createElement('div');
      secTech.className = 'verdict-section';
      var thtml = '<div class="section-title">MITRE ATT&CK</div><div class="mitre-row">';
      techs.forEach(function (t) {
        var tid = t.technique_id || t;
        var tname = t.name || '';
        thtml += '<a class="mitre-chip" href="https://attack.mitre.org/techniques/' + String(tid).replace('.', '/') + '/" target="_blank" rel="noopener">' +
          '<span class="tid">' + esc(tid) + '</span>' +
          (tname ? '<span class="tname">' + esc(tname) + '</span>' : '') +
        '</a>';
      });
      thtml += '</div>';
      secTech.innerHTML = thtml;
      card.appendChild(secTech);
    }

    if (summary || raw) {
      var secExplain = document.createElement('div');
      secExplain.className = 'verdict-section';
      var explainText = summary || extractSummaryText(raw);
      secExplain.innerHTML =
        '<div class="section-title">AI Summary</div>' +
        '<div class="explain-text">' + esc(explainText.replace(/\*\*(.+?)\*\*/g, '$1')) + '</div>';
      card.appendChild(secExplain);
    }

    var secActions = document.createElement('div');
    secActions.className = 'verdict-section';
    secActions.innerHTML =
      '<div style="display:flex;gap:6px;flex-wrap:wrap">' +
        '<button class="explain-btn" data-ioc="' + escAttr(ioc) + '">Explain</button>' +
      '</div>';
    card.appendChild(secActions);

    var explainPanel = document.createElement('div');
    explainPanel.className = 'explain-panel';
    explainPanel.style.display = 'none';
    explainPanel.innerHTML = '<div class="explain-text explain-skeleton"></div>';
    card.appendChild(explainPanel);

    messages.appendChild(card);
    scrollBottom();
  }

  function generateFindings(sev, cat, ioc) {
    var findings = [];
    if (sev === 'CRITICAL') {
      findings.push('Known malicious indicator');
      findings.push('High confidence threat detection');
      findings.push('Immediate action recommended');
    } else if (sev === 'HIGH') {
      findings.push('Suspicious activity detected');
      findings.push('Corroborated by threat intelligence');
      findings.push('Review recommended');
    } else if (sev === 'MEDIUM') {
      findings.push('Potentially suspicious indicator');
      findings.push('Limited threat intelligence signals');
    } else if (sev === 'LOW' || sev === 'CLEAN') {
      findings.push('No known threats detected');
      findings.push('Indicator appears legitimate');
      findings.push('No blacklist hits');
    } else {
      findings.push('No threat intelligence data available');
      findings.push('Insufficient information for classification');
    }
    if (cat && cat !== 'Unknown' && cat !== 'Unclassified') {
      findings.push('Category: ' + cat);
    }
    return findings;
  }

  function extractSummaryText(raw) {
    if (!raw) return 'No analysis available.';
    var lines = raw.split('\n').filter(function (l) {
      return l.trim() && !l.match(/^\|\|\|/) && !l.match(/^```/);
    });
    return lines.slice(0, 3).join(' ').substring(0, 200);
  }

  function truncateText(s, max) {
    if (!s) return '';
    if (s.length <= max) return s;
    return s.substring(0, max).replace(/\s+\S*$/, '') + '...';
  }

  function showRawResponse(text) {
    var div = document.createElement('div');
    div.className = 'verdict-card';
    div.style.padding = '16px';
    div.innerHTML = '<div class="explain-text">' + esc(text || 'No analysis available.') + '</div>';
    messages.appendChild(div);
    scrollBottom();
  }

  function showError(text) {
    var div = document.createElement('div');
    div.className = 'verdict-card';
    div.style.padding = '16px';
    div.style.borderColor = 'rgba(239,68,68,0.3)';
    div.innerHTML = '<div class="explain-text" style="color:var(--danger)">' + esc(text) + '</div>';
    messages.appendChild(div);
    scrollBottom();
  }

  function showThinking() {
    var div = document.createElement('div');
    div.className = 'thinking-wrap';
    div.id = 'thinking-msg';
    div.innerHTML = '<div class="thinking-dots"><span></span><span></span><span></span></div>';
    messages.appendChild(div);
    scrollBottom();
  }

  function hideThinking() {
    var el = $('thinking-msg');
    if (el) el.remove();
  }

  function toggleExplain(btn) {
    var card = btn.closest('.verdict-card');
    if (!card) return;
    var panel = card.querySelector('.explain-panel');
    if (!panel) {
      panel = document.createElement('div');
      panel.style.display = 'none';
      panel.innerHTML = '<div class="explain-text explain-skeleton"></div>';
      card.appendChild(panel);
    }

    var open = panel.style.display === 'block';
    panel.style.display = open ? 'none' : 'block';

    if (!open && !panel.dataset.loaded) {
      panel.dataset.loaded = '1';
      var ioc = btn.dataset.ioc;
      btn.disabled = true;

      var controller = new AbortController();
      var timeout = setTimeout(function () { controller.abort(); }, 15000);

      fetch(API + '/api/explain', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ioc: ioc }),
        signal: controller.signal
      })
        .then(function (r) {
          clearTimeout(timeout);
          if (!r.ok) throw new Error('Error ' + r.status);
          return r.json();
        })
        .then(function (data) {
          btn.disabled = false;
          renderExplain(panel, data);
        })
        .catch(function (err) {
          clearTimeout(timeout);
          btn.disabled = false;
          panel.innerHTML = '<div class="explain-text" style="color:var(--danger)">' + esc(err.message) + '</div>';
        });
    }
  }

  function renderExplain(panel, data) {
    var text = data.explanation || data.text || 'No explanation available.';
    panel.innerHTML = '<div class="explain-text">' + esc(text) + '</div>';
  }

  function checkHealth() {
    var controller = new AbortController();
    var timeout = setTimeout(function () { controller.abort(); }, 3000);
    fetch(API + '/health', { signal: controller.signal })
      .then(function (r) {
        clearTimeout(timeout);
        if (!r.ok) throw new Error('Status ' + r.status);
        return r.json();
      })
      .then(function (h) {
        var ok = h.status === 'healthy';
        if (searchBtn.disabled && !searchInput.value.trim()) {
          searchBtn.disabled = false;
        }
      })
      .catch(function () {
        clearTimeout(timeout);
      });
  }

  function toast(msg, type) {
    var container = $('toast-container');
    var el = document.createElement('div');
    el.className = 'toast toast-' + (type || 'info');
    el.textContent = msg;
    container.appendChild(el);
    setTimeout(function () {
      if (el.parentNode) el.remove();
    }, 3000);
  }

  function sendBg(msg, cb) {
    try {
      chrome.runtime.sendMessage(msg).then(function (resp) {
        if (cb) cb(resp || {});
      }).catch(function () {
        if (cb) cb(null);
      });
    } catch (e) { if (cb) cb(null); }
  }

  function addLiveDetection(evt) {
    var container = $('live-feed-container');
    var list = $('live-list');
    if (!container || !list) return;
    if (container.style.display === 'none' || container.style.display === '') {
      container.style.display = 'block';
    }

    var item = document.createElement('div');
    item.className = 'live-item';
    var dotColor = '#22C55E';
    if (evt.severity === 'CRITICAL' || evt.severity === 'HIGH') dotColor = '#EF4444';
    else if (evt.severity === 'MEDIUM') dotColor = '#F59E0B';
    item.innerHTML =
      '<span class="live-dot" style="background:' + dotColor + '"></span>' +
      '<span class="live-ioc">' + esc(evt.ioc || '') + '</span>' +
      '<span class="live-type">' + esc(evt.type || '') + '</span>';
    item.addEventListener('click', function () {
      searchInput.value = evt.ioc || '';
      searchBtn.disabled = false;
      send();
    });

    list.insertBefore(item, list.firstChild);

    var count = $('live-count');
    if (count) count.textContent = list.children.length;

    while (list.children.length > 30) {
      list.removeChild(list.lastChild);
    }
  }

  function fetchLiveBuffer() {
    sendBg({ type: 'get-live-feed' }, function (resp) {
      if (!resp || !resp.events) return;
      resp.events.slice().reverse().forEach(function (evt) {
        addLiveDetection(evt);
      });
    });
  }

  function scrollBottom() {
    requestAnimationFrame(function () {
      messages.scrollTop = messages.scrollHeight;
    });
  }

  function extractJson(text, prefix) {
    var re = new RegExp('\\|\\|\\|' + prefix + ':(\\{.*?\\})\\|\\|\\|');
    var m = text.match(re);
    if (m) { try { return JSON.parse(m[1]); } catch (e) {} }
    return null;
  }

  function copyText(text, btn) {
    try {
      navigator.clipboard.writeText(text);
      btn.classList.add('copied');
      btn.innerHTML =
        '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>' +
        'Copied!';
      setTimeout(function () {
        btn.classList.remove('copied');
        btn.innerHTML =
          '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>' +
          'Copy';
      }, 2000);
    } catch (e) {
      toast('Copy failed', 'error');
    }
  }

  function esc(s) {
    if (s == null) return '';
    return String(s).replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  function escAttr(s) {
    if (s == null) return '';
    return String(s).replace(/"/g, '&quot;');
  }
})();
