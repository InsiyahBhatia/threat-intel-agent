const IOC_RE = {
  ipv4: /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g,
  sha256: /\b[A-Fa-f0-9]{64}\b/g,
  md5: /\b[A-Fa-f0-9]{32}\b/g,
  sha1: /\b[A-Fa-f0-9]{40}\b/g,
  domain: /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|ru|cn|de|uk|xyz|top|info|biz|co|ai|app|gov|edu|mil|tv|cc|me|us|ca|fr|jp|br|au|in|nl|se|no|fi|dk|pl|cz|ch|at|be|es|pt|it|gr|tr|il|sa|ae|za|ng|ke|gh|tz|ug|rw|et|eg|ma|dz|sn|ci|cm|cd|ao|mz|zm|zw|bw|ls|sz|na|mg|mu|sc|km|cv|st|gw|gn|sl|lr|gm|ne|bf|ml|mr|td|sd|ss|so|dj|er|cf|cg|ga|gq|bi)\b/i
};

let apiBase = 'http://localhost:8000';
let apiBaseNormalized = apiBase;
let apiKey = '';
const invCache = new Map();

function normalizeApiBase(url) {
  return url.replace(/\/+$/, '');
}

function apiFetch(path, options) {
  options = options || {};
  options.headers = options.headers || {};
  if (apiKey) {
    options.headers['Authorization'] = 'Bearer ' + apiKey;
  }
  return fetch(apiBaseNormalized + path, options);
}

chrome.storage.sync.get({ apiBase: apiBase, apiKey: '' }, function (items) {
  apiBase = items.apiBase;
  apiKey = items.apiKey || '';
  apiBaseNormalized = normalizeApiBase(apiBase);
  refreshBlocklist();
});
const blocklist = new Set();
const rtBuffer = [];
const rtStats = { totalDetections: 0, severityCounts: {}, typeCounts: {}, topIocs: [] };
const seenIocs = new Set();
let sidebarPorts = [];
let pendingResults = [];
let alertCount = 0;

// AbortSignal.timeout polyfill for older Chrome (< 110)
if (!AbortSignal.timeout) {
  AbortSignal.timeout = function (ms) {
    var ctrl = new AbortController();
    setTimeout(function () { ctrl.abort(); }, ms);
    return ctrl.signal;
  };
}

chrome.runtime.onInstalled.addListener(function () {
  createContextMenus();
});

chrome.runtime.onStartup.addListener(function () {
  refreshBlocklist();
});

chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: true }).catch(function () {});

chrome.alarms.create('health', { periodInMinutes: 5 });
chrome.alarms.create('poll-alerts', { periodInMinutes: 1 });
chrome.alarms.onAlarm.addListener(function (alarm) {
  if (alarm.name === 'health') refreshBlocklist();
  if (alarm.name === 'poll-alerts') pollAlerts();
});

// Keyboard command handler
chrome.commands.onCommand.addListener(function (cmd) {
  if (cmd === 'investigate-selection') {
    chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
      if (tabs && tabs[0]) {
        // ask content script for selected text
        chrome.tabs.sendMessage(tabs[0].id, { type: 'get-selection' }, function (resp) {
          if (chrome.runtime.lastError || !resp || !resp.text) {
            // fallback: open sidebar
            try { chrome.sidePanel.open({ tabId: tabs[0].id }); } catch (e) {}
            return;
          }
          var text = resp.text.trim().split(/\s+/)[0];
          if (!isValidIoc(text)) {
            try { chrome.sidePanel.open({ tabId: tabs[0].id }); } catch (e) {}
            return;
          }
          // open sidebar and start investigation
          var tabId = tabs[0].id;
          try { chrome.sidePanel.open({ tabId: tabId }); } catch (e) {}
          investigate(text, tabId, function (result) {
            if (result && result.verdict) {
              // queue result so it can be delivered when sidebar connects
              pendingResults.push({ ioc: text, result: result, tabId: tabId });
              broadcastToSidebar({ type: 'page-investigation', ioc: text, result: result }, tabId);
            }
          });
        });
      }
    });
  } else if (cmd === 'scan-page') {
    chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
      if (tabs && tabs[0]) {
        chrome.tabs.sendMessage(tabs[0].id, { type: 'scan-page' }, function () {
          if (chrome.runtime.lastError) { /* tab may not have content script */ }
        });
      }
    });
  }
});

chrome.contextMenus.onClicked.addListener(function (info, tab) {
  if (!info.selectionText || !tab) return;
  var text = info.selectionText.trim().split(/\s+/)[0];
  if (!isValidIoc(text)) return;
  if (info.menuItemId === 'block-ioc') {
    blockIoc(text, function () {});
  } else {
    investigate(text, tab.id, function () {});
  }
});

chrome.tabs.onUpdated.addListener(function (tabId, changeInfo) {
  if (changeInfo.status === 'loading') clearBadge(tabId);
});

chrome.runtime.onMessage.addListener(function (msg, sender, respond) {
  switch (msg.type) {
    case 'open-sidebar-investigate':
      try {
        if (sender.tab) chrome.sidePanel.open({ tabId: sender.tab.id });
      } catch (e) {}
      investigate(msg.ioc, sender.tab ? sender.tab.id : null, function (result) {
        if (result && result.verdict) broadcastToSidebar({ type: 'page-investigation', ioc: msg.ioc, result: result }, sender.tab ? sender.tab.id : undefined);
        respond(result);
      });
      return true;
    case 'investigate-ioc':
      investigate(msg.ioc, sender.tab ? sender.tab.id : null, respond);
      return true;
    case 'investigation-result':
      if (sender.tab) {
        try {
          chrome.tabs.sendMessage(sender.tab.id, msg, function () {
            if (chrome.runtime.lastError) { /* tab may have navigated away */ }
          });
        } catch (e) {}

      }
      respond({ ok: true });
      break;
    case 'block-ioc':
      blockIoc(msg.ioc, respond);
      break;
    case 'check-blocklist':
      respond({ blocked: msg.ioc ? blocklist.has(msg.ioc.toLowerCase()) : false });
      break;
    case 'get-cache':
      var key = msg.ioc ? msg.ioc.toLowerCase() : '';
      respond({ cached: invCache.has(key), result: invCache.get(key) || null });
      break;
    case 'open-sidebar':
      chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
        if (tabs[0]) {
          try { chrome.sidePanel.open({ tabId: tabs[0].id }); } catch (e) {}
        }
      });
      respond({ ok: true });
      break;
    case 'mark-malicious':
      if (sender.tab) markTabMalicious(sender.tab.id, msg.severity || 'HIGH');
      respond({ ok: true });
      break;
    case 'clear-badge':
      if (sender.tab) clearBadge(sender.tab.id);
      respond({ ok: true });
      break;
    case 'settings-updated':
      if (msg.apiBase) { apiBase = msg.apiBase; apiBaseNormalized = normalizeApiBase(apiBase); }
      if (msg.apiKey !== undefined) { apiKey = msg.apiKey || ''; }
      refreshBlocklist();
      respond({ ok: true });
      break;
    case 'ping':
      respond({ ok: true, apiBase: apiBaseNormalized });
      break;
    case 'ioc-detected':
      recordDetection(msg.ioc, msg.typeLabel || msg.iocType, msg.severity);
      respond({ ok: true });
      break;
    case 'ioc-batch-detected':
      if (msg.batch && Array.isArray(msg.batch)) {
        msg.batch.forEach(function (item) {
          recordDetection(item.ioc, item.typeLabel || item.iocType, null);
        });
      }
      respond({ ok: true });
      break;
    case 'get-live-feed':
      respond({ events: rtBuffer.slice(-30), stats: rtStats, alertCount: alertCount });
      break;
    case 'sidebar-connect':
      respond({ ok: true });
      break;
    case 'get-rt-stats':
      respond(rtStats);
      break;
    default:
      respond({});
  }
  return true;
});

chrome.runtime.onConnect.addListener(function (port) {
  if (port.name === 'sidebar') {
    sidebarPorts.push(port);
    port.onMessage.addListener(function (msg) {
      if (msg.type === 'tab-id') {
        port._tabId = msg.tabId;
        // drain any pending investigation results for this tab
        if (pendingResults.length > 0) {
          var drained = pendingResults.splice(0);
          drained.forEach(function (pr) {
            if (!pr.tabId || pr.tabId === msg.tabId) {
              try { port.postMessage({ type: 'page-investigation', ioc: pr.ioc, result: pr.result }); } catch (e) {}
            }
          });
        }
      }
    });
    port.onDisconnect.addListener(function () {
      sidebarPorts = sidebarPorts.filter(function (p) { return p !== port; });
    });
  }
});

function broadcastToSidebar(msg, tabId) {
  sidebarPorts.forEach(function (p) {
    if (tabId && p._tabId && p._tabId !== tabId) return;
    try { p.postMessage(msg); } catch (e) {}
  });
}

function persistStats() {
  chrome.storage.local.set({ detectionCount: rtStats.totalDetections });
}

function recordDetection(ioc, type, severity) {
  var key = (ioc || '').toLowerCase().trim();
  if (seenIocs.has(key)) return;
  // FIFO cap to prevent memory leaks (avoids nuking entire set)
  if (seenIocs.size >= 10000) {
    var first = seenIocs.values().next().value;
    if (first) seenIocs.delete(first);
  }
  seenIocs.add(key);

  rtStats.totalDetections++;
  var sev = (severity || 'unknown').toUpperCase();
  rtStats.severityCounts[sev] = (rtStats.severityCounts[sev] || 0) + 1;
  var t = type || 'unknown';
  rtStats.typeCounts[t] = (rtStats.typeCounts[t] || 0) + 1;

  rtStats.topIocs.unshift({ ioc: ioc, type: t, severity: sev, time: Date.now() });
  if (rtStats.topIocs.length > 50) rtStats.topIocs.length = 50;

  var evt = { ioc: ioc, type: t, severity: sev, time: Date.now(), source: 'page' };
  rtBuffer.push(evt);
  if (rtBuffer.length > 200) rtBuffer.splice(0, rtBuffer.length - 200);

  broadcastToSidebar({ type: 'new-detection', event: evt, stats: rtStats });
  persistStats();
}

function pollAlerts() {
  apiFetch('/api/alerts?limit=5', { signal: AbortSignal.timeout(5000) })
    .then(function (r) { return r.json(); })
    .then(function (data) {
      if (data.alerts && data.alerts.length > 0) {
        alertCount = data.stats ? data.stats.total : data.alerts.length;
        broadcastToSidebar({ type: 'alerts-update', alertCount: alertCount });
      }
    })
    .catch(function () {});
}

function createContextMenus() {
  try {
    chrome.contextMenus.removeAll(function () {
      chrome.contextMenus.create({
        id: 'investigate-ioc',
        title: 'Investigate with Threat Intel',
        contexts: ['selection']
      });
      chrome.contextMenus.create({
        id: 'block-ioc',
        title: 'Block this IOC',
        contexts: ['selection']
      });
    });
  } catch (e) {}
}

function investigate(ioc, tabId, callback) {
  if (!ioc || !ioc.trim()) { if (callback) callback({ error: 'No IOC provided' }); return; }
  if (!isValidIoc(ioc)) { if (callback) callback({ error: 'Not a valid IOC' }); return; }

  var key = ioc.toLowerCase().trim();
  if (invCache.has(key)) {
    var cached = invCache.get(key);
    // LRU: re-insert to move to end of Map
    invCache.delete(key);
    invCache.set(key, cached);
    if (tabId) sendVerdictToTab(tabId, ioc, cached);
    if (callback) callback(cached);
    return;
  }

  var controller = new AbortController();
  var timeout = setTimeout(function () { controller.abort(); }, 15000);

  apiFetch('/api/chat', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ message: key }),
    signal: controller.signal
  })
    .then(function (r) {
      clearTimeout(timeout);
      if (!r.ok) throw new Error('API error ' + r.status);
      return r.json();
    })
    .then(function (data) {
      var result = parseResponse(data.response || '');
      invCache.set(key, result);
      if (invCache.size > 500) {
        var first = invCache.keys().next().value;
        if (first) invCache.delete(first);
      }
      if (tabId) sendVerdictToTab(tabId, ioc, result);
      if (callback) callback(result);
    })
    .catch(function (err) {
      clearTimeout(timeout);
      if (callback) callback({ error: err.message || 'Request failed' });
    });
}

function sendVerdictToTab(tabId, ioc, result) {
  try {
    chrome.tabs.sendMessage(tabId, {
      type: 'investigation-result',
      ioc: ioc,
      verdict: result.verdict,
      campaign: result.campaign,
      summary: result.summary
    }, function () {
      if (chrome.runtime.lastError) {
        // suppress expected error when tab no longer has content script injected
      }
    });
  } catch (e) {}
}

function blockIoc(ioc, callback) {
  if (!ioc) { if (callback) callback({ error: 'No IOC provided' }); return; }
  apiFetch('/api/blocklist', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ iocs: [ioc.trim()] }),
    signal: AbortSignal.timeout(10000)
  })
    .then(function (r) {
      if (!r.ok) throw new Error('Blocklist API error ' + r.status);
      blocklist.add(ioc.trim().toLowerCase());
      notify('Blocklisted', ioc + ' added to blocklist');
      if (callback) callback({ ok: true });
    })
    .catch(function (err) {
      if (callback) callback({ error: err.message });
    });
}

function refreshBlocklist() {
  apiFetch('/api/blocklist', { signal: AbortSignal.timeout(10000) })
    .then(function (r) { return r.json(); })
    .then(function (data) {
      blocklist.clear();
      var items = data.blocklist || data.iocs;
      if (items && Array.isArray(items)) {
        items.forEach(function (item) {
          if (typeof item === 'string') blocklist.add(item.toLowerCase());
          else if (item.ioc) blocklist.add(item.ioc.toLowerCase());
        });
      }
    })
    .catch(function () {});
}

function markTabMalicious(tabId, severity) {
  if (!tabId) return;
  var color = '#FF4D4D';
  var text = '!';
  if (severity === 'CRITICAL') { color = '#b91c2a'; text = '!!!'; }
  else if (severity === 'HIGH') { color = '#b45309'; text = '!!'; }
  else { color = '#9ca3af'; text = '?'; }
  try {
    chrome.action.setBadgeBackgroundColor({ tabId: tabId, color: color });
    chrome.action.setBadgeText({ tabId: tabId, text: text });
    chrome.action.setTitle({ tabId: tabId, title: severity + ' severity detected on this page' });
  } catch (e) {}
}

function clearBadge(tabId) {
  if (!tabId) return;
  try { chrome.action.setBadgeText({ tabId: tabId, text: '' }); } catch (e) {}
}

function notify(title, message) {
  try {
    chrome.notifications.create({
      type: 'basic', iconUrl: 'icons/brand-icon.png',
      title: title, message: message, priority: 1
    });
  } catch (e) {}
}

function parseResponse(text) {
  var result = { summary: text || '', verdict: null, campaign: null };
  if (!text) return result;
  var vm = text.match(/\|\|\|VERDICT:(\{[\s\S]*?\})\|\|\|/);
  if (vm) { try { result.verdict = JSON.parse(vm[1]); } catch (e) {} }
  var cm = text.match(/\|\|\|CAMPAIGN:(\{[\s\S]*?\})\|\|\|/);
  if (cm) { try { result.campaign = JSON.parse(cm[1]); } catch (e) {} }
  return result;
}

function isValidIoc(str) {
  if (!str || typeof str !== 'string') return false;
  var s = str.trim();
  if (!s || s.length < 4 || s.length > 255) return false;
  function test(re) { re.lastIndex = 0; var m = re.exec(s); return m && m[0] === s; }
  return test(IOC_RE.ipv4) || test(IOC_RE.sha256) || test(IOC_RE.md5) || test(IOC_RE.sha1) || test(IOC_RE.domain);
}
