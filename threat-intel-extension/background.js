const IOC_RE = {
  ipv4: /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g,
  sha256: /\b[A-Fa-f0-9]{64}\b/g,
  md5: /\b[A-Fa-f0-9]{32}\b/g,
  sha1: /\b[A-Fa-f0-9]{40}\b/g,
  domain: /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|ru|cn|de|uk|xyz|top|info|biz|co|ai|app|gov|edu|mil|tv|cc|me|us|ca|fr|jp|br|au|in|nl|se|no|fi|dk|pl|cz|ch|at|be|es|pt|it|gr|tr|il|sa|ae|za|ng|ke|gh|tz|ug|rw|et|eg|ma|dz|sn|ci|cm|cd|ao|mz|zm|zw|bw|ls|sz|na|mg|mu|sc|km|cv|st|gw|gn|sl|lr|gm|ne|bf|ml|mr|td|sd|ss|so|dj|er|cf|cg|ga|gq|bi)\b/i,
  combined: new RegExp(
    '(' + /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g.source + ')|(' + /\b[A-Fa-f0-9]{64}\b/g.source + ')|(' + /\b[A-Fa-f0-9]{32}\b/g.source + ')|(' + /\b[A-Fa-f0-9]{40}\b/g.source + ')|(' + /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|ru|cn|de|uk|xyz|top|info|biz|co|ai|app|gov|edu|mil|tv|cc|me|us|ca|fr|jp|br|au|in|nl|se|no|fi|dk|pl|cz|ch|at|be|es|pt|it|gr|tr|il|sa|ae|za)\b/i.source + ')', 'g'
  )
};

let apiBase = 'http://localhost:8000';
const invCache = new Map();
const blocklist = new Set();
const rtBuffer = [];
const rtStats = { totalDetections: 0, severityCounts: {}, typeCounts: {}, topIocs: [] };
const seenIocs = new Set();
let sidebarPorts = [];
let alertCount = 0;

// AbortSignal.timeout polyfill for older Chrome (< 110)
if (!AbortSignal.timeout) {
  AbortSignal.timeout = function (ms) {
    var ctrl = new AbortController();
    setTimeout(function () { ctrl.abort(); }, ms);
    return ctrl.signal;
  };
}

chrome.storage.sync.get({ apiBase: apiBase }, function (items) {
  apiBase = items.apiBase;
  refreshBlocklist();
});

chrome.runtime.onInstalled.addListener(function () {
  createContextMenus();
});

chrome.runtime.onStartup.addListener(function () {
  refreshBlocklist();
});

chrome.action.onClicked.addListener(function (tab) {
  try {
    chrome.sidePanel.open({ tabId: tab.id });
  } catch (e) {
    chrome.tabs.create({ url: chrome.runtime.getURL('sidebar.html') });
  }
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
          try { chrome.sidePanel.open({ tabId: tabs[0].id }); } catch (e) {}
          investigate(text, tabs[0].id, function (result) {
            if (result && result.verdict) {
              broadcastToSidebar({ type: 'page-investigation', ioc: text, result: result }, tabs[0].id);
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
    case 'mark-malicious':
      if (sender.tab) markTabMalicious(sender.tab.id, msg.severity || 'HIGH');
      respond({ ok: true });
      break;
    case 'clear-badge':
      if (sender.tab) clearBadge(sender.tab.id);
      respond({ ok: true });
      break;
    case 'settings-updated':
      if (msg.apiBase) { apiBase = msg.apiBase; refreshBlocklist(); }
      respond({ ok: true });
      break;
    case 'ping':
      respond({ ok: true, apiBase: apiBase });
      break;
    case 'ioc-detected':
      recordDetection(msg.ioc, msg.typeLabel || msg.iocType, msg.severity);
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
}

function pollAlerts() {
  fetch(apiBase + '/api/alerts?limit=5', { signal: AbortSignal.timeout(5000) })
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

  fetch(apiBase + '/api/chat', {
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
  fetch(apiBase + '/api/blocklist', {
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
  fetch(apiBase + '/api/blocklist', { signal: AbortSignal.timeout(10000) })
    .then(function (r) { return r.json(); })
    .then(function (data) {
      blocklist.clear();
      if (data.iocs && Array.isArray(data.iocs)) {
        data.iocs.forEach(function (item) {
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
  var vm = text.match(/\|\|\|VERDICT:(\{.*?\})\|\|\|/);
  if (vm) { try { result.verdict = JSON.parse(vm[1]); } catch (e) {} }
  var cm = text.match(/\|\|\|CAMPAIGN:(\{.*?\})\|\|\|/);
  if (cm) { try { result.campaign = JSON.parse(cm[1]); } catch (e) {} }
  return result;
}

function isValidIoc(str) {
  if (!str || typeof str !== 'string') return false;
  var s = str.trim();
  if (!s || s.length < 4 || s.length > 255) return false;
  // Use individual patterns for reliable full-match validation
  IOC_RE.ipv4.lastIndex = 0;
  if (IOC_RE.ipv4.exec(s) && s === RegExp.lastMatch) return true;
  IOC_RE.sha256.lastIndex = 0;
  if (IOC_RE.sha256.exec(s) && s === RegExp.lastMatch) return true;
  IOC_RE.md5.lastIndex = 0;
  if (IOC_RE.md5.exec(s) && s === RegExp.lastMatch) return true;
  IOC_RE.sha1.lastIndex = 0;
  if (IOC_RE.sha1.exec(s) && s === RegExp.lastMatch) return true;
  IOC_RE.domain.lastIndex = 0;
  if (IOC_RE.domain.exec(s) && s === RegExp.lastMatch) return true;
  return false;
}
