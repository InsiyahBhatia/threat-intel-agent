(function () {
  var apiBase = 'http://localhost:8000';
  var statusEl = document.getElementById('status');
  var pageIocCountEl = document.getElementById('pageIocCount');
  var totalDetectionsEl = document.getElementById('totalDetections');
  var quickIocInput = document.getElementById('quickIoc');
  var quickSearchBtn = document.getElementById('quickSearchBtn');

  chrome.storage.sync.get('apiBase', function (data) {
    if (data.apiBase) apiBase = data.apiBase;
    checkHealth();
  });

  function checkHealth() {
    var ctrl = new AbortController();
    var to = setTimeout(function () { ctrl.abort(); }, 3000);
    fetch(apiBase + '/health', { signal: ctrl.signal })
      .then(function (r) { return r.json(); })
      .then(function (d) {
        clearTimeout(to);
        statusEl.textContent = 'API: OK';
        statusEl.style.color = '#34D399';
      })
      .catch(function () {
        clearTimeout(to);
        statusEl.textContent = 'API: unreachable';
        statusEl.style.color = '#EF4444';
      });
  }

  // Query page IOC count from content script
  function queryPageIocCount() {
    chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
      if (!tabs[0] || !tabs[0].id) return;
      chrome.tabs.sendMessage(tabs[0].id, { type: 'get-iocs' }, function (resp) {
        if (chrome.runtime.lastError) return;
        if (resp && resp.count !== undefined) pageIocCountEl.textContent = resp.count;
      });
    });
  }

  // Query total detections from storage
  function queryTotalDetections() {
    chrome.storage.local.get('detectionCount', function (d) {
      totalDetectionsEl.textContent = d.detectionCount || 0;
    });
  }

  queryPageIocCount();
  queryTotalDetections();

  // Quick IOC search
  function isValidIoc(text) {
    var ipv4 = /^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$/;
    var sha256 = /^[A-Fa-f0-9]{64}$/;
    var md5 = /^[A-Fa-f0-9]{32}$/;
    var sha1 = /^[A-Fa-f0-9]{40}$/;
    var domain = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|ru|cn|de|uk|xyz|top|info|biz|co|ai|app|gov|edu|mil|tv|cc|me|us|ca|fr|jp|br|au|in|nl|se|no|fi|dk|pl|cz|ch|at|be|es|pt|it|gr|tr|il|sa|ae|za|ng|ke|gh|tz|ug|rw|et|eg|ma|dz|sn|ci|cm|cd|ao|mz|zm|zw|bw|ls|sz|na|mg|mu|sc|km|cv|st|gw|gn|sl|lr|gm|ne|bf|ml|mr|td|sd|ss|so|dj|er|cf|cg|ga|gq|bi)$/i;
    return ipv4.test(text) || sha256.test(text) || md5.test(text) || sha1.test(text) || domain.test(text);
  }

  function investigateIoc(text) {
    chrome.runtime.sendMessage({
      type: 'open-sidebar-investigate',
      ioc: text.trim()
    });
    window.close();
  }

  quickIocInput.addEventListener('input', function () {
    quickSearchBtn.disabled = !isValidIoc(quickIocInput.value.trim());
  });

  quickIocInput.addEventListener('keydown', function (e) {
    if (e.key === 'Enter' && !quickSearchBtn.disabled) {
      investigateIoc(quickIocInput.value);
    }
  });

  quickSearchBtn.addEventListener('click', function () {
    investigateIoc(quickIocInput.value);
  });

  // Clipboard investigation
  document.getElementById('investigateClipboard').addEventListener('click', function () {
    navigator.clipboard.readText().then(function (text) {
      text = text.trim();
      if (!text) return;
      var parts = text.split(/\s+/);
      var ioc = parts[0];
      if (!isValidIoc(ioc)) {
        statusEl.textContent = 'Clipboard: not a valid IOC';
        statusEl.style.color = '#FBBF24';
        return;
      }
      investigateIoc(ioc);
    }).catch(function () {
      statusEl.textContent = 'Clipboard: permission denied';
      statusEl.style.color = '#EF4444';
    });
  });

  document.getElementById('openSidebar').addEventListener('click', function () {
    chrome.runtime.sendMessage({ type: 'open-sidebar' });
    window.close();
  });

  document.getElementById('openSettings').addEventListener('click', function () {
    chrome.runtime.openOptionsPage();
    window.close();
  });
})();
