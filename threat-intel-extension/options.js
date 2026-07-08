(function () {
  var apiUrl = document.getElementById('apiUrl');
  var apiKey = document.getElementById('apiKey');
  var autoScan = document.getElementById('autoScan');
  var saveBtn = document.getElementById('saveBtn');
  var testBtn = document.getElementById('testBtn');
  var stat = document.getElementById('stat');

  chrome.storage.sync.get({ apiBase: 'http://localhost:8000', apiKey: '', autoScan: true }, function (items) {
    apiUrl.value = items.apiBase; apiKey.value = items.apiKey || ''; autoScan.checked = items.autoScan;
  });

  saveBtn.addEventListener('click', save);
  testBtn.addEventListener('click', testConn);
  apiUrl.addEventListener('keydown', function (e) { if (e.key === 'Enter') save(); });

  function save() {
    var url = apiUrl.value.trim();
    var key = apiKey.value.trim();
    if (!url) { showStat('URL required', 'err'); return; }
    if (!url.startsWith('http://') && !url.startsWith('https://')) { showStat('Must start with http:// or https://', 'err'); return; }
    var clean = url.replace(/\/+$/, '');
    chrome.storage.sync.set({ apiBase: clean, apiKey: key, autoScan: autoScan.checked }, function () {
      if (chrome.runtime.lastError) { showStat('Save failed', 'err'); return; }
      showStat('Saved', 'suc');
      try {
        chrome.runtime.sendMessage({ type: 'settings-updated', apiBase: clean, apiKey: key }, function () {
          if (chrome.runtime.lastError) { /* background may have restarted */ }
        });
      } catch (e) {}
    });
  }

  function testConn() {
    var url = apiUrl.value.trim().replace(/\/+$/, '');
    var key = apiKey.value.trim();
    if (!url) { showStat('Enter a URL', 'err'); return; }
    showStat('Testing...', 'info');
    var c = new AbortController();
    var t = setTimeout(function () { c.abort(); }, 5000);
    var headers = { 'Accept': 'application/json' };
    if (key) { headers['Authorization'] = 'Bearer ' + key; }
    fetch(url + '/health', { signal: c.signal, headers: headers }).then(function (r) {
      clearTimeout(t);
      if (!r.ok) throw new Error('Status ' + r.status);
      return r.json();
    }).then(function (h) {
      showStat(h.status === 'healthy' ? 'Connected' : 'Degraded (' + h.status + ')', h.status === 'healthy' ? 'suc' : 'info');
    }).catch(function (err) {
      clearTimeout(t);
      showStat(err.name === 'AbortError' ? 'Timed out' : 'Failed: ' + err.message, 'err');
    });
  }

  function showStat(msg, type) {
    stat.textContent = msg; stat.className = 'stat ' + (type || '');
    clearTimeout(stat._t); stat._t = setTimeout(function () { stat.textContent = ''; stat.className = 'stat'; }, 4000);
  }
})();
