(function () {
  var st = document.getElementById('status');

  document.getElementById('openSidebar').addEventListener('click', function () {
    chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
      if (tabs && tabs[0]) {
        try { chrome.sidePanel.open({ tabId: tabs[0].id }); } catch (e) {
          chrome.tabs.create({ url: 'sidebar.html' });
        }
      }
      window.close();
    });
  });

  document.getElementById('openSettings').addEventListener('click', function () {
    chrome.runtime.openOptionsPage();
    window.close();
  });

  chrome.storage.sync.get({ apiBase: 'http://localhost:8000' }, function (items) {
    var c = new AbortController();
    var t = setTimeout(function () { c.abort(); }, 3000);
    fetch(items.apiBase + '/health', { signal: c.signal })
      .then(function (r) { return r.json(); })
      .then(function (h) {
        clearTimeout(t);
        st.textContent = h.status === 'healthy' ? 'API Online' : 'API Degraded';
        st.style.color = h.status === 'healthy' ? '#166534' : '#b45309';
      })
      .catch(function () {
        clearTimeout(t);
        st.textContent = 'API Offline';
        st.style.color = '#b91c2a';
      });
  });
})();
