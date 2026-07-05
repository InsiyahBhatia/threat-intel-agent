(function () {
  if (document.documentElement.getAttribute('data-tia') === '1') return;
  document.documentElement.setAttribute('data-tia', '1');

  var tooltipTimer = null, tooltipEl = null, tooltipLeaveTimer = null, scanTimer = null;
  var tooltipTarget = null;
  var reportedIocs = new Set();
  var reportBatch = [];
  var MAX_SIGHTINGS = 5000;
  var reportTimer = null;
  var PATTERNS = [
    { name: 'ip', re: /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g },
    { name: 'sha256', re: /\b[A-Fa-f0-9]{64}\b/g },
    { name: 'md5', re: /\b[A-Fa-f0-9]{32}\b/g },
    { name: 'sha1', re: /\b[A-Fa-f0-9]{40}\b/g },
    { name: 'domain', re: /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|ru|cn|de|uk|xyz|top|info|biz|co|ai|app|gov|edu|mil|tv|cc|me|us|ca|fr|jp|br|au|in|nl|se|no|fi|dk|pl|cz|ch|at|be|es|pt|it|gr|tr|il|sa|ae|za|ng|ke|gh|tz|ug|rw|et|eg|ma|dz|sn|ci|cm|cd|ao|mz|zm|zw|bw|ls|sz|na|mg|mu|sc|km|cv|st|gw|gn|sl|lr|gm|ne|bf|ml|mr|td|sd|ss|so|dj|er|cf|cg|ga|gq|bi)\b/gi }
  ];
  var combinedRe = new RegExp(PATTERNS.map(function (p) { return '(' + p.re.source + ')'; }).join('|'), 'g');

  function init() {
    if (!document.body) {
      if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', function () { if (document.body) init(); });
      }
      return;
    }
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', scan);
    } else { scan(); }
    var obs = new MutationObserver(function (mutations) {
      if (scanTimer) clearTimeout(scanTimer);
      scanTimer = setTimeout(function () {
        var scanned = 0;
        var MAX_PER_CYCLE = 50;
        for (var i = 0; i < mutations.length && scanned < MAX_PER_CYCLE; i++) {
          var nodes = mutations[i].addedNodes;
          for (var j = 0; j < nodes.length && scanned < MAX_PER_CYCLE; j++) {
            if (nodes[j].nodeType === 1) { scanNode(nodes[j]); scanned++; }
          }
        }
        scanTimer = null;
      }, 250);
    });
    obs.observe(document.body, { childList: true, subtree: true });
  }

  function scan() { if (document.body) scanNode(document.body); }

  function scanNode(root) {
    if (!root || root.nodeType !== 1) return;
    var walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, null, false);
    var nodes = [], node;
    while ((node = walker.nextNode())) nodes.push(node);
    for (var i = 0; i < nodes.length; i++) processText(nodes[i]);
  }

  function processText(textNode) {
    if (!textNode.parentNode) return;
    var p = textNode.parentElement;
    if (!p || p.closest('.tia-ioc, script, style, svg, math, canvas, textarea, input, [data-tia-ignore]')) return;

    var text = textNode.textContent;
    if (!text || text.length < 4 || text.length > 10000) return;

    combinedRe.lastIndex = 0;
    var matches = [], match;
    while ((match = combinedRe.exec(text)) !== null) {
      for (var k = 0; k < PATTERNS.length; k++) {
        if (match[k + 1] !== undefined) {
          matches.push({ value: match[0], index: match.index, type: PATTERNS[k].name });
          break;
        }
      }
    }
    if (matches.length === 0) return;

    for (var m = 0; m < matches.length; m++) {
      var key = matches[m].value + '@' + matches[m].type;
      if (!reportedIocs.has(key)) {
        reportedIocs.add(key);
        // cap to prevent memory leaks on long-lived SPAs
        if (reportedIocs.size > MAX_SIGHTINGS) {
          var first = reportedIocs.values().next().value;
          if (first) reportedIocs.delete(first);
        }
        reportBatch.push({ ioc: matches[m].value, typeLabel: matches[m].type });
      }
    }
    flushReports();

    var frag = document.createDocumentFragment();
    var last = 0;
    for (var i = 0; i < matches.length; i++) {
      var m = matches[i];
      if (m.index < last) continue;
      if (m.index > last) frag.appendChild(document.createTextNode(text.slice(last, m.index)));
      frag.appendChild(createSpan(m.value, m.type));
      last = m.index + m.value.length;
    }
    if (last < text.length) frag.appendChild(document.createTextNode(text.slice(last)));
    try { textNode.parentNode.replaceChild(frag, textNode); } catch (e) {}
  }

  function createSpan(value, type) {
    var span = document.createElement('span');
    span.className = 'tia-ioc';
    span.textContent = value;
    span.setAttribute('data-ioc', value);
    span.setAttribute('data-type', type);

    span.addEventListener('mouseenter', function (e) {
      if (tooltipTimer) clearTimeout(tooltipTimer);
      if (tooltipLeaveTimer) clearTimeout(tooltipLeaveTimer);
      var cx = e.clientX, cy = e.clientY;
      if (tooltipEl) {
        positionTooltipAt(cx, cy);
      } else {
        tooltipTimer = setTimeout(function () { showTooltip(span, cx, cy); }, 100);
      }
    });
    span.addEventListener('mouseleave', function () {
      if (tooltipTimer) { clearTimeout(tooltipTimer); tooltipTimer = null; }
      tooltipLeaveTimer = setTimeout(function () {
        if (tooltipEl) { tooltipEl.remove(); tooltipEl = null; }
      }, 350);
    });
    span.addEventListener('click', function () { investigate(span); });

    return span;
  }

  function showTooltip(el, mx, my) {
    if (tooltipEl) tooltipEl.remove();
    tooltipEl = document.createElement('div');
    tooltipEl.className = 'tia-tp';
    tooltipTarget = el;

    var typeEl = document.createElement('span');
    typeEl.className = 'tia-tp-type';
    typeEl.textContent = (el.getAttribute('data-type') || '').toUpperCase();
    tooltipEl.appendChild(typeEl);

    var ioc = document.createElement('span');
    ioc.className = 'tia-tp-ioc';
    ioc.textContent = el.getAttribute('data-ioc') || '';
    tooltipEl.appendChild(ioc);

    var acts = document.createElement('div');
    acts.className = 'tia-tp-acts';

    var invBtn = document.createElement('button');
    invBtn.className = 'tia-tp-btn tia-tp-inv';
    invBtn.textContent = 'Investigate';
    invBtn.addEventListener('click', function (e) {
      e.stopPropagation(); investigate(el); hideTooltip();
    });
    acts.appendChild(invBtn);

    var blkBtn = document.createElement('button');
    blkBtn.className = 'tia-tp-btn tia-tp-blk';
    blkBtn.textContent = 'Block';
    blkBtn.addEventListener('click', function (e) {
      e.stopPropagation();
      sendBg({ type: 'block-ioc', ioc: el.getAttribute('data-ioc') });
      hideTooltip();
    });
    acts.appendChild(blkBtn);
    tooltipEl.appendChild(acts);

    var ft = document.createElement('div');
    ft.className = 'tia-tp-ft';
    ft.textContent = 'Click to investigate';
    tooltipEl.appendChild(ft);

    positionTooltipAt(mx, my);
    if (document.body) document.body.appendChild(tooltipEl);

    tooltipEl.addEventListener('mouseenter', function () {
      if (tooltipLeaveTimer) clearTimeout(tooltipLeaveTimer);
    });
    tooltipEl.addEventListener('mouseleave', function () {
      tooltipLeaveTimer = setTimeout(function () {
        if (tooltipEl) { tooltipEl.remove(); tooltipEl = null; }
      }, 250);
    });
  }

  function positionTooltipAt(mx, my) {
    var left = mx + 10, top = my + 10;
    if (left + 220 > window.innerWidth) left = mx - 220 - 10;
    if (left < 4) left = 4;
    if (top + 110 > window.innerHeight) top = my - 110 - 10;
    if (top < 4) top = 4;
    tooltipEl.style.left = left + 'px';
    tooltipEl.style.top = top + 'px';
  }

  function hideTooltip() {
    if (tooltipEl) { tooltipEl.remove(); tooltipEl = null; }
    if (tooltipTimer) { clearTimeout(tooltipTimer); tooltipTimer = null; }
    tooltipTarget = null;
  }

  function investigate(el) {
    if (!el) return;
    var ioc = el.getAttribute('data-ioc');
    el.classList.add('tia-loading');
    el.classList.remove('tia-done');

    sendBg({ type: 'open-sidebar-investigate', ioc: ioc }, function (resp) {
      el.classList.remove('tia-loading');
      if (resp && resp.verdict) {
        applyVerdict(el, resp.verdict);
      } else if (resp && resp.error) {
        el.classList.add('tia-err');
      } else {
        el.classList.add('tia-err');
      }
    });
  }

  function applyVerdict(el, verdict) {
    var sev = (verdict.severity || 'UNKNOWN').toUpperCase();
    el.classList.add('tia-done');
    el.setAttribute('data-severity', sev);
    el.title = sev + ' | ' + (verdict.threat_category || '') + ' | ' + (verdict.confidence || '') + '%';

    var existing = el.querySelector('.tia-badge');
    if (existing) existing.remove();

    var badge = document.createElement('span');
    badge.className = 'tia-badge tia-badge-' + sev.toLowerCase();
    badge.textContent = sev;
    el.appendChild(badge);

    if (sev === 'CRITICAL' || sev === 'HIGH') {
      sendBg({ type: 'mark-malicious', severity: sev });
    }
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

  chrome.runtime.onMessage.addListener(function (msg, sender, respond) {
    switch (msg.type) {
      case 'scan-page':
        scan();
        // flash all highlighted IOCs to show scan completed
        var iocs = document.querySelectorAll('.tia-ioc');
        iocs.forEach(function (el, i) {
          setTimeout(function () { el.classList.add('tia-kb-scan'); }, i * 20);
          setTimeout(function () { el.classList.remove('tia-kb-scan'); }, i * 20 + 1200);
        });
        respond({ ok: true, count: iocs.length });
        break;
      case 'get-iocs': respond({ count: document.querySelectorAll('.tia-ioc').length }); break;
      case 'get-selection':
        respond({ text: window.getSelection ? window.getSelection().toString() : '' });
        break;
      case 'investigation-result':
        if (msg.ioc) {
          var els = document.querySelectorAll('[data-ioc="' + escapeCSS(msg.ioc) + '"]');
          for (var i = 0; i < els.length; i++) {
            if (msg.verdict) applyVerdict(els[i], msg.verdict);
          }
        }
        respond({ ok: true });
        break;
      default: respond({});
    }
    return true;
  });

  window.addEventListener('scroll', function () {
    if (tooltipTarget) hideTooltip();
  }, { passive: true });
  init();

  function flushReports() {
    if (reportBatch.length === 0) return;
    var batch = reportBatch.splice(0); // clear the batch
    try {
      // send each IOC individually since the background listener expects single items
      batch.forEach(function (item) {
        chrome.runtime.sendMessage({ type: 'ioc-detected', ioc: item.ioc, typeLabel: item.typeLabel, severity: null }).catch(function () {});
      });
    } catch (e) {}
  }

  function escapeCSS(str) { return str ? String(str).replace(/"/g, '\\"') : ''; }
  function esc(s) { return s == null ? '' : String(s).replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;'); }
})();
