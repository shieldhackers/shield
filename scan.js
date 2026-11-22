/* Shield website scanner page (simple version): no server needed.
   Type a site, tick the box, and get one-click links to free scanning services. */
(function () {
  var out = document.getElementById('scan-results');
  var btn = document.getElementById('remote-btn');
  var input = document.getElementById('remote-url');
  if (!out || !btn || !input) return;

  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined) e.textContent = text;
    return e;
  }

  function cleanDomain(value) {
    var d = value.trim().replace(/^[a-z]+:\/\//i, '').split(/[\/?#]/)[0].toLowerCase();
    return /^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$/.test(d) ? d : null;
  }

  function scan() {
    out.textContent = '';
    if (!input.value.trim()) { out.textContent = 'Enter a website address first.'; return; }
    if (!document.getElementById('remote-consent').checked) { out.textContent = 'Tick the box to confirm you own this site or have permission to test it.'; return; }
    var host = cleanDomain(input.value);
    if (!host) { out.textContent = 'That does not look like a valid website. Try example.com'; return; }
    var e = encodeURIComponent(host);

    var services = [
      ['Security Headers', 'Grades the site A to F on its security headers.', 'https://securityheaders.com/?q=' + e + '&followRedirects=on'],
      ['Mozilla Observatory', 'Checks headers, cookies and other best practices.', 'https://developer.mozilla.org/en-US/observatory/analyze?host=' + e],
      ['SSL Labs', 'Tests the HTTPS certificate and encryption setup.', 'https://www.ssllabs.com/ssltest/analyze.html?d=' + e],
      ['Google Safe Browsing', 'Shows whether Google lists the site as unsafe.', 'https://transparencyreport.google.com/safe-browsing/search?url=' + e],
      ['VirusTotal', 'Checks the site against many security vendors.', 'https://www.virustotal.com/gui/search/' + e]
    ];

    out.appendChild(el('h2', '', 'Scan ' + host));
    out.appendChild(el('p', 'scan-note', 'Click a button to open that service with ' + host + ' already filled in. Results appear on their site.'));
    var ul = el('ul', 'scan-list');
    services.forEach(function (s) {
      var li = el('li', 'finding');
      li.appendChild(el('strong', '', s[0]));
      li.appendChild(el('div', '', s[1]));
      var a = el('a', '', 'Open ' + s[0]);
      a.href = s[2]; a.target = '_blank'; a.rel = 'noopener noreferrer';
      li.appendChild(a);
      ul.appendChild(li);
    });
    out.appendChild(ul);
    out.appendChild(el('p', 'scan-note', 'Scan only sites you own or have permission to test. A good grade does not prove a site is secure.'));
  }

  btn.addEventListener('click', scan);
  input.addEventListener('keydown', function (ev) { if (ev.key === 'Enter') scan(); });
})();
