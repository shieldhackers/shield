/* Shield website scanner page: scans another site through the Shield scan service. */
(function () {
  var WORKER_URL = 'PASTE-YOUR-WORKER-URL-HERE';
  var out = document.getElementById('scan-results');
  var btn = document.getElementById('remote-btn');
  if (!out || !btn) return;

  var ORDER = { HIGH: 0, MEDIUM: 1, LOW: 2, INFO: 3 };
  var PENALTY = { HIGH: 25, MEDIUM: 10, LOW: 3, INFO: 0 };
  var HEADERS = [
    ['content-security-policy', 'MEDIUM', 'Helps block XSS and data injection.', "Send Content-Security-Policy: default-src 'self'."],
    ['strict-transport-security', 'MEDIUM', 'Forces browsers to use HTTPS.', 'Send Strict-Transport-Security: max-age=31536000.'],
    ['x-frame-options', 'MEDIUM', 'Protects against clickjacking.', 'Send X-Frame-Options: DENY.'],
    ['x-content-type-options', 'LOW', 'Stops MIME-type sniffing.', 'Send X-Content-Type-Options: nosniff.'],
    ['referrer-policy', 'LOW', 'Controls how much referrer data is leaked.', 'Send Referrer-Policy: strict-origin-when-cross-origin.'],
    ['permissions-policy', 'LOW', 'Restricts browser features like camera and location.', 'Send a Permissions-Policy header.']
  ];

  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined) e.textContent = text;
    return e;
  }

  function render(findings, passed, target) {
    findings.sort(function (a, b) { return ORDER[a.sev] - ORDER[b.sev]; });
    var counts = { HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 }, score = 100;
    findings.forEach(function (f) { counts[f.sev]++; score -= PENALTY[f.sev]; });
    score = Math.max(0, score);
    var grade = score >= 90 ? 'A' : score >= 80 ? 'B' : score >= 70 ? 'C' : score >= 60 ? 'D' : 'F';
    var verdict, cls;
    if (counts.HIGH) { verdict = 'NOT SAFE: serious issues found'; cls = 'bad'; }
    else if (score >= 90) { verdict = 'LOOKS GOOD: no major issues found'; cls = 'good'; }
    else if (score >= 70) { verdict = 'NEEDS IMPROVEMENT'; cls = 'warn'; }
    else { verdict = 'AT RISK: several weaknesses found'; cls = 'bad'; }

    out.textContent = '';
    var banner = el('div', 'verdict ' + cls);
    banner.appendChild(el('div', 'score', score + '/100 (' + grade + ')'));
    banner.appendChild(el('div', 'verdict-text', verdict));
    banner.appendChild(el('div', 'verdict-counts', 'HIGH: ' + counts.HIGH + '  MEDIUM: ' + counts.MEDIUM + '  LOW: ' + counts.LOW + '  INFO: ' + counts.INFO));
    out.appendChild(banner);
    out.appendChild(el('p', 'scan-note', 'Target: ' + target + ' (passive check of public headers, cookies and forms only)'));

    var ul = el('ul', 'scan-list');
    findings.forEach(function (f) {
      var li = el('li', 'finding sev-' + f.sev.toLowerCase());
      li.appendChild(el('strong', '', '[' + f.sev + '] ' + f.title));
      li.appendChild(el('div', '', f.detail));
      if (f.fix) li.appendChild(el('div', 'fix', 'Fix: ' + f.fix));
      ul.appendChild(li);
    });
    out.appendChild(ul);

    var det = el('details', 'passed');
    det.appendChild(el('summary', '', passed.length + ' check(s) passed'));
    var pl = el('ul', 'scan-list');
    passed.forEach(function (p) { pl.appendChild(el('li', '', 'OK: ' + p)); });
    det.appendChild(pl);
    out.appendChild(det);
    out.appendChild(el('p', 'scan-note', 'This scan checks only common issues. It cannot prove a site is secure.'));

    var dl = el('button', '', 'Download Report');
    dl.type = 'button';
    dl.addEventListener('click', function () {
      var lines = ['Shield scan report', target, new Date().toISOString(), 'Score: ' + score + '/100 (' + grade + ') - ' + verdict, ''];
      findings.forEach(function (f) { lines.push('[' + f.sev + '] ' + f.title + ' - ' + f.detail + (f.fix ? ' | Fix: ' + f.fix : '')); });
      lines.push('', 'Passed: ' + passed.join('; '));
      var a = document.createElement('a');
      a.href = URL.createObjectURL(new Blob([lines.join('\n')], { type: 'text/plain' }));
      a.download = 'shield-report.txt';
      document.body.appendChild(a); a.click(); a.remove();
    });
    out.appendChild(dl);
  }

  async function scan() {
    var target = document.getElementById('remote-url').value.trim();
    if (!target) { out.textContent = 'Enter a website address first.'; return; }
    if (!document.getElementById('remote-consent').checked) { out.textContent = 'Tick the box to confirm you own this site or have permission to test it.'; return; }
    if (WORKER_URL.indexOf('PASTE') === 0) { out.textContent = 'The scan service is not connected yet. Set WORKER_URL in scan.js.'; return; }
    if (!/^https?:\/\//i.test(target)) target = 'https://' + target;
    btn.disabled = true;
    out.textContent = 'Scanning ' + target + ' ...';
    try {
      var r = await fetch(WORKER_URL, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url: target }) });
      var d = await r.json();
      if (!r.ok) { out.textContent = 'Error: ' + (d.error || r.status); return; }
      var findings = [], passed = [];
      var add = function (sev, title, detail, fix) { findings.push({ sev: sev, title: title, detail: detail, fix: fix || '' }); };
      var https = d.finalUrl.indexOf('https:') === 0;
      if (https) passed.push('Site is served over HTTPS'); else add('HIGH', 'Site is not served over HTTPS', 'Traffic can be read or changed in transit.', 'Enable HTTPS on the host.');
      HEADERS.forEach(function (x) {
        var name = x[0], val = d.headers[name];
        if (name === 'strict-transport-security' && !https) return;
        if (!val) { add(x[1], 'Missing ' + name, x[2], x[3]); return; }
        if (name === 'content-security-policy' && /unsafe-inline|unsafe-eval/.test(val)) add('MEDIUM', 'CSP allows unsafe-inline or unsafe-eval', 'This weakens protection against XSS.', 'Remove unsafe directives and use nonces or hashes.');
        else passed.push(name + ' header present');
      });
      if (d.headers.server) add('INFO', 'Server header discloses technology', 'Server: ' + d.headers.server, 'Hide or genericize the Server header if possible.');
      if (d.headers['x-powered-by']) add('LOW', 'X-Powered-By discloses technology', 'X-Powered-By: ' + d.headers['x-powered-by'], 'Remove the X-Powered-By header.');
      d.cookies.forEach(function (c) {
        var name = c.split('=')[0], low = c.toLowerCase();
        if (https && low.indexOf('secure') === -1) add('MEDIUM', "Cookie '" + name + "' missing Secure flag", 'It can be sent over unencrypted connections.', 'Add the Secure attribute.');
        if (low.indexOf('httponly') === -1) add('MEDIUM', "Cookie '" + name + "' missing HttpOnly flag", 'JavaScript can read this cookie.', 'Add the HttpOnly attribute.');
        if (low.indexOf('samesite') === -1) add('LOW', "Cookie '" + name + "' missing SameSite attribute", 'Increases CSRF risk.', 'Add SameSite=Lax or Strict.');
      });
      d.forms.forEach(function (f, i) {
        var label = 'Form #' + (i + 1) + ' (' + f.method.toUpperCase() + ')';
        if (f.hasPassword && f.method === 'get') add('HIGH', label + ' sends a password via GET', 'Credentials would appear in URLs and logs.', 'Use method="post".');
        if (/^http:/i.test(f.action) && https) add('HIGH', label + ' submits over HTTP', 'Form data would be sent unencrypted.', 'Use an https:// action.');
        if (f.method === 'post' && !f.hasCsrf) add('MEDIUM', label + ' has no visible CSRF token', 'Cross-site requests could submit this form.', 'Add a per-session CSRF token checked on the server.');
      });
      d.extScriptsNoSri.forEach(function (u) { add('MEDIUM', 'External resource without integrity check', u, 'Add an integrity attribute (SRI) or self-host the file.'); });
      if (d.mixed) add('MEDIUM', 'Mixed content (' + d.mixed + ' HTTP resource(s) on an HTTPS page)', 'Insecure resources can be tampered with.', 'Load them over https://.');
      render(findings, passed, d.finalUrl);
    } catch (e) {
      out.textContent = 'Scan failed: ' + e.message;
    } finally {
      btn.disabled = false;
    }
  }

  btn.addEventListener('click', scan);
  document.getElementById('remote-url').addEventListener('keydown', function (ev) { if (ev.key === 'Enter') scan(); });
})();
