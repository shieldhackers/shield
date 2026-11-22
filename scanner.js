/* Shield in-browser scanner: checks THIS site only (browsers block cross-site scanning). */
(function () {
  var btn = document.getElementById('scan-btn');
  var out = document.getElementById('scan-results');
  if (!btn || !out) return;

  var ORDER = { HIGH: 0, MEDIUM: 1, LOW: 2, INFO: 3 };
  var PENALTY = { HIGH: 25, MEDIUM: 10, LOW: 3, INFO: 0 };
  var CSRF = ['csrf', 'xsrf', 'authenticity_token', '_token', 'nonce'];
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
  function metaHas(attr, value) {
    return Array.prototype.some.call(document.getElementsByTagName('meta'), function (m) {
      return (m.getAttribute(attr) || '').toLowerCase() === value;
    });
  }
  function metaContent(attr, value) {
    var m = Array.prototype.filter.call(document.getElementsByTagName('meta'), function (x) {
      return (x.getAttribute(attr) || '').toLowerCase() === value;
    })[0];
    return m ? m.getAttribute('content') || '' : '';
  }
  async function fetchText(url) {
    try {
      var r = await fetch(url, { cache: 'no-store' });
      return r.ok ? { text: await r.text(), res: r } : null;
    } catch (e) { return null; }
  }

  async function run() {
    var findings = [], passed = [];
    var add = function (sev, title, detail, fix) { findings.push({ sev: sev, title: title, detail: detail, fix: fix || '' }); };
    var pass = function (msg) { passed.push(msg); };
    btn.disabled = true;
    out.textContent = 'Scanning... checking headers, forms, scripts and exposed files.';

    var page = await fetchText(location.href.split('#')[0]);
    if (!page) {
      out.textContent = 'Scan failed. Open the site through http://localhost or your GitHub Pages link, not as a local file.';
      btn.disabled = false;
      return;
    }
    var h = page.res.headers;
    var isLocal = location.hostname === 'localhost' || location.hostname === '127.0.0.1';

    // Transport
    if (location.protocol === 'https:') pass('Site is served over HTTPS');
    else if (!isLocal) add('HIGH', 'Site is not served over HTTPS', 'Traffic can be read or changed in transit.', 'Enable HTTPS on your host.');

    // Headers
    HEADERS.forEach(function (x) {
      var name = x[0], val = h.get(name);
      if (name === 'strict-transport-security' && location.protocol !== 'https:') return;
      if (name === 'content-security-policy' && !val && metaHas('http-equiv', name)) {
        add('LOW', 'CSP is set by a meta tag only', 'Meta CSP works but cannot use frame-ancestors or report-only mode.', 'Prefer a real CSP header where your host allows it.');
        return;
      }
      if (name === 'referrer-policy' && !val && metaContent('name', 'referrer')) { pass('Referrer policy set via meta tag'); return; }
      if (!val) { add(x[1], 'Missing ' + name, x[2], x[3]); return; }
      if (name === 'content-security-policy' && /unsafe-inline|unsafe-eval/.test(val)) {
        add('MEDIUM', 'CSP allows unsafe-inline or unsafe-eval', 'This weakens protection against XSS.', 'Remove unsafe directives and use nonces or hashes.');
      } else pass(name + ' header present');
    });
    if (h.get('server')) add('INFO', 'Server header discloses technology', 'Server: ' + h.get('server'), 'Hide or genericize the Server header if possible.');
    if (h.get('x-powered-by')) add('LOW', 'X-Powered-By discloses technology', 'X-Powered-By: ' + h.get('x-powered-by'), 'Remove the X-Powered-By header.');

    // Cookies readable by JavaScript are by definition not HttpOnly
    if (document.cookie) add('LOW', 'Cookies readable by JavaScript', 'Cookies: ' + document.cookie.split(';').map(function (c) { return c.split('=')[0].trim(); }).join(', '), 'Set HttpOnly (and Secure, SameSite) on session cookies.');
    else pass('No JavaScript-readable cookies');

    // Forms
    Array.prototype.forEach.call(document.forms, function (f, i) {
      var method = (f.getAttribute('method') || 'get').toLowerCase();
      var action = f.getAttribute('action');
      var names = Array.prototype.map.call(f.elements, function (x) { return (x.name || '').toLowerCase(); });
      var label = 'Form #' + (i + 1) + ' (' + method.toUpperCase() + ')';
      if (f.querySelector('input[type=password]') && method === 'get') add('HIGH', label + ' sends a password via GET', 'Credentials would appear in URLs and logs.', 'Use method="post".');
      if (action && /^http:/i.test(action) && location.protocol === 'https:') add('HIGH', label + ' submits over HTTP', 'Form data would be sent unencrypted.', 'Use an https:// action.');
      if (method === 'post' && !names.some(function (n) { return CSRF.some(function (c) { return n.indexOf(c) !== -1; }); })) add('MEDIUM', label + ' has no CSRF token', 'Cross-site requests could submit this form.', 'Add a per-session CSRF token checked on the server.');
      if (!action || action === '#') add('INFO', label + ' has no backend', 'Action is "' + (action || '') + '", so submissions go nowhere.', 'Connect the form to a secure backend or form service.');
    });

    // Scripts, styles, links, frames
    Array.prototype.forEach.call(document.querySelectorAll('script[src],link[rel=stylesheet][href]'), function (n) {
      var u = new URL(n.src || n.href, location.href);
      if (u.origin !== location.origin && !n.integrity) add('MEDIUM', 'External resource without integrity check', u.href, 'Add an integrity attribute (SRI) or self-host the file.');
    });
    var inline = document.querySelectorAll('script:not([src])').length;
    if (inline) add('LOW', inline + ' inline script(s) found', 'Inline scripts prevent a strict CSP.', 'Move scripts to separate files.');
    var handlers = 0;
    Array.prototype.forEach.call(document.getElementsByTagName('*'), function (n) {
      Array.prototype.forEach.call(n.attributes, function (a) { if (/^on/i.test(a.name)) handlers++; });
    });
    if (handlers) add('LOW', handlers + ' inline event handler(s) found', 'Inline handlers (onclick=...) weaken CSP.', 'Use addEventListener in a script file.');
    Array.prototype.forEach.call(document.querySelectorAll('a[target=_blank]'), function (a) {
      if (!/noopener|noreferrer/.test(a.rel || '')) add('LOW', 'Link opens a new tab without rel="noopener"', a.href, 'Add rel="noopener noreferrer".');
    });
    Array.prototype.forEach.call(document.querySelectorAll('iframe:not([sandbox])'), function (f) {
      add('LOW', 'iframe without sandbox attribute', f.src || '(no src)', 'Add a sandbox attribute.');
    });
    if (location.protocol === 'https:') {
      Array.prototype.forEach.call(document.querySelectorAll('[src^="http:"],[href^="http:"]'), function (n) {
        add('MEDIUM', 'Mixed content (HTTP resource on HTTPS page)', n.getAttribute('src') || n.getAttribute('href'), 'Load the resource over https://.');
      });
    }

    // Exposed files (same site, plain GET requests)
    var leaks = 0;
    var gitCfg = await fetchText(new URL('.git/config', location.href).href);
    if (gitCfg && gitCfg.text.indexOf('[core]') !== -1) { leaks++; add('HIGH', 'Exposed .git/config', 'Your repository metadata is downloadable.', 'Block access to .git and redeploy only the site files.'); }
    var env = await fetchText(new URL('.env', location.href).href);
    if (env && /^[A-Z_]+=/m.test(env.text) && env.text.indexOf('<html') === -1) { leaks++; add('HIGH', 'Exposed .env file', 'Secrets may be downloadable.', 'Remove the file and rotate any secrets in it.'); }
    if (!leaks) pass('No exposed .git or .env files found');
    var sec = await fetchText(new URL('.well-known/security.txt', location.href).href);
    if (sec && sec.text.indexOf('<html') === -1) pass('security.txt present');
    else add('INFO', 'No security.txt', 'Researchers have no contact for reporting issues.', 'Add /.well-known/security.txt with a contact address.');

    render(findings, passed);
    btn.disabled = false;
    btn.textContent = 'Scan Again';
  }

  function render(findings, passed) {
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

    if (/github\.io$/.test(location.hostname)) {
      out.appendChild(el('p', 'scan-note', 'Note: GitHub Pages does not allow custom security headers, so some header findings come from the host, not your code.'));
    }

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

    out.appendChild(el('p', 'scan-note', 'This scan checks only this site, only for common issues. It cannot prove a site is secure.'));

    var dl = el('button', 'cta-button', 'Download Report');
    dl.type = 'button';
    dl.addEventListener('click', function () {
      var lines = ['Shield scan report', location.href, new Date().toISOString(), 'Score: ' + score + '/100 (' + grade + ') - ' + verdict, ''];
      findings.forEach(function (f) { lines.push('[' + f.sev + '] ' + f.title + ' - ' + f.detail + (f.fix ? ' | Fix: ' + f.fix : '')); });
      lines.push('', 'Passed: ' + passed.join('; '));
      var a = document.createElement('a');
      a.href = URL.createObjectURL(new Blob([lines.join('\n')], { type: 'text/plain' }));
      a.download = 'shield-report.txt';
      document.body.appendChild(a);
      a.click();
      a.remove();
    });
    out.appendChild(dl);
  }

  btn.addEventListener('click', run);
})();
