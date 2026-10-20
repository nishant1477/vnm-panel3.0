#!/usr/bin/env node
// 74-template-audit.js — machine-verified audit of EVERY render() and include()
// call in first-party code against the actual view files.
//
// Checks:
//  A. Every literal res.render('x') target resolves to views/x.ejs
//  B. Every dynamic render() is accounted for (allowlist: platform.js page()
//     registry — its literal targets are extracted and verified too)
//  C. Every include('p') inside every .ejs resolves relative to that file
//  D. Every dynamic include is accounted for (allowlist: none today)
//  E. Every .ejs file under views/ compiles cleanly with ejs.compile
//  F. Every compiled template that references bare locals declares them via
//     res.locals middleware or passes them at every call site (spot-checked
//     for the 404 templates: title/message/code/siteLogo)
//
// Exit 0 = audit clean. Any FAIL exits 1.
// Run from anywhere: node tests/template-audit.js (paths are checkout-relative).

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const VIEWS = path.join(ROOT, 'views');

// First-party JS that can serve requests. node_modules excluded everywhere.
const JS_DIRS = [
  path.join(ROOT, 'app.js'),
  path.join(ROOT, 'shield.js'),
  path.join(ROOT, 'platform.js'),
  path.join(ROOT, 'lib'),
  path.join(ROOT, 'watchdog'),
  path.join(ROOT, 'node-agent'),
  path.join(ROOT, 'license-server'),
];

const results = [];
const check = (name, ok, extra = '') => {
  results.push([name, ok]);
  console.log((ok ? 'PASS' : 'FAIL') + ' ' + name + (extra ? ' — ' + extra : ''));
};

function listFiles(dir, ext, out = []) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    if (e.name === 'node_modules' || e.name === '.git' || e.name === 'test-bin') continue;
    const p = path.join(dir, e.name);
    if (e.isDirectory()) listFiles(p, ext, out);
    else if (e.isFile() && p.endsWith(ext)) out.push(p);
  }
  return out;
}

// ---------- collect first-party JS ----------
const jsFiles = [];
for (const d of JS_DIRS) {
  if (!fs.existsSync(d)) continue;
  if (fs.statSync(d).isFile()) jsFiles.push(d);
  else listFiles(d, '.js', jsFiles);
}

// ---------- A+B: render() targets ----------
const renderTargets = new Map(); // view -> [where]
const dynamicRenders = [];
const renderRe = /\.render\(\s*(?:'([^']+)'|"([^"]+)")/g;
const dynRenderRe = /\.render\(\s*[^'"\s)]/;

for (const f of jsFiles) {
  const src = fs.readFileSync(f, 'utf8');
  const lines = src.split('\n');
  lines.forEach((line, i) => {
    let m;
    const re = new RegExp(renderRe.source, 'g');
    while ((m = re.exec(line))) {
      const view = m[1] || m[2];
      if (!renderTargets.has(view)) renderTargets.set(view, []);
      renderTargets.get(view).push(path.relative(ROOT, f) + ':' + (i + 1));
    }
    if (dynRenderRe.test(line)) {
      dynamicRenders.push(path.relative(ROOT, f) + ':' + (i + 1) + ' → ' + line.trim().slice(0, 90));
    }
  });
}

// platform.js page('view', ...) registry feeds the dynamic res.render(view, ...)
const pageRe = /page\(\s*'([^']+)'\s*,/g;
{
  const src = fs.readFileSync(path.join(ROOT, 'platform.js'), 'utf8');
  let m;
  while ((m = pageRe.exec(src))) {
    if (!renderTargets.has(m[1])) renderTargets.set(m[1], ['platform.js page() registry']);
  }
}

let missingViews = 0;
for (const [view, where] of [...renderTargets].sort()) {
  const p = path.join(VIEWS, view + '.ejs');
  const ok = fs.existsSync(p);
  if (!ok) missingViews++;
  check('render target exists: ' + view, ok, ok ? '' : 'referenced at ' + where.join(', '));
}

// Every dynamic render must be the platform.js page() indirection (validated above)
const dynAllowed = /^platform\.js:\d+ → \(req, res\) => res\.render\(view,/;
for (const d of dynamicRenders) {
  check('dynamic render accounted for: ' + d.split(' → ')[0], dynAllowed.test(d), d);
}

// ---------- C+D: includes inside views ----------
const ejsFiles = listFiles(VIEWS, '.ejs');
const includeRe = /include\(\s*(?:'([^']+)'|"([^"]+)")\s*\)/g;
const dynIncludeRe = /include\(\s*[^'"\s)]/;
let missingIncludes = 0;
const includeTargets = new Set();
for (const f of ejsFiles) {
  const src = fs.readFileSync(f, 'utf8');
  src.split('\n').forEach((line, i) => {
    let m;
    const re = new RegExp(includeRe.source, 'g');
    while ((m = re.exec(line))) {
      const inc = m[1] || m[2];
      if (inc.endsWith('.ejs') === false && !inc.includes('.')) {
        // partials referenced without extension are fine (Express/EJS resolves .ejs)
      }
      includeTargets.add(inc);
      const resolved = path.resolve(path.dirname(f), inc.endsWith('.ejs') ? inc : inc + '.ejs');
      if (!fs.existsSync(resolved)) {
        missingIncludes++;
        check('include exists: ' + inc + ' (from ' + path.relative(VIEWS, f) + ':' + (i + 1) + ')', false);
      }
    }
    if (dynIncludeRe.test(line)) {
      check('dynamic include accounted for: ' + path.relative(VIEWS, f) + ':' + (i + 1), false, line.trim().slice(0, 90));
    }
  });
}
check('all includes resolve (' + [...includeTargets].sort().join(', ') + ')', missingIncludes === 0);

// ---------- E: compile every view ----------
let compileFails = 0;
const ejs = require(path.join(ROOT, 'node_modules', 'ejs'));
for (const f of ejsFiles) {
  const src = fs.readFileSync(f, 'utf8');
  try {
    ejs.compile(src, { filename: f });
  } catch (e) {
    compileFails++;
    check('ejs compiles: ' + path.relative(VIEWS, f), false, e.message.split('\n')[0]);
  }
}
check('all ' + ejsFiles.length + ' views compile cleanly', compileFails === 0);

// ---------- F: render-with-locals spot check for the 404 pair ----------
// Render both 404 templates with the exact locals each call site passes,
// plus an empty-locals worst case — neither may throw.
{
  const cases = [
    ['users/404', { title: 'Page Not Found - VNM Panel', message: 'Page not found' }, 'exact 404-handler locals'],
    ['users/404', { message: 'VM not found' }, 'vm-detail 404 locals'],
    ['admin/404', { title: 'Invalid User ID - VNM Panel', code: 400, message: 'Invalid User ID' }, 'invalid-user-id locals'],
    ['admin/404', { title: 'Built-in Template Not Found - VNM Panel', code: 400, message: 'Built-in Template Not Found' }, 'missing-template locals'],
    ['admin/404', {}, 'empty locals (worst case)'],
  ];
  for (const [view, locals, label] of cases) {
    try {
      const html = ejs.render(fs.readFileSync(path.join(VIEWS, view + '.ejs'), 'utf8'),
        { ...locals, siteLogo: '/images/logo-new.svg', filename: path.join(VIEWS, view + '.ejs') });
      check('render ' + view + ' with ' + label, html.length > 200 && !html.includes('ReferenceError'), html.length + ' bytes');
    } catch (e) {
      check('render ' + view + ' with ' + label, false, e.message.split('\n')[0]);
    }
  }
}

// ---------- summary ----------
const fails = results.filter(r => !r[1]).length;
console.log('\n==== TEMPLATE AUDIT: ' + (results.length - fails) + '/' + results.length + ' checks passed ====');
if (fails) {
  console.log('AUDIT FAILED — ' + fails + ' problem(s)');
  process.exit(1);
}
console.log('AUDIT CLEAN — every render() target, include() path and view compiles');
