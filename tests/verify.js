// Headless checks for template/report_template.html.
//
//   npm i -D playwright && npx playwright install chromium
//   node tests/verify.js
//
// 1. Regression: the original sample (FT=1, BN=1) gives the same issues and delivery
//    figures as before the FT/BN payload model was added.
// 2. Ground truth: generateSampleData2() simulates both link layers (SN/NESN, ack, flush)
//    and returns what really happened to every payload. The analyzer must reach the same
//    delivered/lost verdict for every payload, for several BN/FT/error-rate settings.
// 3. Timing: exactly the injected timing anomalies are flagged, nothing else.
// 4. Edge cases: timestamp formats, BN/FT from trace columns, no SN/NESN, no Timestamp/Direction.
// 5. Reports (needs python3 or python): the sample report from procedures.py opens by itself,
//    as plain JSON and gzip+base64, and both give the same findings and ISO results.
const path = require('path');
const fs = require('fs');
const os = require('os');
const { execFileSync } = require('child_process');
const { chromium } = require('playwright');

const FILE = 'file://' + path.resolve(__dirname, '..', 'template', 'report_template.html');
let failed = 0;
const check = (name, ok, info) => { console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok || info === undefined ? '' : '  ' + JSON.stringify(info)}`); if (!ok) failed++; };

// Original sample, recorded from the viewer before the payload model (commit bfd93f0)
const SAMPLE1 = {
  counts: { nack: 76, crcRecovered: 78, noResp: 10, seSkip: 2, payloadZero: 1, crcLost: 3, payloadEmpty: 2, ecSkip: 3, payloadLen: 1 },
  delivery: [[383, 17, 0], [388, 10, 0], [366, 29, 5], [375, 21, 4]], // first, retx, lost per stream+direction
};

const TRUTH_CONFIGS = [
  { drops: false },
  { drops: false, seed: 11, crc: 0.08 },
  { drops: false, seed: 5, crc: 0.15, noResp: 0.02 },
  { drops: false, bnC: 1, ftC: 1, bnP: 1, ftP: 1 },
  { drops: false, bnC: 1, ftC: 3, bnP: 1, ftP: 3, crc: 0.2, seed: 3 },
  { drops: false, bnC: 2, ftC: 1, bnP: 1, ftP: 1, crc: 0.1, seed: 9 },
  { drops: false, mismatch: 0.05, crc: 0.1, seed: 8 }, // sniffer CRC sometimes disagrees with the receiver
  // BN that doesn't divide NSE: payloads flush in the middle of an event
  { drops: false, bnC: 3, ftC: 1, bnP: 1, ftP: 1, crc: 0.1, seed: 2 },
  { drops: false, bnC: 2, ftC: 2, bnP: 2, ftP: 2, nse: 5, sub: 0.88, crc: 0.3, seed: 1 },
  { drops: false, bnC: 3, ftC: 3, bnP: 3, ftP: 1, crc: 0.3, seed: 1 },
  { drops: false, bnC: 1, ftC: 2, bnP: 1, ftP: 2, crc: 0.3, seed: 3 },
  // Capture loss (0x01 events 350-351, 0x02:330 SE2): verdicts for captured payloads must still match
  { drops: true },
  { drops: true, seed: 3, crc: 0.2 },
];
// Wider sweep: BN 1–3, FT 1–3, NSE 4–6, CRC 10%/30%, 4 seeds (set FUZZ=1; takes a few minutes)
if (process.env.FUZZ) {
  for (const [bnC, ftC, bnP, ftP] of [[1,2,1,2],[2,2,1,2],[1,3,1,3],[2,3,1,2],[1,2,2,2],[2,2,2,2],[3,1,1,1],[3,2,2,2],[3,3,3,1],[2,1,2,1]])
    for (const nse of [4, 5, 6]) for (const crc of [0.1, 0.3]) for (const seed of [1, 2, 3, 4])
      TRUTH_CONFIGS.push({ bnC, ftC, bnP, ftP, nse, sub: Math.min(1.1, 4.4 / nse), crc, seed, drops: false });
}

(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1400, height: 900 } });
  const errors = [];
  page.on('pageerror', e => errors.push(e.message));
  await page.goto(FILE);

  // 1. Regression
  const s1 = await page.evaluate(() => {
    const g = generateSampleData(); loadData(g.headers, g.data, {});
    const counts = {}; issues.forEach(i => counts[i.type] = (counts[i.type] || 0) + 1);
    const delivery = computeDelivery().map(x => { const n = { first: 0, retx: 0, lost: 0, carry: 0 }; x.list.forEach(e => { if (e.st) n[e.st] += e.n || 1; }); return [n.first, n.retx, n.lost, n.carry]; });
    return { counts, delivery };
  });
  check('sample 1: issue counts unchanged', JSON.stringify(s1.counts) === JSON.stringify(SAMPLE1.counts), s1.counts);
  check('sample 1: delivery unchanged', JSON.stringify(s1.delivery.map(d => d.slice(0, 3))) === JSON.stringify(SAMPLE1.delivery) && s1.delivery.every(d => d[3] === 0), s1.delivery);

  // 2 + 3. Ground truth
  for (const cfg of TRUTH_CONFIGS) {
    const r = await page.evaluate(opts => {
      const g = generateSampleData2(opts); loadData(g.headers, g.data, g.iso);
      const last = (opts.events || 400) - 1, bad = [];
      sduModel.forEach(m => {
        const dir = dirShort(m.dir);
        // Payloads still open at the end of the capture are only judged if they were delivered
        const tp = g.truth.payloads.filter(x => x.sid === m.sid && x.dir === dir && (x.flushEv <= last || x.delivered));
        const byRow = new Map(tp.filter(x => x.firstRow !== null).map(x => [x.firstRow, x]));
        let del = 0, lost = 0;
        m.list.forEach(e => {
          if (e.st === null) return;
          const w = e.n || 1; if (e.st === 'lost') lost += w; else del += w;
          const t = byRow.get(e.oi);
          if (t && (e.st !== 'lost') !== t.delivered) bad.push([m.sid, dir, e.ec, e.st, t.delivered]);
        });
        const tDel = tp.filter(x => x.delivered).length, tLost = tp.filter(x => !x.delivered).length;
        // With capture loss, payloads never captured are counted lost by design: only check captured ones
        if (!opts.drops && (del !== tDel || lost !== tLost)) bad.push([m.sid, dir, 'count', del, lost, 'truth', tDel, tLost]);
      });
      const got = issues.filter(i => /Timing$/.test(i.type)).map(i => `${i.type}|${i.sid}|${i.ec}`).sort();
      const exp = g.truth.timing.map(t => `${t.kind}|${t.sid}|${t.ec}`).sort();
      return { bad, timingOk: JSON.stringify(got) === JSON.stringify(exp), got, exp };
    }, cfg);
    check(`truth ${JSON.stringify(cfg)}: every payload verdict matches`, r.bad.length === 0, r.bad.slice(0, 5));
    check(`truth ${JSON.stringify(cfg)}: timing flags = injected`, r.timingOk, { got: r.got, exp: r.exp });
  }

  // 4. Edge cases
  const ts = await page.evaluate(() => [['12.345 ms', 12345], ['12345 us', 12345], ['12345 µs', 12345], ['0.012345 s', 12345], ['12 345.000 µs', 12345],
    ['0:00:00.012345', 12345], ['12.345', 12345], ['12345000 ns', 12345]].map(([v, e]) => [v, tsUs(v), Math.abs(tsUs(v) - e) < 1e-6]));
  check('timestamp formats parse to µs', ts.every(x => x[2]), ts.filter(x => !x[2]));

  const csv = await page.evaluate(() => {
    try { localStorage.clear(); } catch (e) {}
    const g = generateSampleData2({ drops: false });
    const h = [...g.headers, 'BN', 'FT'], d = g.data.map(r => [...r, r[2].startsWith('Central') ? '2' : '1', '2']);
    loadData(h, d);
    return [...linkInfo.values()].map(v => `${v.bn}/${v.ft}/${v.src}`);
  });
  check('BN/FT read from trace columns', JSON.stringify(csv) === JSON.stringify(['2/2/컬럼', '1/2/컬럼', '2/2/컬럼', '1/2/컬럼']), csv);

  const noSn = await page.evaluate(() => {
    const g = generateSampleData(), keep = g.headers.map((h, i) => i).filter(i => !['SN', 'NESN'].includes(g.headers[i]));
    loadData(keep.map(i => g.headers[i]), g.data.map(r => keep.map(i => r[i])), {});
    const c = {}; issues.forEach(i => c[i.type] = (c[i.type] || 0) + 1); return c;
  });
  // Same as the viewer before the payload model on this input
  check('without SN/NESN: same result as before', JSON.stringify(noSn) === JSON.stringify({ crcRecovered: 78, noResp: 10, seSkip: 2, payloadZero: 1, crcLost: 3, payloadEmpty: 2, ecSkip: 3, payloadLen: 1 }), noSn);

  const noTs = await page.evaluate(() => {
    const g = generateSampleData(), keep = g.headers.map((h, i) => i).filter(i => !['Timestamp', 'Direction'].includes(g.headers[i]));
    loadData(keep.map(i => g.headers[i]), g.data.map(r => keep.map(i => r[i])), {});
    switchTab('timeline'); tlMode = 'timing'; drawTimeline(); tlMode = 'grid'; switchTab('issues');
    return !issueChecks.anchorTiming.on && !issueChecks.slotTiming.on;
  });
  check('without Timestamp/Direction: timing checks off, views still draw', noTs);

  const robust = await page.evaluate(() => {
    const out = {};
    // No SN column with BN=2 on a clean link: no losses
    let g = generateSampleData2({ drops: false, crc: 0, noResp: 0, inject: false, timing: false });
    let keep = g.headers.map((h, i) => i).filter(i => !['SN', 'NESN'].includes(g.headers[i]));
    loadData(keep.map(i => g.headers[i]), g.data.map(r => keep.map(i => r[i])), g.iso);
    out.noSnLost = computeDelivery().reduce((a, x) => a + x.list.filter(e => e.st === 'lost').reduce((b, e) => b + (e.n || 1), 0), 0);
    // Absurd BN is clamped to 15 and finishes quickly
    g = generateSampleData2({ drops: false });
    let t = performance.now(); loadData(g.headers, g.data, { bnC: 200000, ftC: 2, bnP: 1, ftP: 2 });
    out.bnClamp = [...linkInfo.values()][0].bn; out.bnMs = performance.now() - t;
    // One row with a far-off Event Counter doesn't break the analysis
    g = generateSampleData2({ drops: false }); const bad = [...g.data[5]]; bad[5] = '50000000'; g.data.push(bad);
    t = performance.now(); loadData(g.headers, g.data, g.iso); out.outlierMs = performance.now() - t; out.outlierIssues = issues.length;
    // Unit-less timestamps in seconds are recognised and timing still works
    g = generateSampleData2();
    const ti = g.headers.indexOf('Timestamp'); g.data.forEach(r => { r[ti] = (parseFloat(r[ti]) / 1000).toFixed(9).replace(/(\d{3})(?=\d)/g, '$1 ').replace(/^(\d+)\.(.*)$/, (m, a, b) => a + '.' + b); });
    loadData(g.headers, g.data, g.iso);
    out.autoUnit = tsAutoUnit;
    out.secTiming = issues.filter(i => /Timing$/.test(i.type)).map(i => `${i.type}|${i.sid}|${i.ec}`).sort().join() === g.truth.timing.map(x => `${x.kind}|${x.sid}|${x.ec}`).sort().join();
    // Per-capture parameters are not carried over to the next file with the same columns
    try { localStorage.clear(); } catch (e) {}
    g = generateSampleData2(); loadData(g.headers, g.data, g.iso); isoUser = { ...isoUser, tolUs: 30 }; saveMapping();
    g = generateSampleData2(); loadData(g.headers, g.data); out.carried = { ...isoUser };
    return out;
  });
  check('no SN, BN=2, clean link: no losses', robust.noSnLost === 0, robust.noSnLost);
  check('BN clamped to 15, fast', robust.bnClamp === 15 && robust.bnMs < 3000, robust);
  check('outlier Event Counter: no error, fast', robust.outlierIssues > 0 && robust.outlierMs < 3000, robust);
  check('unit-less timestamps in seconds detected, timing flags = injected', robust.autoUnit === 's' && robust.secTiming, robust);
  check('only timestamp unit / tolerance carried to the next file', JSON.stringify(robust.carried) === '{"tolUs":30}', robust.carried);

  check('no page errors', errors.length === 0, errors);

  // 5. Reports with the data inside (report.py), plain and gzip+base64
  const py = ['python3', 'python'].find(c => { try { execFileSync(c, ['--version'], { stdio: 'ignore' }); return true; } catch (e) { return false; } });
  if (!py) console.log('SKIP  reports (no python3/python)');
  else {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'airviewer-'));
    const results = {};
    for (const [name, args] of [['plain', []], ['gzip', ['--gzip']]]) {
      const out = path.join(dir, name + '.html');
      execFileSync(py, [path.resolve(__dirname, '..', 'procedures.py'), '--sample', '-o', out, ...args], { stdio: 'ignore' });
      const p = await browser.newPage(); const errs = [];
      p.on('pageerror', e => errs.push(e.message)); p.on('dialog', d => { errs.push('dialog'); d.dismiss(); });
      await p.goto('file://' + out);
      let r;
      try {
        await p.waitForFunction(() => document.getElementById('findPanel').classList.contains('active'), null, { timeout: 15000 });
        r = await p.evaluate(() => ({ findings: fd.findings.map(f => f.kind + '@' + f.t.toFixed(6)).join(','), iso: rawData.length, issues: issues.length }));
      } catch (e) { r = { error: e.message }; }
      results[name] = r;
      check(`report: ${name} opens`, !errs.length && !r.error && r.iso > 0 && r.findings.length > 0, { ...r, errs });
      await p.close();
    }
    check('report: gzip gives the same result', JSON.stringify(results.plain) === JSON.stringify(results.gzip));
    fs.rmSync(dir, { recursive: true, force: true });
  }

  await browser.close();
  console.log(failed ? `\n${failed} check(s) failed` : '\nall checks passed');
  process.exit(failed ? 1 : 0);
})();
