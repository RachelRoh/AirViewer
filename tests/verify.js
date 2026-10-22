// Headless checks for ellisys_viewer.html.
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
// 4. Edge cases: timestamp formats, BN/FT from CSV columns, no SN/NESN, no Timestamp/Direction.
const path = require('path');
const { chromium } = require('playwright');

const FILE = 'file://' + path.resolve(__dirname, '..', 'ellisys_viewer.html');
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
];

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
    const delivery = computeDelivery().map(x => { const n = { first: 0, retx: 0, lost: 0, carry: 0 }; x.list.forEach(e => { if (e.st) n[e.st]++; }); return [n.first, n.retx, n.lost, n.carry]; });
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
          if (e.st === 'lost') lost++; else del++;
          const t = byRow.get(e.oi);
          if (t && (e.st !== 'lost') !== t.delivered) bad.push([m.sid, dir, e.ec, e.st, t.delivered]);
        });
        const tDel = tp.filter(x => x.delivered).length, tLost = tp.filter(x => !x.delivered).length;
        if (del !== tDel || lost !== tLost) bad.push([m.sid, dir, 'count', del, lost, 'truth', tDel, tLost]);
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
  check('BN/FT read from CSV columns', JSON.stringify(csv) === JSON.stringify(['2/2/CSV', '1/2/CSV', '2/2/CSV', '1/2/CSV']), csv);

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

  check('no page errors', errors.length === 0, errors);
  await browser.close();
  console.log(failed ? `\n${failed} check(s) failed` : '\nall checks passed');
  process.exit(failed ? 1 : 0);
})();
