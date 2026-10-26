#!/usr/bin/env python3
"""Make an AirViewer report: an HTML file with the capture inside it.

The report opens by double-click and needs no file picker or drag & drop, so it works
on PCs where the browser may not read local files. Nothing leaves the PC: the script
only reads the CSV and writes one HTML file next to it.

    python airviewer.py capture.csv                 # writes capture_airviewer.html and opens it
    python airviewer.py capture.csv -o report.html --no-open
    python airviewer.py capture.csv --bn-c 2 --ft-c 2 --bn-p 1 --ft-p 2

The CSV is an Ellisys Overview export (any column order; see README for useful columns).
Needs Python 3.8+ and ellisys_viewer.html in the same folder. Standard library only.
"""
import argparse
import base64
import csv
import datetime
import gzip
import io
import json
import os
import pathlib
import shutil
import subprocess
import sys
import webbrowser

HERE = os.path.dirname(os.path.abspath(__file__))
TEMPLATE = os.path.join(HERE, 'ellisys_viewer.html')
DATA_TAG = '<script id="airviewer-data" type="{type}"{enc}>{payload}</script>'
GZIP_ABOVE = 8 * 1024 * 1024  # JSON larger than this is stored gzip+base64 (about 5-10x smaller)


def read_text(path):
    """Read a CSV export whatever its encoding (UTF-8 with or without BOM, UTF-16, Korean Windows CP949)."""
    raw = open(path, 'rb').read()
    if raw.startswith(b'\xff\xfe') or raw.startswith(b'\xfe\xff'):
        return raw.decode('utf-16'), 'utf-16'
    if raw.startswith(b'\xef\xbb\xbf'):
        return raw[3:].decode('utf-8'), 'utf-8-sig'
    # UTF-16 without BOM: every other byte is zero in an ASCII-heavy file
    if len(raw) >= 4 and raw[1:200:2].count(0) > 50:
        return raw.decode('utf-16-le'), 'utf-16-le'
    for enc in ('utf-8', 'cp949'):
        try:
            return raw.decode(enc), enc
        except UnicodeDecodeError:
            pass
    return raw.decode('latin-1'), 'latin-1'


def parse_csv(text):
    """Header row + data rows. Delimiter: whichever of comma, tab, semicolon splits the header most."""
    lines = [l for l in text.splitlines() if l.strip()]
    if len(lines) < 2:
        raise SystemExit('CSV에 헤더와 데이터 행이 필요합니다.')
    head = lines[0]
    delim = max([',', '\t', ';'], key=lambda d: (head.count(d), d == ','))
    rows = list(csv.reader(io.StringIO('\n'.join(lines)), delimiter=delim))
    headers = [h.strip() for h in rows[0]]
    n = len(headers)
    data = []
    for r in rows[1:]:
        if len(r) < n - 1:  # same tolerance as the viewer: drop broken lines
            continue
        r = [c.strip() for c in r[:n]] + [''] * max(0, n - len(r))
        data.append(r)
    if not data:
        raise SystemExit('읽을 수 있는 데이터 행이 없습니다.')
    return headers, data, delim


def embed(template, payload_obj, force_gzip=False):
    raw = json.dumps(payload_obj, ensure_ascii=False, separators=(',', ':'))
    if force_gzip or len(raw.encode('utf-8')) > GZIP_ABOVE:
        payload = base64.b64encode(gzip.compress(raw.encode('utf-8'), 6)).decode('ascii')
        tag = DATA_TAG.format(type='application/octet-stream', enc=' data-encoding="gzip+base64"', payload=payload)
    else:
        # Keep the JSON from closing the <script> element or breaking JS parsing
        safe = raw.replace('<', '\\u003c').replace('\u2028', '\\u2028').replace('\u2029', '\\u2029')
        tag = DATA_TAG.format(type='application/json', enc='', payload=safe)
    idx = template.rfind('</body>')
    if idx < 0:
        raise SystemExit('ellisys_viewer.html에서 </body>를 찾지 못했습니다.')
    return template[:idx] + tag + '\n' + template[idx:]


def open_file(path):
    """Open in the default browser; from WSL, hand the Windows path to the Windows browser."""
    is_wsl = hasattr(os, 'uname') and 'microsoft' in os.uname().release.lower()
    if is_wsl:
        if shutil.which('wslview'):
            subprocess.run(['wslview', path])
            return
        if shutil.which('explorer.exe') and shutil.which('wslpath'):
            win = subprocess.run(['wslpath', '-w', os.path.abspath(path)], capture_output=True, text=True).stdout.strip()
            subprocess.run(['explorer.exe', win])  # explorer.exe exits non-zero even on success
            return
    webbrowser.open(pathlib.Path(path).resolve().as_uri())  # file:///C:/... on Windows


def main(argv=None):
    try:  # a Korean Windows console (cp949) can't print every character; never fail on that
        sys.stdout.reconfigure(errors='replace')
    except (AttributeError, ValueError):
        pass
    ap = argparse.ArgumentParser(description='Ellisys CSV export를 데이터가 들어 있는 AirViewer HTML 리포트로 만듭니다.')
    ap.add_argument('csv', help='Ellisys Overview CSV export (.csv / .tsv / .txt)')
    ap.add_argument('-o', '--out', help='출력 HTML (기본: <입력 이름>_airviewer.html)')
    ap.add_argument('--no-open', action='store_true', help='만든 뒤 브라우저로 열지 않음')
    ap.add_argument('--gzip', action='store_true', help='크기와 상관없이 압축해서 넣기')
    g = ap.add_argument_group('ISO 파라미터 (생략하면 리포트의 ISO 파라미터 패널/CSV 컬럼/기본값)')
    for opt, key, typ in (('--bn-c', 'bnC', int), ('--ft-c', 'ftC', int), ('--bn-p', 'bnP', int), ('--ft-p', 'ftP', int),
                          ('--nse', 'nse', int), ('--iso-ms', 'isoMs', float), ('--sub-ms', 'subMs', float),
                          ('--tol-us', 'tolUs', float)):
        g.add_argument(opt, dest=key, type=typ)
    g.add_argument('--ts-unit', dest='tsUnit', choices=['auto', 's', 'ms', 'us', 'ns'])
    a = ap.parse_args(argv)

    if not os.path.isfile(TEMPLATE):
        raise SystemExit(f'뷰어 파일이 없습니다: {TEMPLATE} (airviewer.py와 같은 폴더에 두세요)')
    text, enc = read_text(a.csv)
    headers, rows, delim = parse_csv(text)
    iso = {k: getattr(a, k) for k in ('bnC', 'ftC', 'bnP', 'ftP', 'nse', 'isoMs', 'subMs', 'tolUs', 'tsUnit')
           if getattr(a, k) is not None}
    payload = {'source': os.path.basename(a.csv), 'created': datetime.datetime.now().isoformat(timespec='seconds'),
               'headers': headers, 'rows': rows}
    if iso:
        payload['iso'] = iso
    html = embed(open(TEMPLATE, encoding='utf-8').read(), payload, a.gzip)
    out = a.out or os.path.splitext(a.csv)[0] + '_airviewer.html'
    with open(out, 'w', encoding='utf-8', newline='\n') as f:
        f.write(html)
    print(f'{len(rows):,} rows · {len(headers)} columns · {enc} · 구분자 {delim!r} → {out} ({os.path.getsize(out)/1e6:.1f} MB)')
    if not a.no_open:
        open_file(out)


if __name__ == '__main__':
    main()
