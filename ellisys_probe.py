#!/usr/bin/env python3
"""Check what the Ellisys Remote Control API can give AirViewer from a .btt trace.

DRAFT — written from the public ellisys-analysis-automation docs, not yet run against a
real analyzer. Run it on the Windows PC with the Ellisys Bluetooth Analyzer:

    1. Install the Python SDK that ships with the analyzer (Sdk/Analysis/Python):
         python -m pip install -e <Ellisys folder>/Sdk/Analysis/Python
    2. Start the analyzer with Remote Control enabled (see the SDK guide for the port).
    3. python ellisys_probe.py C:\\traces\\capture.btt [--port 12345]

It prints a short report: analyzer version, overview names, item fields, and a few
example item descriptions about CIS/ISO. Hex bytes and Bluetooth addresses are masked,
so the report can be shared without the payload. Nothing is sent anywhere; the script
only talks to the analyzer on this PC. Each step reports its own error and the rest go on.
"""
import argparse
import re
import sys

HEXRUN = re.compile(r'\b(?:[0-9A-Fa-f]{2}[:\- ]){2,}[0-9A-Fa-f]{2}\b')   # byte runs, BD_ADDR
LONGHEX = re.compile(r'0x[0-9A-Fa-f]{9,}')


def mask(s, width=150):
    s = HEXRUN.sub('<hex>', str(s))
    s = LONGHEX.sub('0x<long>', s)
    return s if len(s) <= width else s[:width] + '…'


def step(title, fn):
    print(f'\n## {title}')
    try:
        fn()
    except Exception as e:  # keep going: each step is independent
        print(f'  [실패] {type(e).__name__}: {mask(e, 300)}')


def main():
    ap = argparse.ArgumentParser(description='Ellisys Remote API로 .btt에서 AirViewer가 읽을 수 있는 정보를 확인합니다.')
    ap.add_argument('btt', help='트레이스 파일 경로 (분석기 PC 기준)')
    ap.add_argument('--host', default='localhost')
    ap.add_argument('--port', type=int, default=12345, help='Remote Control 포트 (SDK 가이드 확인)')
    ap.add_argument('--items', type=int, default=12, help='overview마다 보여줄 예시 수')
    a = ap.parse_args()

    try:
        import ellisys_analysis_automation as ea
        from ellisys_analysis_automation import ItemField
    except ImportError as e:
        sys.exit(f'ellisys_analysis_automation을 찾지 못했습니다 ({e}). Ellisys 설치 폴더의 Sdk/Analysis/Python을 pip로 설치하세요.')

    print('# AirViewer probe')
    with ea.connect(a.host, a.port) as analyzer:
        step('Analyzer', lambda: print(' ', getattr(analyzer.app_info(), 'version', '?')))
        step('Load', lambda: (analyzer.load(a.btt, timeout=600.0), print('  ok')))
        names = []

        def overviews():
            names.extend(analyzer.overviews())
            for n in names:
                print('  -', n)
        step('Overviews', overviews)
        step('ItemField members', lambda: print(' ', ', '.join(f.name for f in ItemField)))

        le = [n for n in names if 'low energy' in n.lower() or ' le ' in f' {n.lower()} '] or names[:1]
        for name in le:
            def show(name=name):
                with analyzer.overview(name) as ov:
                    print(f'  items: {ov.root.child_count:,}')
                    fields = list(ItemField)
                    shown = 0
                    # Items about CIS / isochronous data first; fall back to the first items
                    try:
                        cur = ov.search_cursor(description=['*CIS*', '*ISO*', '*Isochronous*'])
                    except Exception as e:
                        print(f'  (search 불가: {type(e).__name__}) 처음 항목을 보여줍니다')
                        cur = ov.root.cursor()
                    for item in cur.stream():
                        print('  ·', mask(getattr(item, 'description', item)))
                        shown += 1
                        if shown >= a.items:
                            break
                    # Which fields come back per record (values masked)
                    try:
                        recs = ov.root.cursor().take(3).records(*fields)
                        for r in recs:
                            print('  record:', {k: mask(v, 60) for k, v in vars(r).items()} if hasattr(r, '__dict__') else mask(r))
                    except Exception as e:
                        print(f'  records(*ItemField) 실패: {type(e).__name__}: {mask(e, 200)}')
            step(f'Overview "{name}"', show)
    print('\n# 끝. 위 내용을 그대로(또는 요약해서) 전달해 주세요.')


if __name__ == '__main__':
    main()
