#!/usr/bin/env python3
"""Turn an Ellisys .btt trace into a self-contained LE Audio report.

    python airviewer.py capture.btt                 -> capture.html
    python airviewer.py capture.btt --explore       -> what the trace contains (field names etc.)

Drives the Ellisys Bluetooth Analyzer through its Remote Control API (Python SDK
`ellisys-analysis-automation`): loads the trace, pulls the CIS/BIS packets out of the Low Energy
overview, and embeds them in a copy of the report template, which opens straight on the analysis.
The analyzer application must be running with the Remote Control plugin enabled (port 12345).
"""
import argparse
import os
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import report

HERE = Path(__file__).resolve().parent
# The SDK shipped in Ellisys' Remote Control archive (bta_remote_api) is used as is; it only
# needs its zeroc-ice runtime installed (requirements.txt)
SDK = HERE / "bta_remote_api" / "Sdk" / "Analysis" / "Python"
sys.path.insert(0, str(SDK))
try:
    import ellisys_analysis_automation as ea
    from ellisys_analysis_automation import ItemField
except ModuleNotFoundError as exc:
    sys.exit(f"{exc}. Install the SDK runtime: python -m pip install -r {HERE / 'requirements.txt'}"
             if exc.name == "Ice" else f"{exc}. Expected the Ellisys SDK in {SDK}")

# Server-side filter tried first: keeps only the ISO lines, so the rest of the capture
# (advertising, other devices) is never transferred. Falls back to ISO_MATCH if it matches nothing.
ISO_QUERY = 'Item = "**CIS**", "**BIS**", "**ISO**"'
ISO_MATCH = re.compile(r"\b(CIS|BIS|ISO|Isochronous)\b", re.I)

# Viewer column name -> Ellisys field/column names it can come from (first match wins).
# Put first in the report, so the viewer's auto-detection picks these over the raw columns.
CANONICAL = [
    ("CIG ID", re.compile(r"^cig[ _]?(id)?$", re.I)),
    ("CIS ID", re.compile(r"^cis[ _]?(id)?$", re.I)),
    ("BIG Handle", re.compile(r"^big[ _]?(handle|id)?$", re.I)),
    ("BIS ID", re.compile(r"^bis[ _]?(id|index|number)?$", re.I)),
    ("Direction", re.compile(r"^(direction|dir)$", re.I)),
    ("Event Counter", re.compile(r"^((cis|bis|iso)[ _]?)?event[ _]?(counter|count|number)$", re.I)),
    ("Subevent", re.compile(r"^sub[ _-]?event([ _]?(counter|number|index))?$", re.I)),
    ("SN", re.compile(r"^(sn|sequence number)$", re.I)),
    ("NESN", re.compile(r"^(nesn|next expected sequence number)$", re.I)),
    ("NPI", re.compile(r"^(npi|null pdu indicator)$", re.I)),
    ("CRC", re.compile(r"^crc([ _]?(status|result|check))?$", re.I)),
    ("Status", re.compile(r"^status$", re.I)),
    ("Payload Length", re.compile(r"^(payload[ _]?)?length$", re.I)),
    ("Payload", re.compile(r"^(payload|(iso(chronous)?[ _]?)?data)$", re.I)),
    ("Channel", re.compile(r"^(rf[ _]?)?channel([ _]?(index|number))?$", re.I)),
    ("RSSI", re.compile(r"^rssi$", re.I)),
    ("PHY", re.compile(r"^phy$", re.I)),
]
CIS_IN_TEXT = re.compile(r"\bCIS\s*(?:ID)?\s*[:=#]?\s*(0x[0-9A-Fa-f]+|\d+)")
BIS_IN_TEXT = re.compile(r"\bBIS\s*(?:ID|Index)?\s*[:=#]?\s*(0x[0-9A-Fa-f]+|\d+)")
SAMPLE_PACKETS = 200    # packets read in full to learn the field names
LEAF_PROOF = 20         # leaves in a row at one depth before that depth is taken as packet level


def in_wsl():
    try:
        return "microsoft" in Path("/proc/version").read_text().lower()
    except OSError:
        return False


def analyzer_path(path):
    """The trace path as the analyzer application (Windows) sees it."""
    if re.match(r"^([A-Za-z]:[\\/]|\\\\)", path):
        return path
    # A WSL path to a Windows drive, also when this runs on Windows Python (py.exe from WSL)
    m = re.match(r"^/mnt/([A-Za-z])(/.*)?$", path)
    if m:
        return f"{m.group(1).upper()}:" + (m.group(2) or "/").replace("/", "\\")
    full = os.path.abspath(path)
    if in_wsl():
        return subprocess.run(["wslpath", "-w", full], check=True, capture_output=True,
                              text=True).stdout.strip()
    return full


def local_path(path):
    """*path* as this Python sees it: on Windows Python, /mnt/c/... is C:\\..."""
    return Path(analyzer_path(path) if os.name == "nt" else path)


def candidate_hosts(host):
    if host:
        return [host]
    hosts = ["localhost"]
    if in_wsl():  # the analyzer runs on the Windows side; without mirrored networking it is the gateway
        route = subprocess.run(["ip", "route"], capture_output=True, text=True).stdout
        m = re.search(r"default via (\S+)", route)
        if m:
            hosts.append(m.group(1))
    return hosts


def connect(host, port):
    errors = []
    for h in candidate_hosts(host):
        try:
            return ea.connect(h, port)
        except ea.ConnectionFailed as exc:
            errors.append(f"{h}:{port} ({exc})")
    sys.exit("Cannot reach the Ellisys analyzer: " + "; ".join(errors)
             + "\nIs the analyzer running with the Remote Control plugin enabled?"
             + (" From WSL, also allow port 12345 in the Windows firewall, or run this script"
                " with Windows Python." if in_wsl() else ""))


def pick_overview(analyzer, name):
    names = analyzer.overviews()
    if name:
        if name not in names:
            sys.exit(f"No overview {name!r}. Available: {', '.join(names)}")
        return name
    return next((n for n in names if "low energy" in n.lower()), None)


# -- Details XML -------------------------------------------------------------------------------
def _value(el):
    v = el.get("value")
    if v is None:
        v = el.get("Value")
    return (el.text or "").strip() if v is None else v


def parse_report(xml_text):
    """{name: value} of an item's Details XML: overview columns first, then the leaf fields.

    A name can occur several times (a field in a header and in the payload); the first wins.
    """
    fields = {}
    if not xml_text:
        return fields
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return fields
    columns = [el for el in root.iter() if (el.get("name") or el.get("Name")) == "Overview Columns"]
    seen = set()
    for container in columns:
        for el in container:
            name = el.get("name") or el.get("Name")
            if name and name not in fields:
                fields[name] = _value(el)
            seen.add(el)
    for el in root.iter():
        name = el.get("name") or el.get("Name")
        if not name or el in seen or name == "Overview Columns" or len(el):
            continue  # containers group fields; their values are summaries
        fields.setdefault(name, _value(el))
    return fields


# -- traversal ---------------------------------------------------------------------------------
def iter_packets(ov, fields, match, limit=None):
    """Yield (ItemRecord, line text) of the ISO packets: items without children, inside a
    matching line. The line text is the Item text of the packets' summary lines, which often
    names the stream ("CIS 0x01 ...") when the packet itself doesn't.

    The overview groups packets under summary lines, how deep depends on the decoder, so this
    descends into every matching line. Once LEAF_PROOF matching items in a row at one depth have
    no children, that depth is taken as the packet level and children are no longer counted
    (counting is one round-trip per item).
    """
    leaf_depth = None
    streak = {}
    count = 0

    def walk(cursor, depth, line):
        nonlocal leaf_depth, count
        for rec in cursor.stream_records(*fields):
            desc = rec.description or ""
            if line is None and not match(desc):
                continue
            text = desc if line is None else f"{line} {desc}"
            if leaf_depth is not None and depth >= leaf_depth:
                children = 0
            else:
                child = cursor[rec.position:rec.position + 1][0]
                child_cursor = child.cursor()
                children = child_cursor.total
            if children:
                streak[depth] = 0
                yield from walk(child_cursor, depth + 1, text)
            else:
                streak[depth] = streak.get(depth, 0) + 1
                if leaf_depth is None and streak[depth] >= LEAF_PROOF:
                    leaf_depth = depth
                yield rec, text
                count += 1
            if limit is not None and count >= limit:
                return

    yield from walk(ov.root.cursor(), 0, None)


def narrow_to_iso(ov):
    """Apply ISO_QUERY; returns False (query cleared) if it matched nothing."""
    try:
        ov.set_query(ISO_QUERY)
    except ea.OperationError:
        return False
    if ov.root.cursor().total:
        return True
    ov.set_query("")
    return False


def column_plan(names):
    """(header, {header: source name}) with the viewer's names first, then the raw columns."""
    taken, plan = set(), {}
    for canon, rx in CANONICAL:
        src = next((n for n in names if n not in taken and (n == canon or rx.match(n.strip()))), None)
        if src is not None:
            plan[canon] = src
            taken.add(src)
    header = ["Timestamp"] + list(plan) + [n for n in names if n not in taken and n != "Timestamp"]
    return header, plan


def to_row(rec, text, header, plan):
    f = parse_report(rec.xml)
    row = {"Timestamp": f"{rec.time_ps / 1e9:.6f}" if rec.time_ps is not None else ""}
    for h in header[1:]:
        row[h] = f.get(plan.get(h, h), "")
    # No CIS/BIS ID field: the Item text usually names the stream
    for canon, rx in (("CIS ID", CIS_IN_TEXT), ("BIS ID", BIS_IN_TEXT)):
        if canon in row and not row[canon]:
            m = rx.search(text)
            if m:
                row[canon] = m.group(1)
    return [row[h] for h in header]


def extract(analyzer, overview, query=None, sample=SAMPLE_PACKETS, log=print):
    """(header, rows) of the ISO packets in *overview* of the loaded trace."""
    with analyzer.overview(overview) as ov:
        if query:
            ov.set_query(query)
            match = lambda d: True
            log(f"Query: {query}")
        elif narrow_to_iso(ov):
            match = lambda d: True
            log(f"Query: {ISO_QUERY}")
        else:
            match = ISO_MATCH.search
            log("ISO query matched nothing; filtering by item text instead (slower)")

        # 1. Learn the field names from the first packets (full Details)
        names = []
        for rec, _ in iter_packets(ov, (ItemField.DESCRIPTION, ItemField.XML), match, limit=sample):
            for n in parse_report(rec.xml):
                if n not in names:
                    names.append(n)
        if not names:
            return [], []
        header, plan = column_plan(names)
        if "CIS ID" not in plan and "BIS ID" not in plan:
            header.insert(1, "CIS ID")  # filled from the Item text in to_row
        log("Columns: " + ", ".join(f"{h}<-{plan[h]}" if plan.get(h, h) != h else h for h in header))

        # 2. All packets, only those fields
        wanted = ItemField.xml_filtered("Overview Columns", *[n for n in names])
        rows = []
        for rec, text in iter_packets(ov, (ItemField.DESCRIPTION, ItemField.TIME, wanted), match):
            rows.append(to_row(rec, text, header, plan))
            if len(rows) % 10000 == 0:
                log(f"  {len(rows)} packets")
        return header, rows


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0],
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("trace", help=".btt file (a WSL path is converted for the Windows analyzer)")
    p.add_argument("-o", "--out", help="output .html (default: next to the trace)")
    p.add_argument("--host", help="analyzer host (default: localhost, then the Windows host from WSL)")
    p.add_argument("--port", type=int, default=12345)
    p.add_argument("--overview", help="overview name (default: the Low Energy overview)")
    p.add_argument("--query", help="Ellisys overview query selecting the packets, instead of the "
                                   "built-in CIS/BIS filter")
    p.add_argument("--devices", nargs="+", metavar="ADDR",
                   help="keep only these devices (AA:BB:CC:DD:EE:FF) — faster on busy captures")
    p.add_argument("--timeout", type=float, default=600, help="trace load timeout, s")
    p.add_argument("--explore", action="store_true",
                   help="print what the trace contains (overviews, item texts, field names, devices)")
    args = p.parse_args(argv)

    trace = analyzer_path(args.trace)
    out = local_path(args.out) if args.out else local_path(args.trace).with_suffix(".html")
    with connect(args.host, args.port) as analyzer:
        print(f"Loading {trace}")
        analyzer.load(trace, timeout=args.timeout)
        if args.explore:
            from ellisys_analysis_automation import discovery
            text = discovery.explore(analyzer, overview=pick_overview(analyzer, args.overview))
            print(text)
            out.with_suffix(".explore.txt").write_text(text, encoding="utf-8")
            return
        if args.devices:
            analyzer.bluetooth.configure_device_filter(ea.DeviceFilterMode.KEEP_ONLY, args.devices)
        try:
            overview = pick_overview(analyzer, args.overview)
            print(f"Overview: {overview or analyzer.active_overview()}")
            header, rows = extract(analyzer, overview, args.query)
        finally:
            if args.devices:
                analyzer.bluetooth.configure_device_filter(ea.DeviceFilterMode.KEEP_ALL, [])
    if not rows:
        sys.exit("No CIS/BIS packets found. Run with --explore to see what the trace contains, "
                 "then pass --overview / --query.")
    report.write_html(out, Path(args.trace).name, header, rows)
    print(f"{len(rows)} packets -> {out}")


if __name__ == "__main__":
    main()
