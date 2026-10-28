"""Checks for airviewer.py against a fake analyzer (no Ellisys app or SDK needed).

    python3 tests/test_airviewer.py
"""
import json
import re
import sys
import tempfile
import types
import unittest
from dataclasses import dataclass
from pathlib import Path

# -- fake SDK: only the surface airviewer.py uses ------------------------------------------------
sdk = types.ModuleType("ellisys_analysis_automation")


class ItemField:
    DESCRIPTION, TIME, XML = "description", "time", "xml"

    @staticmethod
    def xml_filtered(*names):
        return ("xml", names)


@dataclass
class ItemRecord:
    position: int
    description: str = None
    time_ps: int = None
    xml: str = None


class Node:
    def __init__(self, desc, time_ps=0, fields=None, columns=None, children=()):
        self.desc, self.time_ps, self.children = desc, time_ps, list(children)
        self.fields, self.columns = fields or {}, columns or {}

    def xml(self, names=None):
        keep = lambda n: names is None or n in names
        cols = "".join(f'<Item name="{k}" value="{v}"/>' for k, v in self.columns.items())
        body = "".join(f'<Item name="{k}" value="{v}"/>' for k, v in self.fields.items() if keep(k))
        over = f'<Item name="Overview Columns">{cols}</Item>' if keep("Overview Columns") else ""
        # Details group fields under containers, as the real report does
        return f'<Report>{over}<Item name="Link Layer">{body}</Item></Report>'


class Cursor:
    def __init__(self, scope, node):
        self.scope, self.node = scope, node

    @property
    def total(self):
        self.scope.counts += 1
        return len(self.scope.visible(self.node))

    def stream_records(self, *fields):
        for i, n in enumerate(self.scope.visible(self.node)):
            rec = ItemRecord(i)
            for f in fields:
                if f == ItemField.DESCRIPTION:
                    rec.description = n.desc
                elif f == ItemField.TIME:
                    rec.time_ps = n.time_ps
                elif f == ItemField.XML:
                    rec.xml = n.xml()
                else:
                    rec.xml = n.xml(f[1])
            yield rec

    def __getitem__(self, s):
        return [Item(self.scope, n) for n in self.scope.visible(self.node)[s]]


class Item:
    def __init__(self, scope, node):
        self.scope, self.node = scope, node

    def cursor(self):
        return Cursor(self.scope, self.node)


class Scope:
    def __init__(self, tree):
        self.tree, self.query, self.counts = tree, "", 0

    def visible(self, node):
        if node is self.tree and 'Item = "**CIS**"' in self.query:
            return [n for n in node.children if "CIS" in n.desc]
        return node.children

    @property
    def root(self):
        return Item(self, self.tree)

    def set_query(self, q):
        self.query = q

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class Analyzer:
    def __init__(self, tree, query_works=True):
        self.scope = Scope(tree)
        if not query_works:
            self.scope.visible = lambda node: node.children if node is not tree or "**" not in self.scope.query else []

    def overviews(self):
        return ["BR/EDR Overview", "Low Energy Overview"]

    def overview(self, name):
        return self.scope


class OperationError(Exception):
    pass


sdk.ItemField, sdk.OperationError, sdk.ConnectionFailed = ItemField, OperationError, OSError
sys.modules["ellisys_analysis_automation"] = sdk
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import airviewer  # noqa: E402


def capture(events=30):
    """Advertising + CIS 0x01/0x02 event lines, each with a C->P and a P->C packet."""
    top = []
    for ec in range(events):
        top.append(Node("ADV_IND", ec * 10_000_000_000))
        for cis in (1, 2):
            t = ec * 10_000_000_000 + cis * 1_000_000_000
            pkts = [Node("LL Data", t + k * 150_000_000,
                         columns={"Item": "LL Data", "Communication": d},
                         fields={"CIS Event Counter": ec, "Sub-Event Number": 1, "SN": ec % 2,
                                 "NESN": ec % 2, "NPI": 0, "Length": 40, "Data": "00 11",
                                 "CRC": "OK", "RF Channel": 3, "RSSI": -40})
                    for k, d in enumerate(("Central to Peripheral", "Peripheral to Central"))]
            top.append(Node(f"CIS 0x0{cis} Event {ec}", t, children=pkts))
    return Node("root", children=top)


class Extract(unittest.TestCase):
    def run_extract(self, analyzer):
        return airviewer.extract(analyzer, "Low Energy Overview", log=lambda *a: None)

    def test_packets_and_columns(self):
        header, rows = self.run_extract(Analyzer(capture()))
        self.assertEqual(len(rows), 30 * 2 * 2)  # no advertising, no summary lines
        for name in ("Timestamp", "CIS ID", "Event Counter", "Subevent", "SN", "NESN", "NPI",
                     "CRC", "Payload Length", "Payload", "Channel", "RSSI"):
            self.assertIn(name, header)
        canon = header.index("RSSI")
        self.assertLess(canon, header.index("Communication"), "viewer columns come first")
        row = dict(zip(header, rows[2]))
        self.assertEqual(row["CIS ID"], "0x02")  # from the Item text of the event line
        self.assertEqual(row["Event Counter"], "0")
        self.assertEqual(row["Timestamp"], "2.000000")  # ms

    def test_fallback_without_query(self):
        header, rows = self.run_extract(Analyzer(capture(), query_works=False))
        self.assertEqual(len(rows), 120)

    def test_stops_counting_children_at_packet_level(self):
        a = Analyzer(capture(200))
        self.run_extract(a)
        # top level is counted per event line, packets only until LEAF_PROOF leaves in a row
        self.assertLess(a.scope.counts, 2 * (400 + 2 * airviewer.LEAF_PROOF + airviewer.SAMPLE_PACKETS))

    def test_nothing_found(self):
        self.assertEqual(self.run_extract(Analyzer(Node("root", children=[Node("ADV_IND")]))), ([], []))


class Output(unittest.TestCase):
    def test_html_embeds_rows_safely(self):
        header, rows = ["Timestamp", "Payload"], [["1.0", "</script><b>x"]]
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "r.html"
            airviewer.report.write_html(out, "a.btt", header, rows)
            page = out.read_text(encoding="utf-8")
        m = re.search(r'<script type="application/json" id="embeddedReport">(.*?)</script>', page, re.S)
        self.assertIsNotNone(m)
        self.assertEqual(json.loads(m.group(1))["rows"], rows)
        self.assertLess(page.index('id="embeddedReport"'), page.index("<script>"))

    def test_paths(self):
        self.assertEqual(airviewer.analyzer_path(r"C:\t\a.btt"), r"C:\t\a.btt")
        self.assertEqual(airviewer.analyzer_path("/mnt/c/traces/a b.btt"), r"C:\traces\a b.btt")
        self.assertEqual(airviewer.candidate_hosts("10.0.0.2"), ["10.0.0.2"])


if __name__ == "__main__":
    unittest.main()
