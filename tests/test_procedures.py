"""Checks for procedures.py on the sample link (sample_link.py).

    python3 tests/test_procedures.py
"""
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import procedures  # noqa: E402
import report  # noqa: E402
import sample_link  # noqa: E402
from procedures import Event  # noqa: E402


def find(results, rule, where):
    """The result of *rule* started at LE event *where*, or on BR/EDR link *where*."""
    for r in results:
        if r["rule"] != rule:
            continue
        if isinstance(where, str) and r["link"] == where:
            return r
        if isinstance(where, int) and r["steps"][0]["event"] == where:
            return r
    return None


class Sample(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.results = procedures.check(sample_link.events())

    def test_every_injected_case(self):
        for rule, where, status in sample_link.EXPECTED:
            with self.subTest(rule=rule, where=where):
                r = find(self.results, rule, where)
                self.assertIsNotNone(r, "not found")
                self.assertEqual(r["status"], status, r["detail"])

    def test_nothing_else(self):
        self.assertEqual(len(self.results), len(sample_link.EXPECTED))

    def test_missing_step_is_marked(self):
        r = find(self.results, "Encryption Start", 700)
        self.assertEqual([s["captured"] for s in r["steps"]], [True, True, False, True, True])

    def test_unreached_steps_listed(self):
        r = find(self.results, "Page / Connection Setup", sample_link.PAGE_LOST)
        self.assertEqual(r["reached"], 3)
        self.assertEqual([s["label"] for s in r["steps"][3:]], ["ID", "POLL", "NULL / DM1 / DH1"])

    def test_late_answer(self):
        r = find(self.results, "Page / Connection Setup", sample_link.PAGE_LATE)
        self.assertTrue(r["steps"][3].get("late"))
        self.assertIn("한도 5 ms", r["detail"])

    def test_findings(self):
        f = procedures.analyze(sample_link.events())["findings"]
        kinds = [x["kind"] for x in f]
        self.assertEqual(kinds.count("corrupt"), 2)        # the P→C burst and the single C→P error
        burst = next(x for x in f if x["kind"] == "corrupt")
        self.assertEqual(burst["title"], "CRC 에러 13개")
        self.assertEqual(len(f), sum(s != "pass" for _, _, s in sample_link.EXPECTED) + 2)
        self.assertEqual([x["t"] for x in f], sorted(x["t"] for x in f))

    def test_spec_left_open(self):
        self.assertTrue(all(r["spec"] is None for r in self.results))


class Rules(unittest.TestCase):
    def test_reject_without_opcode_answers_newest(self):
        evs = [Event(0.0, "L", "C", "LL_LENGTH_REQ"), Event(0.1, "L", "C", "LL_CIS_REQ"),
               Event(0.2, "L", "P", "LL_REJECT_EXT_IND"), Event(50.0, "L", "C", "Empty")]
        st = {r["rule"]: r["status"] for r in procedures.check_sequences(evs)}
        self.assertEqual(st, {"Data Length Update": "timeout", "CIS Establishment": "rejected"})

    def test_retransmission_is_not_a_new_procedure(self):
        evs = [Event(0.0, "L", "C", "LL_FEATURE_REQ"), Event(0.01, "L", "C", "LL_FEATURE_REQ"),
               Event(0.02, "L", "P", "LL_FEATURE_RSP")]
        self.assertEqual([r["status"] for r in procedures.check_sequences(evs)], ["pass"])

    def test_links_are_separate(self):
        evs = [Event(0.0, "A", "C", "LL_FEATURE_REQ"), Event(0.01, "B", "P", "LL_FEATURE_RSP")]
        self.assertEqual([r["status"] for r in procedures.check_sequences(evs)], ["unknown"])


class Output(unittest.TestCase):
    def test_report_embeds_procedures(self):
        data = procedures.analyze(sample_link.events())
        results = data["procedures"]
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "p.html"
            report.write_html(out, "sample", **data)
            page = out.read_text(encoding="utf-8")
        m = re.search(r'id="embeddedReport">(.*?)</script>', page, re.S)
        data = json.loads(m.group(1))
        self.assertEqual(len(data["procedures"]), len(results))
        self.assertEqual(data["rows"], [])

    def test_sample_report_asks_for_iso_after_cis(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "s.html"
            procedures.main(["--sample", "-o", str(out)])
            page = out.read_text(encoding="utf-8")
        data = json.loads(re.search(r'id="embeddedReport">(.*?)</script>', page, re.S).group(1))
        cis_ind = next(e.t for e in sample_link.events() if e.pdu == "LL_CIS_IND")
        self.assertGreater(data["iso_sample"]["offset_ms"], cis_ind * 1e3)


if __name__ == "__main__":
    unittest.main()
