#!/usr/bin/env python3
"""Spec procedure checks: did what the spec says must happen actually happen on the link?

    python3 procedures.py --sample              -> procedures_sample.html (prototype)

The report is built around time: analyze() returns the problem points (findings) found in the
capture, the notable packets, and the procedure results, and the viewer shows what happened
around any point in time.

Rules are data (RULES), checked against a list of Events (one per packet). Two kinds:

- sequence: a trigger PDU starts a procedure; each following step must come from the given
  side within a time limit (LL_FEATURE_REQ -> LL_FEATURE_RSP, BR/EDR page ID -> ID -> FHS ...).
- instant: a PDU announces parameters that take effect at a connection event (its Instant);
  the link must use them from that event on (LL_CONNECTION_UPDATE_IND, LL_CHANNEL_MAP_IND ...).

PROTOTYPE: spec references and the numbers taken from the spec are not checked yet. Each rule
has spec=None and lists in "tbd" which of its values are provisional; the report shows both.
"""
import argparse
from dataclasses import dataclass, field

STATUSES = ("pass", "fail", "rejected", "timeout", "late", "missing", "unknown")
# pass      all steps seen / parameters applied at the instant
# fail      parameters not applied, instant already passed, ...
# rejected  the peer answered with a reject PDU
# timeout   a step did not come within its limit
# late      it came, but after its limit
# missing   the procedure went on, but a step in between is not in the capture (sniffer loss?)
# unknown   the capture ends (or lacks the fields) before the outcome is known


@dataclass
class Event:
    """One packet, as the checks see it (filled from the Ellisys trace, or by sample_link.py)."""
    t: float                    # s
    link: str                   # one link (LE access address, BR/EDR device ...)
    sender: str                 # "C" (Central / Master) or "P" (Peripheral / Slave)
    pdu: str                    # LL_FEATURE_REQ, ID, FHS, POLL, Empty ...
    event: int | None = None    # LE connection event counter
    fields: dict = field(default_factory=dict)
    index: int = 0              # position in the trace


def _seq(name, layer, steps, reject=(), tbd=("within",)):
    return {"name": name, "kind": "sequence", "layer": layer, "steps": steps,
            "reject": list(reject), "spec": None, "tbd": list(tbd)}


def _step(pdu, sender, within=None):
    """*sender*: "C", "P", "init" (who sent the trigger), "peer" (the other side) or "any"."""
    return {"pdu": [pdu] if isinstance(pdu, str) else list(pdu), "from": sender, "within": within}


LL_TIMEOUT = 40.0        # LL procedure response timeout, s (provisional)
LL_REJECT = ("LL_REJECT_EXT_IND", "LL_REJECT_IND", "LL_UNKNOWN_RSP")
SLOT = 625e-6

RULES = [
    _seq("Version Exchange", "LE LL", [
        _step("LL_VERSION_IND", "any"),
        _step("LL_VERSION_IND", "peer", LL_TIMEOUT)]),
    _seq("Feature Exchange", "LE LL", [
        _step(["LL_FEATURE_REQ", "LL_PERIPHERAL_FEATURE_REQ"], "any"),
        _step("LL_FEATURE_RSP", "peer", LL_TIMEOUT)], reject=LL_REJECT),
    _seq("Data Length Update", "LE LL", [
        _step("LL_LENGTH_REQ", "any"),
        _step("LL_LENGTH_RSP", "peer", LL_TIMEOUT)], reject=LL_REJECT),
    _seq("PHY Update (Central)", "LE LL", [
        _step("LL_PHY_REQ", "C"),
        _step("LL_PHY_RSP", "P", LL_TIMEOUT),
        _step("LL_PHY_UPDATE_IND", "C", LL_TIMEOUT)], reject=LL_REJECT),
    _seq("PHY Update (Peripheral)", "LE LL", [
        _step("LL_PHY_REQ", "P"),
        _step("LL_PHY_UPDATE_IND", "C", LL_TIMEOUT)], reject=LL_REJECT),
    _seq("Encryption Start", "LE LL", [
        _step("LL_ENC_REQ", "C"),
        _step("LL_ENC_RSP", "P", LL_TIMEOUT),
        _step("LL_START_ENC_REQ", "P", LL_TIMEOUT),
        _step("LL_START_ENC_RSP", "C", LL_TIMEOUT),
        _step("LL_START_ENC_RSP", "P", LL_TIMEOUT)], reject=LL_REJECT),
    _seq("CIS Establishment", "LE LL", [
        _step("LL_CIS_REQ", "C"),
        _step("LL_CIS_RSP", "P", LL_TIMEOUT),
        _step("LL_CIS_IND", "C", LL_TIMEOUT)], reject=LL_REJECT),
    # The page train repeats ID until the device answers; a repeated step restarts its timer
    _seq("Page / Connection Setup", "BR/EDR Baseband", [
        _step("ID", "C"),
        _step("ID", "P", 2 * SLOT),
        _step("FHS", "C", 2 * SLOT),
        _step("ID", "P", 8 * SLOT),
        _step("POLL", "C", 32 * SLOT),
        _step(["NULL", "DM1", "DH1"], "P", 32 * SLOT)]),
    {"name": "Connection Update", "kind": "instant", "layer": "LE LL",
     "trigger": "LL_CONNECTION_UPDATE_IND", "check": "interval",
     "spec": None, "tbd": ["Instant 이후 첫 간격 판정", "허용 오차 50 µs"]},
    {"name": "Channel Map Update", "kind": "instant", "layer": "LE LL",
     "trigger": "LL_CHANNEL_MAP_IND", "check": "channels", "spec": None, "tbd": []},
    {"name": "PHY Update Instant", "kind": "instant", "layer": "LE LL",
     "trigger": "LL_PHY_UPDATE_IND", "check": "phy", "spec": None, "tbd": []},
]
INTERVAL_TOL = 50e-6     # s (provisional)


# -- sequence rules -----------------------------------------------------------------------------
def _side_ok(step, sender, initiator):
    want = step["from"]
    return (want == "any" or want == sender or (want == "init" and sender == initiator)
            or (want == "peer" and sender != initiator))


def _dur(s):
    return f"{s:g} s" if s >= 1 else f"{s * 1e3:g} ms"


def _step_result(step, ev=None, captured=True):
    return {"label": " / ".join(step["pdu"]), "sender": ev.sender if ev else step["from"],
            "t": ev.t if ev else None, "event": ev.event if ev else None,
            "index": ev.index if ev else None, "captured": captured}


class _Open:
    def __init__(self, rule, ev):
        self.rule, self.link, self.initiator = rule, ev.link, ev.sender
        self.steps = [_step_result(rule["steps"][0], ev)]
        self.last = ev
        self.gap = False

    @property
    def next(self):
        return len(self.steps)

    def expected_sender(self, k):
        want = self.rule["steps"][k]["from"]
        return {"init": self.initiator, "peer": "P" if self.initiator == "C" else "C"}.get(want, want)

    def result(self, status, detail, t_end=None):
        steps = list(self.steps)
        reached = self.next
        if status == "rejected":
            reached -= 1                                       # the last entry is the reject PDU
        for k in range(reached, len(self.rule["steps"]) if status != "rejected" else 0):  # never reached
            s = _step_result(self.rule["steps"][k], captured=False)
            s["sender"] = self.expected_sender(k)
            steps.append(s)
        for k, s in enumerate(steps):
            if s["sender"] in ("any", "init", "peer"):
                s["sender"] = self.expected_sender(k) if k else self.initiator
            is_reject = status == "rejected" and k == len(steps) - 1      # the reject PDU, not a step
            s["within"] = None if is_reject or k >= len(self.rule["steps"]) else self.rule["steps"][k]["within"]
        chain = []
        for k, st in enumerate(self.rule["steps"]):
            who = self.expected_sender(k) if k else self.initiator
            chain.append(f"{'C→P' if who == 'C' else 'P→C'} {' / '.join(st['pdu'])}"
                         + (f" ({_dur(st['within'])} 안에)" if st["within"] else ""))
        return {"rule": self.rule["name"], "kind": "sequence", "layer": self.rule["layer"],
                "link": self.link, "status": status, "detail": detail, "expected": " → ".join(chain),
                "t": self.steps[0]["t"],
                "t_end": t_end if t_end is not None else max(s["t"] for s in steps if s["t"] is not None),
                "steps": steps, "reached": reached, "spec": self.rule["spec"],
                "tbd": self.rule["tbd"]}


def _rejects(ev, inst, open_):
    """Does reject PDU *ev* end *inst*? It names the rejected opcode ("Reject Opcode"); without
    that field, it is taken as the answer to the newest open procedure on the link."""
    opcode = ev.fields.get("Reject Opcode")
    if opcode is not None:
        return opcode in inst.last.pdu or any(opcode in s["pdu"] for s in inst.rule["steps"][:inst.next])
    newest = max((i for i in open_ if i.link == ev.link), key=lambda i: i.steps[0]["t"])
    return newest is inst


def check_sequences(events, rules=None):
    rules = [r for r in (rules or RULES) if r["kind"] == "sequence"]
    t_end = events[-1].t if events else 0.0
    open_, results = [], []
    overdue = []    # (result, procedure, step) of timeouts whose answer may still come: then "late"

    def close(inst, status, detail, t_end=None):
        open_.remove(inst)
        results.append(inst.result(status, detail, t_end))
        return results[-1]

    def time_out(inst, nxt):
        r = close(inst, "timeout", f"{nxt['pdu'][0]} 없음 ({_dur(nxt['within'])} 안에)",
                  inst.last.t + nxt["within"])
        overdue.append((r, inst, nxt))

    for ev in events:
        # Time out first: this packet may be the late answer
        for inst in [i for i in open_ if i.link == ev.link]:
            nxt = inst.rule["steps"][inst.next]
            if nxt["within"] is not None and ev.t - inst.last.t > nxt["within"]:
                time_out(inst, nxt)
        consumed = False
        for entry in [o for o in overdue if o[1].link == ev.link]:
            r, inst, nxt = entry
            if ev.pdu in nxt["pdu"] and _side_ok(nxt, ev.sender, inst.initiator):
                k = r["reached"]
                r["steps"][k] = {**_step_result(nxt, ev), "late": True, "within": nxt["within"]}
                r.update(status="late", reached=k + 1, t_end=ev.t, detail=(
                    f"{ev.pdu} {_dur(ev.t - inst.last.t)} 뒤에 옴 (한도 {_dur(nxt['within'])})"))
                overdue.remove(entry)
                consumed = True
                break
        if consumed:
            continue
        for inst in [i for i in open_ if i.link == ev.link]:
            steps = inst.rule["steps"]
            if ev.pdu in inst.rule["reject"] and ev.sender != inst.last.sender and _rejects(ev, inst, open_):
                inst.steps.append({"label": ev.pdu, "sender": ev.sender, "t": ev.t,
                                   "event": ev.event, "index": ev.index, "captured": True})
                close(inst, "rejected", f"{ev.pdu}로 거절됨")
                consumed = True
                continue
            prev = steps[inst.next - 1]
            if ev.pdu in prev["pdu"] and ev.sender == inst.last.sender:
                inst.last = ev                 # retransmission / page train: same step again
                s = inst.steps[-1]
                s["repeats"] = s.get("repeats", 1) + 1
                s["t_last"] = ev.t
                consumed = True
                continue
            # The next step, or a later one (the ones in between are not in the capture)
            for k in range(inst.next, len(steps)):
                if ev.pdu in steps[k]["pdu"] and _side_ok(steps[k], ev.sender, inst.initiator):
                    for j in range(inst.next, k):
                        missed = _step_result(steps[j], captured=False)
                        missed["sender"] = inst.expected_sender(j)
                        inst.steps.append(missed)
                        inst.gap = True
                    inst.steps.append(_step_result(steps[k], ev))
                    inst.last = ev
                    consumed = True
                    break
            if consumed and inst.next == len(steps):
                if inst.gap:
                    close(inst, "missing", "절차는 끝났지만 중간 단계가 캡처에 없음")
                else:
                    close(inst, "pass", f"{len(steps)}단계 모두 확인")
            if consumed:
                break
        if consumed:
            continue
        for rule in rules:
            first = rule["steps"][0]
            if (ev.pdu in first["pdu"] and _side_ok(first, ev.sender, ev.sender)
                    and not any(i.rule is rule and i.link == ev.link for i in open_)):
                open_.append(_Open(rule, ev))
                # a new attempt: an old timeout of this procedure is no longer answered late
                overdue[:] = [o for o in overdue if not (o[1].rule is rule and o[1].link == ev.link)]
                break

    for inst in list(open_):
        nxt = inst.rule["steps"][inst.next]
        if nxt["within"] is not None and t_end - inst.last.t > nxt["within"]:
            time_out(inst, nxt)
        else:
            close(inst, "unknown", f"{nxt['pdu'][0]}를 기다리는 중에 캡처가 끝남")
    return results


# -- instant rules ------------------------------------------------------------------------------
def _link_events(events):
    """Per link: {event counter: {"anchor": t, "channels": set, "phy": {sender: phy}}}."""
    out = {}
    for ev in events:
        if ev.event is None:
            continue
        e = out.setdefault(ev.link, {}).setdefault(ev.event, {"anchor": ev.t, "channels": set(), "phy": {}})
        e["anchor"] = min(e["anchor"], ev.t)
        if "Channel" in ev.fields:
            e["channels"].add(ev.fields["Channel"])
        if "PHY" in ev.fields:
            e["phy"].setdefault(ev.sender, ev.fields["PHY"])
    return out


def _instant_expected(rule, ev, instant):
    if rule["check"] == "interval" and "Interval" in ev.fields:
        what = f"연결 간격 {ev.fields['Interval'] * 1.25:g} ms"
    elif rule["check"] == "channels" and "Channel Map" in ev.fields:
        what = f"새 채널 맵 ({len(ev.fields['Channel Map'])}개 채널)만"
    elif rule["check"] == "phy":
        what = f"PHY C→P {ev.fields.get('PHY C→P')}, P→C {ev.fields.get('PHY P→C')}"
    else:
        what = "새 값"
    return f"이벤트 {instant}(Instant)부터 {what} 사용 · Instant는 송신 이벤트 {ev.event}보다 뒤"


def _instant_result(rule, ev, status, detail, checks, instant, t_instant=None, evidence=None):
    steps = [_step_result({"pdu": [ev.pdu], "from": ev.sender}, ev)]
    steps.append({"label": f"Instant {instant}" if instant is not None else "Instant ?",
                  "sender": "instant", "t": t_instant, "event": instant, "index": None, "captured": True})
    return {"rule": rule["name"], "kind": "instant", "layer": rule["layer"], "link": ev.link,
            "status": status, "detail": detail, "expected": _instant_expected(rule, ev, instant),
            "t": ev.t, "t_end": t_instant or ev.t,
            "steps": steps, "checks": checks, "evidence": evidence or [], "spec": rule["spec"], "tbd": rule["tbd"]}


def _check_instant(rule, ev, link, until=None):
    """*until*: the next instant of the same procedure on the link; its parameters apply from there."""
    instant = ev.fields.get("Instant")
    if instant is None or ev.event is None:
        return _instant_result(rule, ev, "unknown", "Instant 또는 Event Counter 필드 없음", [], instant)
    if (instant - ev.event) % 65536 >= 32767:
        return _instant_result(rule, ev, "fail",
                               f"Instant {instant}가 이미 지남 (송신 이벤트 {ev.event})", [], instant)
    after = sorted(e for e in link if e >= instant and (until is None or e < until))
    if not after:
        return _instant_result(rule, ev, "unknown", "Instant 이후가 캡처에 없음", [], instant)
    result = lambda status, detail, checks, evidence=None: _instant_result(
        rule, ev, status, detail, checks, instant, link[after[0]]["anchor"], evidence)

    if rule["check"] == "interval":
        want = ev.fields["Interval"] * 1.25e-3
        before = [e for e in sorted(link) if ev.event <= e < instant and e + 1 in link and e + 1 < instant]
        old = link[before[-1] + 1]["anchor"] - link[before[-1]]["anchor"] if before else None
        pair = next((e for e in after if e + 1 in link and e > instant), None)
        if pair is None:
            return result("unknown", "Instant 이후 연속한 이벤트가 없음", [])
        got = link[pair + 1]["anchor"] - link[pair]["anchor"]
        checks = [f"Instant 전 간격 {old * 1e3:.3f} ms" if old is not None else "Instant 전 간격: 측정 불가",
                  f"이벤트 {pair}→{pair + 1} 간격 {got * 1e3:.3f} ms (기대 {want * 1e3:.3f} ms)"]
        ok = abs(got - want) <= INTERVAL_TOL
        evidence = []
        for e in range(instant - 3, pair + 3):
            if e in link:
                d = link[e]["anchor"] - link[e - 1]["anchor"] if e - 1 in link else None
                evidence.append({"event": e, "t": link[e]["anchor"], "value": d,
                                 "expect": (want if e > instant else None if e == instant else old)
                                 if d is not None else None,
                                 "note": "Instant" if e == instant else ""})
        return result("pass" if ok else "fail",
                      f"새 간격 {want * 1e3:g} ms " + ("적용됨" if ok else f"미적용 (실제 {got * 1e3:.3f} ms)"), checks, evidence)

    if rule["check"] == "channels":
        chm = set(ev.fields["Channel Map"])
        bad = [(e, sorted(link[e]["channels"] - chm)) for e in after if link[e]["channels"] - chm]
        checks = [f"새 맵 {len(chm)}개 채널, Instant 이후 {len(after)}개 이벤트 확인"]
        if bad:
            e, chs = bad[0]
            more = f" 외 {len(bad) - 1}개 이벤트" if len(bad) > 1 else ""
            checks.append(f"맵에 없는 채널 사용: 이벤트 {e} ch {', '.join(map(str, chs))}{more}")
            evidence = [{"event": e2, "t": link[e2]["anchor"], "value": ", ".join(map(str, c2)), "note": "맵에 없음"}
                        for e2, c2 in bad[:20]]
            return result("fail", f"Instant 이후 맵에 없는 채널 사용 ({len(bad)}개 이벤트)", checks, evidence)
        return result("pass", "Instant 이후 모든 채널이 새 맵 안에 있음", checks)

    if rule["check"] == "phy":
        want = {"C": ev.fields.get("PHY C→P"), "P": ev.fields.get("PHY P→C")}
        bad = [(e, s, p) for e in after for s, p in link[e]["phy"].items() if want.get(s) and p != want[s]]
        checks = [f"기대 PHY C→P {want['C']}, P→C {want['P']}"]
        if bad:
            e, s, p = bad[0]
            checks.append(f"이벤트 {e} {'C→P' if s == 'C' else 'P→C'} {p}")
            evidence = [{"event": e2, "t": link[e2]["anchor"], "value": f"{'C→P' if s2 == 'C' else 'P→C'} {p2}",
                         "note": f"기대 {want[s2]}"} for e2, s2, p2 in bad[:20]]
            return result("fail", f"Instant 이후 이전 PHY 사용 ({len(bad)}건)", checks, evidence)
        return result("pass", "Instant 이후 새 PHY 사용", checks)
    raise ValueError(rule["check"])


def check_instants(events, rules=None):
    rules = {r["trigger"]: r for r in (rules or RULES) if r["kind"] == "instant"}
    links = _link_events(events)
    triggers = [ev for ev in events if ev.pdu in rules]
    out = []
    for i, ev in enumerate(triggers):
        # Instants that already passed never take effect, so they don't bound the earlier one
        later = [x.fields.get("Instant") for x in triggers[i + 1:]
                 if x.pdu == ev.pdu and x.link == ev.link and x.fields.get("Instant") is not None
                 and x.event is not None and (x.fields["Instant"] - x.event) % 65536 < 32767]
        out.append(_check_instant(rules[ev.pdu], ev, links.get(ev.link, {}), min(later, default=None)))
    return out


def check(events, rules=None):
    """All procedure results, in trace order."""
    results = check_sequences(events, rules) + check_instants(events, rules)
    return sorted(results, key=lambda r: r["t"])


# -- findings: the points in time worth looking at ----------------------------------------------
BURST_GAP = 0.1          # s: corrupted packets closer than this are one finding

FINDING_KINDS = {
    # kind: (label, procedure statuses it comes from)
    "corrupt": ("깨짐", ()),
    "absent": ("안 옴", ("timeout",)),
    "late": ("늦게 옴", ("late",)),
    "not_applied": ("적용 안 됨", ("fail",)),
    "rejected": ("거절", ("rejected",)),
    "capture": ("캡처 누락 의심", ("missing",)),
    "unknown": ("판정 불가", ("unknown",)),
}


def is_corrupt(ev):
    crc = ev.fields.get("CRC")
    return crc is not None and str(crc).upper() not in ("OK", "PASS", "GOOD")


def corrupt_bursts(events):
    """Corrupted packets per link, grouped into bursts: [(link, [events])]."""
    bursts, last = [], {}
    for ev in events:
        if not is_corrupt(ev):
            continue
        b = last.get(ev.link)
        if b is not None and ev.t - b[1][-1].t <= BURST_GAP:
            b[1].append(ev)
        else:
            last[ev.link] = (ev.link, [ev])
            bursts.append(last[ev.link])
    return bursts


def findings(results, events):
    """Problem points in time order: failed procedures and bursts of corrupted packets."""
    kind_of = {s: k for k, (_, statuses) in FINDING_KINDS.items() for s in statuses}
    out = []
    for i, r in enumerate(results):
        if r["status"] == "pass":
            continue
        out.append({"kind": kind_of[r["status"]], "t": r["t"], "t_end": r["t_end"], "link": r["link"],
                    "title": r["rule"], "detail": r["detail"], "procedure": i})
    for link, evs in corrupt_bursts(events):
        sides = sorted({"C→P" if e.sender == "C" else "P→C" for e in evs})
        out.append({"kind": "corrupt", "t": evs[0].t, "t_end": evs[-1].t, "link": link,
                    "title": f"CRC 에러 {len(evs)}개", "procedure": None,
                    "detail": f"{', '.join(sides)} · {_dur(evs[-1].t - evs[0].t) if len(evs) > 1 else '1개'}"})
    return sorted(out, key=lambda f: f["t"])


def air_log(events):
    """Every packet, for the report's air log (the page hides empty PDUs unless asked)."""
    return [{"t": e.t, "link": e.link, "sender": e.sender, "pdu": e.pdu, "event": e.event,
             "index": e.index, "corrupt": is_corrupt(e),
             "fields": {k: v for k, v in e.fields.items() if k not in ("PHY", "CRC")}}
            for e in events]


def analyze(events, rules=None):
    """What the report embeds: findings, every packet, procedure results, capture span."""
    results = check(events, rules)
    return {"findings": findings(results, events), "events": air_log(events), "procedures": results,
            "span": [events[0].t, events[-1].t] if events else [0, 0]}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--sample", action="store_true", help="check the built-in sample link (prototype)")
    p.add_argument("-o", "--out", default="procedures_sample.html")
    args = p.parse_args(argv)
    if not args.sample:
        p.error("only --sample for now: checks on Ellisys traces come with airviewer.py")
    import report
    import sample_link
    events = sample_link.events()
    data = analyze(events)
    # ISO packets: the page's LE Audio sample, starting just after the CIS is established
    cis_ind = next(e.t for e in events if e.pdu == "LL_CIS_IND")
    report.write_html(args.out, "Sample: LE ACL + CIS + BR/EDR page",
                      iso_sample={"offset_ms": round((cis_ind + 0.010) * 1e3, 3)}, **data)
    counts = {}
    for f in data["findings"]:
        counts[FINDING_KINDS[f["kind"]][0]] = counts.get(FINDING_KINDS[f["kind"]][0], 0) + 1
    print(f"{len(data['findings'])} findings {counts}, {len(data['events'])} packets "
          f"(+ ISO sample analyzed in the page) -> {args.out}")


if __name__ == "__main__":
    main()
