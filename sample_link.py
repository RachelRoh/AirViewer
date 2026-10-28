"""Sample capture for the procedure checks (prototype): one LE ACL link and two BR/EDR pages.

Every procedure below is placed on purpose; EXPECTED lists the verdict each one must get.
The LE link sends an empty PDU each way per connection event unless a control PDU is due.
"""
from procedures import Event

LE = "LE ACL 0x50654C3F"
PAGE_OK = "BR/EDR 00:1B:DC:01:02:03"
PAGE_LOST = "BR/EDR 00:1B:DC:0A:0B:0C"
PAGE_LATE = "BR/EDR 00:1B:DC:0D:0E:0F"
EVENTS = 6000                 # ~45 s: long enough for the 40 s LL timeout to run out
# Corrupted packets: (first event, last event, sender) — a burst of P→C errors, and one C→P
CORRUPT = [(1500, 1512, "P"), (2500, 2500, "C")]

# (event, sender, pdu, fields) — the control PDUs on the LE link
CONTROL = [
    (5, "C", "LL_VERSION_IND", {}), (6, "P", "LL_VERSION_IND", {}),
    (10, "C", "LL_FEATURE_REQ", {}), (11, "P", "LL_FEATURE_RSP", {}),
    (20, "C", "LL_LENGTH_REQ", {}),                                       # never answered
    (30, "C", "LL_CONNECTION_UPDATE_IND", {"Instant": 40, "Interval": 6}),  # 30 -> 7.5 ms, applied
    (100, "C", "LL_CHANNEL_MAP_IND", {"Instant": 110, "Channel Map": list(range(10, 37))}),  # ch 3 used at 115
    (150, "C", "LL_CHANNEL_MAP_IND", {"Instant": 160, "Channel Map": list(range(37))}),
    (200, "C", "LL_CONNECTION_UPDATE_IND", {"Instant": 205, "Interval": 12}),  # 15 ms, never applied
    (300, "C", "LL_PHY_REQ", {}), (301, "P", "LL_PHY_RSP", {}),
    (302, "C", "LL_PHY_UPDATE_IND", {"Instant": 310, "PHY C→P": "2M", "PHY P→C": "2M"}),
    (400, "C", "LL_CONNECTION_UPDATE_IND", {"Instant": 398, "Interval": 6}),  # instant already passed
    (500, "C", "LL_CIS_REQ", {}), (501, "P", "LL_CIS_RSP", {}), (502, "C", "LL_CIS_IND", {}),
    (600, "C", "LL_CIS_REQ", {}), (601, "P", "LL_REJECT_EXT_IND", {"Reject Opcode": "LL_CIS_REQ"}),
    (700, "C", "LL_ENC_REQ", {}), (701, "P", "LL_ENC_RSP", {}),
    # 702: P's LL_START_ENC_REQ is sent but not in the capture
    (703, "C", "LL_START_ENC_RSP", {}), (704, "P", "LL_START_ENC_RSP", {}),
    (900, "P", "LL_FEATURE_REQ", {}), (901, "C", "LL_FEATURE_RSP", {}),
    (EVENTS - 10, "C", "LL_FEATURE_REQ", {}),                              # capture ends first
]

# (rule, link, first event or time) -> verdict
EXPECTED = [
    ("Version Exchange", 5, "pass"),
    ("Feature Exchange", 10, "pass"),
    ("Data Length Update", 20, "timeout"),
    ("Connection Update", 30, "pass"),
    ("Channel Map Update", 100, "fail"),
    ("Channel Map Update", 150, "pass"),
    ("Connection Update", 200, "fail"),
    ("PHY Update (Central)", 300, "pass"),
    ("PHY Update Instant", 302, "pass"),
    ("Connection Update", 400, "fail"),
    ("CIS Establishment", 500, "pass"),
    ("CIS Establishment", 600, "rejected"),
    ("Encryption Start", 700, "missing"),
    ("Feature Exchange", 900, "pass"),
    ("Feature Exchange", EVENTS - 10, "unknown"),
    ("Page / Connection Setup", PAGE_OK, "pass"),
    ("Page / Connection Setup", PAGE_LOST, "timeout"),
    ("Page / Connection Setup", PAGE_LATE, "late"),
]


def _le_events():
    control = {(e, s): (pdu, f) for e, s, pdu, f in CONTROL}
    out, t = [], 0.010
    interval, chm, phy = 30e-3, list(range(37)), "1M"
    pending = {}                                  # instant -> change
    for e, s, pdu, f in CONTROL:
        if pdu == "LL_CONNECTION_UPDATE_IND" and e == 30:
            pending[f["Instant"]] = ("interval", f["Interval"] * 1.25e-3)
        elif pdu == "LL_CHANNEL_MAP_IND":
            pending[f["Instant"]] = ("chm", f["Channel Map"])
        elif pdu == "LL_PHY_UPDATE_IND":
            pending[f["Instant"]] = ("phy", f["PHY C→P"])
    for ec in range(EVENTS):
        kind, value = pending.get(ec, (None, None))
        if kind == "interval":
            interval = value
        elif kind == "chm":
            chm = value
        elif kind == "phy":
            phy = value
        ch = 3 if ec == 115 else chm[(ec * 7) % len(chm)]
        for k, s in enumerate(("C", "P")):
            if (ec, s) == (702, "P"):
                continue                          # lost by the sniffer
            pdu, f = control.get((ec, s), ("Empty", {}))
            crc = {"CRC": "Error"} if any(a <= ec <= b and s == who for a, b, who in CORRUPT) else {}
            out.append(Event(t + k * 150e-6, LE, s, pdu, ec, {"Channel": ch, "PHY": phy, **f, **crc}))
        t += interval
    return out


def _page(link, t0, answered, late_slots=0):
    """A page train of IDs, then the device's ID, FHS and (if *answered*) the rest; the device's
    second ID comes *late_slots* later than usual."""
    slot = 625e-6
    out = [Event(t0 + i * slot / 2, link, "C", "ID") for i in range(24)]
    t = t0 + 24 * slot / 2
    out += [Event(t, link, "P", "ID"), Event(t + slot, link, "C", "FHS")]
    if answered:
        t += late_slots * slot
        out += [Event(t + 2 * slot, link, "P", "ID"), Event(t + 4 * slot, link, "C", "POLL"),
                Event(t + 5 * slot, link, "P", "NULL")]
    return out


def events():
    evs = (_le_events() + _page(PAGE_OK, 1.0, True) + _page(PAGE_LOST, 2.0, False)
           + _page(PAGE_LATE, 3.0, True, late_slots=10))
    evs.sort(key=lambda e: e.t)
    for i, e in enumerate(evs):
        e.index = i
    return evs
