"""Write the report: a copy of template/report_template.html with the data embedded."""
import base64
import datetime
import gzip
import json
import os
import pathlib
import shutil
import subprocess
import webbrowser
from pathlib import Path

TEMPLATE = Path(__file__).resolve().parent / "template" / "report_template.html"
GZIP_ABOVE = 8 * 1024 * 1024  # JSON larger than this is stored gzip+base64 (about 5-10x smaller)


def write_html(path, source, headers=(), rows=(), force_gzip=False, **analysis):
    """*headers*/*rows*: ISO packets for the ISO views; *analysis*: what procedures.analyze
    returns, plus optional "iso" parameters (BN/FT ...) for the ISO analysis."""
    report = {"source": source, "generated": datetime.datetime.now().isoformat(timespec="seconds"),
              "headers": list(headers), "rows": list(rows), **analysis}
    raw = json.dumps(report, ensure_ascii=False, separators=(",", ":"))
    if force_gzip or len(raw.encode("utf-8")) > GZIP_ABOVE:
        payload = base64.b64encode(gzip.compress(raw.encode("utf-8"), 6)).decode("ascii")
        tag = (f'<script type="application/octet-stream" id="embeddedReport" data-encoding="gzip+base64">'
               f'{payload}</script>\n')
    else:
        # Keep packet text from closing the <script> element or breaking JS parsing
        safe = raw.replace("<", "\\u003c").replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")
        tag = f'<script type="application/json" id="embeddedReport">{safe}</script>\n'
    page = TEMPLATE.read_text(encoding="utf-8")
    page = page.replace("<body>\n", "<body>\n" + tag, 1)
    Path(path).write_text(page, encoding="utf-8", newline="\n")


def open_file(path):
    """Open in the default browser; from WSL, hand the Windows path to the Windows browser."""
    is_wsl = hasattr(os, "uname") and "microsoft" in os.uname().release.lower()
    if is_wsl:
        if shutil.which("wslview"):
            subprocess.run(["wslview", str(path)])
            return
        if shutil.which("explorer.exe") and shutil.which("wslpath"):
            win = subprocess.run(["wslpath", "-w", os.path.abspath(path)], capture_output=True, text=True).stdout.strip()
            subprocess.run(["explorer.exe", win])  # explorer.exe exits non-zero even on success
            return
    webbrowser.open(pathlib.Path(path).resolve().as_uri())  # file:///C:/... on Windows
