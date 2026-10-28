"""Write the report: a copy of template/report_template.html with the data embedded."""
import datetime
import json
from pathlib import Path

TEMPLATE = Path(__file__).resolve().parent / "template" / "report_template.html"


def write_html(path, source, headers=(), rows=(), **analysis):
    """*headers*/*rows*: ISO packets for the ISO tabs; *analysis*: what procedures.analyze returns."""
    report = {"source": source, "generated": datetime.datetime.now().isoformat(timespec="seconds"),
              "headers": list(headers), "rows": list(rows), **analysis}
    # "<" escaped so packet text can never close the <script> element
    data = json.dumps(report, ensure_ascii=False, separators=(",", ":")).replace("<", "\\u003c")
    page = TEMPLATE.read_text(encoding="utf-8")
    tag = f'<script type="application/json" id="embeddedReport">{data}</script>\n'
    page = page.replace("<body>\n", "<body>\n" + tag, 1)
    Path(path).write_text(page, encoding="utf-8")
