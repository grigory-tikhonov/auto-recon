import json
from datetime import datetime
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
TEMPLATE_PATH = BASE_DIR / "templates" / "report.html"

def _esc(x):
    return (str(x)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;"))


class ReportGenerator:
    def __init__(self, target):
        self.target = target
        self.timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        self.report_dir = Path("reports") / f"scan_{target.replace('.', '_')}_{self.timestamp}"
        self.report_dir.mkdir(parents=True, exist_ok=True)

    def _build_data(self, scan_results, findings, enriched, msf_map):
        exploits_map, auxiliary_map = {}, {}
        for cve, modules in msf_map.items():
            for m in modules:
                if m.startswith("exploit/"):
                    exploits_map.setdefault(cve, []).append(m)
                else:
                    auxiliary_map.setdefault(cve, []).append(m)

        nvd_hm = sum(
            len([c for c in s.get("cves", []) if c.get("confidence") in ("HIGH", "MEDIUM")])
            for s in enriched
        )

        return {
            "meta": {
                "target": self.target,
                "timestamp": self.timestamp,
                "generated_at": datetime.now().isoformat(timespec="seconds"),
                "tool": "auto-recon (passive scanner)",
            },
            "summary": {
                "open_ports": len(scan_results),
                "builtin_findings": len(findings),
                "nvd_findings_hm": nvd_hm,
                "exploitable_cves": len(exploits_map),
                "auxiliary_cves": len(auxiliary_map),
            },
            "scan_results": scan_results,
            "builtin_findings": findings,
            "nvd_findings": [
                {
                    "port": s["port"],
                    "service": s["service"],
                    "product": s.get("product", ""),
                    "version": s.get("version", ""),
                    "cves": [c for c in s.get("cves", [])
                             if c.get("confidence") in ("HIGH", "MEDIUM")],
                }
                for s in enriched 
                if any(c.get("confidence") in ("HIGH", "MEDIUM")
                       for c in s.get("cves", []))
            ],
            "msf_exploits": exploits_map,
            "msf_auxiliary": auxiliary_map,
        }

    def _render_summary_cards(self, s):
        cards = [
            ("Open ports",      s["open_ports"]),
            ("Built-in DB",     s["builtin_findings"]),
            ("NVD HIGH/MEDIUM", s["nvd_findings_hm"]),
            ("Exploitable",     s["exploitable_cves"]),
            ("Auxiliary",       s["auxiliary_cves"]),
        ]
        return "".join(
            f'<div class="card"><div class="value">{v}</div>'
            f'<div class="label">{_esc(l)}</div></div>'
            for l, v in cards
        )

    def _render_cve_blocks(self, cve_map):
        if not cve_map:
            return "<p class='muted'>None found.</p>"
        html = ""
        for cve, modules in sorted(cve_map.items()):
            mods = "".join(f"<li><code>{_esc(mo)}</code></li>" for mo in modules)
            html += f"<div class='cve'><h4>{_esc(cve)}</h4><ul>{mods}</ul></div>"
        return html

    def _render_builtin(self, findings):
        if not findings:
            return ("<table><tr><td class='muted>None</td></tr></table>")
        rows = ""
        for f in findings:
            rows += (
                f"<tr>"
                f"<td>{f['port']}</td>"
                f"<td>{_esc(f.get('service',''))}</td>"
                f"<td>{_esc(f.get('banner',''))}</td>"
                f"<td><code>{_esc(f.get('cve',''))}</code></td>"
                f"<td>{_esc(f.get('description',''))}</td>"
                f"</tr>"
            )
        return (
            "<table>"
            "<thead><tr><th>Port</th><th>Service</th><th>Banner</th>"
            "<th>CVE</th><th>Notes</th></tr></thead>"
            f"<tbody>{rows}</tbody></table>"
        )

    def _render_nvd(self, nvd_findings):
        if not nvd_findings:
            return "<p class='muted'>No high-confidence NVD findings.</p>"
        html = ""
        for srv in nvd_findings:
            rows = ""
            for c in srv["cves"]:
                sev = (c.get("severity") or "N/A").upper()
                sev_class = {
                    "CRITICAL": "sev-crit", "HIGH": "sev-high",
                    "MEDIUM": "sev-med", "LOW": "sev-low",
                }.get(sev, "sev-na")
                rows += (
                    f"<tr>"
                    f"<td><span class='{sev_class}'>{_esc(c['confidence'])}</span></td>"
                    f"<td><code>{_esc(c['cve_id'])}</code></td>"
                    f"<td>{_esc(c.get('score','N/A'))}</td>"
                    f"<td>{_esc(sev)}</td>"
                    f"</tr>"
                )
            html += (
                f"<h3>Port {srv['port']}/{_esc(srv['service'])} - "
                f"{_esc(srv['product'])} {_esc(srv['version'])}</h3>"
                f"<table><thead><tr><th>Confidence</th><th>CVE</th>"
                f"<th>CVSS</th><th>Severity</th></tr></thead>"
                f"<tbody>{rows}</tbody></table>"
            )
        return html

    def _render_auxiliary_section(self, cve_map):
        if not cve_map:
            return ""
        return (
            "<section><h2>Auxiliary / verification modules</h2>"
            f"{self._render_cve_blocks(cve_map)}</section>"
        )

    def _render_html(self, data):
        template = TEMPLATE_PATH.read_text(encoding="utf-8")
        m, s = data["meta"], data["summary"]

        return (template
            .replace("{{TARGET}}",              _esc(m["target"]))
            .replace("{{GENERATED_AT}}",        _esc(m["generated_at"]))
            .replace("{{TOOL}}",                _esc(m["tool"]))
            .replace("{{SUMMARY_CARDS}}",       self._render_summary_cards(s))
            .replace("{{EXPLOITS_BLOCK}}",      self._render_cve_blocks(data["msf_exploits"]))
            .replace("{{BUILTIN_BLOCK}}",       self._render_builtin(data["builtin_findings"]))
            .replace("{{NVD_BLOCK}}",           self._render_nvd(data["nvd_findings"]))
            .replace("{{AUXILIARY_SECTION}}",   self._render_auxiliary_section(data["msf_auxiliary"]))
        )

    def generate(self, scan_results, findings, enriched, msf_map):
        data = self._build_data(scan_results, findings, enriched, msf_map)
        json_path = self.report_dir / "report.json"
        json_path.write_text(json.dumps(data, indent=2, default=str))
        html_path = self.report_dir / "report.html"
        html_path.write_text(self._render_html(data), encoding="utf-8")
        return json_path, html_path