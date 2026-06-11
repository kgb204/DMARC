#!/usr/bin/env python3
"""DMARC aggregate (RUA) report analyzer.

Parses the XML aggregate reports that mailbox providers (Google, Microsoft,
Yahoo, ...) send to the address in your DMARC ``rua=`` tag, summarizes which
sending sources pass or fail DMARC alignment, and tells you whether it is
safe to move your policy from ``p=none`` -> ``p=quarantine`` -> ``p=reject``.

Stdlib only — no third-party dependencies.

Usage examples:

    # Analyze a folder of downloaded reports (.xml, .xml.gz, .zip, .eml)
    python3 dmarc_analyzer.py reports/

    # Also write an HTML dashboard and machine-readable JSON
    python3 dmarc_analyzer.py reports/ --html dmarc.html --json dmarc.json

    # Pull reports directly from a mailbox over IMAP (e.g. Gmail app password)
    DMARC_IMAP_PASSWORD=xxxx python3 dmarc_analyzer.py \
        --imap-server imap.gmail.com --imap-user you@example.com \
        --save-dir reports/ reports/

    # Resolve source IPs to hostnames (slower, needs network)
    python3 dmarc_analyzer.py reports/ --resolve-dns
"""

from __future__ import annotations

import argparse
import email
import email.policy
import gzip
import html
import io
import json
import os
import socket
import sys
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from xml.etree import ElementTree


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class Record:
    """One <record> row: a source IP and how its mail evaluated."""
    source_ip: str
    count: int
    disposition: str          # none | quarantine | reject
    dkim_aligned: bool        # policy_evaluated/dkim == pass
    spf_aligned: bool         # policy_evaluated/spf == pass
    header_from: str
    dkim_auth_results: list = field(default_factory=list)  # raw (domain, result)
    spf_auth_results: list = field(default_factory=list)

    @property
    def dmarc_pass(self) -> bool:
        return self.dkim_aligned or self.spf_aligned


@dataclass
class Report:
    """One parsed aggregate report file."""
    org_name: str
    report_id: str
    begin: datetime
    end: datetime
    domain: str
    policy: str               # published p=
    subdomain_policy: str
    pct: int
    adkim: str
    aspf: str
    records: list = field(default_factory=list)

    @property
    def dedupe_key(self) -> tuple:
        return (self.org_name, self.report_id)


@dataclass
class SourceStats:
    """Aggregated stats for one source IP across all reports."""
    ip: str
    total: int = 0
    dmarc_pass: int = 0
    dkim_aligned: int = 0
    spf_aligned: int = 0
    dispositions: dict = field(default_factory=dict)
    raw_dkim_pass: int = 0    # raw auth passed even if unaligned (forwarders)
    raw_spf_pass: int = 0
    hostname: str = ""

    @property
    def fail(self) -> int:
        return self.total - self.dmarc_pass


# ---------------------------------------------------------------------------
# File ingestion: .xml / .xml.gz / .zip / .eml -> XML payloads
# ---------------------------------------------------------------------------

def extract_xml_payloads(path: Path) -> list:
    """Return the XML document(s) contained in *path* as a list of bytes."""
    data = path.read_bytes()
    return _payloads_from_bytes(data, path.name)


def _payloads_from_bytes(data: bytes, name: str) -> list:
    lower = name.lower()
    if lower.endswith(".eml"):
        return _payloads_from_eml(data)
    if data[:2] == b"PK":  # zip
        out = []
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            for info in zf.infolist():
                if not info.is_dir():
                    out.extend(_payloads_from_bytes(zf.read(info), info.filename))
        return out
    if data[:2] == b"\x1f\x8b":  # gzip
        inner = gzip.decompress(data)
        return _payloads_from_bytes(inner, lower.removesuffix(".gz") or "report.xml")
    if data.lstrip()[:1] == b"<":
        return [data]
    return []


def _payloads_from_eml(data: bytes) -> list:
    msg = email.message_from_bytes(data, policy=email.policy.default)
    out = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        payload = part.get_payload(decode=True)
        if not payload:
            continue
        out.extend(_payloads_from_bytes(payload, part.get_filename() or "part"))
    return out


def collect_files(paths: list) -> list:
    """Expand files/directories into a flat, sorted list of report files."""
    exts = (".xml", ".gz", ".zip", ".eml")
    files = []
    for p in paths:
        p = Path(p)
        if p.is_dir():
            files.extend(f for f in sorted(p.rglob("*")) if f.is_file() and f.name.lower().endswith(exts))
        elif p.is_file():
            files.append(p)
        else:
            print(f"warning: {p} not found, skipping", file=sys.stderr)
    return files


# ---------------------------------------------------------------------------
# XML parsing
# ---------------------------------------------------------------------------

def _text(el, tag: str, default: str = "") -> str:
    found = el.find(tag)
    return (found.text or "").strip() if found is not None and found.text else default


def parse_report(xml_bytes: bytes) -> Report:
    root = ElementTree.fromstring(xml_bytes)
    # Some reporters wrap everything in a namespace; strip it for simplicity.
    if root.tag.startswith("{"):
        for el in root.iter():
            el.tag = el.tag.split("}", 1)[1]

    meta = root.find("report_metadata")
    policy = root.find("policy_published")
    if meta is None or policy is None:
        raise ValueError("not a DMARC aggregate report (missing metadata/policy)")

    begin = datetime.fromtimestamp(int(_text(meta, "date_range/begin", "0")), tz=timezone.utc)
    end = datetime.fromtimestamp(int(_text(meta, "date_range/end", "0")), tz=timezone.utc)

    report = Report(
        org_name=_text(meta, "org_name", "unknown"),
        report_id=_text(meta, "report_id", "unknown"),
        begin=begin,
        end=end,
        domain=_text(policy, "domain"),
        policy=_text(policy, "p", "none"),
        subdomain_policy=_text(policy, "sp", ""),
        pct=int(_text(policy, "pct", "100") or 100),
        adkim=_text(policy, "adkim", "r"),
        aspf=_text(policy, "aspf", "r"),
    )

    for rec in root.findall("record"):
        row = rec.find("row")
        if row is None:
            continue
        pe = row.find("policy_evaluated")
        auth = rec.find("auth_results")
        dkim_results, spf_results = [], []
        if auth is not None:
            dkim_results = [(_text(d, "domain"), _text(d, "result")) for d in auth.findall("dkim")]
            spf_results = [(_text(s, "domain"), _text(s, "result")) for s in auth.findall("spf")]
        report.records.append(Record(
            source_ip=_text(row, "source_ip"),
            count=int(_text(row, "count", "0") or 0),
            disposition=_text(pe, "disposition", "none") if pe is not None else "none",
            dkim_aligned=(_text(pe, "dkim") == "pass") if pe is not None else False,
            spf_aligned=(_text(pe, "spf") == "pass") if pe is not None else False,
            header_from=_text(rec, "identifiers/header_from"),
            dkim_auth_results=dkim_results,
            spf_auth_results=spf_results,
        ))
    return report


# ---------------------------------------------------------------------------
# Aggregation & recommendation
# ---------------------------------------------------------------------------

@dataclass
class Analysis:
    reports: list
    sources: dict               # ip -> SourceStats
    total: int = 0
    dmarc_pass: int = 0
    skipped: list = field(default_factory=list)

    @property
    def pass_rate(self) -> float:
        return 100.0 * self.dmarc_pass / self.total if self.total else 0.0

    @property
    def date_span_days(self) -> float:
        if not self.reports:
            return 0.0
        begin = min(r.begin for r in self.reports)
        end = max(r.end for r in self.reports)
        return (end - begin).total_seconds() / 86400

    @property
    def current_policy(self) -> str:
        if not self.reports:
            return "unknown"
        return max(self.reports, key=lambda r: r.end).policy

    @property
    def domains(self) -> list:
        return sorted({r.domain for r in self.reports})


def analyze(reports: list) -> Analysis:
    seen = set()
    unique = []
    for r in reports:
        if r.dedupe_key in seen:
            continue
        seen.add(r.dedupe_key)
        unique.append(r)

    analysis = Analysis(reports=unique, sources={})
    for report in unique:
        for rec in report.records:
            s = analysis.sources.setdefault(rec.source_ip, SourceStats(ip=rec.source_ip))
            s.total += rec.count
            analysis.total += rec.count
            if rec.dmarc_pass:
                s.dmarc_pass += rec.count
                analysis.dmarc_pass += rec.count
            if rec.dkim_aligned:
                s.dkim_aligned += rec.count
            if rec.spf_aligned:
                s.spf_aligned += rec.count
            if any(res == "pass" for _, res in rec.dkim_auth_results):
                s.raw_dkim_pass += rec.count
            if any(res == "pass" for _, res in rec.spf_auth_results):
                s.raw_spf_pass += rec.count
            s.dispositions[rec.disposition] = s.dispositions.get(rec.disposition, 0) + rec.count
    return analysis


# Thresholds for the rollout recommendation.
MIN_DAYS = 14          # observe at least this many days of reports
MIN_PASS_RATE = 98.0   # % of mail that must pass DMARC before tightening


def classify_failing_source(s: SourceStats) -> str:
    """Best-effort hint about why a source is failing."""
    if s.dmarc_pass == s.total:
        return ""
    if s.raw_dkim_pass >= s.fail:
        return "DKIM signature valid but domain unaligned — likely a forwarder or a service signing with its own domain; align its DKIM (d=) with your domain"
    if s.raw_spf_pass >= s.fail:
        return "SPF passed for an unaligned domain — likely a third-party sender using its own envelope domain; enable custom return-path/DKIM alignment"
    return "no aligned authentication — either an unauthenticated legitimate sender (add DKIM/SPF) or spoofing (safe to block)"


def recommend(a: Analysis) -> list:
    """Return a list of recommendation strings."""
    recs = []
    if a.total == 0:
        return ["No mail volume found in the supplied reports. Verify your rua= "
                "address is receiving reports and try again in a few days."]

    policy = a.current_policy
    rate = a.pass_rate
    days = a.date_span_days

    if days < MIN_DAYS:
        recs.append(f"Reports only span {days:.1f} days; collect at least {MIN_DAYS} days "
                    "of data before tightening policy (forwarding and low-volume senders "
                    "take time to show up).")

    failing = [s for s in a.sources.values() if s.fail > 0]
    if failing:
        worst = sorted(failing, key=lambda s: s.fail, reverse=True)[:5]
        recs.append("Failing sources to investigate first (by failed volume): "
                    + ", ".join(f"{s.ip} ({s.fail} msgs)" for s in worst))

    domain = a.domains[0] if a.domains else "yourdomain.example"
    if rate >= MIN_PASS_RATE and days >= MIN_DAYS:
        if policy == "none":
            recs.append(f"PASS RATE {rate:.2f}% over {days:.0f} days — ready to tighten. "
                        f"Move to quarantine with a ramp: "
                        f'"v=DMARC1; p=quarantine; pct=25; rua=mailto:dmarc@{domain}" '
                        "then raise pct to 50 -> 100 over 2-4 weeks while watching reports.")
        elif policy == "quarantine":
            recs.append(f"PASS RATE {rate:.2f}% at p=quarantine — ready for the final step: "
                        f'"v=DMARC1; p=reject; rua=mailto:dmarc@{domain}".')
        elif policy == "reject":
            recs.append(f"You are already at p=reject with a {rate:.2f}% pass rate. "
                        "Keep monitoring reports for regressions.")
    else:
        recs.append(f"Pass rate is {rate:.2f}% (target ≥ {MIN_PASS_RATE}%). Fix the failing "
                    "legitimate senders above before tightening, or accept that the failing "
                    "mail will be quarantined/rejected.")
    return recs


# ---------------------------------------------------------------------------
# Output rendering
# ---------------------------------------------------------------------------

def resolve_hostnames(a: Analysis) -> None:
    for s in a.sources.values():
        try:
            s.hostname = socket.gethostbyaddr(s.ip)[0]
        except OSError:
            s.hostname = "(no rDNS)"


def render_text(a: Analysis) -> str:
    out = []
    w = out.append
    w("=" * 72)
    w("DMARC AGGREGATE REPORT ANALYSIS")
    w("=" * 72)
    w(f"Domains:          {', '.join(a.domains) or '-'}")
    w(f"Reports parsed:   {len(a.reports)} (from {len({r.org_name for r in a.reports})} reporting orgs)")
    if a.reports:
        w(f"Date range:       {min(r.begin for r in a.reports):%Y-%m-%d} .. "
          f"{max(r.end for r in a.reports):%Y-%m-%d} ({a.date_span_days:.1f} days)")
        w(f"Published policy: p={a.current_policy}")
    w(f"Total messages:   {a.total}")
    w(f"DMARC pass:       {a.dmarc_pass} ({a.pass_rate:.2f}%)")
    w(f"DMARC fail:       {a.total - a.dmarc_pass}")
    w("")
    w(f"{'SOURCE IP':<40} {'TOTAL':>7} {'PASS':>7} {'FAIL':>7} {'PASS%':>7}")
    w("-" * 72)
    for s in sorted(a.sources.values(), key=lambda s: s.total, reverse=True):
        rate = 100.0 * s.dmarc_pass / s.total if s.total else 0.0
        label = f"{s.ip} {s.hostname}".strip()
        w(f"{label:<40.40} {s.total:>7} {s.dmarc_pass:>7} {s.fail:>7} {rate:>6.1f}%")
        hint = classify_failing_source(s)
        if hint:
            w(f"    -> {hint}")
    w("")
    w("RECOMMENDATIONS")
    w("-" * 72)
    for i, rec in enumerate(recommend(a), 1):
        w(f"{i}. {rec}")
    if a.skipped:
        w("")
        w(f"Skipped {len(a.skipped)} unparseable file(s): " + ", ".join(a.skipped[:10]))
    return "\n".join(out)


def render_json(a: Analysis) -> str:
    return json.dumps({
        "domains": a.domains,
        "reports": len(a.reports),
        "current_policy": a.current_policy,
        "date_span_days": round(a.date_span_days, 1),
        "total_messages": a.total,
        "dmarc_pass": a.dmarc_pass,
        "pass_rate_pct": round(a.pass_rate, 2),
        "sources": [
            {
                "ip": s.ip,
                "hostname": s.hostname,
                "total": s.total,
                "pass": s.dmarc_pass,
                "fail": s.fail,
                "dkim_aligned": s.dkim_aligned,
                "spf_aligned": s.spf_aligned,
                "dispositions": s.dispositions,
                "hint": classify_failing_source(s),
            }
            for s in sorted(a.sources.values(), key=lambda s: s.total, reverse=True)
        ],
        "recommendations": recommend(a),
    }, indent=2)


def render_html(a: Analysis) -> str:
    rate = a.pass_rate
    color = "#2e7d32" if rate >= MIN_PASS_RATE else ("#ef6c00" if rate >= 90 else "#c62828")
    rows = []
    for s in sorted(a.sources.values(), key=lambda s: s.total, reverse=True):
        srate = 100.0 * s.dmarc_pass / s.total if s.total else 0.0
        hint = classify_failing_source(s)
        rows.append(
            "<tr><td>{ip}</td><td>{host}</td><td class='num'>{total}</td>"
            "<td class='num'>{p}</td><td class='num'>{f}</td>"
            "<td class='num'>{r:.1f}%</td><td>{hint}</td></tr>".format(
                ip=html.escape(s.ip), host=html.escape(s.hostname),
                total=s.total, p=s.dmarc_pass, f=s.fail, r=srate,
                hint=html.escape(hint)))
    recs = "".join(f"<li>{html.escape(r)}</li>" for r in recommend(a))
    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>DMARC analysis — {html.escape(', '.join(a.domains))}</title>
<style>
 body {{ font-family: system-ui, sans-serif; margin: 2rem auto; max-width: 70rem; color: #222; }}
 .banner {{ background: {color}; color: #fff; padding: 1rem 1.5rem; border-radius: 8px; font-size: 1.2rem; }}
 table {{ border-collapse: collapse; width: 100%; margin-top: 1.5rem; }}
 th, td {{ border: 1px solid #ddd; padding: .45rem .7rem; text-align: left; font-size: .9rem; }}
 th {{ background: #f5f5f5; }}
 .num {{ text-align: right; font-variant-numeric: tabular-nums; }}
 ul {{ line-height: 1.6; }}
</style></head><body>
<h1>DMARC aggregate report analysis</h1>
<div class="banner">Pass rate: {rate:.2f}% &nbsp;|&nbsp; {a.total} messages &nbsp;|&nbsp;
 {len(a.reports)} reports over {a.date_span_days:.0f} days &nbsp;|&nbsp; policy: p={html.escape(a.current_policy)}</div>
<h2>Recommendations</h2><ul>{recs}</ul>
<h2>Sending sources</h2>
<table><tr><th>Source IP</th><th>Hostname</th><th>Total</th><th>Pass</th><th>Fail</th><th>Pass %</th><th>Hint</th></tr>
{''.join(rows)}</table>
<p>Generated {datetime.now(timezone.utc):%Y-%m-%d %H:%M} UTC by dmarc_analyzer.py</p>
</body></html>"""


# ---------------------------------------------------------------------------
# Optional IMAP fetching
# ---------------------------------------------------------------------------

def fetch_imap(server: str, user: str, password: str, folder: str,
               save_dir: Path, search: str) -> int:
    """Download DMARC report attachments from an IMAP mailbox into save_dir."""
    import imaplib

    save_dir.mkdir(parents=True, exist_ok=True)
    saved = 0
    conn = imaplib.IMAP4_SSL(server)
    try:
        conn.login(user, password)
        conn.select(folder, readonly=True)
        status, data = conn.search(None, search)
        if status != "OK":
            raise RuntimeError(f"IMAP search failed: {status}")
        ids = data[0].split()
        print(f"IMAP: {len(ids)} matching message(s) in {folder!r}", file=sys.stderr)
        for msg_id in ids:
            status, msg_data = conn.fetch(msg_id, "(RFC822)")
            if status != "OK":
                continue
            msg = email.message_from_bytes(msg_data[0][1], policy=email.policy.default)
            for part in msg.walk():
                fname = part.get_filename()
                if not fname or not fname.lower().endswith((".xml", ".gz", ".zip")):
                    continue
                payload = part.get_payload(decode=True)
                if not payload:
                    continue
                target = save_dir / Path(fname).name
                if target.exists() and target.stat().st_size == len(payload):
                    continue
                target.write_bytes(payload)
                saved += 1
    finally:
        try:
            conn.logout()
        except Exception:
            pass
    print(f"IMAP: saved {saved} new attachment(s) to {save_dir}", file=sys.stderr)
    return saved


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Analyze DMARC aggregate (RUA) reports and chart the path to p=reject.")
    ap.add_argument("paths", nargs="*", help="report files or directories (.xml, .xml.gz, .zip, .eml)")
    ap.add_argument("--html", metavar="FILE", help="write an HTML dashboard")
    ap.add_argument("--json", metavar="FILE", help="write machine-readable JSON ('-' for stdout)")
    ap.add_argument("--resolve-dns", action="store_true", help="reverse-resolve source IPs (needs network)")
    imap = ap.add_argument_group("IMAP fetching (optional)")
    imap.add_argument("--imap-server", help="e.g. imap.gmail.com")
    imap.add_argument("--imap-user", help="mailbox login")
    imap.add_argument("--imap-password", help="password / app password (or set $DMARC_IMAP_PASSWORD)")
    imap.add_argument("--imap-folder", default="INBOX", help="folder/label to search (default INBOX)")
    imap.add_argument("--imap-search", default='SUBJECT "Report domain"',
                      help='IMAP SEARCH criteria (default: SUBJECT "Report domain")')
    imap.add_argument("--save-dir", default="dmarc-reports", help="where to save fetched attachments")
    args = ap.parse_args(argv)

    if args.imap_server:
        password = args.imap_password or os.environ.get("DMARC_IMAP_PASSWORD")
        if not args.imap_user or not password:
            ap.error("--imap-server requires --imap-user and a password "
                     "(--imap-password or $DMARC_IMAP_PASSWORD)")
        fetch_imap(args.imap_server, args.imap_user, password,
                   args.imap_folder, Path(args.save_dir), args.imap_search)
        if not args.paths:
            args.paths = [args.save_dir]

    if not args.paths:
        ap.error("no report paths given (and no --imap-server to fetch from)")

    files = collect_files(args.paths)
    if not files:
        print("No report files found.", file=sys.stderr)
        return 1

    reports, skipped = [], []
    for f in files:
        try:
            for payload in extract_xml_payloads(f):
                reports.append(parse_report(payload))
        except Exception as exc:
            skipped.append(f.name)
            print(f"warning: could not parse {f}: {exc}", file=sys.stderr)

    analysis = analyze(reports)
    analysis.skipped = skipped
    if args.resolve_dns:
        resolve_hostnames(analysis)

    print(render_text(analysis))
    if args.html:
        Path(args.html).write_text(render_html(analysis), encoding="utf-8")
        print(f"\nHTML dashboard written to {args.html}", file=sys.stderr)
    if args.json:
        out = render_json(analysis)
        if args.json == "-":
            print(out)
        else:
            Path(args.json).write_text(out, encoding="utf-8")
            print(f"JSON written to {args.json}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
