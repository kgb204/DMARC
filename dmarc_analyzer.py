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
    auth_domains: set = field(default_factory=set)  # domains seen in auth_results
    service: str = ""         # identified sending service ("" = unidentified)

    @property
    def fail(self) -> int:
        return self.total - self.dmarc_pass


# ---------------------------------------------------------------------------
# Sender intelligence: map source IPs to known sending services
# ---------------------------------------------------------------------------

# Best-effort IP prefix map for the largest senders (prefixes end with ".").
IP_PREFIXES = [
    ("209.85.", "Google Workspace / Gmail"), ("172.217.", "Google Workspace / Gmail"),
    ("35.190.", "Google Workspace / Gmail"), ("64.233.", "Google Workspace / Gmail"),
    ("66.102.", "Google Workspace / Gmail"), ("74.125.", "Google Workspace / Gmail"),
    ("108.177.", "Google Workspace / Gmail"), ("142.250.", "Google Workspace / Gmail"),
    ("142.251.", "Google Workspace / Gmail"), ("173.194.", "Google Workspace / Gmail"),
    ("40.92.", "Microsoft 365 / Outlook"), ("40.107.", "Microsoft 365 / Outlook"),
    ("52.100.", "Microsoft 365 / Outlook"), ("52.101.", "Microsoft 365 / Outlook"),
    ("52.102.", "Microsoft 365 / Outlook"), ("52.103.", "Microsoft 365 / Outlook"),
    ("104.47.", "Microsoft 365 / Outlook"),
    ("54.240.", "Amazon SES"), ("23.249.208.", "Amazon SES"),
    ("167.89.", "SendGrid"), ("168.245.", "SendGrid"), ("149.72.", "SendGrid"),
    ("159.135.", "Mailgun"), ("69.72.", "Mailgun"),
]

# rDNS hostname / DKIM-SPF domain suffixes that identify a sending service.
SERVICE_SIGNATURES = [
    ("google.com", "Google Workspace / Gmail"), ("googlemail.com", "Google Workspace / Gmail"),
    ("outlook.com", "Microsoft 365 / Outlook"), ("protection.outlook.com", "Microsoft 365 / Outlook"),
    ("onmicrosoft.com", "Microsoft 365 / Outlook"),
    ("amazonses.com", "Amazon SES"), ("smtp-out.amazonses.com", "Amazon SES"),
    ("sendgrid.net", "SendGrid"), ("sendgrid.info", "SendGrid"),
    ("mailgun.org", "Mailgun"), ("mailgun.net", "Mailgun"),
    ("mcsv.net", "Mailchimp"), ("mcdlv.net", "Mailchimp"), ("rsgsv.net", "Mailchimp"),
    ("mandrillapp.com", "Mandrill / Mailchimp Transactional"),
    ("sparkpostmail.com", "SparkPost"),
    ("mtasv.net", "Postmark"), ("postmarkapp.com", "Postmark"),
    ("sendinblue.com", "Brevo (Sendinblue)"), ("brevo.com", "Brevo (Sendinblue)"),
    ("hubspotemail.net", "HubSpot"),
    ("exacttarget.com", "Salesforce Marketing Cloud"), ("salesforce.com", "Salesforce"),
    ("zendesk.com", "Zendesk"),
    ("pphosted.com", "Proofpoint"), ("ppe-hosted.com", "Proofpoint"),
    ("mimecast.com", "Mimecast"),
    ("messagelabs.com", "Broadcom/Symantec.cloud"),
    ("constantcontact.com", "Constant Contact"),
    ("icloud.com", "Apple iCloud"), ("me.com", "Apple iCloud"),
    ("yahoodns.net", "Yahoo"), ("yahoo.com", "Yahoo"),
    ("zoho.com", "Zoho Mail"), ("zohomail.com", "Zoho Mail"),
    ("fastmail.com", "Fastmail"), ("messagingengine.com", "Fastmail"),
]


def identify_service(s: SourceStats, own_domains: set) -> str:
    """Best-effort identification of which service a source IP belongs to."""
    for prefix, name in IP_PREFIXES:
        if s.ip.startswith(prefix):
            return name
    third_party = sorted(d for d in s.auth_domains if d and d not in own_domains)
    for host in ([s.hostname] if s.hostname else []) + third_party:
        host = host.lower().rstrip(".")
        for suffix, name in SERVICE_SIGNATURES:
            if host == suffix or host.endswith("." + suffix):
                return name
    # Unrecognized, but the signing/envelope domain itself is still a useful label.
    if third_party:
        return third_party[0]
    return ""


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
    dkim_aligned: int = 0
    spf_aligned: int = 0
    daily: dict = field(default_factory=dict)   # date -> [total, pass]
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
        day = report.begin.date()
        bucket = analysis.daily.setdefault(day, [0, 0])
        for rec in report.records:
            s = analysis.sources.setdefault(rec.source_ip, SourceStats(ip=rec.source_ip))
            s.total += rec.count
            analysis.total += rec.count
            bucket[0] += rec.count
            if rec.dmarc_pass:
                s.dmarc_pass += rec.count
                analysis.dmarc_pass += rec.count
                bucket[1] += rec.count
            if rec.dkim_aligned:
                s.dkim_aligned += rec.count
                analysis.dkim_aligned += rec.count
            if rec.spf_aligned:
                s.spf_aligned += rec.count
                analysis.spf_aligned += rec.count
            if any(res == "pass" for _, res in rec.dkim_auth_results):
                s.raw_dkim_pass += rec.count
            if any(res == "pass" for _, res in rec.spf_auth_results):
                s.raw_spf_pass += rec.count
            s.dispositions[rec.disposition] = s.dispositions.get(rec.disposition, 0) + rec.count
            s.auth_domains.update(d for d, _ in rec.dkim_auth_results)
            s.auth_domains.update(d for d, _ in rec.spf_auth_results)

    own_domains = {r.domain for r in unique}
    for s in analysis.sources.values():
        s.service = identify_service(s, own_domains)
    return analysis


def service_breakdown(a: Analysis) -> list:
    """Group sources by identified sending service, largest volume first."""
    groups = {}
    for s in a.sources.values():
        g = groups.setdefault(s.service or "Unidentified", [0, 0, 0])  # sources, total, pass
        g[0] += 1
        g[1] += s.total
        g[2] += s.dmarc_pass
    return sorted(groups.items(), key=lambda kv: kv[1][1], reverse=True)


def suspected_spoofing(a: Analysis) -> list:
    """Sources with failures and no valid authentication at all — likely abuse.

    These never produced a single passing DKIM signature or SPF check (raw,
    not just aligned), so they are very unlikely to be your infrastructure.
    p=reject exists to stop exactly this traffic.
    """
    return sorted(
        (s for s in a.sources.values()
         if s.fail > 0 and s.raw_dkim_pass == 0 and s.raw_spf_pass == 0),
        key=lambda s: s.fail, reverse=True)


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
    own_domains = {r.domain for r in a.reports}
    for s in a.sources.values():
        try:
            s.hostname = socket.gethostbyaddr(s.ip)[0]
        except OSError:
            s.hostname = "(no rDNS)"
            continue
        # rDNS may identify a service that auth domains couldn't.
        s.service = identify_service(s, own_domains)


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
    if a.total:
        w(f"DKIM aligned:     {a.dkim_aligned} ({100.0 * a.dkim_aligned / a.total:.2f}%)")
        w(f"SPF aligned:      {a.spf_aligned} ({100.0 * a.spf_aligned / a.total:.2f}%)")
    w("")
    w("SENDING SERVICES")
    w("-" * 72)
    w(f"{'SERVICE':<38} {'SOURCES':>8} {'TOTAL':>8} {'PASS%':>7}")
    for name, (n_sources, total, passed) in service_breakdown(a):
        rate = 100.0 * passed / total if total else 0.0
        w(f"{name:<38.38} {n_sources:>8} {total:>8} {rate:>6.1f}%")
    w("")
    w("SOURCES")
    w("-" * 72)
    w(f"{'SOURCE IP':<22} {'SERVICE':<24} {'TOTAL':>6} {'PASS':>6} {'FAIL':>6} {'PASS%':>6}")
    for s in sorted(a.sources.values(), key=lambda s: s.total, reverse=True):
        rate = 100.0 * s.dmarc_pass / s.total if s.total else 0.0
        label = s.hostname or s.ip
        w(f"{label:<22.22} {(s.service or '-'):<24.24} {s.total:>6} {s.dmarc_pass:>6} {s.fail:>6} {rate:>5.1f}%")
        if s.hostname:
            w(f"    ip: {s.ip}")
        hint = classify_failing_source(s)
        if hint:
            w(f"    -> {hint}")
    spoofers = suspected_spoofing(a)
    if spoofers:
        w("")
        w("SUSPECTED SPOOFING / ABUSE (no valid authentication at all)")
        w("-" * 72)
        for s in spoofers:
            w(f"{s.ip:<40.40} {s.fail:>7} failed messages")
        w("p=reject exists to stop exactly this traffic — it strengthens the case "
          "for tightening once legitimate senders pass.")
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
        "dkim_aligned": a.dkim_aligned,
        "spf_aligned": a.spf_aligned,
        "daily": {str(day): {"total": t, "pass": p}
                  for day, (t, p) in sorted(a.daily.items())},
        "services": [
            {"service": name, "sources": n, "total": total, "pass": passed}
            for name, (n, total, passed) in service_breakdown(a)
        ],
        "suspected_spoofing": [s.ip for s in suspected_spoofing(a)],
        "sources": [
            {
                "ip": s.ip,
                "hostname": s.hostname,
                "service": s.service,
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
    pct = lambda n: f"{100.0 * n / a.total:.1f}%" if a.total else "-"

    # Daily volume timeline as a stacked CSS bar chart (pass green, fail red).
    days = sorted(a.daily.items())
    max_day = max((t for _, (t, _) in days), default=1) or 1
    bars = []
    for day, (total, passed) in days:
        ph = round(118 * passed / max_day)
        fh = round(118 * (total - passed) / max_day)
        bars.append(
            f"<div class='bar' title='{day}: {total} msgs, {passed} pass'>"
            f"<i class='f' style='height:{fh}px'></i><i class='p' style='height:{ph}px'></i>"
            f"<span>{day:%m-%d}</span></div>")

    svc_rows = []
    for name, (n_sources, total, passed) in service_breakdown(a):
        srate = 100.0 * passed / total if total else 0.0
        svc_rows.append(f"<tr><td>{html.escape(name)}</td><td class='num'>{n_sources}</td>"
                        f"<td class='num'>{total}</td><td class='num'>{srate:.1f}%</td></tr>")

    rows = []
    for s in sorted(a.sources.values(), key=lambda s: s.total, reverse=True):
        srate = 100.0 * s.dmarc_pass / s.total if s.total else 0.0
        hint = classify_failing_source(s)
        rows.append(
            "<tr><td>{ip}</td><td>{host}</td><td>{svc}</td><td class='num'>{total}</td>"
            "<td class='num'>{p}</td><td class='num'>{f}</td>"
            "<td class='num'>{r:.1f}%</td><td>{hint}</td></tr>".format(
                ip=html.escape(s.ip), host=html.escape(s.hostname),
                svc=html.escape(s.service or "-"),
                total=s.total, p=s.dmarc_pass, f=s.fail, r=srate,
                hint=html.escape(hint)))

    spoofers = suspected_spoofing(a)
    threat = ""
    if spoofers:
        items = "".join(f"<li><code>{html.escape(s.ip)}</code> — {s.fail} failed messages</li>"
                        for s in spoofers)
        threat = (f"<h2>Suspected spoofing / abuse</h2><div class='threat'>"
                  f"<p>These sources produced failures with <strong>no valid DKIM or SPF at "
                  f"all</strong> — very unlikely to be your infrastructure. p=reject will "
                  f"stop them.</p><ul>{items}</ul></div>")

    recs = "".join(f"<li>{html.escape(r)}</li>" for r in recommend(a))
    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>DMARC analysis — {html.escape(', '.join(a.domains))}</title>
<style>
 body {{ font-family: system-ui, sans-serif; margin: 2rem auto; max-width: 72rem; color: #222; padding: 0 1rem; }}
 .cards {{ display: flex; gap: 1rem; flex-wrap: wrap; }}
 .card {{ flex: 1 1 9rem; border: 1px solid #ddd; border-radius: 10px; padding: .9rem 1.1rem; }}
 .card b {{ display: block; font-size: 1.6rem; }}
 .card.hero {{ background: {color}; color: #fff; border: 0; }}
 .chart {{ display: flex; align-items: flex-end; gap: 4px; height: 150px; margin: 1rem 0;
           border-bottom: 2px solid #ccc; padding-bottom: 18px; overflow-x: auto; }}
 .bar {{ display: flex; flex-direction: column-reverse; width: 26px; position: relative; }}
 .bar i {{ display: block; }}
 .bar .p {{ background: #2e7d32; }}
 .bar .f {{ background: #c62828; }}
 .bar span {{ position: absolute; bottom: -18px; font-size: .6rem; white-space: nowrap; }}
 table {{ border-collapse: collapse; width: 100%; margin-top: 1rem; }}
 th, td {{ border: 1px solid #ddd; padding: .45rem .7rem; text-align: left; font-size: .9rem; }}
 th {{ background: #f5f5f5; }}
 .num {{ text-align: right; font-variant-numeric: tabular-nums; }}
 .threat {{ border: 1px solid #c62828; border-radius: 10px; padding: .2rem 1.2rem; background: #fff5f5; }}
 ul {{ line-height: 1.6; }}
</style></head><body>
<h1>DMARC analysis — {html.escape(', '.join(a.domains) or 'no data')}</h1>
<div class="cards">
 <div class="card hero">DMARC pass rate<b>{rate:.2f}%</b></div>
 <div class="card">Messages<b>{a.total}</b></div>
 <div class="card">DKIM aligned<b>{pct(a.dkim_aligned)}</b></div>
 <div class="card">SPF aligned<b>{pct(a.spf_aligned)}</b></div>
 <div class="card">Policy<b>p={html.escape(a.current_policy)}</b></div>
 <div class="card">Coverage<b>{a.date_span_days:.0f} days</b></div>
</div>
<h2>Daily volume</h2>
<div class="chart">{''.join(bars) or '<em>no data</em>'}</div>
<h2>Recommendations</h2><ul>{recs}</ul>
{threat}
<h2>Sending services</h2>
<table><tr><th>Service</th><th>Sources</th><th>Messages</th><th>Pass %</th></tr>
{''.join(svc_rows)}</table>
<h2>All sources</h2>
<table><tr><th>Source IP</th><th>Hostname</th><th>Service</th><th>Total</th><th>Pass</th><th>Fail</th><th>Pass %</th><th>Hint</th></tr>
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
