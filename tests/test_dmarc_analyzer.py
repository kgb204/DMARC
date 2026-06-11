"""Tests for dmarc_analyzer. Run with:  python3 -m unittest discover tests"""

import gzip
import io
import sys
import unittest
import zipfile
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import dmarc_analyzer as da

SAMPLE = (Path(__file__).resolve().parent.parent
          / "sample-reports"
          / "google.com!companyfiles.zip!1749427200!1749513600.xml")


def make_report_xml(report_id="r1", policy="none", begin=1749427200, end=1749513600,
                    records=None):
    if records is None:
        records = [("192.0.2.1", 10, "pass", "pass")]
    recs = "".join(f"""
  <record>
    <row>
      <source_ip>{ip}</source_ip>
      <count>{count}</count>
      <policy_evaluated>
        <disposition>none</disposition>
        <dkim>{dkim}</dkim>
        <spf>{spf}</spf>
      </policy_evaluated>
    </row>
    <identifiers><header_from>example.com</header_from></identifiers>
    <auth_results>
      <dkim><domain>example.com</domain><result>{dkim}</result></dkim>
      <spf><domain>example.com</domain><result>{spf}</result></spf>
    </auth_results>
  </record>""" for ip, count, dkim, spf in records)
    return f"""<?xml version="1.0"?>
<feedback>
  <report_metadata>
    <org_name>test.org</org_name>
    <report_id>{report_id}</report_id>
    <date_range><begin>{begin}</begin><end>{end}</end></date_range>
  </report_metadata>
  <policy_published>
    <domain>example.com</domain><adkim>r</adkim><aspf>r</aspf>
    <p>{policy}</p><sp>{policy}</sp><pct>100</pct>
  </policy_published>{recs}
</feedback>""".encode()


class ParseTests(unittest.TestCase):
    def test_parse_sample_file(self):
        report = da.parse_report(SAMPLE.read_bytes())
        self.assertEqual(report.org_name, "google.com")
        self.assertEqual(report.domain, "companyfiles.zip")
        self.assertEqual(report.policy, "none")
        self.assertEqual(len(report.records), 2)
        self.assertEqual(report.begin, datetime(2025, 6, 9, tzinfo=timezone.utc))

    def test_record_pass_fail(self):
        report = da.parse_report(SAMPLE.read_bytes())
        passing, failing = report.records
        self.assertTrue(passing.dmarc_pass)
        self.assertEqual(passing.count, 42)
        self.assertFalse(failing.dmarc_pass)
        # raw auth passed for an unaligned domain
        self.assertIn(("mailer.example.net", "pass"), failing.dkim_auth_results)

    def test_namespaced_xml(self):
        xml = make_report_xml().replace(
            b"<feedback>", b'<feedback xmlns="http://dmarc.org/dmarc-xml/0.1">')
        report = da.parse_report(xml)
        self.assertEqual(report.org_name, "test.org")

    def test_rejects_non_dmarc_xml(self):
        with self.assertRaises(ValueError):
            da.parse_report(b"<html><body>not a report</body></html>")


class IngestionTests(unittest.TestCase):
    def test_gzip_payload(self):
        xml = make_report_xml()
        payloads = da._payloads_from_bytes(gzip.compress(xml), "report.xml.gz")
        self.assertEqual(payloads, [xml])

    def test_zip_payload(self):
        xml = make_report_xml()
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("report.xml", xml)
        payloads = da._payloads_from_bytes(buf.getvalue(), "report.zip")
        self.assertEqual(payloads, [xml])

    def test_eml_with_gzip_attachment(self):
        xml = make_report_xml()
        from email.message import EmailMessage
        msg = EmailMessage()
        msg["Subject"] = "Report domain: example.com"
        msg.set_content("see attachment")
        msg.add_attachment(gzip.compress(xml), maintype="application",
                           subtype="gzip", filename="report.xml.gz")
        payloads = da._payloads_from_bytes(msg.as_bytes(), "report.eml")
        self.assertEqual(payloads, [xml])

    def test_non_xml_bytes_ignored(self):
        self.assertEqual(da._payloads_from_bytes(b"random junk", "foo.xml"), [])


class AnalysisTests(unittest.TestCase):
    def test_aggregation_and_pass_rate(self):
        reports = [da.parse_report(make_report_xml(records=[
            ("192.0.2.1", 90, "pass", "pass"),
            ("192.0.2.2", 10, "fail", "fail"),
        ]))]
        a = da.analyze(reports)
        self.assertEqual(a.total, 100)
        self.assertEqual(a.dmarc_pass, 90)
        self.assertAlmostEqual(a.pass_rate, 90.0)
        self.assertEqual(a.sources["192.0.2.2"].fail, 10)

    def test_dkim_or_spf_alone_passes(self):
        a = da.analyze([da.parse_report(make_report_xml(records=[
            ("192.0.2.3", 5, "pass", "fail"),
            ("192.0.2.4", 5, "fail", "pass"),
        ]))])
        self.assertEqual(a.dmarc_pass, 10)

    def test_duplicate_reports_deduped(self):
        xml = make_report_xml(report_id="dup")
        a = da.analyze([da.parse_report(xml), da.parse_report(xml)])
        self.assertEqual(len(a.reports), 1)
        self.assertEqual(a.total, 10)


class RecommendationTests(unittest.TestCase):
    DAY = 86400

    def _analysis(self, policy, pass_count, fail_count, days=20):
        reports = []
        for d in range(days):
            begin = 1700000000 + d * self.DAY
            records = [("192.0.2.1", pass_count, "pass", "pass")]
            if fail_count:
                records.append(("192.0.2.9", fail_count, "fail", "fail"))
            reports.append(da.parse_report(make_report_xml(
                report_id=f"r{d}", policy=policy, begin=begin,
                end=begin + self.DAY, records=records)))
        return da.analyze(reports)

    def test_ready_for_quarantine(self):
        recs = " ".join(da.recommend(self._analysis("none", 99, 1)))
        self.assertIn("p=quarantine", recs)

    def test_ready_for_reject(self):
        recs = " ".join(da.recommend(self._analysis("quarantine", 100, 0)))
        self.assertIn("p=reject", recs)

    def test_not_ready_low_pass_rate(self):
        recs = " ".join(da.recommend(self._analysis("none", 80, 20)))
        self.assertIn("Fix the failing", recs)
        self.assertNotIn("ready to tighten", recs)

    def test_not_ready_too_few_days(self):
        recs = " ".join(da.recommend(self._analysis("none", 100, 0, days=3)))
        self.assertIn("at least 14 days", recs)

    def test_empty_analysis(self):
        recs = da.recommend(da.analyze([]))
        self.assertIn("No mail volume", recs[0])

    def test_forwarder_classification(self):
        a = da.analyze([da.parse_report(SAMPLE.read_bytes())])
        hint = da.classify_failing_source(a.sources["198.51.100.7"])
        self.assertIn("forwarder", hint)


class SenderIntelligenceTests(unittest.TestCase):
    def test_known_ip_prefix(self):
        a = da.analyze([da.parse_report(SAMPLE.read_bytes())])
        self.assertEqual(a.sources["209.85.220.41"].service, "Google Workspace / Gmail")

    def test_unrecognized_signer_labeled_by_domain(self):
        a = da.analyze([da.parse_report(SAMPLE.read_bytes())])
        # Signs with its own (unaligned, unknown) domain -> label by that domain
        self.assertEqual(a.sources["198.51.100.7"].service, "bounce.mailer.example.net")

    def test_signature_match_on_auth_domain(self):
        s = da.SourceStats(ip="198.51.100.99", auth_domains={"em123.sendgrid.net"})
        self.assertEqual(da.identify_service(s, {"example.com"}), "SendGrid")

    def test_own_domain_signer_unidentified_without_rdns(self):
        s = da.SourceStats(ip="198.51.100.50", auth_domains={"example.com"})
        self.assertEqual(da.identify_service(s, {"example.com"}), "")

    def test_service_breakdown_grouping(self):
        a = da.analyze([da.parse_report(SAMPLE.read_bytes())])
        names = [name for name, _ in da.service_breakdown(a)]
        self.assertIn("Google Workspace / Gmail", names)

    def test_suspected_spoofing(self):
        a = da.analyze([da.parse_report(make_report_xml(records=[
            ("192.0.2.1", 50, "pass", "pass"),
            ("203.0.113.9", 7, "fail", "fail"),
        ]))])
        # the failing source's raw auth also failed -> flagged
        spoofers = da.suspected_spoofing(a)
        self.assertEqual([s.ip for s in spoofers], ["203.0.113.9"])

    def test_forwarder_not_flagged_as_spoofing(self):
        a = da.analyze([da.parse_report(SAMPLE.read_bytes())])
        # 198.51.100.7 fails alignment but has valid raw DKIM (forwarder-like)
        self.assertEqual(da.suspected_spoofing(a), [])

    def test_daily_timeline(self):
        DAY = 86400
        reports = [
            da.parse_report(make_report_xml(report_id="d1", begin=1700000000,
                                            end=1700000000 + DAY)),
            da.parse_report(make_report_xml(report_id="d2", begin=1700000000 + DAY,
                                            end=1700000000 + 2 * DAY)),
        ]
        a = da.analyze(reports)
        self.assertEqual(len(a.daily), 2)
        self.assertEqual(sum(t for t, _ in a.daily.values()), 20)


class RenderTests(unittest.TestCase):
    def test_text_and_html_and_json_render(self):
        a = da.analyze([da.parse_report(SAMPLE.read_bytes())])
        text = da.render_text(a)
        self.assertIn("companyfiles.zip", text)
        self.assertIn("RECOMMENDATIONS", text)
        html_out = da.render_html(a)
        self.assertIn("<table>", html_out)
        import json
        data = json.loads(da.render_json(a))
        self.assertEqual(data["total_messages"], 45)
        self.assertEqual(data["dmarc_pass"], 42)


if __name__ == "__main__":
    unittest.main()
