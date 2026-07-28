import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from ual_app.core import build_message_trace_event_summary, compile_query, email_domains, hunt_suspicious_message_trace, message_trace_ip_columns, parse_message_trace_rows, parse_rdap_domain, read_upload
from ual_app.store import CaseStore


class MessageTraceTests(unittest.TestCase):
    def test_builds_forensic_event_from_message_trace_fields(self):
        event = build_message_trace_event_summary({
            "message_subject": "Important: shared document",
            "SenderAddress": "sender@example.com",
            "RecipientAddress": "recipient@example.net",
            "Status": "Delivered",
            "MessageId": "<message@example.com>",
            "OriginalClientIP": "203.0.113.10",
            "OriginalClientIP_IPAPI_Country": "Canada",
            "OriginalClientIP_IPAPI_Region": "Ontario",
            "OriginalClientIP_IPAPI_City": "Toronto",
            "OriginalClientIP_IPAPI_Hosting": True,
        })
        self.assertEqual(
            event,
            "Subject: Important: shared document; Sender: sender@example.com; Recipient: recipient@example.net",
        )

    def test_normalizes_common_headers_and_retains_originals(self):
        rows = parse_message_trace_rows([{
            "received_time": "2026-07-25T12:00:00Z",
            "sender_address": "sender@example.com",
            "recipient_address": "recipient@example.com",
            "original_client_ip": "203.0.113.10",
            "message_id": "<message@example.com>",
            "message_subject": "Important message",
            "status": "Delivered",
        }])
        row = rows[0]
        self.assertEqual(row["Received"], "2026-07-25T12:00:00Z")
        self.assertEqual(row["SenderAddress"], "sender@example.com")
        self.assertEqual(row["RecipientAddress"], "recipient@example.com")
        self.assertEqual(row["OriginalClientIP"], "203.0.113.10")
        self.assertEqual(row["MessageId"], "<message@example.com>")
        self.assertEqual(row["Subject"], "Important message")
        self.assertEqual(row["received_time"], "2026-07-25T12:00:00Z")

    def test_trace_aliases_support_search(self):
        row = {"SenderAddress": "sender@example.com", "RecipientAddress": "recipient@example.com",
               "OriginalClientIP": "203.0.113.10", "Status": "Delivered"}
        self.assertTrue(compile_query("sender:=sender@example.com ip:=203.0.113.10 status:=Delivered")(row))
        self.assertTrue(compile_query("recipient:*@example.com")(row))

    def test_reads_utf16_message_trace_export_without_nuls(self):
        text = "Received,Sender Address,Recipient Address,Status\r\n2026-07-25T12:00:00Z,sender@example.com,recipient@example.com,Delivered\r\n"
        for raw in (text.encode("utf-16"), text.encode("utf-16-le"), text.encode("utf-16-be")):
            rows = read_upload("trace.csv", raw)
            self.assertEqual(rows[0]["Sender Address"], "sender@example.com")
            self.assertNotIn("\x00", "".join(str(value) for value in rows[0].values()))

    def test_detects_message_trace_ip_columns(self):
        columns = ["Original Client IP", "FromIP", "RecipientAddress", "FromIP_IPAPI_Country"]
        self.assertEqual(message_trace_ip_columns(columns), ["FromIP", "Original Client IP"])

    def test_extracts_email_domains_and_parses_rdap_registration_fields(self):
        self.assertEqual(email_domains('Alice <alice@Example.COM>; bob@sub.example.net'), ["example.com", "sub.example.net"])
        payload = {
            "ldhName": "EXAMPLE.COM", "status": ["client transfer prohibited"],
            "events": [{"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
                       {"eventAction": "expiration", "eventDate": "2027-08-13T04:00:00Z"}],
            "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar"]]]}],
            "nameservers": [{"ldhName": "A.IANA-SERVERS.NET"}], "secureDNS": {"delegationSigned": True},
        }
        parsed = parse_rdap_domain(payload, "example.com")
        self.assertEqual(parsed["Registrar"], "Example Registrar")
        self.assertEqual(parsed["RegistrationDate"], "1995-08-14T04:00:00Z")
        self.assertEqual(parsed["NameServers"], "a.iana-servers.net")
        self.assertEqual(parsed["DNSSEC"], "Signed")

    def test_hunts_new_domains_and_suspicious_subjects(self):
        rows = [
            {"_Row": 1, "SenderAddress": "sender@new-example.com", "Subject": "Important: DocuSign shared with you"},
            {"_Row": 2, "SenderAddress": "sender@old-example.com", "Subject": "Quarterly newsletter"},
            {"_Row": 3, "SenderAddress": "sender@old-example.com", "Subject": "Urgent invoice review"},
        ]
        domains = {
            "new-example.com": {"RegistrationDate": "2026-05-01T00:00:00Z"},
            "old-example.com": {"RegistrationDate": "2010-01-01T00:00:00Z"},
        }
        result = hunt_suspicious_message_trace(rows, domains, ["SenderAddress"], max_age_days=365,
                                               keywords=["Important", "DocuSign", "Urgent", "Invoice"],
                                               now=datetime(2026, 7, 25, tzinfo=timezone.utc))
        self.assertEqual(result["findingCount"], 2)
        self.assertEqual(result["findings"]["1"]["Risk"], "High")
        self.assertEqual(result["findings"]["1"]["NewDomains"], "new-example.com")
        self.assertIn("new-example.com is 85 days old", result["findings"]["1"]["SuspiciousReason"])
        self.assertIn('Subject contains suspicious keywords: "Important", "DocuSign"', result["findings"]["1"]["SuspiciousReason"])
        self.assertEqual(result["findings"]["3"]["Risk"], "Medium")
        ranged = hunt_suspicious_message_trace(rows, domains, ["SenderAddress"], registered_after="2026-04-01",
                                               registered_before="2026-06-01", keywords=[],
                                               now=datetime(2026, 7, 25, tzinfo=timezone.utc))
        self.assertEqual(list(ranged["findings"]), ["1"])

    def test_hunts_surveymonkey_sender_domains_as_review_signal(self):
        rows = [
            {"_Row": 1, "SenderAddress": "survey-noreply@lr.outbound.surveymonkey.com", "Subject": "Your survey"},
            {"_Row": 2, "SenderAddress": "sender@surveymonkey-example.com", "Subject": "Your survey"},
            {"_Row": 3, "sender_address": "sender@research.net", "Subject": "Important response"},
        ]
        result = hunt_suspicious_message_trace(
            rows, {}, [], use_domain_age=False, keywords=["Important"],
            service_domains=["surveymonkey.com", "research.net"],
            now=datetime(2026, 7, 25, tzinfo=timezone.utc),
        )
        self.assertEqual(set(result["findings"]), {"1", "3"})
        self.assertEqual(result["serviceHitCount"], 2)
        self.assertEqual(result["findings"]["1"]["Risk"], "Medium")
        self.assertEqual(result["findings"]["1"]["ServiceDomains"], "lr.outbound.surveymonkey.com")
        self.assertIn("matches surveymonkey.com", result["findings"]["1"]["SuspiciousReason"])
        self.assertEqual(result["findings"]["3"]["Risk"], "High")

    def test_store_keeps_trace_rows_and_enrichment_inside_case(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            case_id = "abcdef123456"
            case_dir = root / case_id
            case_dir.mkdir()
            (case_dir / "meta.json").write_text(json.dumps({"id": case_id, "name": "Trace test"}), encoding="utf-8")
            (case_dir / "rows.jsonl").write_text(json.dumps({"_Row": 1, "Operation": "UserLoggedIn"}) + "\n", encoding="utf-8")
            store = CaseStore(root)
            csv_data = b"Received,Sender Address,Recipient Address,Original Client IP,Status\n2026-07-25T12:00:00Z,sender@example.com,recipient@example.com,203.0.113.10,Delivered\n"
            first = store.create_message_trace(case_id, "trace.csv", csv_data, "Initial trace")
            self.assertEqual(store.message_trace_overview(case_id, first["id"])["summary"]["rows"], 1)
            store.save_message_trace_enrichment(case_id, first["id"], {"203.0.113.10": {"Country": "Canada", "Lookup_Status": "Success"}}, ["OriginalClientIP"])
            self.assertEqual(store.message_trace_rows(case_id, first["id"])[0]["OriginalClientIP_IPAPI_Country"], "Canada")
            store.save_message_trace_domain_enrichment(case_id, first["id"], {"example.com": {"Domain": "example.com", "Registrar": "Example Registrar", "RegistrationDate": "2026-07-01T00:00:00Z", "Lookup_Status": "Success"}}, ["SenderAddress"])
            enriched_row = store.message_trace_rows(case_id, first["id"])[0]
            self.assertEqual(enriched_row["SenderAddress_WHOIS_Registrar"], "Example Registrar")
            store.hunt_message_trace(case_id, first["id"], [enriched_row], registered_after="2026-06-01", registered_before="2026-08-01", keywords=[])
            self.assertTrue(store.message_trace_rows(case_id, first["id"])[0]["MessageTraceHunt.Flag"])
            tagged = store.set_message_trace_row_tags(case_id, first["id"], [1], True)
            self.assertEqual(tagged["taggedCount"], 1)
            self.assertEqual(store.message_trace_rows(case_id, first["id"])[0]["Review.Tag"], "Of interest")
            self.assertEqual(store.message_trace_overview(case_id, first["id"])["summary"]["tagged"], 1)
            generated = store.enable_message_trace_events(case_id, first["id"], [1])
            self.assertEqual(generated["matched"], 1)
            self.assertEqual(store.message_trace_rows(case_id, first["id"])[0]["Event"], "Subject: ; Sender: sender@example.com; Recipient: recipient@example.com")
            self.assertIn("Event", store.message_trace_overview(case_id, first["id"])["columns"])
            self.assertTrue((case_dir / "message-trace" / "traces" / first["id"] / "event-summary.json").is_file())
            exported = store.csv_bytes(store.message_trace_rows(case_id, first["id"]), {}).decode("utf-8-sig")
            self.assertIn("OriginalClientIP_IPAPI_Country", exported)
            self.assertIn("MessageTraceHunt.SuspiciousReason", exported)
            self.assertIn("Event", exported)
            self.assertNotIn("OriginalClientIP_IPAPI_Country", store.rows(case_id)[0])
            replacement = b"Received,Sender Address,Recipient Address,Original Client IP,Status\n2026-07-26T12:00:00Z,new@example.com,recipient@example.com,198.51.100.20,Delivered\n"
            second = store.create_message_trace(case_id, "replacement.csv", replacement, "Follow-up trace")
            self.assertEqual(store.message_trace_rows(case_id, second["id"])[0]["OriginalClientIP"], "198.51.100.20")
            self.assertEqual(store.message_trace_enrichment(case_id, second["id"]), {})
            self.assertNotIn("Review.Tag", store.message_trace_rows(case_id, second["id"])[0])
            self.assertEqual(store.message_trace_rows(case_id, first["id"])[0]["OriginalClientIP_IPAPI_Country"], "Canada")
            traces = store.message_traces(case_id)
            self.assertEqual({trace["name"] for trace in traces}, {"Initial trace", "Follow-up trace"})
            store.delete_message_trace(case_id, second["id"])
            self.assertEqual([trace["id"] for trace in store.message_traces(case_id)], [first["id"]])
            untagged = store.set_message_trace_row_tags(case_id, first["id"], [1], False)
            self.assertEqual(untagged["taggedCount"], 0)
            self.assertNotIn("Review.Tag", store.message_trace_rows(case_id, first["id"])[0])

    def test_existing_single_trace_is_available_as_legacy_dataset(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            case_id = "abcdef123456"
            case_dir = root / case_id
            trace_dir = case_dir / "message-trace"
            trace_dir.mkdir(parents=True)
            (case_dir / "meta.json").write_text(json.dumps({"id": case_id, "name": "Legacy test"}), encoding="utf-8")
            (case_dir / "rows.jsonl").write_text("", encoding="utf-8")
            (trace_dir / "meta.json").write_text(json.dumps({"sourceFile": "old.csv", "uploadedAt": "2026-07-01T00:00:00Z", "rowCount": 1}), encoding="utf-8")
            (trace_dir / "rows.jsonl").write_text(json.dumps({"_Row": 1, "SenderAddress": "sender@example.com"}) + "\n", encoding="utf-8")
            store = CaseStore(root)
            self.assertEqual(store.message_traces(case_id)[0]["id"], "legacy")
            self.assertEqual(store.message_trace_rows(case_id, "legacy")[0]["SenderAddress"], "sender@example.com")
            csv_data = b"Received,Sender Address\n2026-07-25T12:00:00Z,new@example.com\n"
            modern = store.create_message_trace(case_id, "new.csv", csv_data, "New trace")
            store.delete_message_trace(case_id, "legacy")
            self.assertEqual(store.message_trace_rows(case_id, modern["id"])[0]["SenderAddress"], "new@example.com")
            self.assertEqual([trace["id"] for trace in store.message_traces(case_id)], [modern["id"]])


if __name__ == "__main__":
    unittest.main()
