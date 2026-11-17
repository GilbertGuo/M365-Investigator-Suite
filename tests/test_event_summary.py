import json
import unittest

from ual_app.core import build_event_summary


class EventSummaryTests(unittest.TestCase):
    def test_search_query_performed_includes_recorded_query(self):
        for field in ('SearchQueryText', 'QueryText', 'SearchQuery', 'Query', 'SearchText',
                      'AuditData.QueryText', 'AuditData.SearchQueryText', 'Query.QueryText'):
            with self.subTest(field=field):
                event = build_event_summary({'Operation': 'SearchQueryPerformed', 'UserId': 'user@example.com',
                                             'ClientIP': '203.0.113.10', 'Workload': 'SharePoint',
                                             'SiteUrl': 'https://example.sharepoint.com/sites/test', field: '"annual report" AND FileType:pdf'})
                self.assertIn('search query: "annual report" AND FileType:pdf', event)
                self.assertIn('user@example.com', event)
                self.assertIn('203.0.113.10', event)
                self.assertIn('site https://example.sharepoint.com/sites/test', event)

    def test_search_query_named_properties_and_prefixed_fields(self):
        for field in ('OperationProperties', 'AuditData.Parameters', 'ExtendedProperties'):
            for operation in ('SearchQueryPerformed', 'SearchQueryInitiatedExchange', 'SearchQueryInitiatedSharePoint'):
                with self.subTest(field=field, operation=operation):
                    row = {'Operation': operation, field: json.dumps([{'Name': 'QueryText', 'Value': 'invoice AND attachment:pdf'}])}
                    self.assertIn('search query: invoice AND attachment:pdf', build_event_summary(row))

    def test_search_query_preserves_long_text_and_quoted_whitespace(self):
        query = '"two  spaces" AND ' + ' OR '.join(f'term{index}' for index in range(100))
        event = build_event_summary({'Operation': 'SearchQueryPerformed', 'QueryText': query})
        self.assertIn(query, event)
        self.assertNotIn('…', event)

    def test_search_without_query_does_not_invent_one(self):
        event = build_event_summary({'Operation': 'SearchQueryPerformed', 'ObjectId': 'https://example.sharepoint.com', 'QueryText': ''})
        self.assertNotIn('search query:', event)

    def test_nonsearch_event_does_not_include_unrelated_query_metadata(self):
        event = build_event_summary({'Operation': 'FileAccessed', 'Workload': 'SharePoint', 'QueryText': 'unrelated'})
        self.assertNotIn('search query:', event)

    def test_login_stops_after_identity_and_ip_intelligence(self):
        row = {
            "CreationTime": "2026-07-25T12:30:00Z",
            "Operation": "UserLoggedIn",
            "UserId": "analyst@example.com",
            "ClientIP": "203.0.113.10",
            "ClientIP_IPAPI_Country": "Canada",
            "ClientIP_IPAPI_Region": "Ontario",
            "ClientIP_IPAPI_City": "Toronto",
            "ClientIP_IPAPI_ISP": "Example ISP",
            "ClientIP_IPAPI_Proxy_VPN_TOR": False,
            "ClientIP_IPAPI_Hosting": True,
            "Login.DeviceName": "FORENSIC-LT",
            "Login.OS": "Windows 11",
            "Login.IsCompliant": False,
            "Login.IsManaged": True,
            "Login.ResultStatusDetail": "Redirect",
            "Login.UserAuthenticationMethod": "Password",
            "Login.SessionId": "session-123",
            "ResultStatus": "Success",
        }
        event = build_event_summary(row)
        for expected in ("UserLoggedIn", "analyst@example.com", "203.0.113.10", "Canada, Ontario, Toronto",
                         "Example ISP", "Hosting"):
            self.assertIn(expected, event)
        for omitted in ("2026-07-25", "VPN/Proxy/TOR", "FORENSIC-LT", "compliant", "managed",
                        "authentication", "Redirect", "session-123", "result Success"):
            self.assertNotIn(omitted, event)

    def test_true_vpn_flag_is_shown_without_boolean_value(self):
        event = build_event_summary({
            "Operation": "UserLoggedIn", "UserId": "user@example.com", "ClientIP": "203.0.113.10",
            "ClientIP_IPAPI_Proxy_VPN_TOR": "true", "ClientIP_IPAPI_Hosting": "false",
        })
        self.assertIn("; VPN/Proxy/TOR.", event)
        self.assertNotIn("Hosting", event)
        self.assertNotIn("true", event.casefold())

    def test_mail_event_includes_subject_and_message_id(self):
        event = build_event_summary({
            "Operation": "MailItemsAccessed", "Workload": "Exchange", "UserId": "user@example.com",
            "MessageSubject.Subjects": "Invoice review", "InternetMessageIDs": "<id@example.com>",
            "ResultStatus": "Succeeded",
        })
        self.assertIn("subject Invoice review", event)
        self.assertIn("message ID <id@example.com>", event)

    def test_inbox_rule_event_includes_rule_details(self):
        event = build_event_summary({
            "Operation": "New-InboxRule", "UserId": "user@example.com", "InboxRule.Name": "Move invoices",
            "InboxRule.Details": "From=billing@example.com; MoveToFolder=Invoices",
        })
        self.assertIn("rule Move invoices", event)
        self.assertIn("actions From=billing@example.com; MoveToFolder=Invoices", event)


if __name__ == "__main__":
    unittest.main()
