import unittest

from ual_app.core import add_mail_review, compile_query


class MailReviewTests(unittest.TestCase):
    def test_mail_items_accessed_user_agent_string(self):
        for field in ("UserAgentString", "AuditData.UserAgentString"):
            with self.subTest(field=field):
                row = {"Operation": "MailItemsAccessed", field: "SyntheticMailClient/3.0"}
                self.assertEqual(add_mail_review(row)["Mail.UserAgent"], "SyntheticMailClient/3.0")
                self.assertEqual(row[field], "SyntheticMailClient/3.0")
                self.assertTrue(compile_query('useragent:="SyntheticMailClient/3.0"')(row))

    def test_extracts_true_user_agent_from_actor_info_string(self):
        row = {
            "Operation": "MailItemsAccessed",
            "ActorInfoString": "Client=REST;Client=RESTSystem;UserAgent=ExampleClient/1.0 [AppId=00000000-0000-0000-0000-000000000000]",
            "UserAgent": "Client=Legacy;Action=Access",
            "ClientInfoString": "Client=REST;Action=Bind",
        }
        result = add_mail_review(row)
        self.assertEqual(result["Mail.ActorInfoString"], row["ActorInfoString"])
        self.assertEqual(result["Mail.UserAgent"], "ExampleClient/1.0 [AppId=00000000-0000-0000-0000-000000000000]")
        self.assertEqual(result["Mail.ClientInfoString"], row["ClientInfoString"])

    def test_supports_hyphenated_actor_user_agent_format(self):
        row = {
            "Operation": "Send",
            "ActorInfoString": "Client-REST;Client-RESTSystem;UserAgent-[NoUserAgent] [AppId-00000000-0000-0000-0000-000000000000]",
        }
        self.assertEqual(
            add_mail_review(row)["Mail.UserAgent"],
            "[NoUserAgent] [AppId-00000000-0000-0000-0000-000000000000]",
        )

    def test_uses_prefixed_audit_fields_and_reported_user_agent_fallback(self):
        row = {
            "Operation": "SoftDelete",
            "ActorInfoString": "",
            "AuditData.ActorInfoString": "",
            "AuditData.UserAgent": "SyntheticMailClient/2.0",
            "AuditData.ClientInfoString": "Client=OWA",
        }
        result = add_mail_review(row)
        self.assertEqual(result["Mail.UserAgent"], "SyntheticMailClient/2.0")
        self.assertEqual(result["Mail.ClientInfoString"], "Client=OWA")
        self.assertNotIn("Mail.ActorInfoString", result)

    def test_does_not_add_mail_fields_to_non_mail_activity(self):
        row = {"Operation": "FileAccessed", "ActorInfoString": "UserAgent=ExampleClient/1.0"}
        self.assertIs(add_mail_review(row), row)
        self.assertNotIn("Mail.UserAgent", row)


if __name__ == "__main__":
    unittest.main()
