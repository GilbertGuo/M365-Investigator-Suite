import json
import unittest

from ual_app.core import add_inbox_rule_review


class InboxRuleReviewTests(unittest.TestCase):
    def test_extracts_names_from_supported_audit_shapes(self):
        cases = [
            {'Parameters': [{'Name': 'Name', 'Value': 'Review documents'}]},
            {'Parameters': json.dumps([{'Name': 'Name', 'Value': 'Review documents'}])},
            {'Parameters': '', 'AuditData.Parameters': json.dumps([{'Name': 'Name', 'Value': 'Review documents'}])},
            {'OperationProperties': [{'Name': 'RuleName', 'Value': 'Review documents'}]},
            {'AuditData.OperationProperties': json.dumps([{'Name': 'RuleName', 'Value': 'Review documents'}])},
            {'OperationProperties': [{'name': 'rulename', 'value': 'Review documents'}]},
            {'AuditData.RuleName': 'Review documents'},
            {'RuleName': 'Review documents'},
            {'AuditData.Name': 'Review documents'},
            {'Parameters': {'Name': 'Review documents'}},
        ]
        for operation in ('New-InboxRule', 'Set-InboxRule', 'UpdateInboxRules', 'Remove-InboxRule'):
            for fields in cases:
                with self.subTest(operation=operation, fields=fields):
                    row = {'Operation': operation, **fields}
                    self.assertEqual(add_inbox_rule_review(row)['InboxRule.Name'], 'Review documents')

    def test_keeps_rule_details_and_false_values(self):
        result = add_inbox_rule_review({'Operation': 'New-InboxRule', 'Parameters': [
            {'Name': 'Name', 'Value': 'Review documents'}, {'Name': 'Enabled', 'Value': False},
            {'Name': 'Force', 'Value': True},
        ]})
        self.assertEqual(result['InboxRule.Name'], 'Review documents')
        self.assertIs(result['InboxRule.Enabled'], False)
        self.assertEqual(result['InboxRule.Details'], 'Name=Review documents; Enabled=False')

    def test_does_not_treat_an_identity_or_id_as_a_rule_name(self):
        for fields in ({'Parameters': [{'Name': 'Identity', 'Value': 'mailbox@example.com\\123456'}]},
                       {'OperationProperties': [{'Name': 'RuleId', 'Value': '123456'}]}):
            self.assertNotIn('InboxRule.Name', add_inbox_rule_review({'Operation': 'Set-InboxRule', **fields}))

    def test_does_not_add_rule_name_to_non_inbox_activity(self):
        row = {'Operation': 'Send', 'Name': 'Document', 'RuleName': 'Unrelated'}
        self.assertNotIn('InboxRule.Name', add_inbox_rule_review(row))
