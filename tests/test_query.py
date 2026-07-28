import unittest

from ual_app.core import compile_query


class QueryTests(unittest.TestCase):
    def test_exact_empty_matches_missing_and_explicitly_blank_fields(self):
        predicate = compile_query('Login.DeviceName:=""')
        self.assertTrue(predicate({"Operation": "UserLoggedIn"}))
        self.assertTrue(predicate({"Login.DeviceName": ""}))
        self.assertFalse(predicate({"Login.DeviceName": "Managed-Laptop"}))

    def test_excluding_empty_keeps_only_populated_fields(self):
        predicate = compile_query('-Login.DeviceName:=""')
        self.assertFalse(predicate({"Operation": "UserLoggedIn"}))
        self.assertFalse(predicate({"Login.DeviceName": ""}))
        self.assertTrue(predicate({"Login.DeviceName": "Managed-Laptop"}))

    def test_wildcard_does_not_treat_an_absent_field_as_present(self):
        self.assertFalse(compile_query('Login.DeviceName:*')({"Operation": "UserLoggedIn"}))

    def test_time_range_supports_inclusive_and_exclusive_boundaries(self):
        predicate = compile_query("time:>=2026-07-21T12:00:00Z time:<2026-07-22T00:00:00Z")
        self.assertTrue(predicate({"CreationTime": "2026-07-21T12:00:00Z"}))
        self.assertTrue(predicate({"CreationTime": "2026-07-21T23:59:59Z"}))
        self.assertFalse(predicate({"CreationTime": "2026-07-21T11:59:59Z"}))
        self.assertFalse(predicate({"CreationTime": "2026-07-22T00:00:00Z"}))

    def test_time_comparison_accepts_spaced_syntax_and_timezone_offsets(self):
        predicate = compile_query("time: >=2026-07-21T12:00:00Z")
        self.assertTrue(predicate({"CreationTime": "2026-07-21T08:00:00-04:00"}))
        self.assertFalse(predicate({"CreationTime": "2026-07-21T07:59:59-04:00"}))

    def test_numeric_comparisons_are_supported(self):
        predicate = compile_query("_Row:>10 _Row:<=20")
        self.assertTrue(predicate({"_Row": 11}))
        self.assertTrue(predicate({"_Row": 20}))
        self.assertFalse(predicate({"_Row": 10}))
        self.assertFalse(predicate({"_Row": 21}))

    def test_comparison_requires_a_value(self):
        with self.assertRaisesRegex(ValueError, "missing a value"):
            compile_query("time:>")

    def test_or_matches_any_of_multiple_ips(self):
        predicate = compile_query("ip:=1.2.3.4 OR ip:=5.6.7.8")
        self.assertTrue(predicate({"ClientIP": "1.2.3.4"}))
        self.assertTrue(predicate({"ActorIpAddress": "5.6.7.8"}))
        self.assertFalse(predicate({"ClientIP": "9.9.9.9"}))

    def test_or_is_case_insensitive_and_accepts_double_pipe(self):
        self.assertTrue(compile_query("ip:=1.2.3.4 or ip:=5.6.7.8")({"ClientIP": "5.6.7.8"}))
        self.assertTrue(compile_query("ip:=1.2.3.4 || ip:=5.6.7.8")({"ClientIP": "1.2.3.4"}))

    def test_and_binds_more_tightly_than_or(self):
        predicate = compile_query("user:=alice@example.com AND ip:=1.2.3.4 OR user:=bob@example.com ip:=5.6.7.8")
        self.assertTrue(predicate({"UserId": "alice@example.com", "ClientIP": "1.2.3.4"}))
        self.assertTrue(predicate({"UserId": "bob@example.com", "ClientIP": "5.6.7.8"}))
        self.assertFalse(predicate({"UserId": "alice@example.com", "ClientIP": "5.6.7.8"}))

    def test_parentheses_group_multiple_selected_values(self):
        predicate = compile_query('(ip:=1.2.3.4 OR ip:=5.6.7.8) AND operation:=UserLoggedIn')
        self.assertTrue(predicate({"ClientIP": "1.2.3.4", "Operation": "UserLoggedIn"}))
        self.assertTrue(predicate({"ClientIP": "5.6.7.8", "Operation": "UserLoggedIn"}))
        self.assertFalse(predicate({"ClientIP": "1.2.3.4", "Operation": "UserLoginFailed"}))
        self.assertFalse(predicate({"ClientIP": "9.9.9.9", "Operation": "UserLoggedIn"}))

    def test_nested_parentheses_and_quoted_parenthesis_values(self):
        predicate = compile_query('(user:=alice@example.com OR (user:=bob@example.com AND ip:=5.6.7.8))')
        self.assertTrue(predicate({"UserId": "alice@example.com", "ClientIP": "9.9.9.9"}))
        self.assertTrue(predicate({"UserId": "bob@example.com", "ClientIP": "5.6.7.8"}))
        self.assertFalse(predicate({"UserId": "bob@example.com", "ClientIP": "9.9.9.9"}))
        self.assertTrue(compile_query('Subject:="Review (urgent)"')({"Subject": "Review (urgent)"}))

    def test_invalid_parentheses_are_rejected(self):
        for query in ('(ip:=1.2.3.4', 'ip:=1.2.3.4)', '()', '(ip:=1.2.3.4 OR)'):
            with self.subTest(query=query), self.assertRaisesRegex(ValueError, "Invalid query"):
                compile_query(query)

    def test_incomplete_boolean_expressions_are_rejected(self):
        for query in ("OR ip:=1.2.3.4", "ip:=1.2.3.4 OR", "ip:=1.2.3.4 OR AND ip:=5.6.7.8"):
            with self.subTest(query=query), self.assertRaisesRegex(ValueError, "complete expressions"):
                compile_query(query)


if __name__ == "__main__":
    unittest.main()
