import unittest

from ual_app.app_mapping import UNKNOWN_APP, add_app_name_mapping, app_reference, is_app_id_field


class AppMappingTests(unittest.TestCase):
    def test_recognizes_flat_and_nested_app_id_fields(self):
        self.assertTrue(is_app_id_field("ApplicationId"))
        self.assertTrue(is_app_id_field("AppAccessContext.ClientAppId"))
        self.assertFalse(is_app_id_field("AppMapping.ApplicationId"))
        self.assertFalse(is_app_id_field("ApplicationName"))

    def test_maps_known_microsoft_app(self):
        row = {"ApplicationId": "D3590ED6-52B3-4102-AEFF-AAD2292AB01C"}
        add_app_name_mapping(row)
        self.assertEqual(row["AppMapping.ApplicationId"], "Microsoft Office")

    def test_marks_unlisted_uuid_without_mapping_non_uuid_values(self):
        row = {"ApplicationId": "11111111-1111-1111-1111-111111111111", "ClientAppId": "not-a-uuid"}
        add_app_name_mapping(row)
        self.assertEqual(row["AppMapping.ApplicationId"], UNKNOWN_APP)
        self.assertNotIn("AppMapping.ClientAppId", row)

    def test_reference_has_source_metadata_and_entries(self):
        reference = app_reference()
        self.assertGreaterEqual(len(reference["apps"]), 270)
        self.assertEqual(reference["source"], "https://learn.microsoft.com/en-us/power-platform/admin/apps-to-allow")


if __name__ == "__main__":
    unittest.main()
