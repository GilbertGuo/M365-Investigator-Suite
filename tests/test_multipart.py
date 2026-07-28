import unittest

from ual_app.server import parse_multipart_form


class MultipartFormTests(unittest.TestCase):
    def test_reads_text_and_uploaded_file(self):
        boundary = "M365InvestigatorBoundary"
        body = (
            f"--{boundary}\r\n"
            'Content-Disposition: form-data; name="name"\r\n\r\n'
            "Case 42\r\n"
            f"--{boundary}\r\n"
            'Content-Disposition: form-data; name="file"; filename="audit.csv"\r\n'
            "Content-Type: text/csv\r\n\r\n"
            "UserId,Operation\r\nuser@example.com,UserLoggedIn\r\n"
            f"--{boundary}--\r\n"
        ).encode()
        form = parse_multipart_form(f"multipart/form-data; boundary={boundary}", body)
        self.assertEqual(form.getfirst("name"), "Case 42")
        self.assertEqual(form["file"].filename, "audit.csv")
        self.assertEqual(form["file"].file.read(), b"UserId,Operation\r\nuser@example.com,UserLoggedIn")

    def test_rejects_non_multipart_content(self):
        with self.assertRaisesRegex(ValueError, "multipart"):
            parse_multipart_form("application/json", b"{}")

    def test_rejects_missing_boundary(self):
        with self.assertRaisesRegex(ValueError, "Invalid multipart"):
            parse_multipart_form("multipart/form-data", b"not a form")


if __name__ == "__main__":
    unittest.main()
