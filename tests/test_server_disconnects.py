import unittest

from ual_app.server import Handler


class DisconnectingWriter:
    def write(self, _body):
        raise BrokenPipeError(32, "Broken pipe")


class ServerDisconnectTests(unittest.TestCase):
    def test_json_response_ignores_browser_disconnect(self):
        handler = object.__new__(Handler)
        handler.wfile = DisconnectingWriter()
        handler.send_response = lambda _status: None
        handler.send_header = lambda _name, _value: None
        handler.end_headers = lambda: None

        handler.json_response({"rows": [1, 2, 3]})

    def test_get_dispatch_does_not_turn_disconnect_into_500(self):
        handler = object.__new__(Handler)
        handler.path = "/api/cases"

        def disconnect(_data, status=200):
            raise ConnectionResetError(54, "Connection reset by peer")

        handler.json_response = disconnect
        handler.do_GET()


if __name__ == "__main__":
    unittest.main()
