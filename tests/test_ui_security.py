import unittest
import sys
import types
from unittest.mock import patch

from privacylens.ui.security import LOCAL_BIND_HOST, new_session_token, serve_local, validate_local_request


class LocalUISecurityTests(unittest.TestCase):
    def test_random_session_token_and_origin_host_guards(self):
        first, second = new_session_token(), new_session_token()
        self.assertNotEqual(first, second)
        self.assertTrue(validate_local_request("127.0.0.1:8765", "http://127.0.0.1:8765", first, first, 8765))
        for host, origin, token in (
            ("0.0.0.0:8765", "http://127.0.0.1:8765", first),
            ("127.0.0.1:8765", "http://localhost:8765", first),
            ("127.0.0.1:8765", "", first),
            ("127.0.0.1:8765", "http://127.0.0.1:8765", "wrong"),
        ):
            with self.subTest(host=host, origin=origin):
                with self.assertRaises(PermissionError):
                    validate_local_request(host, origin, token, first, 8765)
        self.assertEqual(LOCAL_BIND_HOST, "127.0.0.1")

    def test_server_runner_cannot_bind_to_non_loopback(self):
        uvicorn = types.ModuleType("uvicorn")
        calls = []
        uvicorn.run = lambda *args, **kwargs: calls.append((args, kwargs))
        with patch.dict(sys.modules, {"uvicorn": uvicorn}):
            serve_local(object(), 8123)
        self.assertEqual(calls[0][1]["host"], "127.0.0.1")


if __name__ == "__main__": unittest.main()
