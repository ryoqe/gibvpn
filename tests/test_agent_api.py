import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import agent_api
import ai_probe


class TestAgentApiAuthorization(unittest.TestCase):
    def test_local_host_allowed(self):
        for host in ("127.0.0.1:7781", "localhost:7781", "127.0.0.1"):
            ok, _ = agent_api.is_authorized({"Host": host}, "t" * 32)
            self.assertTrue(ok, host)

    def test_foreign_host_rejected(self):
        ok, reason = agent_api.is_authorized({"Host": "evil.example:7781"}, "t")
        self.assertFalse(ok)
        self.assertIn("host", reason)

    def test_missing_host_rejected(self):
        ok, _ = agent_api.is_authorized({}, "t")
        self.assertFalse(ok)

    def test_browser_origin_rejected(self):
        ok, reason = agent_api.is_authorized(
            {"Host": "127.0.0.1:7781", "Origin": "https://evil.example"}, "t"
        )
        self.assertFalse(ok)
        self.assertIn("origin", reason)

    def test_token_optional_by_default(self):
        headers = {"Host": "127.0.0.1:7781"}
        self.assertTrue(agent_api.is_authorized(headers, "secret")[0])
        self.assertTrue(
            agent_api.is_authorized({**headers, "X-GibVPN-Token": "secret"}, "secret")[0]
        )
        self.assertFalse(
            agent_api.is_authorized({**headers, "X-GibVPN-Token": "wrong"}, "secret")[0]
        )

    def test_token_required_when_enabled(self):
        headers = {"Host": "127.0.0.1:7781"}
        self.assertFalse(
            agent_api.is_authorized(headers, "secret", require_token=True)[0]
        )
        self.assertTrue(
            agent_api.is_authorized(
                {**headers, "X-GibVPN-Token": "secret"}, "secret", require_token=True
            )[0]
        )


class TestOmniConfig(unittest.TestCase):
    def test_defaults_use_home_and_source_has_no_username(self):
        config = ai_probe.resolve_omni_config({})
        home = os.path.expanduser("~")
        self.assertEqual(config["key_path"], os.path.join(home, "jarvis", "omni-api-key.txt"))
        with open(ai_probe.__file__, encoding="utf-8") as handle:
            self.assertNotIn("merka", handle.read())

    def test_environment_overrides(self):
        config = ai_probe.resolve_omni_config({
            "GIBVPN_OMNI_DIR": r"D:\omni",
            "GIBVPN_OMNI_BASE": "http://127.0.0.1:9999/",
            "GIBVPN_OMNI_MODEL": "test-model",
            "GIBVPN_OMNI_AUTH_PATH": r"D:\auth.txt",
        })
        self.assertEqual(config["base"], "http://127.0.0.1:9999")
        self.assertEqual(config["model"], "test-model")
        self.assertEqual(config["key_path"], os.path.join(r"D:\omni", "omni-api-key.txt"))
        self.assertEqual(config["auth_path"], r"D:\auth.txt")


class TestOmniProxyBackup(unittest.TestCase):
    def tearDown(self):
        ai_probe.clear_proxy_backup()

    def test_backup_roundtrip_and_clear(self):
        ai_probe.save_proxy_backup({"host": "127.0.0.1", "port": 10808, "type": "socks5"})
        exists, prev = ai_probe.load_proxy_backup()
        self.assertTrue(exists)
        self.assertEqual(prev["port"], 10808)
        ai_probe.clear_proxy_backup()
        self.assertFalse(ai_probe.load_proxy_backup()[0])

    def test_none_previous_value_is_preserved(self):
        ai_probe.save_proxy_backup(None)
        exists, prev = ai_probe.load_proxy_backup()
        self.assertTrue(exists)
        self.assertIsNone(prev)

    def test_recover_restores_and_clears(self):
        ai_probe.save_proxy_backup(None)
        with mock.patch.object(ai_probe, "omni_restore_proxy") as restore:
            self.assertEqual(ai_probe.recover_proxy_backup(), "restored")
            restore.assert_called_once_with(None)
        self.assertFalse(ai_probe.load_proxy_backup()[0])

    def test_recover_keeps_backup_when_omniroute_down(self):
        ai_probe.save_proxy_backup({"host": "x", "port": 1, "type": "socks5"})
        with mock.patch.object(ai_probe, "omni_restore_proxy", side_effect=OSError):
            self.assertEqual(ai_probe.recover_proxy_backup(), "pending")
        self.assertTrue(ai_probe.load_proxy_backup()[0])


if __name__ == "__main__":
    unittest.main()
