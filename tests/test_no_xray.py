import os
import sys
import tempfile
import json
import time
import base64
import subprocess
import unittest
from unittest import mock

# Make sure project root is on path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import appcore
import builder
from PyQt6.QtWidgets import QApplication
from gui import (
    GibVPNApp, SettingsDialog, ServerListDialog,
    SubscriptionManagerDialog, PingSitesDialog,
)


SAMPLE_VLESS = (
    "vless://a1b2c3d4-e5f6-7890-abcd-ef1234567890@example.com:443?"
    "type=tcp&security=reality&sni=example.com&pbk=PublicKey123&sid=ShortID&"
    "fp=firefox&flow=xtls-rprx-vision#MyServer"
)

SAMPLE_TROJAN = "trojan://password@trojan.example.com:443?type=ws&sni=trojan.example.com#TrojanTest"
SAMPLE_SS = "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@ss.example.com:8388#SSTest"


def make_vmess(**overrides):
    cfg = {
        "add": "vmess.example.com",
        "port": 443,
        "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
        "aid": 0,
        "net": "tcp",
        "tls": "",
        "ps": "VMessTest",
    }
    cfg.update(overrides)
    return "vmess://" + base64.b64encode(json.dumps(cfg).encode()).decode()


class TestBuilder(unittest.TestCase):
    def test_parse_vless_extracts_fields(self):
        srv = builder.parse_vless(SAMPLE_VLESS, "test-tag")
        self.assertIsNotNone(srv)
        self.assertEqual(srv["protocol"], "vless")
        self.assertEqual(srv["tag"], "test-tag")
        vnext = srv["settings"]["vnext"][0]
        self.assertEqual(vnext["address"], "example.com")
        self.assertEqual(vnext["port"], 443)
        self.assertEqual(vnext["users"][0]["id"], "a1b2c3d4-e5f6-7890-abcd-ef1234567890")
        self.assertEqual(srv["streamSettings"]["network"], "tcp")

    def test_server_key_for_protocols(self):
        vless = builder.parse_vless(SAMPLE_VLESS, "v")
        self.assertEqual(builder.server_key(vless), "example.com:443#a1b2c3d4")

        trojan = builder.parse_trojan(SAMPLE_TROJAN, "t")
        self.assertEqual(builder.server_key(trojan), "trojan.example.com:443#TrojanTest")

        ss = builder.parse_shadowsocks(SAMPLE_SS, "s")
        self.assertEqual(builder.server_key(ss), "ss.example.com:8388#SSTest")

    def test_get_parsed_servers_from_file(self):
        servers = builder.get_parsed_servers()
        self.assertIsInstance(servers, list)
        if servers:
            for srv in servers:
                vnext = srv.get("settings", {}).get("vnext", [{}])[0]
                self.assertIn("address", vnext)
                self.assertIn("port", vnext)

    def test_generate_test_config(self):
        servers = builder.get_parsed_servers()
        if not servers:
            self.skipTest("no servers to build config")
        result = builder.generate_test_config(servers)
        self.assertTrue(result)
        self.assertTrue(os.path.exists("config.json"))
        with open("config.json", "r", encoding="utf-8") as f:
            cfg = json.load(f)
        self.assertIn("inbounds", cfg)
        self.assertEqual(len(cfg["inbounds"]), len(servers))
        with tempfile.TemporaryDirectory() as tmp:
            probe_path = os.path.join(tmp, "probe.json")
            self.assertTrue(builder.generate_test_config(servers, config_path=probe_path))
            self.assertTrue(os.path.exists(probe_path))

    def test_parse_vless_without_query(self):
        url = "vless://a1b2c3d4-e5f6-7890-abcd-ef1234567890@1.2.3.4:443#SimpleVless"
        srv = builder.parse_vless(url, "vless-simple")
        self.assertIsNotNone(srv)
        self.assertEqual(srv["protocol"], "vless")
        self.assertEqual(srv["remark"], "SimpleVless")
        self.assertEqual(srv["settings"]["vnext"][0]["address"], "1.2.3.4")
        self.assertEqual(srv["settings"]["vnext"][0]["port"], 443)

    def test_parse_shadowsocks_sip002(self):
        payload = base64.b64encode(b"aes-256-gcm:password123@1.2.3.4:8388").decode()
        url = f"ss://{payload}#SIP002Server"
        srv = builder.parse_shadowsocks(url, "ss-sip002")
        self.assertIsNotNone(srv)
        self.assertEqual(srv["protocol"], "shadowsocks")
        self.assertEqual(srv["remark"], "SIP002Server")
        self.assertEqual(srv["settings"]["servers"][0]["address"], "1.2.3.4")
        self.assertEqual(srv["settings"]["servers"][0]["port"], 8388)
        self.assertEqual(srv["settings"]["servers"][0]["method"], "aes-256-gcm")

    def test_parse_trojan_default_port(self):
        url = "trojan://secretpass@trojan.test#TrojanNoPort"
        srv = builder.parse_trojan(url, "trojan-noport")
        self.assertIsNotNone(srv)
        self.assertEqual(srv["protocol"], "trojan")
        self.assertEqual(srv["remark"], "TrojanNoPort")
        self.assertEqual(srv["settings"]["servers"][0]["address"], "trojan.test")
        self.assertEqual(srv["settings"]["servers"][0]["port"], 443)

    def test_generate_final_config_with_zapret_and_quic_block(self):
        srv = builder.parse_vless(SAMPLE_VLESS, "test-tag")
        self.assertTrue(builder.generate_final_config(srv, use_zapret=True, block_quic=True))
        with open("config.json", "r", encoding="utf-8") as f:
            cfg = json.load(f)

        # Check blackhole outbound for QUIC blocking
        outbound_tags = [o.get("tag") for o in cfg.get("outbounds", [])]
        self.assertIn("blocked", outbound_tags)

        # Check routing rules
        rules = cfg.get("routing", {}).get("rules", [])
        has_quic_block = any(
            r.get("outboundTag") == "blocked" and r.get("port") == "443" and r.get("network") == "udp"
            for r in rules
        )
        self.assertTrue(has_quic_block)

        # Check direct domains contains youtube when use_zapret=True
        youtube_rule = next(
            (
                r for r in rules
                if r.get("outboundTag") == "direct"
                and "domain:youtubei.googleapis.com" in r.get("domain", [])
            ),
            {},
        )
        direct_rule = next(
            (
                r for r in rules
                if r.get("outboundTag") == "direct"
                and "domain:ru" in r.get("domain", [])
            ),
            {},
        )
        direct_domains = direct_rule.get("domain", [])
        self.assertIn("geosite:youtube", direct_domains)
        self.assertNotIn("domain:chatgpt.com", direct_domains)
        self.assertNotIn("domain:openai.com", direct_domains)

        warp_rule = next(
            (r for r in rules if r.get("outboundTag") == "warp-proxy" and r.get("domain")),
            {},
        )
        self.assertTrue(set(builder.GPT_DOMAINS).issubset(set(warp_rule.get("domain", []))))
        self.assertIn("geosite:google-gemini", warp_rule.get("domain", []))
        self.assertIn("domain:gemini.google.com", warp_rule.get("domain", []))
        self.assertNotIn("full:www.google.com", builder.BASE_HEALTH_DOMAINS)
        self.assertLess(rules.index(youtube_rule), rules.index(warp_rule))
        self.assertLess(rules.index(warp_rule), rules.index(direct_rule))

        health_rule = next(
            (r for r in rules if r.get("domain") == builder.BASE_HEALTH_DOMAINS),
            {},
        )
        self.assertEqual(health_rule.get("outboundTag"), "best-proxy")

    def test_tun_config_prevents_xray_routing_loop(self):
        config_path = builder.generate_tun_config(interface_name="gibvpn-tun")
        with open(config_path, "r", encoding="utf-8") as f:
            cfg = json.load(f)

        tun = cfg["inbounds"][0]
        self.assertEqual(tun["interface_name"], "gibvpn-tun")
        self.assertEqual(tun["address"], ["172.19.0.1/30"])
        self.assertTrue(tun["auto_route"])
        self.assertEqual(tun["mtu"], builder.TUN_MTU)
        self.assertEqual(tun["mtu"], 1400)
        self.assertEqual(tun["stack"], "mixed")
        dns_servers = cfg["dns"]["servers"]
        self.assertEqual(dns_servers[0]["tag"], "remote-dns")
        self.assertEqual(dns_servers[0]["type"], "tcp")
        self.assertEqual(dns_servers[0]["server"], "1.1.1.1")
        self.assertEqual(dns_servers[0]["detour"], "xray-out")
        local_dns = next((s for s in dns_servers if s.get("tag") == "local-dns"), None)
        self.assertIsNotNone(local_dns)
        self.assertEqual(local_dns["type"], "local")
        self.assertEqual(local_dns["detour"], "direct")
        self.assertIn(cfg["route"]["default_domain_resolver"], ("local-dns", "direct-dns-gateway"))

        rules = cfg["route"]["rules"]
        quic_reject = next(
            r for r in rules
            if r.get("network") == "udp" and r.get("port") == 443
        )
        self.assertEqual(quic_reject["action"], "reject")
        self.assertEqual(quic_reject["method"], "default")
        self.assertTrue(quic_reject["no_drop"])
        bypass = next(r for r in rules if "xray.exe" in r.get("process_name", []))
        self.assertEqual(bypass["outbound"], "direct")
        self.assertIn("xray.exe", bypass["process_name"])
        self.assertNotIn("GibVPN_Smart_v3.exe", bypass["process_name"])
        dns_rule = next(r for r in rules if r.get("port") == 53)
        self.assertEqual(dns_rule["action"], "hijack-dns")
        antigravity_proc = next(
            r for r in rules if "Antigravity.exe" in r.get("process_name", [])
        )
        self.assertEqual(antigravity_proc["outbound"], "xray-warp-out")
        antigravity_path = next(
            r for r in rules if any(r"(?i).*\\antigravity\\.*" in x for x in r.get("process_path_regex", []))
        )
        self.assertEqual(antigravity_path["outbound"], "xray-warp-out")
        self.assertEqual(cfg["route"]["final"], "xray-out")

    def test_tun_mode_pins_server_without_mutating_source(self):
        srv = builder.parse_vless(SAMPLE_VLESS, "test-tag")
        original_address = srv["settings"]["vnext"][0]["address"]
        with mock.patch.object(
            builder, "_resolved_ip", return_value="203.0.113.7"
        ):
            self.assertTrue(builder.generate_final_config(
                srv, resolve_endpoints=True
            ))
        with open("config.json", "r", encoding="utf-8") as f:
            cfg = json.load(f)
        best = next(o for o in cfg["outbounds"] if o["tag"] == "best-proxy")
        self.assertEqual(
            best["settings"]["vnext"][0]["address"], "203.0.113.7"
        )
        self.assertEqual(
            srv["settings"]["vnext"][0]["address"], original_address
        )

    def test_parse_vless_xhttp(self):
        # Current Xray supports XHTTP + REALITY directly.
        url_reality = "vless://uuid123@de.bootless.ru:8443?type=xhttp&path=%2Fapi%2Fv2%2Fstream&mode=packet-up&security=reality&pbk=key123&sni=yandex.net#GermanyXHTTP"
        srv = builder.parse_vless(url_reality, "xhttp-tag")
        self.assertIsNotNone(srv)
        self.assertEqual(srv["protocol"], "vless")
        self.assertEqual(srv["remark"], "GermanyXHTTP")
        self.assertEqual(srv["streamSettings"]["network"], "xhttp")
        self.assertEqual(srv["streamSettings"]["xhttpSettings"]["mode"], "packet-up")

        # XHTTP + TLS uses the same native transport.
        url_tls = "vless://uuid123@de.bootless.ru:8443?type=xhttp&path=%2Fapi%2Fv2%2Fstream&mode=packet-up&security=tls&sni=yandex.net#GermanyXHTTP"
        srv2 = builder.parse_vless(url_tls, "xhttp-tag2")
        self.assertIsNotNone(srv2)
        self.assertEqual(srv2["streamSettings"]["network"], "xhttp")
        self.assertEqual(srv2["streamSettings"]["xhttpSettings"]["path"], "/api/v2/stream")

    def test_generate_final_config_with_direct_apps(self):
        srv = builder.parse_vless(SAMPLE_VLESS, "test-tag")
        with tempfile.TemporaryDirectory() as tmp:
            apps_file = "direct_apps.txt"
            with open(apps_file, "w", encoding="utf-8") as f:
                f.write("telegram.exe\ndiscord.exe\n")
            try:
                self.assertTrue(builder.generate_final_config(srv))
                with open("config.json", "r", encoding="utf-8") as f:
                    cfg = json.load(f)
                rules = cfg.get("routing", {}).get("rules", [])
                proc_rule = next((r for r in rules if "process" in r), None)
                self.assertIsNotNone(proc_rule)
                self.assertIn("telegram.exe", proc_rule["process"])
            finally:
                if os.path.exists(apps_file):
                    os.remove(apps_file)

    def test_zapret_helpers(self):
        zapret_dir = appcore.find_default_zapret_dir()
        self.assertIsNotNone(zapret_dir)
        presets = appcore.get_zapret_presets(zapret_dir)
        self.assertTrue(len(presets) > 0)

    def test_detect_country(self):
        srv_de = {"remark": "🇩🇪 Frankfurt Server", "settings": {"vnext": [{"address": "1.2.3.4", "port": 443}]}}
        srv_us = {"remark": "[US] Fast Node", "settings": {"vnext": [{"address": "5.6.7.8", "port": 443}]}}
        srv_nl = {"remark": "Amsterdam NL", "settings": {"vnext": [{"address": "9.9.9.9", "port": 443}]}}
        srv_unknown = {"remark": "Random Proxy", "settings": {"vnext": [{"address": "10.0.0.1", "port": 443}]}}

        flag_de, name_de = builder.detect_country(srv_de)
        self.assertEqual(flag_de, "🇩🇪")
        self.assertEqual(name_de, "Германия")

        flag_us, name_us = builder.detect_country(srv_us)
        self.assertEqual(flag_us, "🇺🇸")
        self.assertEqual(name_us, "США")

        flag_nl, name_nl = builder.detect_country(srv_nl)
        self.assertEqual(flag_nl, "🇳🇱")
        self.assertEqual(name_nl, "Нидерланды")

        flag_unk, name_unk = builder.detect_country(srv_unknown)
        self.assertEqual(flag_unk, "🌐")
        self.assertEqual(name_unk, "Другая")

    def test_parse_vmess_bad_aid_does_not_crash(self):
        # aid as "" / None / object used to raise and kill the whole parse.
        for bad_aid in ("", None, {}, "abc"):
            srv = builder.parse_vmess(make_vmess(aid=bad_aid), "v")
            self.assertIsNotNone(srv, f"aid={bad_aid!r}")
            self.assertEqual(srv["settings"]["vnext"][0]["users"][0]["alterId"], 0)

        srv = builder.parse_vmess(make_vmess(aid="64"), "v")
        self.assertEqual(srv["settings"]["vnext"][0]["users"][0]["alterId"], 64)

    def test_get_parsed_servers_skips_bad_lines(self):
        with tempfile.TemporaryDirectory() as tmp:
            sub_file = os.path.join(tmp, "sub.txt")
            with open(sub_file, "w", encoding="utf-8") as f:
                f.write(SAMPLE_VLESS + "\n")
                f.write("not-a-link-at-all\n")
                # valid base64 but broken vmess JSON structure (non-int port)
                f.write(make_vmess(port="not-a-port") + "\n")
                f.write(SAMPLE_SS + "\n")
            servers = builder.get_parsed_servers(sub_file)
        keys = [builder.server_key(s) for s in servers]
        self.assertIn("example.com:443#a1b2c3d4", keys)
        self.assertIn("ss.example.com:8388#SSTest", keys)
        self.assertEqual(len(servers), 2)

    def test_get_warp_reserved_parsing(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing_path = os.path.join(tmp, "missing.toml")
            self.assertEqual(builder.get_warp_reserved(account_path=missing_path), [0, 0, 0])

            custom_file = os.path.join(tmp, "wgcf-account.toml")
            with open(custom_file, "w", encoding="utf-8") as f:
                f.write("reserved = [12, 34, 56]\n")
            self.assertEqual(builder.get_warp_reserved(account_path=custom_file), [12, 34, 56])

            with open(custom_file, "w", encoding="utf-8") as f:
                f.write("reserved = '7,8,9'\n")
            self.assertEqual(builder.get_warp_reserved(account_path=custom_file), [7, 8, 9])

    def test_generate_final_config_does_not_mutate_server(self):
        old_cwd = os.getcwd()
        with tempfile.TemporaryDirectory() as tmp:
            os.chdir(tmp)
            try:
                server = builder.parse_vless(SAMPLE_VLESS, "proxy-0")
                original_tag = server["tag"]
                self.assertTrue(builder.generate_final_config(server))
                self.assertEqual(server["tag"], original_tag)
                with open(os.path.join(builder.WORK_DIR, "config.json"), "r", encoding="utf-8") as f:
                    cfg = json.load(f)
                self.assertEqual(cfg["outbounds"][0]["tag"], "best-proxy")
                # built-in domains must not be duplicated
                direct_rule = next(
                    r for r in cfg["routing"]["rules"] if r.get("outboundTag") == "direct"
                )
                direct = direct_rule["domain"]
                self.assertEqual(len(direct), len(set(direct)))
            finally:
                os.chdir(old_cwd)

    def test_save_decoded_subscription_encodings(self):
        from unittest import mock

        class FakeResp:
            def __init__(self, content):
                self.content = content
                self.encoding = None

            def raise_for_status(self):
                pass

        plain = SAMPLE_VLESS + "\n" + SAMPLE_TROJAN + "\n"
        cases = {
            "utf8": plain.encode("utf-8"),
            "utf8_b64": base64.b64encode(plain.encode("utf-8")),
            "utf16_bom": plain.encode("utf-16"),      # codec adds BOM
            "utf16le": plain.encode("utf-16-le"),
            "b64_of_utf16le": base64.b64encode(plain.encode("utf-16-le")),
        }
        with tempfile.TemporaryDirectory() as tmp:
            for name, payload in cases.items():
                out = os.path.join(tmp, f"{name}.txt")
                with mock.patch("requests.get", return_value=FakeResp(payload)):
                    ok, details = builder.save_decoded_subscription("https://x.test/sub", out)
                self.assertTrue(ok, f"{name}: {details}")
                servers = builder.get_parsed_servers(out)
                self.assertEqual(len(servers), 2, name)


class TestSettingsPersistence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication(sys.argv)
        cls.app.setStyle("Fusion")
        cls.temp_dir = tempfile.mkdtemp()

    def test_save_and_load_settings(self):
        settings_path = os.path.join(self.temp_dir, "test_settings.json")

        app1 = GibVPNApp()
        app1.settings_file = settings_path
        app1.overlay_color.setAlpha(77)
        app1.top_crop = 123
        app1.bottom_crop = 456
        app1.current_mode = "max"
        app1.check_sites = {"Custom": "https://example.org"}
        app1.subscriptions = [
            {"name": "TestSub", "url": "https://sub.example.com", "active": True, "states": {"a:1": "favorite"}}
        ]
        app1.active_subscription_index = 0
        app1.autostart_enabled = False
        app1.save_settings()

        self.assertTrue(os.path.exists(settings_path))

        app2 = GibVPNApp()
        app2.settings_file = settings_path
        app2.load_settings()

        self.assertEqual(app2.overlay_color.alpha(), 77)
        self.assertEqual(app2.top_crop, 123)
        self.assertEqual(app2.bottom_crop, 456)
        self.assertEqual(app2.current_mode, "max")
        self.assertEqual(app2.check_sites, {"Custom": "https://example.org"})
        self.assertEqual(len(app2.subscriptions), 1)
        self.assertEqual(app2.subscriptions[0]["name"], "TestSub")
        self.assertEqual(app2.subscriptions[0]["url"], "https://sub.example.com")
        self.assertEqual(app2.active_subscription_index, 0)

    def test_placeholder_ping_site_is_repaired(self):
        settings_path = os.path.join(self.temp_dir, "placeholder_sites.json")
        with open(settings_path, "w", encoding="utf-8") as handle:
            json.dump({"check_sites": {"Test": "https://example.com"}}, handle)

        app = GibVPNApp()
        app.settings_file = settings_path
        app.load_settings()
        self.assertIn("Cloudflare", app.check_sites)
        self.assertNotIn("Test", app.check_sites)

    def test_dead_server_is_not_an_availability_result(self):
        fake_app = mock.Mock()
        fake_app.check_sites = {
            "Cloudflare": "https://cp.cloudflare.com/generate_204",
            "Google": "https://www.google.com/generate_204",
        }
        session = mock.Mock()
        session.get.side_effect = OSError("remote server is unavailable")
        results = []

        with mock.patch("gui.requests.Session", return_value=session):
            GibVPNApp.availability_test_proxy(fake_app, 11000, results, 4)

        self.assertEqual(results, [])

    def test_connection_mode_is_saved_as_exclusive_state(self):
        settings_path = os.path.join(self.temp_dir, "connection_mode.json")
        app = GibVPNApp()
        app.settings_file = settings_path
        app._apply_connection_mode("tun")
        app.save_settings()

        with open(settings_path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        self.assertEqual(data["connection_mode"], "tun")
        self.assertTrue(data["use_tun"])
        self.assertFalse(data["use_system_proxy"])

    def test_legacy_conflicting_modes_are_migrated_to_tun(self):
        settings_path = os.path.join(self.temp_dir, "legacy_conflict.json")
        with open(settings_path, "w", encoding="utf-8") as handle:
            json.dump({
                "use_tun": True,
                "use_system_proxy": True,
            }, handle)

        app = GibVPNApp()
        app.settings_file = settings_path
        app.load_settings()

        self.assertEqual(app.connection_mode, "tun")
        self.assertTrue(app.use_tun)
        self.assertFalse(app.use_system_proxy)
        with open(settings_path, "r", encoding="utf-8") as handle:
            migrated = json.load(handle)
        self.assertEqual(migrated["connection_mode"], "tun")
        self.assertFalse(migrated["use_system_proxy"])

    def test_selecting_tun_requests_admin_restart(self):
        app = GibVPNApp()
        app.settings_file = os.path.join(self.temp_dir, "uac_mode.json")
        with mock.patch.object(appcore, "is_windows_admin", return_value=False), \
             mock.patch.object(appcore, "restart_as_windows_admin", return_value=False) as restart, \
             mock.patch("gui.QMessageBox.warning"):
            app.set_connection_mode("proxy")
            app.set_connection_mode("tun")

        restart.assert_called_once_with(extra_args=None)
        self.assertEqual(app.connection_mode, "tun")
        self.assertTrue(app.use_tun)
        self.assertFalse(app.use_system_proxy)

    def test_starting_tun_requests_admin_and_resumes_vpn(self):
        app = GibVPNApp()
        app.settings_file = os.path.join(self.temp_dir, "uac_start.json")
        app._apply_connection_mode("tun")
        with mock.patch.object(appcore, "is_windows_admin", return_value=False), \
             mock.patch.object(appcore, "restart_as_windows_admin", return_value=False) as restart, \
             mock.patch("gui.QMessageBox.warning"):
            app.toggle_vpn()

        restart.assert_called_once_with(extra_args=["--start-vpn"])
        self.assertFalse(app.is_running)


class TestSubscriptions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication(sys.argv)
        cls.app.setStyle("Fusion")

    def test_filter_servers(self):
        app = GibVPNApp()
        sub = {"name": "Test", "url": "", "active": True, "states": {}}
        servers = [
            builder.parse_vless(SAMPLE_VLESS, "v"),
            builder.parse_trojan(SAMPLE_TROJAN, "t"),
            builder.parse_shadowsocks(SAMPLE_SS, "s"),
        ]
        sub["states"][builder.server_key(servers[0])] = "favorite"
        sub["states"][builder.server_key(servers[2])] = "blocked"
        favorites, regular, blocked = app._filter_servers(servers, sub)
        self.assertEqual(len(favorites), 1)
        self.assertEqual(len(regular), 1)
        self.assertEqual(len(blocked), 1)
        self.assertEqual(builder.server_key(favorites[0]), "example.com:443#a1b2c3d4")
        self.assertEqual(builder.server_key(regular[0]), "trojan.example.com:443#TrojanTest")
        self.assertEqual(builder.server_key(blocked[0]), "ss.example.com:8388#SSTest")


class TestLogRotation(unittest.TestCase):
    def test_log_exception_rotates_large_log(self):
        old_path = appcore.LOG_PATH
        with tempfile.TemporaryDirectory() as tmp:
            appcore.LOG_PATH = os.path.join(tmp, "err.log")
            try:
                with open(appcore.LOG_PATH, "w", encoding="utf-8") as f:
                    f.write("x" * (appcore.MAX_LOG_BYTES + 1))
                appcore.log_exception("rotate me")
                self.assertTrue(os.path.exists(appcore.LOG_PATH + ".old"))
                # Fresh log must be small again
                self.assertLess(os.path.getsize(appcore.LOG_PATH), 1024 * 1024)
            finally:
                appcore.LOG_PATH = old_path


class TestProcessRegistry(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication(sys.argv)

    def test_kill_orphaned_xray_only_kills_own(self):
        app = GibVPNApp()
        own = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
        foreign = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
        try:
            app._xray_processes.add(own)
            app.kill_orphaned_xray()
            own.wait(timeout=10)
            self.assertIsNotNone(own.poll(), "own process must be terminated")
            self.assertIsNone(foreign.poll(), "foreign process must survive")
            self.assertEqual(len(app._xray_processes), 0)
        finally:
            foreign.terminate()
            foreign.wait()


class TestUpdaterSecurity(unittest.TestCase):
    def test_version_comparison_never_downgrades(self):
        self.assertTrue(appcore.is_newer_version("3.0.10", "3.0.9"))
        self.assertFalse(appcore.is_newer_version("3.0.6", "3.0.7"))
        self.assertFalse(appcore.is_newer_version("v3.0.7", "3.0.7"))

    def test_rejects_update_with_wrong_sha256(self):
        ok, message = appcore.apply_downloaded_app_update(
            b"MZ-not-a-real-update", "GibVPN_Smart_v3.exe", "0" * 64
        )
        self.assertFalse(ok)
        self.assertIn("SHA-256", message)


class TestLogFilter(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication(sys.argv)

    def _make_app(self):
        app = GibVPNApp()
        app.settings_file = os.path.join(tempfile.mkdtemp(), "settings.json")
        return app

    def test_log_buffer_initialized_and_stores_levels(self):
        # Regression: _log_lines must exist before the first log() call,
        # otherwise _log_slot raises AttributeError at startup.
        app = self._make_app()
        before = len(app._log_lines)
        app.log("plain info message")
        app.log("WARNING something odd")
        app.log("ERROR something broke")
        levels = [lvl for lvl, _ in app._log_lines[before:]]
        self.assertEqual(levels, [1, 2, 3])

    def test_level_filter_and_search(self):
        app = self._make_app()
        app.log("info alpha")
        app.log("WARNING beta")
        app.log("ERROR gamma")

        app.log_level_combo.setCurrentIndex(2)  # WARN+
        app._refresh_log_view()
        text = app.log_box.toPlainText()
        self.assertIn("beta", text)
        self.assertIn("gamma", text)
        self.assertNotIn("alpha", text)

        app.log_level_combo.setCurrentIndex(0)
        app.log_search.setText("gamma")
        app._refresh_log_view()
        text = app.log_box.toPlainText()
        self.assertIn("gamma", text)
        self.assertNotIn("beta", text)

    def test_clear_log_empties_buffer(self):
        app = self._make_app()
        app.log("to be cleared")
        app.clear_log()
        # clear_log itself logs a confirmation line; only it remains
        self.assertEqual(len(app._log_lines), 1)


class TestCustomServers(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication(sys.argv)

    def _make_app(self):
        app = GibVPNApp()
        app.settings_file = os.path.join(tempfile.mkdtemp(), "settings.json")
        app.subscriptions = []
        app.custom_links = []
        return app

    def test_add_validate_dedupe(self):
        app = self._make_app()
        ok, _ = app.add_custom_link(SAMPLE_VLESS)
        self.assertTrue(ok)
        ok, msg = app.add_custom_link(SAMPLE_VLESS)
        self.assertFalse(ok, "duplicate must be rejected")
        ok, msg = app.add_custom_link("https://not-a-proxy")
        self.assertFalse(ok, "unsupported link must be rejected")
        servers = app._get_custom_servers()
        self.assertEqual(len(servers), 1)
        self.assertEqual(servers[0]["tag"], "custom-0")
        self.assertEqual(builder.server_key(servers[0]), "example.com:443#a1b2c3d4")

    def test_start_possible_without_subscription(self):
        app = self._make_app()
        servers, sub = app._collect_servers_for_start()
        self.assertIsNone(servers, "no subscription and no own links -> cannot start")
        app.add_custom_link(SAMPLE_VLESS)
        servers, sub = app._collect_servers_for_start()
        self.assertIsNotNone(servers)
        self.assertIsNone(sub)
        self.assertEqual(len(servers), 1)

    def test_remove_by_key(self):
        app = self._make_app()
        app.add_custom_link(SAMPLE_VLESS)
        self.assertEqual(app.remove_custom_servers({"example.com:443#a1b2c3d4"}), 1)
        self.assertEqual(app._get_custom_servers(), [])

    def test_custom_links_persisted(self):
        path = os.path.join(tempfile.mkdtemp(), "settings.json")
        app = self._make_app()
        app.settings_file = path
        app.add_custom_link(SAMPLE_VLESS)

        app2 = GibVPNApp()
        app2.settings_file = path
        app2.load_settings()
        self.assertEqual(app2.custom_links, [SAMPLE_VLESS])

    def test_fmt_speed_formatting(self):
        self.assertEqual(builder.fmt_speed(0), "FAIL")
        self.assertEqual(builder.fmt_speed(-10), "FAIL")
        self.assertEqual(builder.fmt_speed(512 * 1024), "512 KB/s")
        self.assertEqual(builder.fmt_speed(5 * 1024 * 1024), "5.0 MB/s")

    def test_combined_subscriptions_mode(self):
        app = self._make_app()
        app.subscriptions = [
            {"name": "Sub 1", "url": "http://sub1", "active": True, "states": {}},
            {"name": "Sub 2", "url": "http://sub2", "active": False, "states": {}},
        ]
        app.active_subscription_index = -1
        sub = app._active_subscription()
        self.assertIsNotNone(sub)
        self.assertTrue(sub.get("is_combined"))
        self.assertEqual(sub.get("name"), "★ Все подписки (Объединённый список)")


class TestTrafficStats(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication(sys.argv)

    def test_final_config_has_stats_api(self):
        old_cwd = os.getcwd()
        with tempfile.TemporaryDirectory() as tmp:
            os.chdir(tmp)
            try:
                server = builder.parse_vless(SAMPLE_VLESS, "proxy-0")
                self.assertTrue(builder.generate_final_config(server))
                with open(os.path.join(builder.WORK_DIR, "config.json"), "r", encoding="utf-8") as f:
                    cfg = json.load(f)
                self.assertIn("stats", cfg)
                self.assertEqual(cfg["api"]["services"], ["StatsService"])
                api_in = next(i for i in cfg["inbounds"] if i["tag"] == "api-in")
                self.assertEqual(api_in["protocol"], "dokodemo-door")
                self.assertEqual(api_in["port"], builder.XRAY_API_PORT)
                self.assertTrue(cfg["policy"]["system"]["statsInboundUplink"])
                self.assertTrue(cfg["policy"]["system"]["statsInboundDownlink"])
                api_rule = next(
                    r for r in cfg["routing"]["rules"] if r.get("outboundTag") == "api"
                )
                self.assertEqual(api_rule["inboundTag"], ["api-in"])
            finally:
                os.chdir(old_cwd)

    def test_fmt_bytes(self):
        self.assertEqual(GibVPNApp._fmt_bytes(512), "512 B")
        self.assertEqual(GibVPNApp._fmt_bytes(2048), "2.0 KB")
        self.assertEqual(GibVPNApp._fmt_bytes(5 * 1024 ** 2), "5.0 MB")

    def test_query_inbound_traffic_parses_api_json(self):
        from unittest import mock
        app = GibVPNApp()
        payload = {"stat": [
            {"name": "inbound>>>socks-in>>>traffic>>>uplink", "value": 100},
            {"name": "inbound>>>socks-in>>>traffic>>>downlink", "value": 900},
            {"name": "inbound>>>http-in>>>traffic>>>uplink", "value": 7},
            {"name": "inbound>>>http-in>>>traffic>>>downlink"},  # zero counter: no value
            {"name": "inbound>>>api-in>>>traffic>>>uplink", "value": 555},  # excluded
            {"name": "user>>>u>>>traffic>>>uplink", "value": 1},           # excluded
        ]}
        with mock.patch("subprocess.run") as run:
            run.return_value = subprocess.CompletedProcess([], 0, stdout=json.dumps(payload), stderr="")
            up, down = app._query_inbound_traffic()
        self.assertEqual((up, down), (107, 900))

    def test_query_inbound_traffic_failures(self):
        from unittest import mock
        app = GibVPNApp()
        with mock.patch("subprocess.run") as run:
            run.return_value = subprocess.CompletedProcess([], 1, stdout="", stderr="boom")
            self.assertEqual(app._query_inbound_traffic(), (None, None))
            run.return_value = subprocess.CompletedProcess([], 0, stdout="not json", stderr="")
            self.assertEqual(app._query_inbound_traffic(), (None, None))

    def test_status_text_shows_traffic(self):
        app = GibVPNApp()
        app._conn_name = "Test"
        app._connected_at = time.time()
        app._traffic_up = 2048
        app._traffic_down = 4096
        text = app._running_status_text()
        self.assertIn("2.0KB", text)
        self.assertIn("4.0KB", text)


class TestBackupAndRestore(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication(sys.argv)

    def test_export_and_import_full_backup(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = GibVPNApp()
            app.settings_file = os.path.join(tmp, "settings.json")
            app.exc_file = os.path.join(tmp, "direct_domains.txt")
            app.warp_file = os.path.join(tmp, "warp_domains.txt")

            with open(app.exc_file, "w", encoding="utf-8") as f:
                f.write("domain:mycustomsite.ru\n")

            app.ping_timeout = 7.5
            backup = app.export_full_backup()
            self.assertEqual(backup["version"], "3.0")
            self.assertIn("settings", backup)
            self.assertIn("domain:mycustomsite.ru\n", backup["direct_domains"])

            # Mutate local state
            app.ping_timeout = 1.0
            app.save_settings()

            # Restore backup
            ok, msg = app.import_full_backup(backup)
            self.assertTrue(ok)
            self.assertEqual(app.ping_timeout, 7.5)


class TestSmokeRender(unittest.TestCase):
    """Offscreen smoke render: the main window and dialogs must build and paint."""
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication(sys.argv)

    def test_main_window_renders(self):
        from PyQt6.QtGui import QResizeEvent
        from PyQt6.QtCore import QSize
        w = GibVPNApp()
        w.settings_file = os.path.join(tempfile.mkdtemp(), "settings.json")
        w.setGeometry(0, 0, 1120, 680)
        w.show()
        self.assertEqual(w.btn_gpt_check.text(), "🧠 Проверить GPT")
        w.resizeEvent(QResizeEvent(QSize(1120, 680), QSize(640, 480)))
        for _ in range(10):
            QApplication.processEvents()
        w.repaint()
        pix = w.grab()
        target = os.path.join(appcore.WORK_DIR, "gui_preview.png")
        if os.path.exists(target):
            try:
                os.remove(target)
            except Exception:
                pass
        pix.save(target, "PNG")
        w.close()

    def test_dialogs_build_and_render(self):
        w = GibVPNApp()
        w.settings_file = os.path.join(tempfile.mkdtemp(), "settings.json")
        dlg_sets = SettingsDialog(w)
        dlg_sets.show()
        QApplication.processEvents()
        pix_sets = dlg_sets.grab()
        pix_sets.save(os.path.join(appcore.WORK_DIR, "settings_preview.png"))
        dlg_sets.close()

        for dlg in (
            ServerListDialog(w),
            PingSitesDialog(w),
            SubscriptionManagerDialog(w, w),
        ):
            dlg.show()
            QApplication.processEvents()
            pix = dlg.grab()
            self.assertFalse(pix.isNull())
            dlg.close()

    def test_qinputdialog_imported(self):
        import dialogs
        self.assertTrue(hasattr(dialogs, 'QInputDialog'))
        self.assertTrue(hasattr(dialogs, 'QMenu'))

    def test_appcore_xray_helpers(self):
        self.assertTrue(callable(getattr(appcore, 'start_xray_process', None)))
        self.assertTrue(callable(getattr(appcore, 'stop_xray_process', None)))

    def test_kill_orphaned_xray_preserves_main_process(self):
        w = GibVPNApp()
        main_proc = object()
        test_proc = object()
        w.xray_process = main_proc
        w._xray_processes.add(main_proc)
        w._xray_processes.add(test_proc)
        w.kill_orphaned_xray()
        self.assertIn(main_proc, w._xray_processes)
        self.assertNotIn(test_proc, w._xray_processes)

    def test_context_menus_do_not_crash(self):
        from PyQt6.QtCore import QPoint
        import dialogs
        w = GibVPNApp()
        w.subscriptions = [{"name": "Test Sub", "url": "https://example.com/sub", "active": True}]
        w.active_subscription_index = 0
        
        with mock.patch.object(dialogs.QMenu, 'exec', return_value=None):
            # Test ServerListDialog
            dlg_srv = ServerListDialog(w)
            dlg_srv.servers = [builder.parse_vless(SAMPLE_VLESS, "test-tag")]
            dlg_srv._fill_table()
            dlg_srv.show()
            QApplication.processEvents()
            if dlg_srv.table.rowCount() > 0:
                dlg_srv.table.selectRow(0)
                # Must not throw NameError or AttributeError
                dlg_srv.table.customContextMenuRequested.emit(QPoint(10, 10))
            dlg_srv.close()

            # Test SubscriptionManagerDialog
            dlg_sub = SubscriptionManagerDialog(w, w)
            dlg_sub.show()
            QApplication.processEvents()
            if dlg_sub.table.rowCount() > 0:
                dlg_sub.table.selectRow(0)
                dlg_sub.table.customContextMenuRequested.emit(QPoint(10, 10))
            dlg_sub.close()


class TestProxyRecoveryAndAutostart(unittest.TestCase):
    def test_is_gibvpn_local_proxy_supports_prefixes_and_ports(self):
        self.assertTrue(appcore._is_gibvpn_local_proxy("127.0.0.1:10808"))
        self.assertTrue(appcore._is_gibvpn_local_proxy("http://127.0.0.1:10809"))
        self.assertTrue(appcore._is_gibvpn_local_proxy("socks5://127.0.0.1:10808"))
        self.assertTrue(appcore._is_gibvpn_local_proxy("socks5h://127.0.0.1:10810"))
        self.assertTrue(appcore._is_gibvpn_local_proxy("http://127.0.0.1:10811/"))
        self.assertTrue(appcore._is_gibvpn_local_proxy("127.0.0.1:11809"))
        self.assertFalse(appcore._is_gibvpn_local_proxy("127.0.0.1:8080"))
        self.assertFalse(appcore._is_gibvpn_local_proxy("192.168.1.1:10808"))

    def test_recover_windows_system_proxy_without_backup(self):
        with mock.patch("os.path.exists", return_value=False), \
             mock.patch.object(appcore, "read_windows_system_proxy", return_value={
                 "ProxyEnable": {"value": 1},
                 "ProxyServer": {"value": "127.0.0.1:10809"}
             }), \
             mock.patch("winreg.OpenKey"), \
             mock.patch("winreg.SetValueEx") as mock_set:
            recovered = appcore.recover_windows_system_proxy()
            self.assertTrue(recovered)
            mock_set.assert_called_with(mock.ANY, "ProxyEnable", 0, mock.ANY, 0)

    def test_recover_user_environment_proxy_without_backup(self):
        with mock.patch("os.path.exists", return_value=False), \
             mock.patch.object(appcore, "read_user_environment_proxy", return_value={
                 "HTTP_PROXY": {"value": "http://127.0.0.1:10809"},
                 "HTTPS_PROXY": {"value": "http://127.0.0.1:10809"},
                 "ALL_PROXY": {"value": "socks5://127.0.0.1:10808"},
             }), \
             mock.patch("winreg.CreateKeyEx"), \
             mock.patch("winreg.DeleteValue") as mock_del, \
             mock.patch.object(appcore, "_broadcast_environment_change"):
            recovered = appcore.recover_user_environment_proxy()
            self.assertTrue(recovered)
            self.assertEqual(mock_del.call_count, 3)

    def test_get_physical_default_gateway_detection(self):
        gw = builder.get_physical_default_gateway()
        # If running on Windows host with route print, gw should be a valid IP string or None in CI
        if gw:
            self.assertTrue(gw.count(".") == 3)
            self.assertFalse(gw.startswith("172.19."))

    def test_sync_autostart_path(self):
        app = (
            QApplication.instance()
            or QApplication(["test", "-platform", "offscreen"])
        )
        w = GibVPNApp()
        with mock.patch("sys.frozen", True, create=True), \
             mock.patch("sys.executable", r"C:\app\GibVPN_Smart_v3.exe"), \
             mock.patch("winreg.OpenKey"), \
             mock.patch("winreg.QueryValueEx", return_value=(r"C:\old\GibVPN_Smart_v3.exe", 1)), \
             mock.patch("winreg.SetValueEx") as mock_set:
            w.sync_autostart_path()
            mock_set.assert_called_with(
                mock.ANY, "GibVPN", 0, mock.ANY, r'"C:\app\GibVPN_Smart_v3.exe"'
            )


if __name__ == "__main__":
    # On Windows the PyQt offscreen teardown can segfault during interpreter
    # shutdown (widgets garbage-collected after QApplication is gone), failing
    # the build even when every test passed. Run the suite, then hard-exit
    # with the suite's real status, skipping the flaky teardown.
    program = unittest.main(exit=False)
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(0 if program.result.wasSuccessful() else 1)
