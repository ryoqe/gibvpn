import unittest
import os
import json
import tempfile
import builder
import appcore


class TestSubscriptionParser(unittest.TestCase):
    def test_get_device_hwid(self):
        hwid = appcore.get_device_hwid()
        self.assertIsInstance(hwid, str)
        self.assertTrue(len(hwid) > 0)

    def test_xray_outbound_to_link_vless(self):
        ob = {
            "protocol": "vless",
            "tag": "proxy-1",
            "remark": "Test VLESS Server",
            "settings": {
                "vnext": [{
                    "address": "example.com",
                    "port": 443,
                    "users": [{
                        "id": "12345678-1234-1234-1234-123456789abc",
                        "encryption": "none",
                        "flow": "xtls-rprx-vision"
                    }]
                }]
            },
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "serverName": "google.com",
                    "publicKey": "testpubkey",
                    "shortId": "1234",
                    "spiderX": "/"
                }
            }
        }
        link = builder._xray_outbound_to_link(ob)
        self.assertIsNotNone(link)
        self.assertTrue(link.startswith("vless://"))
        self.assertIn("example.com:443", link)
        self.assertIn("xtls-rprx-vision", link)
        self.assertIn("pbk=testpubkey", link)

        parsed = builder.parse_link(link, "test")
        self.assertIsNotNone(parsed)
        self.assertEqual(builder.server_address(parsed), "example.com")
        self.assertEqual(builder.server_port(parsed), 443)

    def test_extract_links_from_json_array(self):
        sample_json = [
            {
                "protocol": "vless",
                "tag": "nl-vless",
                "remark": "Netherlands Fast",
                "settings": {
                    "vnext": [{
                        "address": "nl.example.com",
                        "port": 8443,
                        "users": [{"id": "11111111-2222-3333-4444-555555555555"}]
                    }]
                }
            },
            {
                "protocol": "vmess",
                "tag": "de-vmess",
                "settings": {
                    "vnext": [{
                        "address": "de.example.com",
                        "port": 443,
                        "users": [{"id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "alterId": 0}]
                    }]
                }
            }
        ]
        links = builder._extract_links_from_json(json.dumps(sample_json))
        self.assertEqual(len(links), 2)
        self.assertTrue(links[0].startswith("vless://"))
        self.assertTrue(links[1].startswith("vmess://"))

    def test_extract_links_from_singbox_json(self):
        sample_singbox = {
            "outbounds": [
                {
                    "type": "vless",
                    "tag": "singbox-node",
                    "server": "singbox.example.com",
                    "server_port": 443,
                    "uuid": "abcdef12-3456-7890-abcd-ef1234567890",
                    "network": "tcp",
                    "tls": {
                        "enabled": True,
                        "server_name": "example.com"
                    }
                }
            ]
        }
        links = builder._extract_links_from_json(json.dumps(sample_singbox))
        self.assertEqual(len(links), 1)
        self.assertTrue(links[0].startswith("vless://"))
        self.assertIn("singbox.example.com", links[0])


if __name__ == "__main__":
    unittest.main()
