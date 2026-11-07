import json
import os
import re
import pathlib
import time
import tempfile
import threading
import unittest
from types import SimpleNamespace
from unittest import mock

import builder
from ai_probe import flow_response_result
from gui import GibVPNApp
import appcore
from dialogs import ServerListDialog


def response(body, url="https://flow.google.com/", code=200):
    return SimpleNamespace(text=body, url=url, status_code=code)


class FlowChecks(unittest.TestCase):
    def test_normal_page(self):
        self.assertTrue(flow_response_result(response('<title>Google Flow</title><a>Sign in</a>'))[0])

    def test_country_redirect(self):
        self.assertFalse(flow_response_result(response('Flow', 'https://flow.google.com/unsupported-country'))[0])

    def test_country_page_and_image(self):
        for body in ("<h1>Flow is not available in your country</h1>",
                     '<img src="/assets/unsupported-country.png">',
                     '<img alt="Unsupported country">',
                     '<h1>Flow недоступен в вашей стране</h1>',
                     '<script>window.location.href="/unsupported-country"</script>'):
            with self.subTest(body=body):
                self.assertFalse(flow_response_result(response(body))[0])

    def test_js_route_dictionary_not_country_page(self):
        body = '<title>Google Flow</title><a>Sign in</a><script>routes=["unsupported-country","location=unsupported"]</script>'
        self.assertTrue(flow_response_result(response(body))[0])

    def test_errors_and_unknown_pages(self):
        for r in (response("", code=403), response(""), response("Sign in", "https://accounts.google.com/"),
                  response("<title>Google Flow</title>Sign in", "https://www.google.com/sorry/index")):
            self.assertFalse(flow_response_result(r)[0])


SERVER = {"protocol": "trojan", "tag": "sample", "remark": "Gemini",
          "settings": {"servers": [{"address": "example.com", "port": 443, "password": "test"}]}}


class StartupAndSelectionChecks(unittest.TestCase):
    def test_connect_selected_never_changes_favorites(self):
        dlg = mock.Mock()
        dlg._selected_index.return_value = 0
        dlg.servers = [SERVER]
        dlg.parent_app.connect_server.return_value = True
        ServerListDialog.connect_selected(dlg)
        dlg.parent_app.connect_server.assert_called_once_with(SERVER, 0)
        dlg.parent_app._set_server_state.assert_not_called()
        dlg.parent_app.save_settings.assert_not_called()
        dlg.accept.assert_called_once()

    def test_double_click_connects_clicked_row(self):
        dlg = mock.Mock()
        index = mock.Mock()
        index.isValid.return_value = True
        index.row.return_value = 3
        ServerListDialog.connect_double_clicked(dlg, index)
        dlg.table.selectRow.assert_called_once_with(3)
        dlg.connect_selected.assert_called_once()
        dlg.toggle_favorite_row.assert_not_called()

    def cached_app(self):
        app = mock.Mock(current_mode='max', connection_mode='tun', xray_process=None)
        app.last_connection = {'mode': 'max', 'connection_mode': 'tun', 'server_key': builder.server_key(SERVER)}
        app._collect_servers_for_start.return_value = ([SERVER], {})
        app._server_state.return_value = 'unused'
        return app

    def test_cached_start_skips_full_scan(self):
        app = self.cached_app(); select = mock.Mock()
        with mock.patch.object(appcore, 'wait_for_network_ready', return_value=True):
            GibVPNApp._resume_last_or_select(app, select)
        app._start_best_server.assert_called_once_with(SERVER, 0, 0, verify_before_tun=True)
        select.assert_not_called()

    def test_bad_cached_server_falls_back_and_blocked_server_is_not_used(self):
        for blocked in (False, True):
            with self.subTest(blocked=blocked):
                app = self.cached_app(); select = mock.Mock()
                app._server_state.return_value = 'blocked' if blocked else 'unused'
                app._start_best_server.side_effect = RuntimeError('unreachable')
                with mock.patch.object(appcore, 'wait_for_network_ready', return_value=True):
                    GibVPNApp._resume_last_or_select(app, select)
                select.assert_called_once()
                if blocked: app._start_best_server.assert_not_called()

    def test_no_network_never_starts_or_scans(self):
        app = self.cached_app(); select = mock.Mock()
        with mock.patch.object(appcore, 'wait_for_network_ready', return_value=False):
            with self.assertRaisesRegex(RuntimeError, 'Windows'):
                GibVPNApp._resume_last_or_select(app, select)
        app._start_best_server.assert_not_called(); select.assert_not_called()

    def test_explicit_mode_selection_does_not_resume_cache(self):
        app = mock.Mock(manual_server=None, current_mode='max')
        GibVPNApp._start_current_mode(app, resume_last=False)
        app._run_vpn_worker.call_args.args[0]()
        app.smart_start_max_availability.assert_called_once()
        app._resume_last_or_select.assert_not_called()

    def test_unresolved_server_cannot_install_tun_or_start_xray(self):
        app = mock.Mock(use_tun=True, use_zapret=False, connection_mode='tun')
        with mock.patch.object(appcore, 'is_windows_admin', return_value=True), \
             mock.patch.object(appcore, 'find_conflicting_vpn_adapters', return_value=[]), \
             mock.patch.object(appcore, 'find_free_local_port_block', return_value=32000), \
             mock.patch.object(builder, 'configure_local_ports'), \
             mock.patch.object(appcore, 'configure_local_proxy_ports'), \
             mock.patch.object(builder, '_pin_server_endpoint', return_value=SERVER), \
             mock.patch.object(builder, 'generate_final_config') as generate, \
             mock.patch('socket.getaddrinfo', side_effect=OSError('no dns')):
            with self.assertRaisesRegex(RuntimeError, 'определить адрес'):
                GibVPNApp._start_best_server(app, SERVER, 0, 0)
        generate.assert_not_called()
        app._spawn_xray.assert_not_called(); app._spawn_tun.assert_not_called()

    def test_windows_network_wait_does_not_accept_link_local_address(self):
        with mock.patch.object(appcore.socket, 'socket') as factory, \
             mock.patch.object(appcore.time, 'sleep'):
            factory.return_value.__enter__.return_value.getsockname.side_effect = [
                ('169.254.1.2', 1000), ('192.168.50.2', 1001)]
            self.assertTrue(appcore.wait_for_network_ready(timeout=1))

    def test_dns_lookup_has_a_deadline(self):
        def slow(*args, **kwargs):
            time.sleep(0.05)
            return [(None, None, None, None, ('203.0.113.17', 0))]
        with mock.patch.object(builder.socket, 'getaddrinfo', side_effect=slow):
            started = time.monotonic()
            self.assertEqual(builder._resolved_ip('deadline.invalid', timeout=0.001), 'deadline.invalid')
            self.assertLess(time.monotonic() - started, 0.04)

    def test_cached_check_rejects_captive_page_and_uses_base_vpn_fallback(self):
        app = mock.Mock(proxy_dict={'https': 'http://127.0.0.1:1'})
        with mock.patch('gui.requests.Session') as factory:
            session = factory.return_value.__enter__.return_value
            session.get.return_value.__enter__.return_value.status_code = 200
            self.assertFalse(GibVPNApp._base_proxy_ready(app))
            self.assertEqual(session.get.call_count, 2)
            session.get.return_value.__enter__.return_value.status_code = 204
            self.assertTrue(GibVPNApp._base_proxy_ready(app))

    def test_health_probes_precede_warp_and_direct_domains(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, 'xray.json')
            builder.generate_final_config(SERVER, config_path=path)
            rules = json.loads(pathlib.Path(path).read_text(encoding='utf-8'))['routing']['rules']
            health = next(r for r in rules if r.get('domain') == builder.BASE_HEALTH_DOMAINS)
            ai = next(r for r in rules if 'domain:gemini.google.com' in r.get('domain', []))
            direct = next(r for r in rules if r.get('outboundTag') == 'direct' and 'domain' in r)
            self.assertLess(rules.index(health), rules.index(ai))
            self.assertLess(rules.index(health), rules.index(direct))

    def test_helper_cache_skips_hashing_but_detects_changes(self):
        with tempfile.TemporaryDirectory() as src, tempfile.TemporaryDirectory() as dst:
            pathlib.Path(src, 'xray.exe').write_bytes(b'engine')
            with mock.patch.object(appcore.sys, '_MEIPASS', src, create=True):
                self.assertEqual(appcore.get_work_dir(dst), dst)
                with mock.patch.object(appcore, '_copy_if_changed', wraps=appcore._copy_if_changed) as copy:
                    self.assertEqual(appcore.get_work_dir(dst), dst)
                    copy.assert_not_called()
                pathlib.Path(dst, 'xray.exe').write_bytes(b'changed-engine')
                appcore.get_work_dir(dst)
                self.assertEqual(pathlib.Path(dst, 'xray.exe').read_bytes(), b'engine')

    def test_runtime_version_and_redacted_diagnostics(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(appcore, 'APP_DIR', tmp):
            appcore.write_runtime_info()
            record = json.loads(pathlib.Path(tmp, 'runtime.json').read_text(encoding='utf-8'))
            self.assertEqual(record['version'], appcore.CURRENT_APP_VERSION)
            self.assertEqual(record['pid'], os.getpid())
            appcore.write_session_log('failure https://subscription.invalid/private-secret vless://private-link')
            text = pathlib.Path(tmp, 'session.log').read_text(encoding='utf-8')
            self.assertNotIn('private-secret', text)
            self.assertNotIn('private-link', text)


class FinalsRoutingChecks(unittest.TestCase):
    def config(self, enabled):
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.object(builder, 'WORK_DIR', tmp), \
             mock.patch.object(builder, 'get_physical_default_gateway', return_value=None):
            path = builder.generate_tun_config(finals_split_enabled=enabled)
            with open(path, encoding='utf-8') as f:
                return json.load(f)

    def first_action(self, cfg, path, network, port):
        for rule in cfg['route']['rules']:
            if rule.get('action') == 'sniff':
                continue
            if 'process_name' in rule or 'process_path' in rule:
                continue
            if 'domain_regex' in rule or 'domain_suffix' in rule:
                continue
            if 'process_path_regex' in rule and not any(re.search(p, path) for p in rule['process_path_regex']):
                continue
            if 'network' in rule and rule['network'] != network:
                continue
            if 'port' in rule and rule['port'] != port:
                continue
            if 'protocol' in rule:
                continue
            return rule.get('outbound', rule['action'])
        return cfg['route']['final']

    def test_only_finals_udp_is_direct_and_dns_stays_captured(self):
        cfg = self.config(True)
        game = r'C:\Program Files (x86)\Steam\steamapps\common\The Finals\Discovery\Binaries\Win64\Discovery.exe'
        for port in (443, 7777, 30000):
            self.assertEqual(self.first_action(cfg, game, 'udp', port), 'direct')
        self.assertEqual(self.first_action(cfg, game, 'tcp', 443), 'games-vpn-out')
        for network in ('tcp', 'udp'):
            self.assertEqual(self.first_action(cfg, game, network, 53), 'hijack-dns')
        other = r'C:\OtherGame\Discovery.exe'
        self.assertEqual(self.first_action(cfg, other, 'udp', 7777), 'xray-out')
        self.assertEqual(self.first_action(cfg, other, 'udp', 443), 'reject')
        self.assertEqual(self.first_action(cfg, other, 'tcp', 443), 'xray-out')
        self.assertEqual(cfg['dns']['rules'][0]['server'], 'remote-dns')

    def test_disabled_profile_has_no_game_listener_or_route(self):
        cfg = self.config(False)
        self.assertFalse(any(o['tag'] == 'games-vpn-out' for o in cfg['outbounds']))
        self.assertFalse(any(builder.FINALS_PROCESS_PATH_REGEX in r.get('process_path_regex', []) for r in cfg['route']['rules']))
        game = r'D:\SteamLibrary\steamapps\common\The Finals\Discovery.exe'
        self.assertEqual(self.first_action(cfg, game, 'udp', 7777), 'xray-out')

    def test_service_listener_uses_base_vpn_with_or_without_warp(self):
        for warp in (True, False):
            with self.subTest(warp=warp), tempfile.TemporaryDirectory() as tmp:
                path = os.path.join(tmp, 'xray.json')
                builder.generate_final_config(SERVER, config_path=path, local_port_base=26000,
                                              finals_split_enabled=True, warp_enabled=warp)
                with open(path, encoding='utf-8') as f:
                    cfg = json.load(f)
                inbound = next(i for i in cfg['inbounds'] if i['tag'] == 'games-socks-in')
                self.assertEqual(inbound['port'], 26004)
                self.assertEqual(inbound['listen'], '127.0.0.1')
                self.assertFalse(inbound['settings']['udp'])
                route = next(r for r in cfg['routing']['rules'] if 'games-socks-in' in r.get('inboundTag', []))
                self.assertEqual(route['outboundTag'], 'best-proxy')

    def test_toggle_saves_without_interrupting_live_vpn(self):
        app = mock.Mock(is_running=True)
        GibVPNApp.set_finals_split_enabled(app, True)
        self.assertIs(app.finals_split_enabled, True)
        app.save_settings.assert_called_once()
        app.stop_vpn.assert_not_called()
        app._start_current_mode.assert_not_called()
        app._run_vpn_worker.assert_not_called()


class RoutingChecks(unittest.TestCase):
    def test_steam_cloud_exception_precedes_application_bypass(self):
        with tempfile.TemporaryDirectory() as tmp:
            apps = os.path.join(tmp, 'direct_apps.txt')
            with open(apps, 'w', encoding='utf-8') as f:
                f.write(r'C:\Program Files (x86)\Steam\steam.exe' + '\n')
            original_find = builder._find_file_path
            with mock.patch.object(builder, 'WORK_DIR', tmp), \
                 mock.patch.object(builder, 'get_physical_default_gateway', return_value=None), \
                 mock.patch.object(builder, '_find_file_path', side_effect=lambda name: apps if name == 'direct_apps.txt' else original_find(name)):
                path = builder.generate_tun_config()
            with open(path, encoding='utf-8') as f:
                cfg = json.load(f)
            rules = cfg['route']['rules']
            cloud = next(r for r in rules if builder.STEAM_CLOUD_S3_REGEX in r.get('domain_regex', []))
            steam = next(r for r in rules if r.get('outbound') == 'direct' and 'steamwebhelper.exe' in r.get('process_name', []))
            early_sniff = next(r for r in rules if r.get('action') == 'sniff' and r.get('port') == 443)
            self.assertLess(rules.index(early_sniff), rules.index(cloud))
            self.assertLess(rules.index(cloud), rules.index(steam))
            self.assertEqual(cloud['outbound'], 'xray-out')
            self.assertEqual(steam['outbound'], 'direct')
            pattern = re.compile(builder.STEAM_CLOUD_S3_REGEX)
            for host in ('steamcloud-dub.s3.dualstack.eu-west-1.amazonaws.com',
                         'steamcloud-frf.s3.eu-central-1.amazonaws.com'):
                self.assertIsNotNone(pattern.fullmatch(host))
            for host in ('store.steampowered.com', 'steamcommunity.com', 'gemini.google.com',
                         'another-bucket.s3.eu-west-1.amazonaws.com',
                         'steamcloud-dub.s3.eu-west-1.amazonaws.com.attacker.example'):
                self.assertIsNone(pattern.fullmatch(host))

    def test_steam_cloud_xray_route_precedes_direct_domains_without_warp(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, 'config.json')
            builder.generate_final_config(SERVER, warp_enabled=False, config_path=path)
            with open(path, encoding='utf-8') as f:
                rules = json.load(f)['routing']['rules']
            cloud = next(r for r in rules if 'regexp:' + builder.STEAM_CLOUD_S3_REGEX in r.get('domain', []))
            direct = next(r for r in rules if r.get('outboundTag') == 'direct' and 'domain' in r)
            self.assertEqual(cloud['outboundTag'], 'best-proxy')
            self.assertLess(rules.index(cloud), rules.index(direct))

    def test_disabled_warp_never_loads_profile_and_protects_domains(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(builder, 'get_warp_settings') as profile:
            path = os.path.join(tmp, 'probe.json')
            before = (builder.SOCKS_PORT, builder.WARP_SOCKS_PORT)
            builder.generate_final_config(SERVER, warp_enabled=False, config_path=path, local_port_base=25000)
            profile.assert_not_called()
            with open(path, encoding='utf-8') as f:
                cfg = json.load(f)
            self.assertNotIn('warp-proxy', [o['tag'] for o in cfg['outbounds']])
            self.assertEqual([i['port'] for i in cfg['inbounds']], [25000, 25001, 25002, 25003, 25077])
            ai = next(r for r in cfg['routing']['rules'] if 'domain:flow.google.com' in r.get('domain', []))
            self.assertEqual(ai['outboundTag'], 'best-proxy')
            special = next(r for r in cfg['routing']['rules'] if 'warp-socks-in' in r.get('inboundTag', []))
            self.assertEqual(special['outboundTag'], 'best-proxy')
            self.assertEqual(before, (builder.SOCKS_PORT, builder.WARP_SOCKS_PORT))
            self.assertEqual(SERVER['tag'], 'sample')

    def test_manual_start_does_not_probe(self):
        app = mock.Mock()
        app.manual_server = SERVER
        app.current_mode = 'auto'
        GibVPNApp._start_current_mode(app)
        job = app._run_vpn_worker.call_args.args[0]
        job()
        app._start_best_server.assert_called_once_with(SERVER, 0, 0)
        app.smart_start_auto.assert_not_called()

    def test_manual_connect_uses_selected_server(self):
        app = mock.Mock()
        app._worker = None
        app.is_running = False
        app.connection_mode = 'proxy'
        self.assertTrue(GibVPNApp.connect_server(app, SERVER, 7))
        app._run_vpn_worker.call_args.args[0]()
        app._start_best_server.assert_called_once_with(SERVER, 7, 0)
        app._start_current_mode.assert_not_called()

    def test_selection_continues_after_first_four_and_includes_regular(self):
        servers = [dict(SERVER, remark=f'Server {i}', tag=f'srv{i}') for i in range(9)]
        app = mock.Mock()
        app.warp_enabled = False
        app.ai_last_servers = {}
        app._collect_servers_for_start.return_value = (servers, None)
        app._filter_servers.return_value = (servers[:2], servers[2:], [])
        app._ai_route_works.side_effect = lambda srv: srv is servers[7]
        app._ai_e2e_works.side_effect = lambda srv: (True, 'E2E ok (mock)', 100)
        with mock.patch('gui.os.path.exists', return_value=True), \
             mock.patch('gui.omni_available', return_value=True):
            GibVPNApp._smart_start_auto_inner(app)
        app._start_best_server.assert_called_once_with(servers[7], 7, 0)
        app._ai_e2e_works.assert_called_once_with(servers[7])
        self.assertEqual(app._ai_route_works.call_count, 8)

    def test_e2e_rejects_flow_passing_server(self):
        """Сервер, прошедший Flow, но не давший живой ответ модели, не подключается."""
        servers = [dict(SERVER, remark=f'Server {i}', tag=f'srv{i}') for i in range(4)]
        app = mock.Mock()
        app.warp_enabled = False
        app.ai_last_servers = {}
        app._collect_servers_for_start.return_value = (servers, None)
        app._filter_servers.return_value = ([], servers, [])
        app._ai_route_works.side_effect = lambda srv: True
        app._ai_e2e_works.side_effect = lambda srv: (False, 'регион не поддерживается', None)
        with mock.patch('gui.os.path.exists', return_value=True), \
             mock.patch('gui.omni_available', return_value=True):
            GibVPNApp._smart_start_auto_inner(app)
        app._start_best_server.assert_not_called()
        self.assertEqual(app._ai_e2e_works.call_count, 4)

    def test_omni_unavailable_falls_back_to_flow_only(self):
        """Без OmniRoute ИИ-режим работает по-старому: Flow-победитель подключается."""
        servers = [dict(SERVER, remark=f'Server {i}', tag=f'srv{i}') for i in range(4)]
        app = mock.Mock()
        app.warp_enabled = False
        app.ai_last_servers = {}
        app._collect_servers_for_start.return_value = (servers, None)
        app._filter_servers.return_value = ([], servers, [])
        app._ai_route_works.side_effect = lambda srv: srv is servers[1]
        with mock.patch('gui.os.path.exists', return_value=True), \
             mock.patch('gui.omni_available', return_value=False):
            GibVPNApp._smart_start_auto_inner(app)
        app._start_best_server.assert_called_once_with(servers[1], 1, 0)
        app._ai_e2e_works.assert_not_called()

    def test_missing_profile_fails_instead_of_claiming_success(self):
        app = mock.Mock(warp_enabled=True)
        with mock.patch.object(builder, 'get_warp_settings', return_value=None):
            self.assertFalse(GibVPNApp._ai_route_works(app, SERVER))
        app._spawn_xray.assert_not_called()

    def test_warp_profile_is_never_probed_concurrently(self):
        from concurrent.futures import ThreadPoolExecutor
        servers = [dict(SERVER, remark=f'Server {i}', tag=f'srv{i}') for i in range(4)]
        app = mock.Mock()
        app.warp_enabled = True
        app.ai_last_servers = {}
        app._collect_servers_for_start.return_value = (servers, None)
        app._filter_servers.return_value = ([], servers, [])
        app._ai_route_works.side_effect = lambda srv: srv is servers[2]
        app._ai_e2e_works.side_effect = lambda srv: (True, 'E2E ok (mock)', 100)
        with mock.patch('gui.os.path.exists', return_value=True), \
             mock.patch.object(builder, 'get_warp_settings', return_value={'profile': 'test'}), \
             mock.patch('gui.ThreadPoolExecutor', wraps=ThreadPoolExecutor) as pool, \
             mock.patch('gui.omni_available', return_value=True):
            GibVPNApp._smart_start_auto_inner(app)
        pool.assert_called_once_with(max_workers=1)
        app._start_best_server.assert_called_once_with(servers[2], 2, 0)
        self.assertEqual(app._ai_route_works.call_count, 3)

    def test_plain_vpn_really_probes_and_reaps_on_timeout(self):
        app = mock.Mock()
        app.warp_enabled = False
        app._ai_probe_lock = threading.Lock()
        app._ai_probe_ports = set()
        app.use_zapret = False
        app.block_quic = True
        proc = app._spawn_xray.return_value
        proc.poll.return_value = None
        with mock.patch('gui.appcore.wait_for_local_port', return_value=True), \
             mock.patch('gui.requests.Session') as session:
            session.return_value.get.side_effect = __import__('requests').Timeout()
            self.assertFalse(GibVPNApp._ai_route_works(app, SERVER))
        app._reap_xray.assert_called_once_with(proc)
        session.return_value.close.assert_called_once()
        self.assertEqual(app._ai_probe_ports, set())


if __name__ == '__main__':
    unittest.main()
