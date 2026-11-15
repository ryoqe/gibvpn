"""Run regression tests without changing a running VPN or real user settings."""
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
original_data = Path(os.environ['APPDATA']) / 'GibVPN'
temp = tempfile.TemporaryDirectory(prefix='gibvpn_tests_', ignore_cleanup_errors=True)
os.environ['APPDATA'] = temp.name
os.environ['LOCALAPPDATA'] = temp.name
os.environ['QT_QPA_PLATFORM'] = 'offscreen'
fixture = Path(temp.name) / 'GibVPN'
fixture.mkdir()
for filename in ('wgcf-profile.conf', 'wgcf-account.toml'):
    source = original_data / filename
    if source.exists():
        shutil.copy2(source, fixture / filename)
for filename in ('xray.exe', 'geoip.dat', 'geosite.dat'):
    source = ROOT / filename
    if source.exists():
        shutil.copy2(source, fixture / filename)
if (ROOT / 'zapret_bin').exists():
    shutil.copytree(ROOT / 'zapret_bin', fixture / 'zapret_bin')
os.chdir(fixture)
sys.path.insert(0, str(ROOT))
# APPDATA isolates backups/settings; intercept Windows registry writes too.
import winreg
with mock.patch.object(winreg, 'SetValueEx'), mock.patch.object(winreg, 'DeleteValue'):
    suite = unittest.TestSuite()
    for pattern in ('test_no_xray.py', 'test_ai_routing.py',
                    'test_agent_api.py', 'test_subscription_parser.py'):
        suite.addTests(unittest.defaultTestLoader.discover(str(ROOT / 'tests'), pattern=pattern))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
sys.stdout.flush()
sys.stderr.flush()
os.chdir(ROOT)
temp.cleanup()
# Some PyQt builds crash at offscreen interpreter teardown. The test status
# is already known; the OS releases handles and the fixture remains isolated.
os._exit(0 if result.wasSuccessful() else 1)
