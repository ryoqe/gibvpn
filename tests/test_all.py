import requests
import builder
import subprocess
import time
import urllib3
urllib3.disable_warnings()

servers = builder.get_parsed_servers()
builder.generate_test_config(servers)
proc = subprocess.Popen(['xray.exe', 'run', '-c', 'config.json'])
time.sleep(2)

for i in range(len(servers)):
    port = 11000 + i
    proxies = {'http': f'http://127.0.0.1:{port}', 'https': f'http://127.0.0.1:{port}'}
    try:
        res = requests.get('http://www.google.com/generate_204', proxies=proxies, timeout=5, verify=False)
        print(f"Server {i}: {res.status_code}")
    except Exception as e:
        print(f"Server {i}: FAIL {type(e).__name__}")
proc.terminate()
