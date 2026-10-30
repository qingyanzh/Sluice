"""Offline CLI integration checks. Invoked by local-check.sh with a private HOME.

Only the smoke check opens sockets, always on numeric loopback addresses. Config
validation never starts listeners or automatic health checks. Remote example rule
lists are replaced in temporary copies; source examples are never edited.
"""
import errno
import http.client
import json
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import sys
import time
from urllib.parse import urlencode
import zipfile

ROOT = Path(os.environ['SLUICE_LOCAL_CHECK_ROOT'])
FIX = Path(os.environ['SLUICE_LOCAL_CHECK_FIXTURES'])
BIN = os.environ['SLUICE_LOCAL_CHECK_BINARY']
WORK = Path(os.environ['CHECK_WORK'])


def cli(*args):
    result = subprocess.run([BIN, *map(str, args)], check=True, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=60)
    print(result.stdout, end='', flush=True)
    return result.stdout


def write(name, text):
    path = WORK / name
    path.write_text(text)
    return path


def links():
    return [line for line in (FIX / 'links.txt').read_text().splitlines()
            if line and not line.startswith('#')]


def offline_copy(source):
    # `check` loads RULE-SET / DOMAIN-SET and subscriptions. Substitute their
    # remote contents with local fixtures, preserving all other config lines.
    text = source.read_text()
    out = []
    for line in text.splitlines(keepends=True):
        if line.lstrip().startswith(('#', ';', '//')):
            out.append(line)
            continue
        match = re.match(r'(\s*(RULE-SET|DOMAIN-SET),)(https?://[^,\s]+)', line, re.I)
        if match:
            fixture = FIX / ('rules.list' if match[2].upper() == 'RULE-SET' else 'domains.list')
            print(f'Offline substitution: {source}: {match[3]} -> {fixture}')
            line = line[:match.start(3)] + str(fixture) + line[match.end(3):]
        line = re.sub(r'(policy-path\s*=\s*)https?://[^,\s]+',
                      lambda m: m[1] + str(FIX / 'clash.yaml'), line, flags=re.I)
        out.append(line)
    return write(source.name, ''.join(out))


def examples():
    files = sorted(p for p in (ROOT / 'examples').rglob('*') if p.is_file())
    assert files, 'No example files found'
    for source in files:
        print(f'Checking example {source.relative_to(ROOT)}', flush=True)
        # Preserve relative local resources beside each temporary copy.
        cli('check', offline_copy(source))


def generated():
    files = sorted(Path(os.environ['SLUICE_GENERATED_CONFIG_DIR']).glob('*.conf'))
    assert {p.stem for p in files} == {'starter', 'select', 'url-test', 'fallback', 'load-balance'}, files
    for source in files:
        cli('check', source)


def converted():
    result = [cli('convert', link).strip() for link in links()]
    assert len(result) == 8, 'Update expectations when adding a supported protocol'
    return result


def convert():
    nodes = converted()
    config = write('converted.conf', '[Proxy]\n' + '\n'.join(nodes) + '\n[Rule]\nFINAL,REJECT\n')
    assert '8 proxies' in cli('check', config)


def imports():
    for filename, expected in [('clash.yaml', ['Clash-SS', 'Clash-Trojan']),
                               ('surge.conf', ['Surge-SS', 'Surge-AnyTLS'])]:
        source = FIX / filename
        config = write('import.conf', f'[Proxy Group]\nImported = select, policy-path={source}\n[Rule]\nFINAL,Imported\n')
        assert '2 proxies' in cli('check', config)
        # The first imported node must actually resolve through the group.
        output = cli('route', config, '127.0.0.1:80')
        assert f'outbound: {expected[0]}' in output, output


def mmdb(path):
    """Tiny synthetic MMDB: one 24-bit node, both leaves point to one record.

    All IPv4s map to reserved country ZZ / private ASN 64512. No real geodata,
    downloaded files, or Python dependencies are needed for offline matching.
    """
    def header(kind, size):
        assert size < 29
        return bytes([(kind << 5) | size]) if kind < 8 else bytes([size, kind - 7])

    def encode(value):
        if isinstance(value, str):
            data = value.encode()
            return header(2, len(data)) + data
        if isinstance(value, int):
            data = value.to_bytes(max(1, (value.bit_length() + 7) // 8), 'big')
            return header(6, len(data)) + data
        if isinstance(value, list):
            return header(11, len(value)) + b''.join(map(encode, value))
        return header(7, len(value)) + b''.join(encode(k) + encode(v) for k, v in value.items())

    metadata = dict(binary_format_major_version=2, binary_format_minor_version=0,
                    build_epoch=0, database_type='LocalCheck', description={'en': 'Synthetic'},
                    ip_version=4, languages=['en'], node_count=1, record_size=24)
    record = {'country': {'iso_code': 'ZZ'}, 'autonomous_system_number': 64512}
    path.write_bytes((17).to_bytes(3, 'big') * 2 + b'\0' * 16 + encode(record)
                     + b'\xab\xcd\xefMaxMind.com' + encode(metadata))


def assert_route(config, case):
    output = cli('route', config, case['target'], *case.get('args', []))
    fields = dict(re.findall(r'^\s*(rule|policy|outbound):\s+(.*)$', output, re.M))
    expected = case.get('outbound', 'DIRECT')
    assert fields == dict(rule=case['rule'], policy=expected, outbound=expected), (case, fields)


def routes():
    for case in json.loads((FIX / 'routes.json').read_text()):
        assert_route(FIX / 'rules.conf', case)
    db = WORK / 'synthetic.mmdb'
    mmdb(db)
    for setting, rule in [('geoip-db', 'GEOIP,ZZ'), ('asn-db', 'IP-ASN,64512')]:
        config = write('geo.conf', f'[General]\n{setting} = {db}\ndns-server = 127.0.0.1\n[Rule]\n{rule},DIRECT,no-resolve\nFINAL,REJECT\n')
        assert_route(config, dict(target='127.0.0.1', rule=rule))
    # Invalid context must fail before any router or DNS work.
    for args in [['--proto', 'SCTP'], ['--src', 'invalid'], ['--in-port', 'bad'], ['--url'], ['--unknown', 'x']]:
        result = subprocess.run([BIN, 'route', str(FIX / 'rules.conf'), '127.0.0.1', *args], capture_output=True)
        assert result.returncode != 0, args


def ca():
    cli('mitm', 'gen-ca')
    directory = Path.home() / 'Library/Application Support/Sluice'
    assert (directory / 'ca.key').stat().st_size > 0
    assert (directory / 'ca.crt').stat().st_size > 0
    subprocess.run(['openssl', 'x509', '-in', str(directory / 'ca.crt'), '-noout', '-subject'], check=True)


def diag():
    nodes = converted()
    # Include every credential from the share links and imported fixture formats
    # in the config and log, plus a fake subscription URL. The comment exercises
    # URL redaction without causing `diag`'s nested `check` to fetch anything.
    subscription = 'http://127.0.0.1:9/sub/local-subscription-secret?token=local-token-secret'
    text = ('[Proxy]\n' + '\n'.join(nodes) + '\n[Proxy Group]\n'
            + f'Clash = select, policy-path={FIX / "clash.yaml"}\n'
            + f'Surge = select, policy-path={FIX / "surge.conf"}\n'
            + f'# policy-path={subscription}\n[Rule]\nFINAL,REJECT\n')
    # Imported fixture node definitions are also included so their passwords
    # really are present in the exported configuration, not merely the manifest.
    surge_nodes = (FIX / 'surge.conf').read_text().split('[Proxy]\n')[1].split('[Rule]')[0]
    text = text.replace('[Proxy]\n', '[Proxy]\n' + surge_nodes
                        + 'Clash-SS = ss, 127.0.0.1, 9, encrypt-method=aes-128-gcm, password=local-clash-password\n'
                        + 'Clash-Trojan = trojan, 127.0.0.1, 9, password=local-clash-trojan\n')
    config = write('diagnostics.conf', text)
    cli('check', config)
    logdir = Path.home() / 'Library/Logs/Sluice'
    logdir.mkdir(parents=True)
    fixtures = '\n'.join((FIX / name).read_text() for name in ['clash.yaml', 'surge.conf'])
    (logdir / 'sluice.log').write_text(text + fixtures + '\n'.join(links()))
    secrets = set(re.findall(r'(?:password|username|uuid|reality-public-key|reality-short-id|obfs-password)\s*[:=]\s*([^,\s}]+)', text + fixtures))
    secrets.update(re.findall(r'https?://[^\s]+', text + fixtures))
    secrets.update(['local-subscription-secret', 'local-token-secret', 'local-surge-token'])
    secrets.update(links())
    # Manifest is derived from the actual config, so adding a credential field
    # cannot silently leave a hand-maintained password list out of date.
    assert len(secrets) >= 23, secrets
    bundle = WORK / 'diagnostics.zip'
    cli('diag', 'export', bundle, config)
    with zipfile.ZipFile(bundle) as archive:
        archive.extractall(WORK / 'unzipped')
        assert any(n.endswith('/config.conf') for n in archive.namelist())
        assert any(n.endswith('/check.txt') for n in archive.namelist())
    for path in (WORK / 'unzipped').rglob('*'):
        if path.is_file():
            data = path.read_bytes()
            for secret in secrets:
                assert secret.encode() not in data, f'Credential leaked in {path.name}: {secret}'
    print(f'PASS: {len(secrets)} fixture secrets absent from all unzipped diagnostics files')


def smoke():
    # Validate file:// sources even when the sandbox prevents the live API check.
    file_sources = f'''LocalSubscription = select, policy-path={(FIX / 'clash.yaml').as_uri()}
[Rule]
RULE-SET,{(FIX / 'rules.list').as_uri()},REJECT
FINAL,REJECT
'''
    assert '2 proxies' in cli('check', write('file-subscription.conf', '[Proxy Group]\n' + file_sources))
    # Reserve distinct free ports together; release immediately before spawning.
    reserved = []
    try:
        for _ in range(3):
            listener = socket.socket()
            reserved.append(listener)
            listener.bind(('127.0.0.1', 0))
        http_port, socks_port, api_port = [s.getsockname()[1] for s in reserved]
    except OSError as error:
        if error.errno in (errno.EPERM, errno.EACCES):
            print(f'SKIP: sandbox denied loopback bind: {error}')
            sys.exit(77)
        raise
    finally:
        for listener in reserved:
            listener.close()
    config = write('smoke.conf', f'''[General]
http-listen = 127.0.0.1:{http_port}
socks5-listen = 127.0.0.1:{socks_port}
api-listen = 127.0.0.1:{api_port}
dns-server = 127.0.0.1
[Proxy Group]
P = select, DIRECT, REJECT, url=http://127.0.0.1:{api_port}/v1/mode
''' + file_sources)
    process = None

    def call(method, path, expected=200):
        connection = http.client.HTTPConnection('127.0.0.1', api_port, timeout=5)
        try:
            connection.request(method, path)
            response = connection.getresponse()
            data = json.loads(response.read())
            assert response.status == expected, (method, path, response.status, data)
            print(f'{method} {path}: {response.status} JSON', flush=True)
            return data
        finally:
            connection.close()

    def interrupted(signum, frame):
        raise SystemExit(128 + signum)

    signal.signal(signal.SIGTERM, interrupted)
    try:
        with (WORK / 'core.log').open('w') as logfile:
            process = subprocess.Popen([BIN, 'run', str(config)], stdout=logfile, stderr=subprocess.STDOUT)
        deadline = time.monotonic() + 10
        while True:
            assert process.poll() is None, (WORK / 'core.log').read_text()
            try:
                call('GET', '/v1/mode')
                break
            except (OSError, http.client.HTTPException):
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.1)
        for path in ['subscriptions', 'policies', 'route?target=127.0.0.1:80', 'mode', 'traffic',
                     'dns', 'connections', 'connections/active', 'stats', 'profile']:
            call('GET', '/v1/' + path)
        policies = call('GET', '/v1/policies')
        subscription = next(group for group in policies if group['group'] == 'LocalSubscription')
        assert {node['name'] for node in subscription['options']} == {'Clash-SS', 'Clash-Trojan'}, subscription
        print('file:// subscription: both fixture nodes appear in /v1/policies', flush=True)
        for method in ['POST', 'PUT']:
            assert call(method, '/v1/policies/P?select=REJECT')['selected'] == 'REJECT'
            assert call(method, '/v1/mode?set=rule')['mode'] == 'rule'
            call(method, '/v1/profile?' + urlencode({'path': str(config)}))
        call('POST', '/v1/reload')
        call('POST', '/v1/dns/flush')
        test = call('POST', f'/v1/nodes/DIRECT/test?url=http://127.0.0.1:{api_port}/v1/mode&timeout=1000')
        # HEAD isn't an API method; a valid local 404 still tests the TCP/HTTP path.
        assert test['ok'] and test['status'] == 404, test
        call('POST', '/v1/policies/P/test')
        bundle = call('POST', '/v1/diag')
        assert Path(bundle['path']).is_file()
        call('DELETE', '/v1/connections/999999999', expected=404)
        call('DELETE', '/v1/connections')
        # SSE is intentionally a stream, not one JSON document. Every data frame
        # must contain valid JSON; wait for a real traffic frame rather than EOF.
        connection = http.client.HTTPConnection('127.0.0.1', api_port, timeout=5)
        try:
            connection.request('GET', '/v1/events?types=traffic')
            response = connection.getresponse()
            assert response.status == 200
            assert response.getheader('Content-Type') == 'text/event-stream'
            while True:
                line = response.readline()
                assert line, 'SSE closed before a traffic frame'
                if line.startswith(b'data: '):
                    json.loads(line[6:])
                    break
            print('GET /v1/events: 200 SSE with valid JSON frame')
        finally:
            connection.close()
        # Exercise both inbounds; FINAL REJECT prevents outbound connections/DNS.
        with socket.create_connection(('127.0.0.1', http_port), timeout=3) as inbound:
            inbound.sendall(b'GET http://127.0.0.1:9/ HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n')
            assert b'403' in inbound.recv(1024).split(b'\r\n')[0]
        with socket.create_connection(('127.0.0.1', socks_port), timeout=3) as inbound:
            inbound.sendall(b'\x05\x01\x00')
            assert inbound.recv(2) == b'\x05\x00'
            inbound.sendall(b'\x05\x01\x00\x01\x7f\x00\x00\x01\x00\x09')
            reply = inbound.recv(10)
            assert reply[:2] == b'\x05\x02', reply
        process.terminate()
        assert process.wait(timeout=5) == 0, 'Core did not shut down cleanly'
        for port in [http_port, socks_port, api_port]:
            with socket.socket() as listener:
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                listener.bind(('127.0.0.1', port))
        print('SIGTERM: clean exit within 5s; HTTP, SOCKS and API ports freed')
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        if sys.exc_info()[0] is not None and (WORK / 'core.log').exists():
            print((WORK / 'core.log').read_text(), flush=True)


if __name__ == '__main__':
    checks = {f.__name__: f for f in [examples, generated, convert, imports, routes, ca, diag, smoke]}
    try:
        checks[sys.argv[1]]()
    except subprocess.CalledProcessError as error:
        print(error.stdout or '', flush=True)
        raise
