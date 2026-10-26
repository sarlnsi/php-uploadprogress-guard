#!/usr/bin/env python3
"""Bounded regression checks, only inside a disposable package test container."""
import argparse
import hashlib
import http.client
import json
import os
from pathlib import Path
import subprocess
import time


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--branch', required=True, choices=['7.3', '7.4'])
    p.add_argument('--output', required=True)
    args = p.parse_args()
    if os.environ.get('PHP_CORE_DISPOSABLE_TEST') != '1':
        raise RuntimeError('Never run this test on a production server')
    php = '/usr/bin/php' + args.branch
    checks = []
    def verify(name, condition):
        checks.append({'name': name, 'pass': bool(condition)})
        if not condition:
            raise RuntimeError('Regression check failed: ' + name)
    def run(command, check=True):
        return subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=check)
    version = run([php, '-n', '-r', 'echo PHP_VERSION;']).stdout.decode()
    verify('php_branch_unchanged', version.startswith(args.branch + '.33'))
    symbols = run(['nm', '-D', php]).stdout
    verify('engine_safe_allocation_function_exported', b'zend_mm_safe_error_ex' in symbols)
    for name, expr in [('plain', "str_repeat('x',33554432);"),
                       ('exception', "try{throw new Exception('bounded test');}finally{str_repeat('x',33554432);}"),
                       ('overflow', "str_repeat('ab',PHP_INT_MAX);")]:
        result = run([php, '-n', '-d', 'memory_limit=16M', '-r',
            "register_shutdown_function(function(){echo 'UNEXPECTED_SHUTDOWN';});" + expr], check=False)
        verify('engine_oom_' + name + '_exit_one', result.returncode == 1)
        verify('engine_oom_' + name + '_skips_shutdown', b'UNEXPECTED_SHUTDOWN' not in result.stdout)
    result = run([php, '-n', '-r', "register_shutdown_function(function(){echo 'NORMAL_SHUTDOWN';});undefined_lab_function();"], check=False)
    verify('ordinary_fatal_still_runs_shutdown', result.returncode == 255 and b'NORMAL_SHUTDOWN' in result.stdout)
    result = run([php, '-r', '$x=["a"=>[1,2,"x"],"b"=>true]; if(unserialize(serialize($x))!==$x)exit(1); echo "OK";'])
    verify('serialize_roundtrip', result.stdout == b'OK')
    prefix = 'php' + args.branch
    for command in [['a2dismod', 'mpm_event'], ['a2enmod', 'mpm_prefork'], ['a2enmod', prefix]]:
        run(command)
    Path('/etc/apache2/conf-enabled/zz-php-core-lab.conf').write_text(
        'ServerName localhost\nKeepAlive Off\n<IfModule mpm_prefork_module>\n'
        'StartServers 1\nMinSpareServers 1\nMaxSpareServers 1\nServerLimit 1\n'
        'MaxRequestWorkers 1\nMaxConnectionsPerChild 0\n</IfModule>\n'
        'php_admin_value memory_limit 32M\nphp_admin_value post_max_size 8M\n'
        'php_admin_value session.upload_progress.enabled 1\n'
        'php_admin_value session.upload_progress.cleanup 0\n')
    endpoint = Path('/var/www/html/php-core-lab.php')
    endpoint.write_text('''<?php
if (isset($_GET['oom'])) {
 register_shutdown_function(function(){echo 'UNEXPECTED_WEB_SHUTDOWN';});
 str_repeat('x',67108864); exit;
}
session_start();
$_SESSION['counter'] = isset($_SESSION['counter']) ? $_SESSION['counter']+1 : 1;
$files = array(); foreach ($_FILES as $k=>$v) {
 $files[$k] = array('error'=>$v['error'], 'sha256'=>$v['error']===0 ? hash_file('sha256',$v['tmp_name']) : '');
}
header('Content-Type: application/json');
echo json_encode(array('version'=>PHP_VERSION,'sapi'=>PHP_SAPI,'pid'=>getmypid(),
 'counter'=>$_SESSION['counter'],'progress'=>isset($_SESSION['upload_progress_probe']),
 'post'=>$_POST,'files'=>$files));
''')
    def request(query='', body=None, content_type=None, cookie=None):
        conn = http.client.HTTPConnection('127.0.0.1', 80, timeout=10)
        headers = {'Connection': 'close'}
        if content_type:
            headers['Content-Type'] = content_type
        if cookie:
            headers['Cookie'] = cookie
        try:
            conn.request('POST' if body is not None else 'GET', '/php-core-lab.php'+query, body, headers)
            response = conn.getresponse()
            raw = response.read()
            return response.status, raw, dict(response.getheaders())
        finally:
            conn.close()
    run(['apache2ctl', 'configtest'])
    run(['apache2ctl', 'start'])
    try:
        first = None
        for _ in range(30):
            try:
                status, raw, headers = request(cookie='PHPSESSID=phpcoretest')
                if status == 200:
                    first = json.loads(raw); break
            except (OSError, ValueError):
                pass
            time.sleep(.2)
        verify('apache_serves_php', first is not None and first['sapi'] == 'apache2handler')
        verify('apache_exact_version_matches_cli', first['version'] == version)
        status, raw, _ = request(cookie='PHPSESSID=phpcoretest')
        second = json.loads(raw)
        verify('sessions_persist', second['counter'] == 2)
        boundary = 'boundedPhpCoreTestBoundary'
        body = ('--'+boundary+'\r\nContent-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nprobe\r\n'
                '--'+boundary+'\r\nContent-Disposition: form-data; name="label"\r\n\r\nnormal\r\n'
                '--'+boundary+'\r\nContent-Disposition: form-data; name="sample"; filename="sample.txt"\r\n'
                'Content-Type: text/plain\r\n\r\nhello\n\r\n--'+boundary+'--\r\n').encode()
        status, raw, _ = request(body=body, content_type='multipart/form-data; boundary='+boundary,
                                 cookie='PHPSESSID=phpcoreupload')
        uploaded = json.loads(raw)
        verify('ordinary_upload_succeeds', status == 200 and uploaded['files']['sample']['error'] == 0)
        verify('upload_digest_preserved', uploaded['files']['sample']['sha256'] == hashlib.sha256(b'hello\n').hexdigest())
        verify('ordinary_post_preserved', uploaded['post']['label'] == 'normal')
        verify('session_upload_progress_neutralized_in_core', not uploaded['progress'])
        status, raw, _ = request(body=b'a=hello&b%5Bc%5D=world', content_type='application/x-www-form-urlencoded')
        verify('urlencoded_forms_work', status == 200 and json.loads(raw)['post']['b']['c'] == 'world')
        previous_pid = uploaded['pid']
        oom_output = b''
        try:
            _, oom_output, _ = request('?oom=1')
        except (OSError, http.client.HTTPException):
            pass
        verify('apache_oom_skips_application_shutdown', b'UNEXPECTED_WEB_SHUTDOWN' not in oom_output)
        recovered = None
        for _ in range(40):
            try:
                status, raw, _ = request()
                if status == 200:
                    recovered = json.loads(raw); break
            except (OSError, ValueError, http.client.HTTPException):
                pass
            time.sleep(.2)
        verify('apache_recovers_after_bounded_oom', recovered is not None)
        verify('apache_replaces_oom_worker', recovered['pid'] != previous_pid)
    finally:
        run(['apache2ctl', 'stop'], check=False)
        endpoint.unlink()
    report = {'scope': 'Bounded regression tests in disposable container; not an RCE exploit or full upstream suite',
              'php_version': version, 'architecture': run(['dpkg','--print-architecture']).stdout.decode().strip(),
              'checks': checks, 'remote_exploit_executed': False, 'host_services_changed': False}
    Path(args.output).write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps({'version': version, 'checks_passed': len(checks)}, indent=2))


if __name__ == '__main__':
    main()
