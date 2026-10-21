#!/usr/bin/env python3
"""Exercise install/rollback in disposable Debian containers. Never targets host Apache."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
IMAGE = 'php:7.4-apache-buster@sha256:54ab36b44088c9baa82213e8bbb54802e1c12e620afbfbf64f41e2e9b8f01211'


def docker(*args, **kwargs):
    r = subprocess.run(['docker'] + list(map(str, args)), stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE, timeout=120)
    if kwargs.get('check', True) and r.returncode:
        raise RuntimeError(r.stderr.decode(errors='replace') + r.stdout.decode(errors='replace'))
    return r


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--build', required=True)
    p.add_argument('--python-runtime', required=True)
    p.add_argument('--output', required=True)
    p.add_argument('--image', default=IMAGE)
    args = p.parse_args()
    output = Path(args.output).resolve()
    output.mkdir(mode=0o700, parents=True)
    build = output/'build'
    build.mkdir(mode=0o755)
    for name in ['manifest.json', 'hp_uploadprogress_guard.so']:
        shutil.copyfile(str(Path(args.build).resolve()/name), str(build/name))
        (build/name).chmod(0o644)
    shim = output/'systemctl'
    shutil.copyfile(str(ROOT/'test/lab/systemctl.py'), str(shim))
    shim.chmod(0o755)
    config = output/'lab.conf'
    config.write_text('ServerName localhost\nKeepAlive Off\n<IfModule mpm_prefork_module>\n'
                      'StartServers 1\nMinSpareServers 1\nMaxSpareServers 1\nServerLimit 1\n'
                      'MaxRequestWorkers 1\nMaxConnectionsPerChild 0\n</IfModule>\n')
    config.chmod(0o644)
    name = 'hp-guard-install-' + uuid.uuid4().hex[:10]
    run = ['run', '-d', '--name', name, '--network', 'none', '--cap-drop', 'ALL',
           '--cap-add', 'SETUID', '--cap-add', 'SETGID', '--cap-add', 'CHOWN', '--cap-add', 'KILL', '--cap-add', 'NET_BIND_SERVICE',
           '--security-opt', 'no-new-privileges', '--memory', '512m', '--pids-limit', '128']
    for source, target in [(ROOT, '/repo'), (build, '/build'), (Path(args.python_runtime).resolve(), '/opt/hp-python'),
                           (shim, '/usr/bin/systemctl'), (config, '/etc/apache2/conf-enabled/zz-lab.conf')]:
        run += ['--mount', 'type=bind,source={},target={},readonly'.format(source, target)]
    init = ('import os,signal,time\n'
            'def reap(*a):\n'
            ' try:\n'
            '  while os.waitpid(-1,os.WNOHANG)[0]: pass\n'
            ' except ChildProcessError: pass\n'
            'signal.signal(signal.SIGCHLD,reap)\n'
            'while True: time.sleep(.2)\n')
    run += [args.image, '/opt/hp-python/bin/python3', '-c', init]
    docker(*run)
    py = '/opt/hp-python/bin/python3'
    results = []
    def verify(label, condition):
        results.append({'name': label, 'pass': bool(condition)})
        if not condition:
            raise RuntimeError('Check failed: ' + label)
    def command_python(code):
        return docker('exec', name, py, '-c', code).stdout.decode()
    def exists(path):
        return command_python('from pathlib import Path; print(Path({!r}).exists())'.format(path)).strip() == 'True'
    def installer(*extra, check=True):
        r = docker('exec', name, py, '/repo/tools/install_php74.py', *extra, check=False)
        with (output/'installer-output.txt').open('ab') as f:
            f.write(r.stdout+r.stderr)
        if check and r.returncode:
            raise RuntimeError(r.stdout.decode(errors='replace') + r.stderr.decode(errors='replace'))
        return r
    install = ['install', '--build', '/build', '--probe-url', 'http://127.0.0.1/hp-guard-probe.php',
               '--probe-file', '/var/www/html/hp-guard-probe.php', '--ini-file', '/usr/local/etc/php/conf.d/99-hp-guard.ini',
               '--php', '/usr/local/bin/php']
    def state_files():
        return json.loads(command_python("from pathlib import Path; import json; print(json.dumps([str(p) for p in Path('/var/backups/hp-guard').glob('*/transaction.json')]))"))
    def cleanup_checks():
        verify('temporary_probe_removed', not exists('/var/www/html/hp-guard-probe.php'))
        verify('temporary_token_removed', command_python("from pathlib import Path; print(len(list(Path('/run').glob('hp-guard-probe-*.token'))))").strip() == '0')
    try:
        docker('exec', name, '/usr/bin/systemctl', 'start', 'apache2.service')
        verify('plan_succeeds', installer(*install).returncode == 0)
        verify('plan_does_not_create_ini', not exists('/usr/local/etc/php/conf.d/99-hp-guard.ini'))
        verify('plan_does_not_create_backup', not exists('/var/backups/hp-guard'))
        verify('install_succeeds', installer(*(install+['--apply'])).returncode == 0)
        transactions = state_files()
        verify('one_transaction_created', len(transactions) == 1)
        first = json.loads(command_python('from pathlib import Path; print(Path({!r}).read_text())'.format(transactions[0])))
        verify('installed_state', first['status'] == 'installed')
        verify('worker_hash_verified', first['after_web']['guard_module_sha256'] == first['module_sha256'])
        verify('hooks_active', first['after_web']['guard_allocation_error_callback_active'] == '1')
        verify('ini_is_world_readable', command_python("import stat; from pathlib import Path; print(oct(stat.S_IMODE(Path('/usr/local/etc/php/conf.d/99-hp-guard.ini').stat().st_mode)))").strip() == '0o644')
        verify('configuration_backup_exists', exists(str(Path(transactions[0]).parent/'configuration.tar.gz')))
        cleanup_checks()
        stops_before = command_python("from pathlib import Path; print(Path('/tmp/hp-lab-service.log').read_text().count('stop apache2.service'))")
        verify('repeat_install_is_idempotent', b'ALREADY_INSTALLED_AND_OBSERVED' in installer(*(install+['--apply'])).stdout)
        verify('repeat_install_does_not_stop_apache', stops_before == command_python("from pathlib import Path; print(Path('/tmp/hp-lab-service.log').read_text().count('stop apache2.service'))"))
        planned = json.loads(installer('rollback', '--transaction', str(Path(transactions[0]).parent)).stdout)
        verify('rollback_plan_names_exact_ini', planned['ini_file'] == '/usr/local/etc/php/conf.d/99-hp-guard.ini' and not planned['changes_applied'])
        verify('rollback_plan_keeps_module_enabled', exists('/usr/local/etc/php/conf.d/99-hp-guard.ini'))
        verify('manual_rollback_succeeds', installer('rollback', '--transaction', str(Path(transactions[0]).parent), '--apply').returncode == 0)
        verify('rollback_removes_only_managed_ini', not exists('/usr/local/etc/php/conf.d/99-hp-guard.ini'))
        docker('exec', name, '/usr/bin/systemctl', 'is-active', 'apache2.service')
        command_python("from pathlib import Path; Path('/tmp/hp-lab-fail-start-once').touch()")
        failure = installer(*(install+['--apply']), check=False)
        verify('failed_start_is_reported', failure.returncode == 1 and b'INSTALL_FAILED_ROLLED_BACK' in failure.stderr)
        verify('failed_start_removes_managed_ini', not exists('/usr/local/etc/php/conf.d/99-hp-guard.ini'))
        docker('exec', name, '/usr/bin/systemctl', 'is-active', 'apache2.service')
        verify('apache_running_after_failure', True)
        cleanup_checks()
        for path in state_files():
            state = json.loads(command_python('from pathlib import Path; print(Path({!r}).read_text())'.format(path)))
            verify('transaction_rolled_back', state['status'] == 'rolled_back')
        report = {'image': args.image, 'checks': results, 'host_services_changed': False,
                  'note': 'Real Apache/module/filesystem in container; systemctl is a test shim, not systemd.'}
        (output/'report.json').write_text(json.dumps(report, indent=2)+'\n')
        print(json.dumps({'passed': len(results), 'report': str(output/'report.json')}, indent=2))
    finally:
        logs = docker('logs', name, check=False)
        (output/'container.log').write_bytes(logs.stdout+logs.stderr)
        details = docker('exec', name, py, '-c', "from pathlib import Path; print('\\n'.join(p.read_text() for p in Path('/var/backups/hp-guard').glob('*/*.log')))", check=False)
        (output/'transaction-logs.txt').write_bytes(details.stdout+details.stderr)
        docker('rm', '-f', name, check=False)


if __name__ == '__main__':
    main()
