#!/usr/bin/env python3
"""Install the PHP 7.4.33 module targeting selected paths of CVE-2026-109618/109619.

Apache only. Plan by default; --apply changes the host. No complete engine patch is attested.
"""
import argparse
import contextlib
import datetime
import fcntl
import grp
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
BACKUPS = Path('/var/backups/hp-guard')
PREFIX = Path('/opt/hp-guard')
RUN = Path('/run')
VERSION = '3.1.0-fork1'
SOURCE_FILES = ['hp_uploadprogress_guard.c', 'config.m4', 'rfc1867/rfc1867_copy-7.4.c']
spec = importlib.util.spec_from_file_location('hp_guard_checker', str(ROOT / 'tools/check_runtime.py'))
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


def require(test, message):
    if not test:
        raise RuntimeError(message)


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def create(path, data, mode=0o600):
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as f:
        os.fchmod(f.fileno(), mode)
        f.write(data)
        f.flush()
        os.fsync(f.fileno())


def save(path, obj):
    temporary = path.with_name(path.name + '.' + uuid.uuid4().hex)
    create(temporary, (json.dumps(obj, ensure_ascii=False, indent=2) + '\n').encode())
    os.replace(str(temporary), str(path))


def secure_file(path):
    s = path.lstat()
    require(stat.S_ISREG(s.st_mode) and s.st_uid == 0 and not s.st_mode & 0o022,
            'Unsafe root-owned file: ' + str(path))


def secure_directory(path, private=False):
    # Refuse symlink traversal and writable ancestors for persistent privileged files.
    for parent in list(reversed(path.parents)) + [path]:
        if not parent.exists():
            mode = 0o700 if private and parent == path else 0o755
            parent.mkdir(mode=mode)
            os.chmod(str(parent), mode)
        s = parent.lstat()
        require(stat.S_ISDIR(s.st_mode) and s.st_uid == 0 and not s.st_mode & 0o022,
                'Unsafe installation directory: ' + str(parent))
    if private:
        os.chmod(str(path), 0o700)


def run(argv, log=None, check=True):
    r = subprocess.run([str(x) for x in argv], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60,
                       env=dict(os.environ, PATH='/usr/sbin:/usr/bin:/sbin:/bin', LC_ALL='C'))
    if log:
        with log.open('ab') as f:
            f.write(('$ ' + ' '.join(map(str, argv)) + '\n').encode() + r.stdout + r.stderr)
    require(not check or r.returncode == 0, 'Command failed: ' + str(argv[0]) +
            ('. See ' + str(log) if log else ': ' + r.stderr.decode(errors='replace')[-800:]))
    return r


class Apache:
    def __init__(self, log=None):
        self.log = log
        self.systemctl = shutil.which('systemctl', path='/usr/bin:/bin')
        self.apachectl = shutil.which('apache2ctl', path='/usr/sbin:/usr/bin:/sbin:/bin')
        require(self.systemctl and self.apachectl, 'systemctl/apache2ctl are required.')

    def active(self):
        return run([self.systemctl, 'is-active', 'apache2.service'], check=False).returncode == 0

    def configtest(self):
        run([self.apachectl, 'configtest'], self.log)

    def stop(self):
        run([self.systemctl, 'stop', 'apache2.service'], self.log)
        pid = run([self.systemctl, 'show', 'apache2.service', '-p', 'MainPID', '--value']).stdout.strip()
        require(pid == b'0' and not self.active(), 'Apache did not fully stop.')

    def start(self):
        run([self.systemctl, 'start', 'apache2.service'], self.log)
        require(self.active(), 'Apache did not become active.')


def read_build(directory):
    directory = directory.resolve(strict=True)
    manifest = json.loads((directory / 'manifest.json').read_text())
    require(manifest.get('kind') == 'additional-mitigation-not-engine-patch' and manifest.get('version') == VERSION,
            'Unknown build manifest; use tools/build_php74.py from this revision.')
    info = manifest['php']
    require([info.get(k) for k in ['major', 'minor', 'release', 'zts', 'debug']] == [7, 4, 33, 0, 0]
            and manifest.get('php_api') == '20190902', 'Build is not PHP 7.4.33 NTS/non-debug.')
    for name in SOURCE_FILES:
        require(manifest.get('source_sha256', {}).get(name) == sha(ROOT / 'src' / name),
                'Build source differs from this checkout: ' + name)
    module = directory / 'hp_uploadprogress_guard.so'
    require(not module.is_symlink() and module.is_file() and module.stat().st_size <= 64 * 1024 * 1024
            and sha(module) == manifest['module_sha256'], 'Module hash/type does not match the manifest.')
    return manifest, module


@contextlib.contextmanager
def temporary_probe(args):
    path = Path(args.probe_file)
    require(path.is_absolute() and path.suffix == '.php' and path.parent.is_dir(), 'Use an existing absolute DocumentRoot path for --probe-file.')
    require(not path.exists() and not path.is_symlink(), 'Probe path already exists; choose a new filename.')
    token = RUN / ('hp-guard-probe-' + uuid.uuid4().hex + '.token')
    token_data = (secrets.token_hex(32) + '\n').encode()
    code = (ROOT / 'tools/runtime-probe.php').read_text()
    require(code.count("'/etc/php-cve-audit.token'") == 1, 'Unexpected probe template.')
    code = code.replace("'/etc/php-cve-audit.token'", repr(str(token))).encode()
    created = []
    try:
        create(token, token_data)
        created.append((token, token.stat().st_ino))
        os.chown(str(token), 0, grp.getgrnam(args.web_group).gr_gid)
        os.chmod(str(token), 0o640)
        create(path, code, 0o644)
        created.append((path, path.stat().st_ino))
        yield token
    finally:
        for file, inode in reversed(created):
            if file.is_file() and not file.is_symlink() and file.stat().st_ino == inode:
                file.unlink()
            elif file.exists() or file.is_symlink():
                print('Cleanup requires manual review; temporary path changed: ' + str(file), file=sys.stderr)


def inspect_before(info, manifest):
    require(re.fullmatch(r'7\.4\.33(?:[-+].*)?', info.get('version', '')) and info.get('sapi') == 'apache2handler',
            'The URL does not serve PHP 7.4.33 mod_php.')
    require(info.get('php_zts') == '0' and info.get('php_debug') == '0'
            and info.get('php_word_bytes') == str(manifest['php']['word_bytes']), 'Web PHP ABI differs from this build.')
    image = Path(info.get('image_path', ''))
    require(image.is_absolute() and image.is_file() and info.get('image_consistent') == '1'
            and sha(image) == info.get('image_sha256'), 'Web worker does not match the local PHP engine on disk.')
    require(info.get('mbstring_encoding_translation') in ('', '0'), 'Native mbstring parser fallback is outside this installation profile.')
    require(re.fullmatch(r'[1-9]\d*[KMG]?', info.get('memory_limit', ''), re.I),
            'Existing memory_limit is outside the tested finite-limit profile; no automatic change is made.')


def restore(transaction, service):
    state_file = transaction / 'transaction.json'
    secure_file(state_file)
    state = json.loads(state_file.read_text())
    require(state.get('kind') == 'hp-guard-install-v1', 'Unknown transaction.')
    if state.get('status') == 'rolled_back':
        return state
    ini = Path(state['ini_file'])
    if ini.exists() or ini.is_symlink():
        require(not ini.is_symlink() and sha(ini) == state['ini_sha256'],
                'INI changed since installation; refusing to remove an administrator change.')
    service.stop()
    if ini.exists():
        ini.unlink()
    service.configtest()
    service.start()
    state['status'] = 'rolled_back'
    save(state_file, state)
    return state


def install(args):
    manifest, module = read_build(Path(args.build))
    checker.validate_url(args.probe_url)
    ini = Path(args.ini_file)
    probe = Path(args.probe_file)
    require(ini.is_absolute() and ini.suffix == '.ini' and probe.is_absolute(), 'Use absolute INI and probe file paths.')
    digest = manifest['module_sha256']
    destination = PREFIX / VERSION / digest[:16] / 'hp_uploadprogress_guard.so'
    plan = {'action': 'install', 'cves': ['CVE-2026-109618', 'CVE-2026-109619'], 'module_sha256': digest,
            'module_destination': str(destination), 'ini_file': str(ini), 'temporary_probe': str(probe),
            'service': 'apache2.service', 'changes_applied': False,
            'scope': 'Additional mitigation; not attestation of the complete engine patch.'}
    if not args.apply:
        print(json.dumps(plan, ensure_ascii=False, indent=2))
        return 0
    require(os.geteuid() == 0, '--apply requires root.')
    require(ini.parent.is_dir(), 'Apache INI directory does not exist; select the correct --ini-file.')
    secure_directory(ini.parent)
    service = Apache()
    require(service.active(), 'Apache must be running before this controlled install.')
    require(run([service.systemctl, 'is-active', 'php7.4-fpm.service'], check=False).returncode != 0,
            'PHP 7.4 FPM is active too; a dedicated multi-SAPI procedure is required.')
    service.configtest()
    php = Path(args.php).resolve(strict=True)
    secure_file(php)
    flags = run([php, '-n', '-r', "echo PHP_MAJOR_VERSION,'.',PHP_MINOR_VERSION,'.',PHP_RELEASE_VERSION,':',(int)PHP_ZTS,':',(int)PHP_DEBUG,':',PHP_INT_SIZE;"])
    require(not flags.stderr and flags.stdout.decode().split(':') == ['7.4.33', '0', '0', str(manifest['php']['word_bytes'])],
            'Selected CLI is not PHP 7.4.33 NTS/non-debug with the expected word size.')
    with temporary_probe(args) as token:
        before = checker.fetch_probe(args.probe_url, token)
        inspect_before(before, manifest)
        existing = before.get('guard_version')
        if ini.exists() or ini.is_symlink() or existing:
            require(ini.is_file() and not ini.is_symlink(), 'Existing module/configuration requires manual review.')
            require('hp-guard installer v1' in ini.read_text() and all(checker.runtime_checks(before, digest).values()),
                    'An existing module/INI differs; this installer does not overwrite it.')
            print('ALREADY_INSTALLED_AND_OBSERVED: ' + str(ini))
            return 0
        secure_directory(BACKUPS, private=True)
        transaction = BACKUPS / (datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ-') + uuid.uuid4().hex[:8])
        transaction.mkdir(mode=0o700)
        stage = transaction / 'module.so'
        # Snapshot into a root-private file before any publication or native code load.
        with module.open('rb') as f:
            data = f.read(64 * 1024 * 1024 + 1)
        require(len(data) <= 64 * 1024 * 1024 and hashlib.sha256(data).hexdigest() == digest, 'Module changed during snapshot.')
        create(stage, data)
        save(transaction / 'manifest.json', manifest)
        secure_directory(destination.parent)
        if destination.exists() or destination.is_symlink():
            secure_file(destination)
            require(sha(destination) == digest, 'An immutable module path has different content.')
        else:
            create(destination, data, 0o644)
        load = run([php, '-n', '-d', 'extension=' + str(destination), '--ri', 'hp_uploadprogress_guard'])
        require(not load.stderr and ('version => ' + VERSION).encode() in load.stdout, 'New module did not load cleanly in CLI.')
        ini_data = ('; hp-guard installer v1; transaction=' + transaction.name + '\n'
                    'extension=' + str(destination) + '\n'
                    'hp_uploadprogress_guard.mode=parse\n'
                    'hp_uploadprogress_guard.detach_upload_progress=1\n'
                    'hp_uploadprogress_guard.force_unlimited_memory=0\n').encode()
        state = {'kind': 'hp-guard-install-v1', 'status': 'backed_up', 'ini_file': str(ini),
                 'ini_sha256': hashlib.sha256(ini_data).hexdigest(), 'module': str(destination),
                 'module_sha256': digest, 'before_web': before, 'was_active': True}
        save(transaction / 'transaction.json', state)
        service.log = transaction / 'install.log'
        # The installer changes only this new INI; retain all existing PHP/Apache configuration as evidence.
        config_paths = [p for p in ['/etc/php/7.4/apache2', '/etc/apache2'] if Path(p).is_dir()]
        run(['tar', '-czf', transaction / 'configuration.tar.gz'] + config_paths, service.log)
        print('TRANSACTION: ' + str(transaction), flush=True)
        try:
            service.stop()
            create(ini, ini_data, 0o644)
            service.configtest()
            service.start()
            after = None
            last_error = 'No matching worker observed.'
            for _ in range(10):
                try:
                    info = checker.fetch_probe(args.probe_url, token)
                    checks = checker.runtime_checks(info, digest)
                    require(all(checks.values()), 'Runtime verification failed: ' + ','.join(k for k, v in checks.items() if not v))
                    require(info.get('image_sha256') == before['image_sha256'], 'PHP engine changed during installation.')
                    require(set(info.get('extensions', '').split(',')) == set(before['extensions'].split(',')) | {'hp_uploadprogress_guard'},
                            'The loaded extensions list changed unexpectedly.')
                    after = info
                    break
                except Exception as exc:
                    last_error = str(exc)
                    time.sleep(1)
            require(after is not None, 'Post-installation HTTP check failed: ' + last_error)
            state.update(status='installed', after_web=after)
            save(transaction / 'transaction.json', state)
        except BaseException:
            try:
                restore(transaction, service)
                print('INSTALL_FAILED_ROLLED_BACK: previous configuration restored.', file=sys.stderr)
            except BaseException as exc:
                state.update(status='rollback_failed', rollback_error=str(exc))
                try:
                    save(transaction / 'transaction.json', state)
                except OSError:
                    pass
                try:
                    run([service.systemctl, 'stop', 'apache2.service'], check=False)
                except (OSError, subprocess.SubprocessError):
                    pass
                print('ROLLBACK_INCOMPLETE_APACHE_STOP_REQUESTED: ' + str(transaction) + '; ' + str(exc), file=sys.stderr)
            raise
        print('MITIGATION_INSTALLED_AND_OBSERVED; complete engine patch not attested.')
        print('Rollback: sudo python3 tools/install_php74.py rollback --transaction ' + str(transaction) + ' --apply')
    return 0


def main(argv=None):
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    p = sub.add_parser('install', help='Show a plan, or install with --apply')
    p.add_argument('--build', required=True)
    p.add_argument('--probe-url', required=True)
    p.add_argument('--probe-file', required=True)
    p.add_argument('--ini-file', default='/etc/php/7.4/apache2/conf.d/99-hp-guard.ini')
    p.add_argument('--php', default='/usr/bin/php7.4')
    p.add_argument('--web-group', default='www-data')
    p.add_argument('--apply', action='store_true')
    p = sub.add_parser('rollback', help='Remove only the INI created by a verified transaction')
    p.add_argument('--transaction', required=True)
    p.add_argument('--apply', action='store_true')
    args = parser.parse_args(argv)
    if not args.apply:
        if args.command == 'install':
            return install(args)
        transaction = Path(args.transaction).resolve(strict=True)
        require(BACKUPS.resolve() in transaction.parents, 'Transaction is outside the root backup directory.')
        secure_file(transaction / 'transaction.json')
        state = json.loads((transaction / 'transaction.json').read_text())
        require(state.get('kind') == 'hp-guard-install-v1', 'Unknown transaction.')
        print(json.dumps({'action': 'rollback', 'transaction': str(transaction), 'ini_file': state['ini_file'],
                          'service': 'apache2.service', 'current_status': state['status'],
                          'changes_applied': False}, indent=2))
        return 0
    require(os.geteuid() == 0, '--apply requires root.')
    secure_directory(BACKUPS, private=True)
    with (BACKUPS / '.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if args.command == 'install':
            return install(args)
        transaction = Path(args.transaction).resolve(strict=True)
        require(BACKUPS.resolve() in transaction.parents, 'Transaction is outside the root backup directory.')
        service = Apache(transaction / 'rollback.log')
        restore(transaction, service)
        print('ROLLED_BACK: mitigation removed; previous configuration active.')
        return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (RuntimeError, OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        print('INSTALLER_FAILED: ' + str(exc), file=sys.stderr)
        raise SystemExit(1)
