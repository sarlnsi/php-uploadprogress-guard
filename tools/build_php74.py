#!/usr/bin/env python3
"""Build a module for the installed PHP 7.4.33 development ABI. Never installs it."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
from php_profiles import MODULE_VERSION, PROFILES, source_files, valid_php

ROOT = Path(__file__).resolve().parents[1]


def call(args, log=None):
    r = subprocess.run([str(x) for x in args], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if log:
        with log.open('ab') as f:
            f.write(r.stdout + r.stderr)
    if r.returncode:
        raise RuntimeError('Command failed: ' + str(args[0]) + ('. See ' + str(log) if log else
                           ': ' + r.stderr.decode(errors='replace')[-1000:]))
    return r.stdout.decode()


def main(argv=None, branch='7.4'):
    p = argparse.ArgumentParser(description='Build for PHP ' + branch + '; never installs.')
    p.add_argument('--php', required=True)
    p.add_argument('--phpize', required=True)
    p.add_argument('--php-config', required=True)
    p.add_argument('--output', required=True, help='New directory; compile as a non-root user')
    args = p.parse_args(argv)
    if os.geteuid() == 0:
        p.error('Compile as a non-root user; nothing needs to be installed by this script.')
    for key in ['php', 'phpize', 'php_config']:
        value = Path(getattr(args, key)).resolve(strict=True)
        if not value.is_file() or not os.access(str(value), os.X_OK):
            p.error('Not an executable file: ' + str(value))
        setattr(args, key, str(value))
    values = call([args.php, '-n', '-r',
        "echo PHP_VERSION, '\\n', PHP_MAJOR_VERSION, '\\n', PHP_MINOR_VERSION, '\\n', "
        "PHP_RELEASE_VERSION, '\\n', (int)PHP_ZTS, '\\n', (int)PHP_DEBUG, '\\n', PHP_INT_SIZE;"])
    # No dependency on the optional PHP JSON extension (Debian often loads it dynamically).
    fields = values.split('\\n')
    if len(fields) != 7:
        p.error('Unexpected target CLI response.')
    info = dict(zip(['version', 'major', 'minor', 'release', 'zts', 'debug', 'word_bytes'],
                    [fields[0]] + [int(value) for value in fields[1:]]))
    if not valid_php(info, branch):
        p.error('Expected PHP ' + branch + ('.33' if branch == '7.4' else '.x') + ' NTS non-debug.')
    config_version = call([args.php_config, '--version']).strip()
    if config_version != info['version']:
        p.error('php-config and the target CLI do not report the same PHP version.')
    include_dir = Path(call([args.php_config, '--include-dir']).strip())
    header = (include_dir / 'Zend/zend_modules.h').read_text()
    match = re.search(r'^#define\s+ZEND_MODULE_API_NO\s+(\d+)\b', header, re.M)
    if not match:
        p.error('Cannot identify the installed development headers API.')
    api = match.group(1)
    phpize_info = call([args.phpize, '--version'])
    if api != PROFILES[branch]['api'] or not re.search(r'Zend Module Api No:\s+' + api + r'\b', phpize_info):
        p.error('Development API mismatch: install the exact development package of this PHP.')
    for tool in ['make', 'gcc', 'objdump']:
        if not shutil.which(tool):
            p.error('Missing build tool: ' + tool)
    output = Path(args.output).resolve()
    output.mkdir(mode=0o700, parents=True)
    src = output / 'source'
    (src / 'rfc1867').mkdir(parents=True)
    hashes = {}
    for name in source_files(branch):
        source = ROOT / 'src' / name
        target = src / name
        target.write_bytes(source.read_bytes())
        hashes[name] = hashlib.sha256(source.read_bytes()).hexdigest()
    log = output / 'build.log'
    original_cwd = Path.cwd()
    try:
        os.chdir(str(src))
        call([args.phpize], log)
        call(['./configure', '--with-php-config=' + args.php_config], log)
        call(['make', '-j1'], log)
    finally:
        os.chdir(str(original_cwd))
    module = output / 'hp_uploadprogress_guard.so'
    shutil.copyfile(str(src / 'modules/hp_uploadprogress_guard.so'), str(module))
    load = subprocess.run([args.php, '-n', '-d', 'extension=' + str(module), '--ri', 'hp_uploadprogress_guard'],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    text = load.stdout.decode(errors='replace')
    if load.returncode or load.stderr or ('version => ' + MODULE_VERSION) not in text:
        raise RuntimeError('The new module did not load cleanly; do not install it.')
    (output / 'module-info.txt').write_text(text)
    versions = [tuple(map(int, x.split('.'))) for x in re.findall(r'GLIBC_(\d+(?:\.\d+)+)',
                call(['objdump', '-T', str(module)]))]
    glibc = max(versions) if versions else (0,)
    if glibc > (2, 28):
        raise RuntimeError('The module requires glibc {}: do not deploy it on Debian 10. Build there.'.format(glibc))
    manifest = {'kind': 'additional-mitigation-not-engine-patch', 'version': MODULE_VERSION,
                'php': info, 'php_api': api, 'config_version': config_version,
                'module_sha256': hashlib.sha256(module.read_bytes()).hexdigest(),
                'source_sha256': hashes, 'max_glibc_symbol': '.'.join(map(str, glibc)),
                'production_installation_performed': False}
    (output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps(manifest, indent=2))
    print('Build only. Module: ' + str(module))


if __name__ == '__main__':
    main()
