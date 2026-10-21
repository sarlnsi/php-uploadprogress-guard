#!/usr/bin/env python3
"""Observe the fork in one actual Apache worker. No exploit or allocation-failure request."""
import argparse
import base64
import json
from pathlib import Path
import re
import secrets
import urllib.parse
import urllib.request


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def validate_url(value):
    url = urllib.parse.urlsplit(value)
    if url.username or url.password or url.fragment or not (
        url.scheme == 'https' or (url.scheme == 'http' and url.hostname in ('127.0.0.1', '::1', 'localhost'))):
        raise ValueError('Use verified HTTPS or local loopback HTTP, without URL credentials or fragment.')
    if any(key == 'nonce' for key, _ in urllib.parse.parse_qsl(url.query, keep_blank_values=True)):
        raise ValueError('Do not supply a nonce in the base URL.')
    return url


def fetch_probe(value, token_file):
    url = validate_url(value)
    token = Path(token_file).read_text().strip()
    if not re.fullmatch(r'[0-9a-fA-F]{64}', token):
        raise ValueError('The token must contain exactly 64 hexadecimal characters.')
    nonce = secrets.token_hex(16)
    query = urllib.parse.parse_qsl(url.query, keep_blank_values=True)
    query.append(('nonce', nonce))
    target = urllib.parse.urlunsplit((url.scheme, url.netloc, url.path, urllib.parse.urlencode(query), ''))
    request = urllib.request.Request(target, headers={'X-PHP-Audit-Token': token, 'Cache-Control': 'no-cache'})
    with urllib.request.build_opener(NoRedirect()).open(request, timeout=20) as response:
        lines = response.read(65537).decode('ascii').splitlines()
    if not lines or lines[0] != 'PHP_CVE_AUDIT_V1':
        raise RuntimeError('Invalid probe response or PHP diagnostic before the probe.')
    info = {}
    for line in lines[1:]:
        key, sep, value = line.partition(':')
        if not sep or not re.fullmatch('[a-z][a-z0-9_]*', key) or key in info:
            raise RuntimeError('Invalid or duplicate probe field.')
        info[key] = base64.b64decode(value, validate=True).decode('utf-8')
    if info.get('nonce') != nonce:
        raise RuntimeError('Stale or substituted response: nonce mismatch.')
    return info


def runtime_checks(info, digest):
    if not re.fullmatch(r'[0-9a-f]{64}', digest):
        raise ValueError('Invalid manifest digest.')
    required = ['guard_mitigation_only', 'guard_multipart_handler_active',
                'guard_allocation_error_callback_active', 'guard_sapi_deactivate_wrapper_active',
                'guard_upload_progress_callback_absent', 'guard_mapping_consistent']
    checks = {key: info.get(key) == '1' for key in required}
    checks.update({'php_7433': bool(re.fullmatch(r'7\.4\.33(?:[-+].*)?', info.get('version', ''))),
                   'apache_mod_php': info.get('sapi') == 'apache2handler',
                   'module_matches_build': info.get('guard_module_sha256') == digest,
                   'fork_version': info.get('guard_version') == '3.1.0-fork1',
                   'mode_parse': info.get('guard_mode') == 'parse',
                   'native_multibyte_fallback_disabled': info.get('mbstring_encoding_translation') in ('', '0'),
                   'finite_memory_limit': bool(re.fullmatch(r'[1-9]\d*[KMG]?', info.get('memory_limit', ''), re.I)),
                   'upload_progress_disabled': info.get('upload_progress') == '0'})
    return checks


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--url', required=True)
    parser.add_argument('--token-file', required=True)
    parser.add_argument('--manifest', required=True)
    args = parser.parse_args()
    manifest = json.loads(Path(args.manifest).read_text())
    info = fetch_probe(args.url, args.token_file)
    checks = runtime_checks(info, manifest['module_sha256'])
    passed = all(checks.values())
    print(json.dumps({'verdict': 'MITIGATION_OBSERVEE_CORRECTIF_MOTEUR_NON_ATTESTE' if passed else 'NON_VALIDE',
                      'checks': checks, 'runtime': info,
                      'scope': 'One worker of one backend; repeat for every server. No exploit attempted.'},
                     ensure_ascii=False, indent=2))
    return 0 if passed else 2


if __name__ == '__main__':
    raise SystemExit(main())
