#!/usr/bin/env python3
"""Fetch pinned PHP source/binary packages through signed Sury repository metadata.

No repositories or packages are installed on the host. Python >= 3.7.
"""
import argparse
import concurrent.futures
import datetime
import email.utils
import hashlib
import json
import lzma
from pathlib import Path, PurePosixPath
import re
import subprocess
import urllib.parse
import urllib.request

BASE = 'https://packages.sury.org/php/'
FINGERPRINT = '15058500A0235D97F5D10063B188E2B695BD4743'
FLOORS = {'7.3': '7.3.33-35', '7.4': '1:7.4.33-31'}


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def paragraphs(text):
    for block in re.split(r'\n\s*\n', text.strip()):
        fields, last = {}, None
        for line in block.splitlines():
            if line.startswith((' ', '\t')):
                if last is None:
                    raise ValueError('Invalid Debian metadata continuation')
                fields[last] += '\n' + line.strip()
            else:
                key, sep, value = line.partition(':')
                if not sep or key in fields:
                    raise ValueError('Invalid or duplicate Debian metadata field')
                fields[key] = value.strip()
                last = key
        yield fields


def safe_relative(value):
    p = PurePosixPath(value)
    if p.is_absolute() or '..' in p.parts or not re.fullmatch(r'[A-Za-z0-9_.+~/%:-]+', value):
        raise ValueError('Unsafe repository path')
    return value


class HTTPSOnly(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        target = urllib.parse.urlsplit(newurl)
        if target.scheme != 'https' or target.hostname != 'packages.sury.org':
            raise ValueError('Unexpected download redirect')
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def download(relative, target, size=None, digest=None):
    relative = safe_relative(relative)
    if target.is_file() and digest and target.stat().st_size == size and sha(target) == digest:
        return
    limit = size if size is not None else 32 * 1024 * 1024
    with urllib.request.build_opener(HTTPSOnly()).open(BASE + relative, timeout=60) as response:
        data = response.read(limit + 1)
    if len(data) > limit or (size is not None and len(data) != size):
        raise ValueError('Download size mismatch: ' + relative)
    if digest is not None and hashlib.sha256(data).hexdigest() != digest:
        raise ValueError('Download checksum mismatch: ' + relative)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)


def entries(value):
    for line in value.strip().splitlines():
        digest, size, name = line.split()
        if not re.fullmatch('[0-9a-f]{64}', digest):
            raise ValueError('Invalid SHA256')
        yield safe_relative(name), int(size), digest


def repository(suite, out):
    if suite not in ('bullseye', 'jammy'):
        raise ValueError('Only explicitly selected current vendor suites are fetched')
    out.mkdir(parents=True, exist_ok=True)
    key = out / 'vendor-key.gpg'
    download('apt.gpg', key)
    release = out / 'InRelease'
    download('dists/' + suite + '/InRelease', release)
    clear = out / 'Release.verified'
    if clear.exists():
        clear.unlink()
    result = subprocess.run(['gpgv', '--status-fd', '2', '--keyring', str(key.resolve()),
                             '--output', str(clear), str(release)],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
    if ('[GNUPG:] VALIDSIG ' + FINGERPRINT + ' ') not in result.stderr.decode():
        raise ValueError('Unexpected repository signing fingerprint')
    fields = next(paragraphs(clear.read_text()))
    if fields.get('Codename', fields.get('Suite')) != suite:
        raise ValueError('Signed suite differs from request')
    now = datetime.datetime.now(datetime.timezone.utc)
    date = email.utils.parsedate_to_datetime(fields['Date'])
    if date > now + datetime.timedelta(hours=1) or now - date > datetime.timedelta(days=7):
        raise ValueError('Repository metadata is stale or from the future')
    if fields.get('Valid-Until') and now > email.utils.parsedate_to_datetime(fields['Valid-Until']):
        raise ValueError('Repository metadata expired')
    checksums = {name: (size, digest) for name, size, digest in entries(fields['SHA256'])}
    return {'suite': suite, 'fingerprint': FINGERPRINT, 'inrelease_sha256': sha(release),
            'key_sha256': sha(key), 'signed_date': fields['Date'], 'checksums': checksums}


def index(repo, out, path):
    size, digest = repo['checksums'][path]
    target = out / path.replace('/', '_')
    download('dists/' + repo['suite'] + '/' + path, target, size, digest)
    return list(paragraphs(lzma.decompress(target.read_bytes()).decode()))


def fetch(suite, out, source_only=False):
    repo = repository(suite, out / 'metadata')
    sources = index(repo, out / 'metadata', 'main/source/Sources.xz')
    selected_sources = {}
    for branch in FLOORS:
        matches = [r for r in sources if r.get('Package') == 'php' + branch]
        if len(matches) != 1:
            raise ValueError('Expected one source version per branch')
        record = matches[0]
        subprocess.run(['dpkg', '--compare-versions', record['Version'], 'ge', FLOORS[branch]], check=True)
        target = out / 'sources' / ('php' + branch)
        files = []
        for filename, size, digest in entries(record['Checksums-Sha256']):
            download(record['Directory'] + '/' + filename, target / filename, size, digest)
            files.append({'file': filename, 'size': size, 'sha256': digest})
        selected_sources[branch] = {'package': record['Package'], 'version': record['Version'], 'files': files}
    report = {'schema': 1, 'vendor': BASE, 'repository': repo, 'sources': selected_sources, 'binaries': {}}
    if not source_only:
        for arch in ('amd64', 'arm64'):
            records = index(repo, out / 'metadata', 'main/binary-' + arch + '/Packages.xz')
            tasks = []
            for branch, source in selected_sources.items():
                selected = []
                for record in records:
                    source_name = record.get('Source', record.get('Package', '')).split(' ')[0]
                    if source_name != 'php' + branch or record['Version'] != source['version']:
                        continue
                    if record['Architecture'] not in (arch, 'all') or record['Package'].endswith(('-dbgsym', '-dbg')):
                        continue
                    filename = Path(record['Filename']).name
                    target = out / 'binaries' / arch / ('php' + branch) / filename
                    tasks.append((record['Filename'], target, int(record['Size']), record['SHA256']))
                    selected.append({'package': record['Package'], 'version': record['Version'],
                                     'architecture': record['Architecture'], 'file': filename,
                                     'sha256': record['SHA256'], 'size': int(record['Size'])})
                required = {'php'+branch+'-cli', 'php'+branch+'-common', 'php'+branch+'-cgi',
                            'php'+branch+'-fpm', 'libapache2-mod-php'+branch}
                if not required.issubset({r['package'] for r in selected}):
                    raise ValueError('Incomplete binary package set for '+branch+'/'+arch)
                report['binaries'][arch + '/php' + branch] = selected
            with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
                futures = [pool.submit(download, *task) for task in tasks]
                for future in futures:
                    future.result()
    (out / 'provenance.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--suite', required=True, choices=['bullseye', 'jammy'])
    p.add_argument('--output', required=True)
    p.add_argument('--source-only', action='store_true')
    args = p.parse_args()
    report = fetch(args.suite, Path(args.output).resolve(), args.source_only)
    print(json.dumps({'suite': args.suite, 'sources': {k: v['version'] for k, v in report['sources'].items()},
                      'binary_packages': {k: len(v) for k, v in report['binaries'].items()}}, indent=2))
