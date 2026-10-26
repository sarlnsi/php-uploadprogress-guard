#!/usr/bin/env python3
"""Identify an installed CLI or one actual web worker against a tested core bundle."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import secrets
import subprocess
import urllib.parse
import urllib.request


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def web_probe(url, token_file):
    parsed=urllib.parse.urlsplit(url)
    if parsed.username or parsed.password or parsed.fragment or not (
       parsed.scheme=='https' or (parsed.scheme=='http' and parsed.hostname in ('127.0.0.1','::1','localhost'))):
        raise ValueError('Use verified HTTPS or HTTP loopback, without credentials or fragment')
    token=Path(token_file).read_text().strip()
    if not re.fullmatch('[0-9a-fA-F]{64}',token):
        raise ValueError('Expected a separate 64-hex audit token')
    nonce=secrets.token_hex(16)
    query=urllib.parse.parse_qsl(parsed.query,keep_blank_values=True)
    if any(k=='nonce' for k,v in query):
        raise ValueError('Do not supply nonce in the base URL')
    query.append(('nonce',nonce))
    target=urllib.parse.urlunsplit((parsed.scheme,parsed.netloc,parsed.path,urllib.parse.urlencode(query),''))
    request=urllib.request.Request(target,headers={'X-PHP-Audit-Token':token,'Cache-Control':'no-cache'})
    with urllib.request.build_opener(NoRedirect()).open(request,timeout=20) as r:
        raw=r.read(65537)
    if len(raw)>65536:
        raise ValueError('Oversized probe response')
    lines=raw.decode('ascii').splitlines()
    if not lines or lines[0]!='PHP_CVE_AUDIT_V1':
        raise ValueError('Unexpected probe response')
    info={}
    for line in lines[1:]:
        key,sep,value=line.partition(':')
        if not sep or not re.fullmatch('[a-z][a-z0-9_]*',key) or key in info:
            raise ValueError('Invalid or repeated probe field')
        info[key]=base64.b64decode(value,validate=True).decode()
    if info.get('nonce')!=nonce:
        raise ValueError('Probe nonce mismatch')
    return info


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--bundle',required=True)
    p.add_argument('--php',help='Optional exact CLI executable, for a separate CLI check')
    p.add_argument('--url',help='Optional temporary administrative probe served by this backend')
    p.add_argument('--token-file')
    args=p.parse_args()
    if not args.php and not args.url:
        p.error('Specify --php and/or --url; CLI alone does not attest Apache')
    if args.url and not args.token_file:
        p.error('--url requires --token-file')
    manifest=json.loads((Path(args.bundle)/'manifest.json').read_text())
    if manifest.get('runtime_tests_passed') is not True:
        raise RuntimeError('No passed runtime tests in manifest')
    digests={r['sha256'] for r in manifest['engine_files'].values()}
    checks={};runtime={}
    if args.php:
        binary=Path(args.php).resolve(strict=True)
        digest=hashlib.sha256(binary.read_bytes()).hexdigest()
        checks['cli_matches_bundle']=digest in digests
        if checks['cli_matches_bundle']:
            version=subprocess.check_output([str(binary),'-n','-r','echo PHP_VERSION;'],timeout=10).decode()
            checks['cli_version_matches_branch']=version.startswith(manifest['php_branch']+'.33')
            runtime['cli']={'path':str(binary),'sha256':digest,'version':version}
    if args.url:
        info=web_probe(args.url,args.token_file)
        checks.update(web_mapping_consistent=info.get('image_consistent')=='1',
                      web_engine_matches_bundle=info.get('image_sha256') in digests,
                      web_sapi_supported=info.get('sapi') in ('apache2handler','fpm-fcgi','cgi-fcgi'),
                      web_version_matches_branch=info.get('version','').startswith(manifest['php_branch']+'.33'),
                      web_64bit_nts=info.get('php_word_bytes')=='8' and info.get('php_zts')=='0')
        runtime['web']=info
    passed=bool(checks) and all(checks.values())
    print(json.dumps({'verdict':'BINAIRE_DU_LOT_CORRIGE_IDENTIFIE' if passed else 'NON_VALIDE',
                      'cves':manifest['cves'],'checks':checks,'runtime':runtime,
                      'scope':'Identifies binaries against this tested source/package provenance; not an exploit test. '
                              'A web check observes one worker of one backend. Restart all workers and repeat for every backend.'},
                     ensure_ascii=False,indent=2))
    return 0 if passed else 2


if __name__=='__main__':
    raise SystemExit(main())
