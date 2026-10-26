#!/usr/bin/env python3
"""Rebuild signed vendor sources for Debian 10 / Ubuntu 20.04, in Docker only."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parent
BASES = {
 'debian10': 'debian:10-slim@sha256:bb3dc79fddbca7e8903248ab916bb775c96ec61014b3d02b4f06043b604726dc',
 'ubuntu20.04': 'ubuntu:20.04@sha256:8feb4d8ca5354def3d8fce243717141ce31e2c428701f6682bd2fafe15388214',
}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--distro',choices=sorted(BASES),required=True)
    p.add_argument('--branch',choices=['7.3','7.4'],required=True)
    p.add_argument('--arch',choices=['amd64','arm64'],required=True)
    p.add_argument('--vendor',required=True)
    p.add_argument('--work',required=True)
    p.add_argument('--builder',default='php-cve-debs-20261026')
    args=p.parse_args()
    vendor=Path(args.vendor).resolve()
    provenance=json.loads((vendor/'provenance.json').read_text())
    source=provenance['sources'][args.branch]
    work=Path(args.work).resolve();work.mkdir(parents=True,exist_ok=True)
    context=work/'context';context.mkdir(exist_ok=True)
    for r in source['files']:
        path=vendor/'sources'/('php'+args.branch)/r['file']
        if hashlib.sha256(path.read_bytes()).hexdigest()!=r['sha256']:
            raise RuntimeError('Source hash mismatch')
        shutil.copyfile(str(path),str(context/path.name))
    shutil.copyfile(str(ROOT/'core_test.py'),str(context/'core_test.py'))
    dsc=next(r['file'] for r in source['files'] if r['file'].endswith('.dsc'))
    dist_suffix='deb10' if args.distro=='debian10' else 'ubuntu20.04'
    version=source['version'].split('+0~',1)[0]+'+sarlnsi20261026.1~'+dist_suffix
    archive_setup = ("printf 'deb [check-valid-until=no] http://archive.debian.org/debian buster main\\n"
                     "deb [check-valid-until=no] http://archive.debian.org/debian-security buster/updates main\\n' > /etc/apt/sources.list"
                     if args.distro=='debian10' else 'true')
    prepare = '''import pathlib,re,hashlib,json,subprocess
p=pathlib.Path('/work/php')
patch=next((p/'debian/patches').glob('*-Avoid-state-corruption-via-bailout.patch'))
subprocess.run(['patch','--dry-run','--batch','--fuzz=0','--reverse','-p1','-i',str(patch)],cwd=p,check=True)
assert 'zend_mm_safe_error_ex' in (p/'Zend/zend_alloc.c').read_text()
assert 'CVE-2026-109618' in (p/'debian/changelog').read_text()
assert 'CVE-2026-109619' in (p/'debian/changelog').read_text()
entry='phpBRANCH (VERSION) unstable; urgency=high\\n\\n  * Local rebuild of signed Sury sources for DISTRO.\\n  * Includes vendor engine backport for CVE-2026-109618/109619.\\n\\n -- Local PHP Security Build <root@localhost>  Mon, 26 Oct 2026 00:00:00 +0000\\n\\n'
c=p/'debian/changelog'; c.write_text(entry+c.read_text())
json.dump({'source_version':'SOURCEVERSION','local_version':'VERSION','distro':'DISTRO','branch':'BRANCH','patch_sha256':hashlib.sha256(patch.read_bytes()).hexdigest(),'source_after_patching_sha256':{str(f.relative_to(p)):hashlib.sha256(f.read_bytes()).hexdigest() for f in p.rglob('*') if f.is_file() and str(f.relative_to(p)) in ['Zend/zend_alloc.c','Zend/zend_execute_API.c','ext/session/session.c','main/SAPI.c','main/main.c','main/rfc1867.c']}},open('/work/source-proof.json','w'),indent=2)
'''
    for key,val in [('SOURCEVERSION',source['version']),('DISTRO',args.distro),('VERSION',version),('BRANCH',args.branch)]:
        prepare=prepare.replace(key,val)
    (context/'prepare.py').write_text(prepare)
    jobs='4' if args.arch=='amd64' else '3'
    dpkg_jobs=('-j' if args.arch=='amd64' else '-J')+jobs
    dockerfile='''FROM BASE AS build
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
ENV DEBIAN_FRONTEND=noninteractive LC_ALL=C.UTF-8
RUN ARCHIVE_SETUP && printf '#!/bin/sh\\nexit 101\\n' > /usr/sbin/policy-rc.d && chmod 755 /usr/sbin/policy-rc.d && apt-get update && apt-get install -y --no-install-recommends build-essential devscripts equivs fakeroot quilt ca-certificates python3 patch
COPY . /input/
WORKDIR /work
RUN dpkg-source -x /input/DSC php
RUN apt-get build-dep -y --no-install-recommends /work/php
RUN python3 /input/prepare.py && groupadd -g 1000 builder && useradd -u 1000 -g 1000 -m builder && chown -R builder:builder /work
USER builder
WORKDIR /work/php
ENV DEB_BUILD_OPTIONS="parallel=JOBS noautodbgsym" SOURCE_DATE_EPOCH=1792972800
RUN --network=none dpkg-buildpackage -b -us -uc DPKG_JOBS > /work/build.log 2>&1 || { tail -100 /work/build.log; exit 1; }
USER root
RUN mkdir /out && cp /work/*.deb /work/*.buildinfo /work/*.changes /work/build.log /work/source-proof.json /out/
RUN mkdir -p /work/withheld && mv /out/php*-litespeed_*.deb /work/withheld/ && apt-get install -y --no-install-recommends apache2 binutils curl /out/*.deb
ENV PHP_CORE_DISPOSABLE_TEST=1
RUN --network=none python3 /input/core_test.py --branch BRANCH --output /out/runtime-tests.json
FROM scratch AS result
COPY --from=build /out/ /
'''
    for key,val in [('BASE',BASES[args.distro]),('ARCHIVE_SETUP',archive_setup),('DSC',dsc),('DPKG_JOBS',dpkg_jobs),('JOBS',jobs),('BRANCH',args.branch)]:
        dockerfile=dockerfile.replace(key,val)
    (context/'Dockerfile').write_text(dockerfile)
    result=work/'result'
    command=['docker','buildx','build','--builder',args.builder,'--platform','linux/'+args.arch,
             '--progress','plain','--output','type=local,dest='+str(result),str(context)]
    with (work/'buildkit.log').open('wb') as log:
        subprocess.run(command,stdout=log,stderr=subprocess.STDOUT,check=True)
    print(json.dumps({'distro':args.distro,'branch':args.branch,'arch':args.arch,'result':str(result)},indent=2),flush=True)


if __name__=='__main__':
    main()
