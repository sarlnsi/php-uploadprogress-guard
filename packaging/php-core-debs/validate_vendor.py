#!/usr/bin/env python3
"""Install signed vendor binaries into a disposable matching distribution and test."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import shlex
import subprocess
from payload_checks import CODE as PAYLOAD_CODE

ROOT=Path(__file__).resolve().parent
BASES={
 'bullseye':'debian:11-slim@sha256:e5b6442dd2e9684cf5e87d8338b5968f3b348636fc0be6d7850a381e3731a2bd',
 'jammy':'ubuntu:22.04@sha256:0a9887931b0e38af2e3487ed39e29436b0535c4f3f52e57745baaf79d1898956',
}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--suite',required=True,choices=sorted(BASES))
    p.add_argument('--branch',required=True,choices=['7.3','7.4'])
    p.add_argument('--arch',required=True,choices=['amd64','arm64'])
    p.add_argument('--vendor',required=True)
    p.add_argument('--work',required=True)
    p.add_argument('--builder',default='php-cve-debs-20261026')
    args=p.parse_args()
    vendor=Path(args.vendor).resolve();work=Path(args.work).resolve()
    context=work/'context';context.mkdir(parents=True,exist_ok=True)
    (context/'debs').mkdir(exist_ok=True)
    proof=json.loads((vendor/'provenance.json').read_text())
    for record in proof['binaries'][args.arch+'/php'+args.branch]:
        src=vendor/'binaries'/args.arch/('php'+args.branch)/record['file']
        if hashlib.sha256(src.read_bytes()).hexdigest()!=record['sha256']:
            raise RuntimeError('Vendor binary hash mismatch')
        shutil.copyfile(str(src),str(context/'debs'/src.name))
    shutil.copyfile(str(vendor/'metadata/vendor-key.gpg'),str(context/'vendor-key.gpg'))
    shutil.copyfile(str(ROOT/'core_test.py'),str(context/'core_test.py'))
    apt_setup = ("printf 'deb [check-valid-until=no] http://archive.debian.org/debian bullseye main\\n"
                 "deb [check-valid-until=no] http://archive.debian.org/debian-security bullseye-security main\\n' > /etc/apt/sources.list"
                 if args.suite == 'bullseye' else 'true')
    dockerfile='''FROM BASE AS test
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
ENV DEBIAN_FRONTEND=noninteractive LC_ALL=C.UTF-8
RUN APT_SETUP && printf '#!/bin/sh\\nexit 101\\n' > /usr/sbin/policy-rc.d && chmod 755 /usr/sbin/policy-rc.d && apt-get update && apt-get install -y --no-install-recommends ca-certificates apache2 binutils python3 curl
COPY . /input/
RUN cp /input/vendor-key.gpg /usr/share/keyrings/php-vendor.gpg && printf 'deb [signed-by=/usr/share/keyrings/php-vendor.gpg] https://packages.sury.org/php/ SUITE main\\n' > /etc/apt/sources.list.d/php-vendor.list && apt-get update
RUN rm -f /etc/apt/apt.conf.d/docker-clean && apt-get install -y --no-install-recommends /input/debs/*.deb
RUN mkdir -p /out/dependencies && cp /var/cache/apt/archives/*.deb /out/dependencies/ && dpkg-query -W -f='${binary:Package} ${Version} ${Architecture}\\n' > /out/installed-packages.txt
ENV PHP_CORE_DISPOSABLE_TEST=1
RUN --network=none python3 /input/core_test.py --branch BRANCH --output /out/runtime-tests.json
FROM scratch AS result
COPY --from=test /out/ /
'''
    for key,value in [('BASE',BASES[args.suite]),('APT_SETUP',apt_setup),('SUITE',args.suite),('BRANCH',args.branch)]:
        dockerfile=dockerfile.replace(key,value)
    dockerfile=dockerfile.replace('FROM scratch AS result',
        'RUN --network=none python3 -c '+shlex.quote('exec('+repr(PAYLOAD_CODE)+')')+'\nFROM scratch AS result')
    (context/'Dockerfile').write_text(dockerfile)
    with (work/'buildkit.log').open('wb') as log:
        subprocess.run(['docker','buildx','build','--builder',args.builder,'--platform','linux/'+args.arch,
                        '--progress','plain','--output','type=local,dest='+str(work/'result'),str(context)],
                       stdout=log,stderr=subprocess.STDOUT,check=True)
    print(json.dumps({'suite':args.suite,'branch':args.branch,'arch':args.arch,'result':str(work/'result')}),flush=True)


if __name__=='__main__':
    main()
