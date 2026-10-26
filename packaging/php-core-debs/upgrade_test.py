#!/usr/bin/env python3
"""Test a real stock-PHP upgrade and local repository planner on disposable amd64."""
import argparse
from pathlib import Path
import shutil
import subprocess

ROOT=Path(__file__).resolve().parent
BASES={'debian10':('debian:10-slim@sha256:bb3dc79fddbca7e8903248ab916bb775c96ec61014b3d02b4f06043b604726dc','7.3'),
       'ubuntu20.04':('ubuntu:20.04@sha256:8feb4d8ca5354def3d8fce243717141ce31e2c428701f6682bd2fafe15388214','7.4')}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--distro',required=True,choices=sorted(BASES))
    p.add_argument('--bundle',required=True)
    p.add_argument('--work',required=True)
    args=p.parse_args();base,branch=BASES[args.distro]
    work=Path(args.work).resolve();context=work/'context';context.mkdir(parents=True,exist_ok=True)
    shutil.copytree(str(Path(args.bundle).resolve()),str(context/'bundle'))
    for name in ['plan_install.py','verify_runtime.py','core_test.py']:
        shutil.copyfile(str(ROOT/name),str(context/name))
    script='''import hashlib,json,pathlib,shlex,subprocess,os
branch='BRANCH'
def run(command):
 r=subprocess.run(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
 if r.returncode:
  print(r.stdout.decode(errors='replace'));print(r.stderr.decode(errors='replace'));r.check_returncode()
 return r
def inv():return run(['dpkg-query','-W','-f=${Version}','php-redis']).stdout.decode()
redis_before=inv()
paths=[pathlib.Path('/etc/php/'+branch+'/'+s+'/php.ini') for s in ['cli','apache2','fpm']]
for path in paths:
 with path.open('a') as f:f.write('\\n; LOCAL_UPGRADE_MARKER\\nmemory_limit=96M\\n')
before={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
old=run(['/usr/bin/php'+branch,'-n','-r','echo PHP_VERSION;']).stdout.decode()
plan=json.loads(run(['python3','/input/plan_install.py','--bundle','/input/bundle','--prepare-repository','/tmp/local-php-repo','--use-system-repositories']).stdout)
assert all(p['package']!='php-redis' for p in plan['selection'])
run(shlex.split(plan['repository_index_command'])[1:])
run(shlex.split(plan['simulation_command'])[1:])
install=shlex.split(plan['installation_command_after_review_and_snapshot'])[1:]
run(install[:1]+['--assume-yes']+install[1:])
assert before=={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
assert redis_before==inv()
assert run(['/usr/bin/php'+branch,'-r','echo extension_loaded("redis") ? "REDIS_OK" : "NO_REDIS";']).stdout==b'REDIS_OK'
verified=json.loads(run(['python3','/input/verify_runtime.py','--bundle','/input/bundle','--php','/usr/bin/php'+branch]).stdout)
assert verified['verdict']=='BINAIRE_DU_LOT_CORRIGE_IDENTIFIE'
pathlib.Path('/out/upgrade-tests.json').write_text(json.dumps({'stock_version':old,'target_branch':branch,'ini_files_preserved':list(before),'third_party_redis_package_preserved':True,'third_party_redis_extension_loads':True,'local_repository_index_and_simulation':'PASS','loaded_cli_matches_bundle':'PASS','selected_packages':plan['selection'],'host_services_changed':False},indent=2)+'\\n')
'''.replace('BRANCH',branch)
    (context/'upgrade.py').write_text(script)
    setup=("printf 'deb [check-valid-until=no] http://archive.debian.org/debian buster main\\n"
           "deb [check-valid-until=no] http://archive.debian.org/debian-security buster/updates main\\n' > /etc/apt/sources.list"
           if args.distro=='debian10' else 'true')
    recipe='''FROM BASE AS test
ENV DEBIAN_FRONTEND=noninteractive LC_ALL=C.UTF-8
RUN SETUP && printf '#!/bin/sh\\nexit 101\\n' >/usr/sbin/policy-rc.d && chmod 755 /usr/sbin/policy-rc.d && apt-get update && apt-get install -y --no-install-recommends python3 binutils apache2 libapache2-mod-phpBRANCH phpBRANCH-fpm php-redis
COPY . /input/
RUN mkdir /out && python3 /input/upgrade.py
ENV PHP_CORE_DISPOSABLE_TEST=1
RUN --network=none python3 /input/core_test.py --branch BRANCH --output /out/post-upgrade-runtime-tests.json
FROM scratch
COPY --from=test /out/ /
'''
    for key,value in [('BASE',base),('SETUP',setup),('BRANCH',branch)]:recipe=recipe.replace(key,value)
    (context/'Dockerfile').write_text(recipe)
    with (work/'buildkit.log').open('wb') as log:
        subprocess.run(['docker','buildx','build','--builder','php-cve-debs-20261026','--platform','linux/amd64','--progress','plain','--output','type=local,dest='+str(work/'result'),str(context)],stdout=log,stderr=subprocess.STDOUT,check=True)
    print(str(work/'result'),flush=True)


if __name__=='__main__':main()
