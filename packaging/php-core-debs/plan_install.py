#!/usr/bin/env python3
"""Verify one DEB bundle and prepare commands for its exact OS/architecture.

Never installs packages, changes repositories globally, or restarts services.
With --prepare-repository, creates a NEW local offline repository directory.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import urllib.parse

SUPPORTED = {('debian','10'),('debian','11'),('ubuntu','20.04'),('ubuntu','22.04')}


def require(value, message):
    if not value:
        raise RuntimeError(message)


def os_info(path=Path('/etc/os-release')):
    result={}
    for line in path.read_text().splitlines():
        key,sep,value=line.partition('=')
        if sep and re.fullmatch('[A-Z_]+',key):
            result[key]=value.strip().strip('"\'')
    return result


def inventory():
    fmt='${binary:Package}\t${Version}\t${source:Package}\t${Architecture}\t${db:Status-Status}\n'
    r=subprocess.run(['dpkg-query','-W','-f='+fmt,'php*','libapache2-mod-php*','libphp*'],
                     stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    records=[]
    for line in r.stdout.decode().splitlines():
        fields=line.split('\t')
        if len(fields)==5 and fields[4]=='installed':
            records.append(dict(zip(['package','version','source','architecture'],
                                    [fields[0].split(':')[0]]+fields[1:4])))
    return records


def verified_files(bundle, manifest):
    files=[]
    for group in ('packages','dependencies'):
        for record in manifest.get(group,[]):
            relative=Path(record['file'])
            require(not relative.is_absolute() and '..' not in relative.parts,
                    'Unsafe bundle path')
            path=bundle/relative
            require(path.is_file() and not path.is_symlink() and bundle in path.resolve().parents,
                    'Missing, symlinked or escaped package: '+str(relative))
            digest=hashlib.sha256(path.read_bytes()).hexdigest()
            require(digest==record['sha256'],'Package checksum mismatch: '+str(relative))
            files.append((path,record))
    require(files,'Empty bundle')
    return files


def select(manifest, records, system, arch):
    require((system.get('ID'),system.get('VERSION_ID')) in SUPPORTED,'Unsupported distribution')
    require((system['ID'],system['VERSION_ID']) == (manifest['os_id'],manifest['os_version']),
            'Bundle does not match this exact distribution release')
    require(arch in ('amd64','arm64') and arch==manifest['architecture'],
            'Bundle architecture mismatch')
    require(manifest.get('schema')==1 and manifest.get('runtime_tests_passed') is True,
            'Untested or unknown bundle manifest')
    branch=manifest['php_branch']
    require(branch in ('7.3','7.4'),'Unsupported PHP branch')
    core=[p for p in records if p['source']=='php'+branch]
    require(core,'No installed packages from PHP '+branch+'; this is a replacement planner')
    require(all(p['architecture'] in (arch,'all') for p in core),'Multiarch PHP installation requires manual review')
    available={p['package']:p for p in manifest['packages']}
    missing={p['package'] for p in core}-set(available)
    require(not missing,'Missing replacements: '+','.join(sorted(missing)))
    selected=[]
    for old in core:
        new=available[old['package']]
        require(subprocess.run(['dpkg','--compare-versions',new['version'],'ge',old['version']]).returncode==0,
                'Refusing a downgrade: '+old['package'])
        require(new['architecture'] in (arch,'all'),'Package architecture mismatch')
        require(re.fullmatch(r'[a-z0-9][a-z0-9+.-]+',new['package']) is not None,'Invalid package name')
        selected.append({'package':old['package'],'installed_version':old['version'],
                         'new_version':new['version'],'file':new['file']})
    return sorted(selected,key=lambda p:p['package'])


def local_repository(directory, files):
    require(directory.is_absolute() and not directory.exists(),'Use a NEW absolute repository directory')
    directory.mkdir(mode=0o755)
    os.chmod(str(directory),0o755)
    pool=directory/'pool';pool.mkdir(mode=0o755)
    paragraphs=[]
    for src,record in files:
        target=pool/src.name
        if target.exists():
            require(hashlib.sha256(target.read_bytes()).hexdigest()==record['sha256'],
                    'Two different packages have the same filename')
            continue
        shutil.copyfile(str(src),str(target));target.chmod(0o644)
        require(hashlib.sha256(target.read_bytes()).hexdigest()==record['sha256'],'Package changed while copying')
        control=subprocess.check_output(['dpkg-deb','--field',str(target)]).decode().rstrip()
        paragraphs.append(control+'\nFilename: pool/'+target.name+'\nSize: '+str(target.stat().st_size)+
                          '\nSHA256: '+record['sha256']+'\n')
    (directory/'Packages').write_text('\n'.join(paragraphs));(directory/'Packages').chmod(0o644)
    # Only this verified local directory is trusted; no unsigned remote repository is used.
    uri='file:'+urllib.parse.quote(str(directory),safe='/')
    (directory/'sources.list').write_text('deb [trusted=yes] '+uri+' ./\n')
    (directory/'sources.list').chmod(0o644)
    (directory/'lists').mkdir(mode=0o755)
    return ['-o','Dir::Etc::sourcelist='+str(directory/'sources.list'),
            '-o','Dir::Etc::sourceparts=-','-o','Dir::State::lists='+str(directory/'lists'),
            '-o','Dir::Cache::pkgcache='+str(directory/'pkgcache.bin'),
            '-o','Dir::Cache::srcpkgcache='+str(directory/'srcpkgcache.bin')]


def shell(command):
    return ' '.join(shlex.quote(str(x)) for x in command)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--bundle',required=True)
    p.add_argument('--prepare-repository',help='Optional NEW absolute directory, preferably /var/tmp/php-cve-repo')
    args=p.parse_args()
    bundle=Path(args.bundle).resolve(strict=True)
    manifest=json.loads((bundle/'manifest.json').read_text())
    # Avoid Path.is_relative_to, which is unavailable on Debian 10 Python 3.7.
    files=verified_files(bundle,manifest)
    arch=subprocess.check_output(['dpkg','--print-architecture']).decode().strip()
    chosen=select(manifest,inventory(),os_info(),arch)
    options=[]
    preparation=None
    if args.prepare_repository:
        options=local_repository(Path(args.prepare_repository),files)
        preparation=shell(['sudo','apt-get']+options+['update'])
    targets=[r['package']+'='+r['new_version'] for r in chosen] if options else [str(bundle/r['file']) for r in chosen]
    command=['sudo','apt-get']+options+['--no-remove','--no-install-recommends']
    print(json.dumps({'scope':'Replacement plan only; no package installed and no service changed',
                      'cves':['CVE-2026-109618','CVE-2026-109619'],'selection':chosen,
                      'repository_index_command':preparation,
                      'simulation_command':shell(command+['--simulate','install']+targets),
                      'installation_command_after_review_and_snapshot':shell(command+['install']+targets),
                      'note':'The optional local repository contains verified dependencies. No global source list is changed. '
                             'Without it, APT uses the server repositories. Package scripts may restart Apache/FPM during actual installation.'},
                     ensure_ascii=False,indent=2))


if __name__=='__main__':
    main()
