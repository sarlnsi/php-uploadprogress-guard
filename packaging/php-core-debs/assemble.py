#!/usr/bin/env python3
"""Publish only successfully tested DEB bundles into a local delivery directory."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import tarfile

from vendor import paragraphs

ROOT=Path(__file__).resolve().parent
ENGINES=['usr/bin/php{v}','usr/bin/php-cgi{v}','usr/sbin/php-fpm{v}',
         'usr/lib/apache2/modules/libphp{v}.so','usr/lib/libphp{v}.so',
         'usr/bin/phpdbg{v}','usr/bin/lsphp{v}']


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fields(path):
    return next(paragraphs(subprocess.check_output(['dpkg-deb','--field',str(path)]).decode()))


def package(path, target_dir, relative):
    control=fields(path)
    destination=target_dir/relative/path.name
    destination.parent.mkdir(parents=True,exist_ok=True)
    if not destination.exists():
        shutil.copyfile(str(path),str(destination))
    digest=sha(path)
    if sha(destination)!=digest:
        raise RuntimeError('Existing delivery file differs')
    return {'package':control['Package'],'version':control['Version'],'architecture':control['Architecture'],
            'source':control.get('Source',control['Package']), 'depends':control.get('Depends',''),
            'file':str(Path(relative)/path.name),'sha256':digest,'size':path.stat().st_size}


def engine_files(debs, branch, architecture):
    engines={}
    allowed={p.format(v=branch) for p in ENGINES}
    for deb in debs:
        if not any(deb.name.startswith(p) for p in ('libapache2-mod-php','libphp','php'+branch+'-cli_',
                                                   'php'+branch+'-cgi_','php'+branch+'-fpm_',
                                                   'php'+branch+'-phpdbg_','php'+branch+'-litespeed_')):
            continue
        data=subprocess.check_output(['dpkg-deb','--fsys-tarfile',str(deb)])
        with tarfile.open(fileobj=io.BytesIO(data),mode='r:') as stream:
            for member in stream:
                name=member.name.lstrip('./')
                if name not in allowed or not member.isfile():
                    continue
                content=stream.extractfile(member).read()
                if content[:4]!=b'\x7fELF' or content[4]!=2 or content[5]!=1:
                    raise RuntimeError('Expected little-endian ELF64 engine')
                machine=int.from_bytes(content[18:20],'little')
                if machine!={'amd64':62,'arm64':183}[architecture]:
                    raise RuntimeError('Wrong CPU in engine payload')
                engines['/'+name]={'sha256':hashlib.sha256(content).hexdigest(),
                                  'package_file':deb.name,'elf_machine':machine}
    required={'/usr/bin/php'+branch,'/usr/lib/apache2/modules/libphp'+branch+'.so'}
    if not required.issubset(engines):
        raise RuntimeError('Required engine payloads missing')
    return engines


def copy_tree(source, target):
    for path in source.rglob('*'):
        if path.is_file():
            dest=target/path.relative_to(source);dest.parent.mkdir(parents=True,exist_ok=True)
            if not dest.exists(): shutil.copyfile(str(path),str(dest))


def assemble(work, destination, partial=False):
    destination.mkdir(parents=True,exist_ok=True)
    rows=[]
    for distro in ('debian10','debian11','ubuntu20.04','ubuntu22.04'):
        for arch in ('amd64','arm64'):
            for branch in ('7.3','7.4'):
                suite='bullseye' if distro.startswith('debian') or distro=='ubuntu20.04' else 'jammy'
                local=distro in ('debian10','ubuntu20.04')
                result=(work/'builds'/(distro+'-php'+branch.replace('.','')+'-'+arch)/'result'
                        if local else work/'validations'/(suite+'-php'+branch.replace('.','')+'-'+arch)/'result')
                report=result/'runtime-tests.json'
                if not report.is_file():
                    if partial: continue
                    raise RuntimeError('Unvalidated matrix entry: '+distro+'/'+arch+'/'+branch)
                tests=json.loads(report.read_text())
                if tests['architecture']!=arch or len(tests['checks'])<21 or not all(c['pass'] for c in tests['checks']):
                    raise RuntimeError('Invalid runtime test report')
                target=destination/(distro+'-'+arch)/('php'+branch)
                target.mkdir(parents=True,exist_ok=True)
                debs=sorted(result.glob('*.deb')) if local else sorted((work/'vendor'/suite/'binaries'/arch/('php'+branch)).glob('*.deb'))
                packages=[package(p,target,'packages') for p in debs]
                dependencies=[package(p,target,'dependencies') for p in sorted((result/'dependencies').glob('*.deb'))]
                manifest={'schema':1,'date':'2026-10-26','os_id':'debian' if distro.startswith('debian') else 'ubuntu',
                          'os_version':distro.replace('debian','',1).replace('ubuntu','',1),
                          'architecture':arch,'php_branch':branch,
                          'cves':['CVE-2026-109618','CVE-2026-109619'],
                          'origin':'local-rebuild-of-signed-vendor-sources' if local else 'vendor-binaries-from-verified-signed-apt-index',
                          'binaries_authenticated_by_vendor_signed_index':not local,
                          'packages':packages,'dependencies':dependencies,
                          'engine_files':engine_files(debs,branch,arch),'runtime_tests_passed':True,
                          'runtime_tests_file':'runtime-tests.json','runtime_tests_sha256':sha(report),
                          'source_provenance':'../../provenance/'+suite+'/provenance.json',
                          'production_installation_performed':False,
                          'scope':'Backported engine fix for the listed two CVEs; not all historical PHP/system vulnerabilities or renewed maintenance.'}
                if local:
                    proof=result/'source-proof.json'
                    shutil.copyfile(str(proof),str(target/proof.name))
                    manifest['source_proof_sha256']=sha(proof)
                shutil.copyfile(str(report),str(target/report.name))
                (target/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
                rows.append({'distro':distro,'arch':arch,'branch':branch,'bundle':str(target.relative_to(destination)),
                             'packages':len(packages),'tests':len(tests['checks']),'origin':manifest['origin']})
    for suite in ('bullseye','jammy'):
        dest=destination/'provenance'/suite
        dest.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(str(work/'vendor'/suite/'provenance.json'),str(dest/'provenance.json'))
        copy_tree(work/'vendor'/suite/'metadata',dest/'metadata')
        for branch in ('7.3','7.4'):
            copy_tree(work/'vendor'/suite/'sources'/('php'+branch),destination/'sources'/suite/('php'+branch))
    tools=destination/'tools';tools.mkdir(exist_ok=True)
    for source in ROOT.iterdir():
        if source.suffix in ('.py','.php','.txt'):
            shutil.copyfile(str(source),str(tools/source.name))
    (destination/'matrix.json').write_text(json.dumps({'complete':len(rows)==16,'bundles':rows},indent=2)+'\n')
    print(json.dumps({'complete':len(rows)==16,'bundles':len(rows),'destination':str(destination)},indent=2))
    return rows


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--work',required=True)
    p.add_argument('--output',required=True)
    p.add_argument('--allow-partial',action='store_true',help='Internal staging only; never label it complete')
    args=p.parse_args()
    assemble(Path(args.work).resolve(),Path(args.output).resolve(),args.allow_partial)
