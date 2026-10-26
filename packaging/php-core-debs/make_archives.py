#!/usr/bin/env python3
"""Create eight per-platform archives only from a fully tested 16-bundle delivery."""
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import tarfile

from plan_install import verified_files, verified_report

DATE='20261026'
PREFIX='php-core-debs-'+DATE


def digest(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda:f.read(1024*1024),b''):h.update(chunk)
    return h.hexdigest()


def normalized(info):
    info.uid=info.gid=0;info.uname=info.gname='';info.mtime=1792972800
    return info


def add_bytes(archive, relative, data):
    info=normalized(tarfile.TarInfo(PREFIX+'/'+relative))
    info.size=len(data);info.mode=0o644
    archive.addfile(info,io.BytesIO(data))


def create(root, destination):
    matrix=json.loads((root/'matrix.json').read_text())
    expected={(d,a,b) for d in ('debian10','debian11','ubuntu20.04','ubuntu22.04')
              for a in ('amd64','arm64') for b in ('7.3','7.4')}
    actual={(r['distro'],r['arch'],r['branch']) for r in matrix['bundles']}
    if matrix.get('complete') is not True or actual!=expected or len(matrix['bundles'])!=16:
        raise RuntimeError('Refusing to distribute an incomplete test matrix')
    for row in matrix['bundles']:
        bundle=root/row['bundle'];manifest=json.loads((bundle/'manifest.json').read_text())
        verified_report(bundle,manifest);verified_files(bundle,manifest)
    destination.mkdir(parents=True,exist_ok=True)
    records=[]
    for distro,arch in sorted({(d,a) for d,a,b in expected}):
        platform=distro+'-'+arch
        suite='jammy' if distro=='ubuntu22.04' else 'bullseye'
        rows=[r for r in matrix['bundles'] if r['distro']==distro and r['arch']==arch]
        name=PREFIX+'-'+platform+'.tar.gz';output=destination/name
        if output.exists():raise RuntimeError('Refusing to overwrite archive: '+str(output))
        files={}
        for relative in (platform,'tools','evidence','sources/'+suite,'provenance/'+suite):
            directory=root/relative
            if not directory.is_dir():raise RuntimeError('Missing archive material: '+relative)
            for path in sorted(directory.rglob('*')):
                if path.is_symlink():raise RuntimeError('Unexpected symlink in delivery')
                if path.is_file() and '__pycache__' not in path.parts:
                    files[str(path.relative_to(root))]=path
        file_hashes={name:digest(path) for name,path in sorted(files.items())}
        local_matrix={'complete':True,'scope':'This archive contains both PHP branches for one OS/architecture; the full delivery has 16 tested bundles.',
                      'bundles':rows,'full_matrix_bundles':16}
        with output.open('xb') as f:
            with gzip.GzipFile(filename='',fileobj=f,mode='wb',compresslevel=6,mtime=0) as zipped:
                with tarfile.open(fileobj=zipped,mode='w|') as archive:
                    for relative,path in sorted(files.items()):
                        archive.add(str(path),arcname=PREFIX+'/'+relative,recursive=False,filter=normalized)
                    add_bytes(archive,'matrix.json',(json.dumps(local_matrix,indent=2)+'\n').encode())
                    add_bytes(archive,'LIRE-MOI.txt',(root/'tools/PROCEDURE.txt').read_bytes())
                    add_bytes(archive,'FILES-SHA256.json',(json.dumps(file_hashes,indent=2)+'\n').encode())
        # Re-read every archived payload, verifying names, types and complete contents.
        seen=set()
        with tarfile.open(str(output),'r:gz') as archive:
            for member in archive:
                if not member.isfile() or not member.name.startswith(PREFIX+'/'):
                    raise RuntimeError('Unexpected archive entry')
                relative=member.name[len(PREFIX)+1:]
                if relative in seen:raise RuntimeError('Duplicate archive entry')
                seen.add(relative)
                if relative in file_hashes:
                    h=hashlib.sha256(archive.extractfile(member).read()).hexdigest()
                    if h!=file_hashes[relative]:raise RuntimeError('Archive payload mismatch')
        if seen!=set(file_hashes)|{'matrix.json','LIRE-MOI.txt','FILES-SHA256.json'}:
            raise RuntimeError('Incomplete archive')
        record={'file':name,'sha256':digest(output),'size':output.stat().st_size,
                'distro':distro,'architecture':arch,'php_branches':['7.3','7.4']}
        records.append(record);print(json.dumps(record),flush=True)
    (destination/'SHA256SUMS').write_text(''.join(r['sha256']+'  '+r['file']+'\n' for r in records))
    (destination/'downloads.json').write_text(json.dumps({'date':'2026-10-26','complete':True,
        'cves':['CVE-2026-109618','CVE-2026-109619'],'archives':records},indent=2)+'\n')


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--delivery',required=True);p.add_argument('--output',required=True)
    a=p.parse_args();create(Path(a.delivery).resolve(),Path(a.output).resolve())
