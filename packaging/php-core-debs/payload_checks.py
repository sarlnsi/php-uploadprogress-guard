"""Read-only payload recording after tests; shared by disposable image recipes."""

CODE = '''import hashlib,json
from pathlib import Path
p=Path('/out/runtime-tests.json')
d=json.loads(p.read_text())
v='.'.join(d['php_version'].split('.')[:2])
paths=['/usr/bin/php'+v,'/usr/bin/php-cgi'+v,'/usr/lib/cgi-bin/php'+v,
 '/usr/sbin/php-fpm'+v,'/usr/lib/apache2/modules/libphp'+v+'.so',
 '/usr/lib/libphp'+v+'.so','/usr/bin/phpdbg'+v,'/usr/bin/lsphp'+v]
d['installed_engine_sha256']={s:hashlib.sha256(Path(s).read_bytes()).hexdigest() for s in paths if Path(s).is_file()}
d['payload_hashes_scope']='Installed files after functional tests; compare with exact DEB payloads. Not a memory attestation.'
proof=Path('/out/source-proof.json')
if proof.is_file():
    s=json.loads(proof.read_text())
    after={name:hashlib.sha256((Path('/work/php')/name).read_bytes()).hexdigest() for name in s['source_after_patching_sha256']}
    assert after==s['source_after_patching_sha256'], 'Patched source changed during compilation'
    s['source_after_compilation_sha256']=after
    proof.write_text(json.dumps(s,indent=2)+'\\n')
    d['patched_source_preserved_during_build']=True
p.write_text(json.dumps(d,indent=2)+'\\n')
'''
