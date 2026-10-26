import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

from plan_install import select, verified_files, verified_report, os_info, local_repository
from vendor import paragraphs, safe_relative
from assemble import canonical_filename


class Boundaries(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.manifest={'schema':1,'os_id':'debian','os_version':'10','architecture':'amd64',
            'php_branch':'7.3','runtime_tests_passed':True,
            'packages':[{'package':'php7.3-common','version':'7.3.33-35','architecture':'amd64',
                         'file':'packages/common.deb','sha256':hashlib.sha256(b'package').hexdigest()}]}
        self.records=[{'package':'php7.3-common','version':'7.3.31-1','source':'php7.3','architecture':'amd64'}]
        self.system={'ID':'debian','VERSION_ID':'10'}

    def choose(self):
        return select(self.manifest,self.records,self.system,'amd64')

    def test_selects_installed_core_only(self):
        self.records.append({'package':'php7.3-redis','version':'1','source':'php-redis','architecture':'amd64'})
        self.assertEqual([r['package'] for r in self.choose()],['php7.3-common'])

    def test_wrong_os_release_is_refused(self):
        self.system['VERSION_ID']='11'
        with self.assertRaisesRegex(RuntimeError,'exact distribution'):
            self.choose()

    def test_wrong_architecture_is_refused(self):
        self.manifest['architecture']='arm64'
        with self.assertRaisesRegex(RuntimeError,'architecture'):
            self.choose()

    def test_incomplete_replacement_set_is_refused(self):
        self.records.append(dict(self.records[0],package='php7.3-cli'))
        with self.assertRaisesRegex(RuntimeError,'Missing replacements'):
            self.choose()

    def test_downgrade_is_refused(self):
        self.records[0]['version']='7.3.33-36'
        with self.assertRaisesRegex(RuntimeError,'downgrade'):
            self.choose()

    def test_untested_bundle_is_refused(self):
        self.manifest['runtime_tests_passed']=False
        with self.assertRaisesRegex(RuntimeError,'Untested'):
            self.choose()

    def test_mixed_architecture_install_is_refused(self):
        self.records[0]['architecture']='arm64'
        with self.assertRaisesRegex(RuntimeError,'Multiarch'):
            self.choose()

    def test_no_installed_branch_is_refused(self):
        self.records[0]['source']='php7.4'
        with self.assertRaisesRegex(RuntimeError,'No installed packages'):
            self.choose()

    def test_checksum_is_checked(self):
        (self.root/'packages').mkdir();(self.root/'packages/common.deb').write_bytes(b'package')
        self.assertEqual(len(verified_files(self.root,self.manifest)),1)
        (self.root/'packages/common.deb').write_bytes(b'tampered')
        with self.assertRaisesRegex(RuntimeError,'checksum'):
            verified_files(self.root,self.manifest)

    def report_fixture(self):
        report={'architecture':'amd64','php_version':'7.3.33',
                'checks':[{'pass':True} for _ in range(21)],
                'installed_engine_sha256':{'/usr/bin/php7.3':'example-sha'}}
        path=self.root/'runtime-tests.json';path.write_text(json.dumps(report))
        self.manifest.update(tested_payload_matches_delivered_debs=True,
            runtime_tests_file=path.name,runtime_tests_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
            engine_files={'/usr/bin/php7.3':{'sha256':'example-sha'}})
        return path,report

    def test_verified_runtime_report_is_accepted(self):
        self.report_fixture();verified_report(self.root,self.manifest)

    def test_changed_runtime_report_is_refused(self):
        path,_=self.report_fixture();path.write_text('{}')
        with self.assertRaisesRegex(RuntimeError,'checksum'):
            verified_report(self.root,self.manifest)

    def test_unmatched_installed_payload_is_refused(self):
        self.report_fixture();self.manifest['engine_files']['/usr/bin/php7.3']['sha256']='other'
        with self.assertRaisesRegex(RuntimeError,'payload mismatch'):
            verified_report(self.root,self.manifest)

    def test_symlink_runtime_report_is_refused(self):
        path,_=self.report_fixture();path.rename(self.root/'other.json');path.symlink_to(self.root/'other.json')
        with self.assertRaisesRegex(RuntimeError,'symlinked'):
            verified_report(self.root,self.manifest)

    def test_symlink_package_is_refused(self):
        (self.root/'packages').mkdir();(self.root/'outside.deb').write_bytes(b'package')
        (self.root/'packages/common.deb').symlink_to(self.root/'outside.deb')
        with self.assertRaisesRegex(RuntimeError,'symlinked'):
            verified_files(self.root,self.manifest)

    def test_bundle_path_traversal_is_refused(self):
        self.manifest['packages'][0]['file']='../outside.deb'
        with self.assertRaisesRegex(RuntimeError,'Unsafe'):
            verified_files(self.root,self.manifest)

    def test_os_release_is_read_without_shell(self):
        path=self.root/'os-release';path.write_text('ID=ubuntu\nVERSION_ID="22.04"\n')
        self.assertEqual(os_info(path),{'ID':'ubuntu','VERSION_ID':'22.04'})

    def test_multiline_debian_metadata(self):
        fields=list(paragraphs('Package: php7.3\nChecksums-Sha256:\n abc 1 x\n def 2 y\n\nPackage: other\n'))
        self.assertEqual(len(fields),2)
        self.assertIn('def 2 y',fields[0]['Checksums-Sha256'])

    def test_duplicate_metadata_field_is_refused(self):
        with self.assertRaisesRegex(ValueError,'duplicate'):
            list(paragraphs('Package: php7.3\nPackage: other\n'))

    def test_remote_path_traversal_is_refused(self):
        with self.assertRaisesRegex(ValueError,'Unsafe'):
            safe_relative('../evil')

    def test_apt_cache_epoch_filename_is_canonicalized(self):
        self.assertEqual(canonical_filename({'Package':'php-common','Version':'2:101+local','Architecture':'all'}),
                         'php-common_101+local_all.deb')

    def test_package_identity_cannot_escape_directory(self):
        with self.assertRaisesRegex(ValueError,'Unsafe'):
            canonical_filename({'Package':'../evil','Version':'1','Architecture':'all'})

    def test_system_sources_are_linked_without_copying_private_contents(self):
        main=self.root/'system.list';main.write_text('private source content');main.chmod(0o600)
        parts=self.root/'system.parts';parts.mkdir()
        source=parts/'vendor.sources';source.write_text('private vendor content');source.chmod(0o600)
        repo=self.root/'repo'
        local_repository(repo,[],True,main,parts)
        self.assertTrue((repo/'sources.parts/00-system-main.list').is_symlink())
        self.assertTrue((repo/'sources.parts/01-system-vendor.sources').is_symlink())
        self.assertNotIn('private',(repo/'sources.list').read_text())
        self.assertEqual(main.stat().st_mode&0o777,0o600)
        self.assertEqual(source.stat().st_mode&0o777,0o600)


if __name__=='__main__':
    unittest.main()
