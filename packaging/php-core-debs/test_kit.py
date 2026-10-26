import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

from plan_install import select, verified_files, os_info
from vendor import paragraphs, safe_relative


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


if __name__=='__main__':
    unittest.main()
