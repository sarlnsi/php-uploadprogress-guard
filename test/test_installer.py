"""Installer transactions with real temporary files and simulated Apache/network operations."""
import argparse
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('installer', str(ROOT / 'tools/install_php74.py'))
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)


class FakeApache:
    def __init__(self):
        self.events = []
        self.running = True
        self.fail_start_once = False
        self.systemctl = 'test-systemctl'
        self.log = None

    def active(self):
        return self.running

    def configtest(self):
        self.events.append('configtest')

    def stop(self):
        self.events.append('stop')
        self.running = False

    def start(self):
        self.events.append('start')
        if self.fail_start_once:
            self.fail_start_once = False
            raise RuntimeError('Simulated restart failure')
        self.running = True


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.build = self.base / 'build'
        self.build.mkdir()
        self.module = self.build / 'hp_uploadprogress_guard.so'
        self.module.write_bytes(b'unit-test-module')
        self.digest = installer.sha(self.module)
        self.manifest = {'kind': 'additional-mitigation-not-engine-patch', 'version': installer.VERSION,
            'php_api': '20190902', 'php': {'major': 7, 'minor': 4, 'release': 33, 'zts': 0, 'debug': 0, 'word_bytes': 8},
            'module_sha256': self.digest, 'source_sha256': {n: installer.sha(ROOT/'src'/n) for n in installer.SOURCE_FILES}}
        (self.build/'manifest.json').write_text(json.dumps(self.manifest))
        self.ini = self.base/'conf'/'99-hp-guard.ini'
        self.ini.parent.mkdir()
        self.engine = self.base/'libphp7.4.so'
        self.engine.write_bytes(b'test-engine')
        self.args = argparse.Namespace(build=str(self.build), probe_url='http://127.0.0.1/probe.php',
            probe_file=str(self.base/'probe.php'), ini_file=str(self.ini), php='/usr/bin/php', web_group='www-data', apply=True)
        self.before = {'version': '7.4.33', 'sapi': 'apache2handler', 'php_zts': '0', 'php_debug': '0',
            'php_word_bytes': '8', 'image_path': str(self.engine), 'image_consistent': '1',
            'image_sha256': installer.sha(self.engine), 'extensions': 'Core,session',
            'memory_limit': '128M', 'mbstring_encoding_translation': ''}
        self.after = dict(self.before, guard_version=installer.VERSION, guard_mode='parse',
            guard_mitigation_only='1', guard_multipart_handler_active='1', guard_allocation_error_callback_active='1',
            guard_sapi_deactivate_wrapper_active='1', guard_upload_progress_callback_absent='1',
            guard_mapping_consistent='1', guard_module_sha256=self.digest, upload_progress='0',
            extensions='Core,session,hp_uploadprogress_guard')
        self.service = FakeApache()
        self.cli_flags = b'7.4.33:0:0:8'

    @contextlib.contextmanager
    def simulated_host(self, after=None):
        count = [0]
        def fetch(*args):
            count[0] += 1
            return self.before if count[0] == 1 else (after or self.after)
        def run(argv, *args, **kwargs):
            if argv[0] == 'test-systemctl':
                return subprocess.CompletedProcess(argv, 3, b'', b'')
            if '-r' in argv:
                return subprocess.CompletedProcess(argv, 0, self.cli_flags, b'')
            return subprocess.CompletedProcess(argv, 0, b'version => 3.1.0-fork1', b'')
        @contextlib.contextmanager
        def probe(args):
            yield self.base/'unused.token'
        with contextlib.ExitStack() as stack:
            for target, value in [('BACKUPS', self.base/'backups'), ('PREFIX', self.base/'modules')]:
                stack.enter_context(patch.object(installer, target, value))
            stack.enter_context(patch.object(installer.os, 'geteuid', return_value=0))
            stack.enter_context(patch.object(installer, 'secure_directory', side_effect=lambda p, **k: p.mkdir(parents=True, exist_ok=True)))
            stack.enter_context(patch.object(installer, 'secure_file', side_effect=lambda p: None))
            stack.enter_context(patch.object(installer, 'Apache', return_value=self.service))
            stack.enter_context(patch.object(installer, 'run', side_effect=run))
            stack.enter_context(patch.object(installer, 'temporary_probe', probe))
            stack.enter_context(patch.object(installer.checker, 'fetch_probe', side_effect=fetch))
            stack.enter_context(patch.object(installer.time, 'sleep'))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            stack.enter_context(contextlib.redirect_stderr(io.StringIO()))
            yield

    def transaction(self):
        return next((self.base/'backups').glob('*/transaction.json'))

    def test_plan_has_no_service_or_network_mutation(self):
        self.args.apply = False
        with patch.object(installer, 'Apache') as service, patch.object(installer.checker, 'fetch_probe') as net:
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(installer.install(self.args), 0)
            service.assert_not_called()
            net.assert_not_called()
        self.assertFalse(self.ini.exists())
        self.assertFalse((self.base/'backups').exists())

    def test_success_and_manual_rollback(self):
        with self.simulated_host():
            self.assertEqual(installer.install(self.args), 0)
            state = self.transaction()
            self.assertEqual(json.loads(state.read_text())['status'], 'installed')
            self.assertIn('force_unlimited_memory=0', self.ini.read_text())
            installer.restore(state.parent, self.service)
            self.assertFalse(self.ini.exists())
            self.assertTrue(self.service.running)
            self.assertEqual(json.loads(state.read_text())['status'], 'rolled_back')

    def test_failed_restart_restores_previous_service(self):
        self.service.fail_start_once = True
        with self.simulated_host():
            with self.assertRaisesRegex(RuntimeError, 'restart failure'):
                installer.install(self.args)
            self.assertFalse(self.ini.exists())
            self.assertTrue(self.service.running)
            self.assertEqual(json.loads(self.transaction().read_text())['status'], 'rolled_back')

    def test_runtime_mismatch_causes_rollback(self):
        with self.simulated_host(dict(self.after, guard_module_sha256='0'*64)):
            with self.assertRaisesRegex(RuntimeError, 'Post-installation HTTP check failed'):
                installer.install(self.args)
            self.assertFalse(self.ini.exists())
            self.assertTrue(self.service.running)

    def test_tampered_build_refused_before_service_changes(self):
        self.module.write_bytes(b'tampered')
        with self.simulated_host():
            with self.assertRaisesRegex(RuntimeError, 'hash/type'):
                installer.install(self.args)
        self.assertEqual(self.service.events, [])

    def test_existing_foreign_ini_is_preserved(self):
        self.ini.write_text('; administrator config')
        with self.simulated_host():
            with self.assertRaisesRegex(RuntimeError, 'differs'):
                installer.install(self.args)
        self.assertEqual(self.ini.read_text(), '; administrator config')
        self.assertNotIn('stop', self.service.events)

    def test_rollback_preserves_later_administrator_edit(self):
        with self.simulated_host():
            installer.install(self.args)
            self.ini.write_text('; later administrator edit')
            with self.assertRaisesRegex(RuntimeError, 'administrator change'):
                installer.restore(self.transaction().parent, self.service)
        self.assertEqual(self.ini.read_text(), '; later administrator edit')

    def test_probe_collision_does_not_overwrite_existing_file(self):
        path = Path(self.args.probe_file)
        path.write_text('existing website file')
        with self.assertRaisesRegex(RuntimeError, 'already exists'):
            with installer.temporary_probe(self.args):
                pass
        self.assertEqual(path.read_text(), 'existing website file')

    def test_http_plaintext_remote_url_is_refused(self):
        self.args.probe_url = 'http://example.invalid/probe.php'
        with self.assertRaises(ValueError):
            installer.install(self.args)

    def test_mismatched_cli_is_refused_before_stop(self):
        self.cli_flags = b'7.4.32:0:0:8'
        with self.simulated_host():
            with self.assertRaisesRegex(RuntimeError, 'Selected CLI'):
                installer.install(self.args)
        self.assertNotIn('stop', self.service.events)

    def test_public_file_mode_is_not_lost_to_private_umask(self):
        previous = os.umask(0o077)
        try:
            file = self.base/'probe-mode.php'
            installer.create(file, b'probe', 0o644)
            self.assertEqual(file.stat().st_mode & 0o777, 0o644)
        finally:
            os.umask(previous)

    def test_probe_and_token_are_cleaned_after_exception(self):
        with patch.object(installer, 'RUN', self.base), patch.object(installer.os, 'chown'):
            with self.assertRaisesRegex(RuntimeError, 'test failure'):
                with installer.temporary_probe(self.args) as token:
                    self.assertEqual(token.stat().st_mode & 0o777, 0o640)
                    self.assertEqual(Path(self.args.probe_file).stat().st_mode & 0o777, 0o644)
                    raise RuntimeError('test failure')
        self.assertFalse(Path(self.args.probe_file).exists())
        self.assertFalse(list(self.base.glob('hp-guard-probe-*.token')))


if __name__ == '__main__':
    unittest.main()
