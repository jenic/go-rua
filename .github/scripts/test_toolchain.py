"""Offline tests of toolchain policy, real Make recipes, and CI configuration."""

import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
FAKE_GO = r'''#!/usr/bin/env python3
import json, os, pathlib, signal, subprocess, sys
root = pathlib.Path(__file__).resolve().parents[1]
args = sys.argv[1:]
with (root / 'calls').open('a') as log:
    log.write(json.dumps([args, {name: os.environ.get(name) for name in
        ('GOTOOLCHAIN', 'GOWORK', 'GOCACHE', 'GOMODCACHE', 'GOPATH')}]) + '\n')
if args == ['env', 'GOVERSION']:
    if os.getenv('PROBE_FAIL'): sys.exit(17)
    print(os.environ['INSTALLED_VERSION'] if os.environ['GOTOOLCHAIN'] == 'local'
          else os.getenv('ACTUAL_VERSION', os.environ['GOTOOLCHAIN']))
elif args == ['mod', 'verify'] or args[0] == 'list': pass
elif args == ['run', 'nested']:
    sys.exit(subprocess.run([sys.executable, __file__, 'version']).returncode)
else:
    if os.getenv('SIGNAL'): os.kill(os.getpid(), signal.SIGTERM)
    print(json.dumps({'args': args, 'toolchain': os.environ['GOTOOLCHAIN'],
                      'work': os.environ['GOWORK'], 'cache': os.environ['GOCACHE'],
                      'modcache': os.environ['GOMODCACHE'], 'gopath': os.environ['GOPATH']}))
    sys.exit(int(os.getenv('COMMAND_EXIT', '0')))
'''


class ToolchainTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        (self.root / 'scripts').mkdir()
        self.helper = self.root / 'scripts/go_toolchain.py'
        shutil.copyfile(ROOT / 'scripts/go_toolchain.py', self.helper)
        shutil.copyfile(ROOT / 'Makefile', self.root / 'Makefile')
        (self.root / '.github/scripts').mkdir(parents=True)
        (self.root / '.github/scripts/test_fixture.py').write_text(
            'import unittest\nclass Fixture(unittest.TestCase):\n'
            '    def test_discovery(self): pass\n')
        (self.root / 'tools').mkdir()
        self.go = self.root / 'tools/go'
        self.go.write_text(FAKE_GO)
        self.go.chmod(0o755)
        self.version = 'go1.26.11'
        self.write_module(self.version)
        self.env = dict(os.environ)
        for name in ('GOTOOLCHAIN', 'GOWORK', 'GO', 'GOCACHE', 'GOMODCACHE', 'GOPATH',
                     'MAKEFLAGS', 'MFLAGS', 'MAKELEVEL', 'MAKEOVERRIDES'):
            self.env.pop(name, None)
        self.env['INSTALLED_VERSION'] = self.version

    def write_module(self, version):
        (self.root / 'go.mod').write_text(f'module fixture\n\ngo 1.26.0\n\ntoolchain {version}\n')

    def run_helper(self, *args, success=True, **env):
        result = subprocess.run([sys.executable, str(self.helper), *map(str, args)],
                                cwd=self.root.parent, env=dict(self.env, **env),
                                capture_output=True, text=True)
        self.assertEqual(result.returncode == 0, success, result.stdout + result.stderr)
        return result

    def run_make(self, *args, success=True, **env):
        result = subprocess.run(['make', '--no-print-directory', *args, f'GO={self.go}'],
                                cwd=self.root, env=dict(self.env, **env),
                                capture_output=True, text=True)
        self.assertEqual(result.returncode == 0, success, result.stdout + result.stderr)
        return result

    def calls(self):
        path = self.root / 'calls'
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def test_print_needs_no_go_and_resolves_own_checkout(self):
        self.go.unlink()
        self.assertEqual(self.run_helper('print').stdout.strip(), self.version)
        (self.root / 'go.mod').write_text('// toolchain default\r\nmodule fixture\r\n'
                                        '\ttoolchain\tgo1.27.3 // reviewed pin\r\n')
        self.assertEqual(self.run_helper('print').stdout.strip(), 'go1.27.3')
        self.assertEqual(self.calls(), [])

    def test_invalid_declarations_fail_before_invoking_go(self):
        for content in ('module fixture\n', 'toolchain default', 'toolchain go1.26',
                        'toolchain go1.26.11rc1', 'toolchain go1.26.11+auto',
                        'toolchain go1.026.11', 'toolchain go1.26.11 extra',
                        'toolchain go1.26.11\ntoolchain go1.26.11',
                        'toolchain go1.26.11;touch injected'):
            with self.subTest(content=content):
                (self.root / 'go.mod').write_text(content)
                self.run_helper('exec', self.go, 'version', success=False)
        (self.root / 'go.mod').unlink()
        self.run_helper('print', success=False)
        self.assertEqual(self.calls(), [])

    def test_exec_preserves_arguments_and_enforces_environment(self):
        args = ['version', 'argument with spaces', '$(touch injected)', '--flag=value']
        result = self.run_helper('exec', self.go, *args, GOWORK='/outside/go.work')
        data = json.loads(result.stdout)
        self.assertEqual(data['args'], args)
        self.assertEqual(data['toolchain'], self.version)
        self.assertEqual(data['work'], 'off')
        for name, directory in [('cache', '.gocache'), ('modcache', '.gomodcache'), ('gopath', '.gopath')]:
            self.assertEqual(data[name], str(self.root / directory))
        self.assertFalse((self.root / 'injected').exists())

    def test_explicit_cache_settings_are_preserved(self):
        data = json.loads(self.run_helper('exec', self.go, 'version',
                          GOCACHE=str(self.root / 'build-cache')).stdout)
        self.assertEqual(data['cache'], str(self.root / 'build-cache'))

    def test_matching_and_empty_overrides_are_accepted(self):
        for override in ('', self.version):
            self.run_helper('exec', self.go, 'version', GOTOOLCHAIN=override)

    def test_conflicting_overrides_fail_before_go(self):
        for override in ('auto', 'local', 'go1.26.10', 'go1.27.0', self.version + '+auto', self.version + '+path'):
            with self.subTest(override=override):
                result = self.run_helper('exec', self.go, 'version', success=False, GOTOOLCHAIN=override)
                self.assertIn('conflicts with go.mod', result.stderr)
        self.assertEqual(self.calls(), [])

    def test_compiler_mismatch_stops_execution(self):
        self.run_helper('exec', self.go, 'version', success=False, ACTUAL_VERSION='go1.27.0')
        self.assertEqual([args for args, _ in self.calls()], [['env', 'GOVERSION']])

    def test_missing_or_unavailable_compiler_fails_without_fallback(self):
        result = self.run_helper('exec', self.go, 'version', success=False, PROBE_FAIL='1')
        self.assertEqual(result.returncode, 17)
        self.assertIn('install or cache', result.stderr)
        self.assertEqual(len(self.calls()), 1)
        self.go.unlink()
        self.run_helper('exec', self.go, 'version', success=False)

    def test_exit_status_and_signal_are_preserved(self):
        result = self.run_helper('exec', self.go, 'version', success=False, COMMAND_EXIT='23')
        self.assertEqual(result.returncode, 23)
        result = self.run_helper('exec', self.go, 'version', success=False, SIGNAL='1')
        self.assertEqual(result.returncode, -signal.SIGTERM)

    def test_installed_check_cannot_switch_compilers(self):
        self.run_helper('check-installed', '--go', self.go)
        self.run_helper('check-installed', '--go', self.go, success=False, INSTALLED_VERSION='go1.27.0')
        self.assertTrue(all(env['GOTOOLCHAIN'] == 'local' for _, env in self.calls()))

    def test_github_environment_transitions_from_setup_go_local_to_exact_version(self):
        env_file = self.root / 'github-env'
        env_file.write_text('GOTOOLCHAIN=local\nOTHER=preserved\n')
        self.run_helper('check-installed', '--github-env', '--go', self.go,
                        GOTOOLCHAIN='local', GITHUB_ENV=str(env_file))
        self.assertEqual(env_file.read_text(),
                         f'GOTOOLCHAIN=local\nOTHER=preserved\nGOTOOLCHAIN={self.version}\n')
        exported = dict(line.split('=', 1) for line in env_file.read_text().splitlines())
        self.run_make('verify', **exported)
        self.run_make('toolchain', **exported)
        calls = self.calls()
        self.assertEqual(calls[0][1]['GOTOOLCHAIN'], 'local')
        self.assertTrue(all(env['GOTOOLCHAIN'] == self.version for _, env in calls[1:]))

    def test_github_environment_is_unchanged_when_installed_compiler_check_fails(self):
        env_file = self.root / 'github-env'
        for failure in ({'INSTALLED_VERSION': 'go1.27.0'}, {'PROBE_FAIL': '1'}):
            with self.subTest(failure=failure):
                env_file.write_text('GOTOOLCHAIN=local\n')
                self.run_helper('check-installed', '--github-env', '--go', self.go,
                                success=False, GOTOOLCHAIN='local',
                                GITHUB_ENV=str(env_file), **failure)
                self.assertEqual(env_file.read_text(), 'GOTOOLCHAIN=local\n')
        self.assertEqual(len(self.calls()), 2)

    def test_github_environment_export_requires_an_environment_file(self):
        env = dict(self.env)
        env.pop('GITHUB_ENV', None)
        self.env = env
        result = self.run_helper('check-installed', '--github-env', '--go', self.go,
                                 success=False, GOTOOLCHAIN='local')
        self.assertIn('GITHUB_ENV', result.stderr)

    def test_installed_check_rejects_other_conflicting_overrides(self):
        for override in ('auto', 'go1.27.0', self.version + '+auto'):
            self.run_helper('check-installed', '--go', self.go, success=False,
                            GOTOOLCHAIN=override)
        self.assertEqual(self.calls(), [])

    def test_nested_go_process_inherits_exact_version(self):
        data = json.loads(self.run_helper('exec', self.go, 'run', 'nested').stdout)
        self.assertEqual(data['toolchain'], self.version)
        self.assertEqual(data['modcache'], str(self.root / '.gomodcache'))

    def test_make_honors_only_go_mod_across_patch_upgrades(self):
        for version in (self.version, 'go1.26.12'):
            self.write_module(version)
            result = self.run_make('toolchain')
            self.assertIn('"toolchain": "' + version + '"', result.stdout)
            self.run_make('verify')
        self.assertTrue(all(env['GOTOOLCHAIN'] in (self.version, 'go1.26.12') for _, env in self.calls()))

    def test_make_environment_and_command_line_overrides_are_checked(self):
        self.run_make('toolchain', f'GOTOOLCHAIN={self.version}')
        self.run_make('toolchain', 'GOTOOLCHAIN=auto', success=False)
        self.run_make('toolchain', GOTOOLCHAIN='go1.27.0', success=False)

    def test_non_go_make_targets_do_not_need_a_compiler_or_declaration(self):
        self.go.unlink()
        (self.root / 'go.mod').unlink()
        self.run_make('help')
        self.run_make('test-release')
        self.assertEqual(self.calls(), [])


class WorkflowToolchainTests(unittest.TestCase):
    def test_workflows_select_from_go_mod_and_validate_before_building(self):
        for name in ('test', 'release'):
            with self.subTest(workflow=name):
                content = (ROOT / f'.github/workflows/{name}.yml').read_text()
                self.assertIn('go-version-file: go.mod', content)
                self.assertIn('check-latest: false', content)
                self.assertIn('cache: false', content)
                self.assertNotRegex(content, r'\bgo-version:')
                self.assertNotIn('GOTOOLCHAIN:', content)
                check = content.index('python3 scripts/go_toolchain.py check-installed --github-env')
                self.assertLess(content.index('uses: actions/setup-go@'), check)
                self.assertLess(check, content.index('run: bash .github/scripts/prepare-linux.sh'))
                self.assertLess(check, content.index('make verify-repro'))
                if name == 'release':
                    self.assertLess(content.index('make test-release-binary'), content.index('uses: actions/attest@'))


if __name__ == '__main__':
    unittest.main()
