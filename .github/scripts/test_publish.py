"""Exercise the real Makefile/publisher with fake tools, never writing Git metadata."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
NOTES = '# Changelog\n\nKeep these signed notes verbatim.\n'
FAKE_TOOL = r'''#!/usr/bin/env python3
import json, os, pathlib, sys
p = pathlib.Path
args = sys.argv[1:]
root = p(os.environ['FIXTURE'])
tool = p(sys.argv[0]).name
with (root / 'calls').open('a') as out: out.write(json.dumps([tool, *args]) + '\n')
def fail(name):
    if os.getenv(name): sys.exit(1)
if tool == 'git':
    if args == ['rev-parse', '--is-inside-work-tree']:
        fail('NO_GIT'); print('true')
    elif args == ['status', '--porcelain']:
        fail('FAIL_STATUS')
        if (os.getenv('DIRTY') or (os.getenv('DIRTY_AFTER_TEST') and (root / 'tested').exists())
            or (os.getenv('DIRTY_AFTER_CLIFF') and (root / 'cliff').exists())): print(' M README.md')
    elif args[:4] == ['remote', 'get-url', '--push', '--all']:
        assert args[4] == os.getenv('RELEASE_REMOTE', 'github')
        fail('NO_REMOTE'); print(os.getenv('REMOTE_URL', 'git@github.com:example/go-rua.git'))
    elif args[:2] == ['tag', '--list']:
        fail('FAIL_TAG_LIST')
        if os.getenv('LOCAL_TAG'): print(args[2])
    elif args[:3] == ['ls-remote', '--exit-code', '--tags']:
        assert args[3] == os.getenv('REMOTE_URL', 'git@github.com:example/go-rua.git')
        if os.getenv('FAIL_REMOTE'): sys.exit(128)
        sys.exit(0 if os.getenv('REMOTE_TAG') else 2)
    elif args == ['rev-parse', '--verify', 'HEAD^{commit}']:
        print(('b' if os.getenv('HEAD_MOVED') and (root / 'cliff').exists() else 'a') * 40)
    elif args[:3] == ['tag', '-s', '--cleanup=verbatim']:
        assert args[3] == '-F' and args[5] == os.environ['VERSION'] and args[6] == 'a' * 40
        (root / 'notes').write_bytes(p(args[4]).read_bytes()); fail('FAIL_SIGN')
    elif args[0] == 'push':
        tag = os.environ['VERSION']
        assert args[1:] == [os.getenv('RELEASE_REMOTE', 'github'), f'refs/tags/{tag}:refs/tags/{tag}']
        fail('FAIL_PUSH')
    elif args[:1] == ['describe']: print('v1.2.2')
    else: raise AssertionError(args)
elif tool == 'ssh':
    assert args[0] == '-G' and len(args) == 2
    fail('FAIL_SSH')
    print('hostname ' + os.getenv('SSH_HOSTNAME', 'gitea.example'))
    print('user ' + os.getenv('SSH_USER', 'git'))
elif tool == 'git-cliff':
    assert args == ['--unreleased', '--tag', os.environ['VERSION']]
    (root / 'cliff').touch(); fail('FAIL_CLIFF')
    if not os.getenv('EMPTY_CLIFF'): print(os.environ['NOTES'], end='')
elif tool == 'go':
    assert os.environ['GOWORK'] == 'off'
    assert os.environ['GOCACHE'] == str(p.cwd() / '.gocache')
    assert os.environ['GOMODCACHE'] == str(p.cwd() / '.gomodcache')
    assert os.environ['GOTOOLCHAIN'] == 'go1.26.10'
    if args == ['mod', 'verify']: fail('FAIL_VERIFY')
    elif args[0] == 'list': pass
    elif args[0] in ['fmt', 'vet']: assert '-mod=readonly' in args
    elif args[0] == 'test':
        assert '-mod=readonly' in args
        (root / 'tested').touch(); fail('FAIL_TEST')
    elif args[0] == 'build':
        assert '-mod=readonly' in args
        target = p(args[args.index('-o') + 1]); target.parent.mkdir(exist_ok=True)
        target.write_text('fake executable')
    elif args[0] == 'run':
        assert args[1] == 'golang.org/x/vuln/cmd/govulncheck@v1.8.0'
        fail('FAIL_SCAN')
    else: raise AssertionError(args)
else: raise AssertionError(tool)
'''


class PublishTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.worktree = self.root / 'worktree'
        scripts = self.worktree / '.github/scripts'
        scripts.mkdir(parents=True)
        for name in ['Makefile', 'publish.sh']:
            shutil.copyfile(ROOT / name, self.worktree / name)
        shutil.copyfile(ROOT / '.github/scripts/release.sh', scripts / 'release.sh')
        (scripts / 'test_check.py').write_text(
            'import os, pathlib, unittest\n'
            'class Check(unittest.TestCase):\n'
            '    def test_release(self):\n'
            '        pathlib.Path(os.environ["FIXTURE"], "release-tested").touch()\n'
            '        self.assertFalse(os.getenv("FAIL_RELEASE_TEST"))\n')
        tools = self.root / 'tools'
        tools.mkdir()
        for name in ['git', 'git-cliff', 'go', 'ssh']:
            path = tools / name
            path.write_text(FAKE_TOOL)
            path.chmod(0o755)
        self.scratch = self.root / 'tmp'
        self.scratch.mkdir()
        self.env = dict(os.environ, PATH=f'{tools}:{os.environ["PATH"]}', FIXTURE=str(self.root),
                        NOTES=NOTES, PUBLISH='0', TMPDIR=str(self.scratch))
        for name in ['MAKEFLAGS', 'MFLAGS', 'MAKELEVEL', 'MAKEOVERRIDES', 'VERSION',
                     'RELEASE_TAG', 'RELEASE_REMOTE', 'GOCACHE', 'GOMODCACHE', 'GOPATH',
                     'GOFLAGS', 'GOTOOLCHAIN', 'GO', 'GOVULNCHECK_VERSION']:
            self.env.pop(name, None)

    def run_make(self, target='publish', version='v1.2.3', success=True, **env):
        result = subprocess.run(['make', '--no-print-directory', target, f'VERSION={version}'],
                                cwd=self.worktree, env=dict(self.env, **env), text=True, capture_output=True)
        self.assertEqual(result.returncode == 0, success, result.stdout + result.stderr)
        self.assertEqual(list(self.scratch.iterdir()), [])
        return result

    def calls(self):
        path = self.root / 'calls'
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def writes(self):
        return [c for c in self.calls() if c[:3] == ['git', 'tag', '-s'] or c[:2] == ['git', 'push']]

    def test_preflight_accepts_versions_and_remote_override_without_writes(self):
        for tag in ['v0.0.0', 'v2.0.0', 'v1.2.3-rc.1']:
            self.run_make('publish-check', version=tag, RELEASE_REMOTE='release-github')
        self.assertEqual(self.writes(), [])
        self.assertFalse((self.root / 'tested').exists())

    def test_invalid_versions_cannot_inject_shell_commands(self):
        for version in ['', '1.2.3', 'v01.2.3', 'v1.2.3-01', 'v1.2.3+build', 'v1.2.3\n',
                        "v1.2.3';touch injected", 'v1.2.3`touch injected`']:
            self.run_make('publish-check', version=version, success=False)
        self.assertEqual(self.calls(), [])
        self.assertFalse((self.worktree / 'injected').exists())

    def test_ssh_alias_is_resolved_locally_and_preserved_for_push(self):
        for url, target in [('github:jenic/go-rua.git', 'github'),
                            ('git@github-work:jenic/go-rua.git', 'git@github-work')]:
            with self.subTest(url=url):
                self.run_make(PUBLISH='1', REMOTE_URL=url, SSH_HOSTNAME='github.com')
                self.assertIn(['ssh', '-G', target], self.calls())
                self.assertIn(['git', 'ls-remote', '--exit-code', '--tags', url, 'refs/tags/v1.2.3'], self.calls())

    def test_alias_resolution_must_succeed_and_match_github_git_user(self):
        for env in [{'SSH_HOSTNAME': 'gitea.example'},
                    {'SSH_HOSTNAME': 'github.com.evil'},
                    {'SSH_HOSTNAME': 'github.com', 'SSH_USER': 'root'},
                    {'FAIL_SSH': '1'}]:
            with self.subTest(env=env):
                self.run_make('publish-check', success=False,
                              REMOTE_URL='github:jenic/go-rua.git', **env)
        self.assertEqual(self.writes(), [])
        self.assertFalse(any(c[:2] == ['git', 'ls-remote'] for c in self.calls()))

    def test_multiple_alias_push_urls_fail_before_ssh_resolution(self):
        self.run_make('publish-check', success=False,
                      REMOTE_URL='github:jenic/go-rua.git\ngithub:other/project.git',
                      SSH_HOSTNAME='github.com')
        self.assertFalse(any(c[0] == 'ssh' for c in self.calls()))

    def test_preconditions_fail_before_tests_or_writes(self):
        for failure in ['NO_GIT', 'FAIL_STATUS', 'DIRTY', 'NO_REMOTE', 'FAIL_TAG_LIST',
                        'LOCAL_TAG', 'REMOTE_TAG', 'FAIL_REMOTE']:
            self.run_make(success=False, PUBLISH='1', **{failure: '1'})
        self.assertEqual(self.writes(), [])
        self.assertFalse((self.root / 'tested').exists())
        for url in ['gitea:example/go-rua.git', 'https://github.com.evil/repo',
                    'git@github.com:a/b.git\ngit@github.com:c/d.git']:
            self.run_make('publish-check', success=False, REMOTE_URL=url)

    def test_default_runs_checks_but_requires_explicit_opt_in(self):
        self.run_make(success=False)
        self.assertTrue((self.root / 'tested').exists())
        self.assertTrue((self.root / 'release-tested').exists())
        self.assertEqual(self.writes(), [])

    def test_checks_then_signed_notes_and_exact_tag_push(self):
        self.run_make(PUBLISH='1')
        self.assertEqual((self.root / 'notes').read_text(), NOTES)
        writes = self.writes()
        self.assertEqual(len(writes), 2)
        self.assertEqual(writes[1], ['git', 'push', 'github', 'refs/tags/v1.2.3:refs/tags/v1.2.3'])
        calls = self.calls()
        self.assertLess(next(i for i, c in enumerate(calls) if c[:2] == ['go', 'test']), calls.index(writes[0]))
        self.assertTrue((self.root / 'release-tested').exists())
        self.assertFalse(Path(writes[0][5]).exists())

    def test_check_failures_and_races_prevent_tagging(self):
        for failure in ['FAIL_VERIFY', 'FAIL_TEST', 'FAIL_SCAN', 'FAIL_RELEASE_TEST',
                        'DIRTY_AFTER_TEST', 'DIRTY_AFTER_CLIFF', 'HEAD_MOVED', 'EMPTY_CLIFF', 'FAIL_CLIFF']:
            for marker in ['tested', 'cliff']:
                (self.root / marker).unlink(missing_ok=True)
            self.run_make(success=False, PUBLISH='1', **{failure: '1'})
        self.assertEqual(self.writes(), [])

    def test_signing_failure_prevents_push(self):
        self.run_make(success=False, PUBLISH='1', FAIL_SIGN='1')
        self.assertEqual(len(self.writes()), 1)

    def test_push_failure_propagates(self):
        self.run_make(success=False, PUBLISH='1', FAIL_PUSH='1')
        self.assertEqual(len(self.writes()), 2)


if __name__ == '__main__':
    unittest.main()
