"""Check optional local skips and fail-closed CI prerequisites without Arch tools."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[2] / 'scripts/integration-upgrade.sh'
BASH = shutil.which('bash')


class ArchPrerequisiteTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.tools = self.root / 'tools'
        self.tools.mkdir()
        (self.tools / 'dirname').symlink_to(shutil.which('dirname'))
        self.env = dict(os.environ, PATH=str(self.tools), RUA_REQUIRE_ARCH_TESTS='1')

    def fake(self, name, body):
        path = self.tools / name
        path.write_text('#!' + BASH + '\n' + body + '\n')
        path.chmod(0o755)

    def run_script(self, success, **env):
        result = subprocess.run([BASH, str(SCRIPT)], env=dict(self.env, **env),
                                capture_output=True, text=True)
        self.assertEqual(result.returncode == 0, success, result.stdout + result.stderr)
        return result.stdout + result.stderr

    def prerequisites(self):
        for tool in ['makepkg', 'pacman', 'vercmp', 'bwrap', 'unshare', 'sha256sum']:
            self.fake(tool, 'exit 0')

    def test_missing_tools_skip_only_in_optional_mode(self):
        self.assertIn('SKIP:', self.run_script(True, RUA_REQUIRE_ARCH_TESTS='0'))
        self.assertIn('FAIL:', self.run_script(False))

    def test_root_user_fails_required_mode(self):
        self.prerequisites()
        self.fake('id', 'echo 0')
        self.assertIn('unprivileged user', self.run_script(False))

    def test_selected_binary_must_exist(self):
        self.prerequisites()
        self.fake('id', 'echo 1000')
        self.assertIn('missing executable', self.run_script(False, RELEASE_BINARY=str(self.root / 'missing')))

    def test_namespace_failure_propagates_before_any_package_build(self):
        self.prerequisites()
        self.fake('id', 'echo 1000')
        self.fake('unshare', 'echo namespace-unavailable >&2; exit 1')
        self.fake('candidate', 'exit 0')
        self.assertIn('namespace-unavailable', self.run_script(False, RELEASE_BINARY=str(self.tools / 'candidate')))


if __name__ == '__main__':
    unittest.main()
