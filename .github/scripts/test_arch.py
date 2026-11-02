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

    def package_fixture_tools(self):
        self.prerequisites()
        for tool in ['mkdir', 'mktemp', 'cat', 'rm', 'cp', 'cmp', 'sha256sum']:
            path = self.tools / tool
            path.unlink(missing_ok=True)
            path.symlink_to(shutil.which(tool))
        self.env['FIXTURE'] = str(self.root)
        self.fake('id', 'echo 1000')
        self.fake('unshare', '''
while [[ ${1:-} == --* ]]; do shift; done
if [[ $1 != true ]]; then exec "$@"; fi
''')
        # Simulate only package creation/installation, not sandbox enforcement.
        self.fake('candidate', '''
case $1 in
  builddir)
    read -r -a extensions <<< "${ARCHIVE_EXTENSIONS-.pkg.tar.zst}"
    for extension in "${extensions[@]}"; do
      printf 'fixture archive' > "$2/go-rua-integration-fixture-1-1-any$extension"
    done
    echo '==> Finished making: go-rua-integration-fixture 1-1'
    ;;
  tarcheck)
    if [[ ${FAIL_REVIEW:-0} == 1 ]]; then exit 19; fi
    printf '%s' "$2" > "$FIXTURE/reviewed-archive"
    ;;
  *) exit 99 ;;
esac
''')
        self.fake('pacman', '''
while (($#)); do
  case $1 in
    --root) transaction_root=$2; shift 2 ;;
    -U) archive=$2; shift 2 ;;
    *) shift ;;
  esac
done
if [[ -n ${archive:-} ]]; then
  mkdir -p "$transaction_root/usr/share/go-rua-integration-fixture"
  cp "$(dirname "$archive")/payload" "$transaction_root/usr/share/go-rua-integration-fixture/payload"
  printf '%s' "$archive" > "$FIXTURE/installed-archive"
fi
''')
        return str(self.tools / 'candidate')

    def test_compressed_package_is_reviewed_and_installed(self):
        binary = self.package_fixture_tools()
        for extension in ['.pkg.tar', '.pkg.tar.zst', '.pkg.tar.gz', '.pkg.tar.xz']:
            with self.subTest(extension=extension):
                output = self.run_script(True, RELEASE_BINARY=binary, ARCHIVE_EXTENSIONS=extension)
                reviewed = (self.root / 'reviewed-archive').read_text()
                self.assertTrue(reviewed.endswith(extension), reviewed)
                self.assertEqual((self.root / 'installed-archive').read_text(), reviewed)
                self.assertIn('PASS:', output)

    def test_missing_or_multiple_archives_have_actionable_errors(self):
        binary = self.package_fixture_tools()
        for extensions, count in [('', 0), ('.pkg.tar.zst .pkg.tar.gz', 2)]:
            with self.subTest(extensions=extensions):
                output = self.run_script(False, RELEASE_BINARY=binary, ARCHIVE_EXTENSIONS=extensions)
                self.assertIn(f'expected exactly one package archive, found {count}', output)
                self.assertIn('payload', output)

    def test_silent_command_failure_reports_stage_and_exit_code(self):
        binary = self.package_fixture_tools()
        output = self.run_script(False, RELEASE_BINARY=binary, FAIL_REVIEW='1')
        self.assertIn('review package archive', output)
        self.assertIn('tarcheck', output)
        self.assertIn('exit 19', output)


if __name__ == '__main__':
    unittest.main()
