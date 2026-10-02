import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
MODULE_PATH = 'github.com/brumbelow/layerleak/v3'


@unittest.skipIf(shutil.which('go') is None, 'the go command is not installed')
class GoModuleScopeTests(unittest.TestCase):
    """npm packages installed for the browser tests must stay outside ./...

    Some npm packages ship Go sources without a go.mod. Without an ignore
    directive, `go vet ./...`, golangci-lint, `go test ./...` and govulncheck
    would build and lint that third-party code as part of layerleak.
    """

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = pathlib.Path(directory.name)
        shutil.copyfile(ROOT / 'go.mod', self.root / 'go.mod')
        self.write('internal/firstparty/firstparty.go', 'package firstparty\n')
        self.write('scripts/tests/node_modules/vendored/golang/pkg/vendored/vendored.go', 'package vendored\n')

    def write(self, name, text):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding='utf-8')

    def list_packages(self):
        env = dict(os.environ, GOFLAGS='-mod=mod', GOPROXY='off', GOWORK='off')
        completed = subprocess.run(
            ['go', 'list', './...'],
            cwd=self.root,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        return completed.stdout.split()

    def test_node_modules_go_sources_are_outside_the_module_pattern(self):
        self.assertEqual(self.list_packages(), [f'{MODULE_PATH}/internal/firstparty'])


if __name__ == '__main__':
    unittest.main()
