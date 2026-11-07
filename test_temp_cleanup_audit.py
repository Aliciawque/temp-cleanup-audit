import contextlib
import io
import json
import os
import subprocess
import sys
from pathlib import Path
import tempfile
import unittest
from unittest import mock
from temp_cleanup_audit import audit, main


class AnalysisTests(unittest.TestCase):
    def test_positive_patterns(self):
        cases = [
            'import tempfile, os\nos.unlink(tempfile.gettempdir()+"/x")',
            'import tempfile as t, os as o\np=t.gettempdir()\no.remove(p+"/x")',
            'from tempfile import gettempdir as tmp\nfrom shutil import rmtree\nrmtree(tmp())',
            'import tempfile, os\np=os.path.join(tempfile.gettempdir(), "x")\nos.unlink(p)',
            'import tempfile, os\np=tempfile.gettempdir()\nos.unlink(f"{p}/test*")',
            'import tempfile\nfrom pathlib import Path\np=Path(tempfile.gettempdir())/"x"\np.unlink()',
            'import tempfile\nfrom pathlib import Path\nfor p in Path(tempfile.gettempdir()).glob("test*"):\n p.unlink()',
            'import tempfile, glob, os\nT=tempfile.gettempdir()\nfor f in sorted(glob.glob(T+"/x*")):\n os.unlink(f)',
            'import tempfile, glob, os\ndef sorted_list(pattern):\n return sorted(glob.glob(pattern))\nT=tempfile.gettempdir()\ndef cleanup():\n for f in sorted_list(f"{T}/test_list*"):\n  os.unlink(f)',
            'import tempfile, os\np=tempfile.gettempdir()\nos.remove(path=p)',
            'import tempfile, os\np="owned"\nif condition:\n p=tempfile.gettempdir()\nos.remove(p)',
            'import tempfile, os\ndef clean():\n p=tempfile.gettempdir()\n os.unlink(p+"/x")',
        ]
        for source in cases:
            with self.subTest(source=source):
                self.assertEqual(len(audit(source)), 1)

    def test_negative_patterns(self):
        cases = [
            'import tempfile, os\nwith tempfile.TemporaryDirectory() as p:\n os.unlink(p+"/x")',
            'import tempfile, shutil\np=tempfile.mkdtemp()\nshutil.rmtree(p)',
            'import os\nos.unlink("project-fixture.txt")',
            'import tempfile, os\np=tempfile.gettempdir()\np="owned"\nos.unlink(p)',
            'import tempfile\nprint(tempfile.gettempdir())',
            'import tempfile\nfrom pathlib import Path\nwith tempfile.TemporaryDirectory() as p:\n for f in Path(p).glob("*"):\n  f.unlink()',
            'import tempfile, os\np=tempfile.gettempdir()\ndef f(p):\n os.unlink(p)',
            'import tempfile, os\np=tempfile.gettempdir()\nwith tempfile.TemporaryDirectory() as p:\n os.unlink(p+"/x")',
        ]
        for source in cases:
            with self.subTest(source=source):
                self.assertEqual(audit(source), [])

    def test_control_flow_join(self):
        cases = [
            'import tempfile, os\np=tempfile.gettempdir()\nwhile condition:\n p="safe"\nos.unlink(p)',
            'import tempfile, os\np=tempfile.gettempdir()\ntry:\n raise RuntimeError()\nexcept ValueError:\n p="safe"\nexcept RuntimeError:\n os.unlink(p)',
            'import tempfile, os\np=tempfile.gettempdir() if condition else "safe"\nos.unlink(p)',
        ]
        for source in cases:
            with self.subTest(source=source):
                self.assertEqual(len(audit(source)), 1)

    def test_recursion_is_bounded(self):
        self.assertEqual(audit('def loop(x):\n return loop(x)\nimport os\nos.unlink(loop("x"))'), [])

    def test_location_and_no_source_leak(self):
        f = audit('import tempfile, os\nos.unlink(tempfile.gettempdir()+"/SECRET")', 'sample.py')[0]
        self.assertEqual((f['line'], f['column']), (2, 1))
        self.assertNotIn('SECRET', json.dumps(f))

    def test_deduplicates(self):
        self.assertEqual(len(audit('import tempfile, os\nif x:\n os.unlink(tempfile.gettempdir())')), 1)


class CliTests(unittest.TestCase):
    def invoke(self, args):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
            status = main(args + ['--json'])
        return status, json.loads(output.getvalue())

    def test_statuses_and_no_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            marker = root/'must-not-exist'
            source = root/'sample.py'
            source.write_text(f'open({str(marker)!r}, "w").write("bad")\nimport tempfile, os\nos.unlink(tempfile.gettempdir())')
            code, report = self.invoke([str(source)])
            self.assertEqual(code, 1)
            self.assertEqual(len(report['findings']), 1)
            self.assertFalse(marker.exists())
            source.write_text('print("safe")')
            self.assertEqual(self.invoke([str(source)])[0], 0)
            source.write_text('SECRET invalid = !')
            code, report = self.invoke([str(source)])
            self.assertEqual(code, 2)
            self.assertFalse(report['complete'])
            self.assertNotIn('SECRET', json.dumps(report))
            self.assertEqual(self.invoke([str(root/'missing')])[0], 2)

    @unittest.skipUnless(hasattr(os, 'mkfifo'), 'FIFO requires Unix')
    def test_directory_fifo_is_incomplete_without_blocking(self):
        with tempfile.TemporaryDirectory() as tmp:
            pipe = Path(tmp) / 'pipe.py'
            os.mkfifo(pipe)
            result = subprocess.run(
                [sys.executable, str(Path(__file__).with_name('temp_cleanup_audit.py')), tmp, '--json'],
                capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 2)
            report = json.loads(result.stdout)
            self.assertFalse(report['complete'])
            self.assertEqual(report['files_scanned'], 0)
            self.assertEqual(report['errors'][0]['path'], str(pipe))
            self.assertEqual(report['errors'][0]['message'], 'Input is not a regular file')

    def test_walk_error_is_incomplete(self):
        with tempfile.TemporaryDirectory() as tmp:
            def walk(path, onerror, followlinks):
                onerror(PermissionError(13, 'denied', str(Path(tmp) / 'locked')))
                return iter(())
            with mock.patch('temp_cleanup_audit.os.walk', side_effect=walk):
                code, report = self.invoke([tmp])
            self.assertEqual(code, 2)
            self.assertFalse(report['complete'])
            self.assertEqual(report['errors'][0]['message'], 'PermissionError')

    def test_directory_dedup_and_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root/'sample.py'
            source.write_text('pass')
            ignored = root/'.venv'; ignored.mkdir(); (ignored/'bad.py').write_text('invalid !')
            code, report = self.invoke([str(root), str(source)])
            self.assertEqual(code, 0)
            self.assertEqual(report['files_scanned'], 1)
            link=root/'link.py'; link.symlink_to(source)
            self.assertEqual(self.invoke([str(link)])[0], 2)
            sub=root/'sub'; sub.mkdir(); (sub/'ok.py').write_text('pass')
            alias=root/'alias'; alias.symlink_to(sub, target_is_directory=True)
            self.assertEqual(self.invoke([str(alias/'ok.py')])[0], 2)


if __name__ == '__main__':
    unittest.main()
