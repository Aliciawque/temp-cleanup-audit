# temp-cleanup-audit

A small, offline Python source audit for cleanup derived from the **shared system temporary directory**. It finds patterns such as `glob(gettempdir() + '/test*')` followed by `unlink`, where a test can delete another invocation's files or unrelated files with the same prefix.

It reads source with Python's AST. It does **not** import or execute scanned code, delete files, make network requests, or repair anything. Findings are review prompts, not proof of a vulnerability or a complete security assessment.

## Run

Python **3.11+**, standard library only; no installation required.

```sh
python temp_cleanup_audit.py path/to/tests
python temp_cleanup_audit.py path/to/tests --json
python -m unittest -v
```

Exit status: **0** no findings in supported patterns; **1** findings; **2** input/read/parse errors (possibly alongside findings). `complete` in JSON means all selected input files were readable and parsable, **not** that all possible program behaviors were analyzed. Directories scan `.py` files, excluding `.git`, `.venv`, and `__pycache__`; symlink files are skipped during directory scans, and explicit symlink inputs produce an error. Directory traversal does not follow symlink directories. Explicit inputs with a symlink component (including ancestors) are rejected. These checks are not race-proof and are not a filesystem sandbox. Directory traversal errors are reported as incomplete scans.

Reports contain filename, line, column, rule, and a fixed explanation. They do not include source snippets or target path values. Filenames can still be sensitive; review reports before sharing.

## Example

```python
import glob
import os
import tempfile

root = tempfile.gettempdir()
for item in glob.glob(f"{root}/test_output*"):
    os.unlink(item)  # TCA001: no exclusive ownership established
```

Use a per-invocation directory when that matches your lifecycle:

```python
import os
import tempfile

with tempfile.TemporaryDirectory(prefix="my-test-") as root:
    # Create and use this invocation's fixtures under root.
    pass
```

The auditor recognizes `TemporaryDirectory`, `mkdtemp`, `mkstemp`, and `NamedTemporaryFile` as fresh allocations. This does not certify subsequent code against path traversal, symlink races, or unsafe lifetime management.

## Rule TCA001

Tracks module imports/aliases and simple assignments from `tempfile.gettempdir()` or `gettempdirb()` into:

- `os.path.join`, normalized paths, string addition/f-strings, `pathlib.Path` and `/`;
- `glob.glob`, `iglob`, `Path.glob/rglob/iterdir`, and `sorted/list/tuple/iter` wrappers;
- loop bindings and basic branches/context managers;
- a bounded summary of top-level functions with direct return expressions (for example a `sorted(glob.glob(pattern))` wrapper).

Reports calls to `os.unlink/remove/rmdir`, `shutil.rmtree`, or path-object `unlink/rmdir` whose target remains derived from that shared root. It does not require a wildcard: deleting a fixed shared name can collide too.

## Limits and tradeoffs

This is a small heuristic, not a Python interpreter or a general taint engine. It can miss class/nested-function flows, dynamic dispatch, comprehensions, local imports, reassigned callable aliases, wrappers with intermediate assignments, hard-coded `/tmp`, `os.environ['TMPDIR']`, and cross-module/cross-function mutation. Call summaries stop after eight levels. Function parameters are unknown unless a simple return wrapper is used at a call site. Module globals are approximated from the module pass, not each call's exact time. Branch, zero-iteration loop, and exception environments use limited provenance joins. The analysis does not model `break`/`continue` or compute a cross-iteration fixed point, and cannot guarantee conservative control-flow coverage. A shared-root child that your program already owns can be flagged; ownership cannot be proved from a name. Absolute path resets (such as `os.path.join(gettempdir(), "/owned")`) and conditional-expression tests may also be over-reported because expression provenance is conservative. There is intentionally no suppression syntax or automatic fix in v0.1.0.

Run existing linters and tests as well. This tool does not replace Bandit, Semgrep, or filesystem isolation. Large or adversarial inputs can consume parser resources; scan trusted source checkouts within normal resource limits.

## Validation and origin

Original implementation inspired by the real cleanup defect in [LZ4 PR #2067](https://github.com/lz4/lz4/pull/2067). On the public LZ4 base `34a4e22ff226a96a7d8a73df57383fdd67828a50`, scanning `tests/cli/test-lz4-list.py` reports its line 211 deletion; on fixed head `c957d31ac9d9df6b386986be565a5b55bbfe2170`, it reports none. No LZ4 source is redistributed here.

The test suite contains nine test methods with 12 positive and eight negative source cases, three control-flow join cases, CLI status/error checks, non-execution checks, and symlink/dedup tests. Executed on Linux/Python 3.12. Windows/macOS and other Python versions have not been run; no hosted CI result is claimed.

Related work: [Bandit B108](https://bandit.readthedocs.io/en/latest/plugins/b108_hardcoded_tmp_directory.html) checks hard-coded temporary paths; [B306](https://bandit.readthedocs.io/en/latest/plugins/b306_mktemp_q.html) checks insecure `mktemp`; [Semgrep](https://semgrep.dev/docs/writing-rules/data-flow/taint-mode/overview) can express broader/custom data-flow rules. This project is a focused, dependency-free cleanup review utility, not a claim that no similar rules exist.

See [Python tempfile documentation](https://docs.python.org/3/library/tempfile.html) for supported lifecycle APIs.

## License

MIT. See LICENSE.
