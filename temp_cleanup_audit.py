"""Read-only, bounded AST audit of cleanup derived from a shared temp root."""
import argparse
import ast
import json
import os
from pathlib import Path
import sys
import tokenize

VERSION = '0.1.0'
SHARED = 'shared-temp'


class Analyzer:
    def __init__(self, tree, filename):
        self.tree, self.filename = tree, filename
        self.aliases = {}
        self.functions = {n.name: n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
        self.findings = {}
        for n in tree.body:
            if isinstance(n, ast.Import):
                for a in n.names:
                    self.aliases[a.asname or a.name] = a.name
            elif isinstance(n, ast.ImportFrom) and n.module:
                for a in n.names:
                    self.aliases[a.asname or a.name] = n.module + '.' + a.name

    def name(self, node):
        if isinstance(node, ast.Name):
            return self.aliases.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            return self.name(node.value) + '.' + node.attr
        return ''

    def value(self, node, env, depth=0):
        if node is None or depth > 8:
            return False
        if isinstance(node, ast.Name):
            return env.get(node.id, False)
        if isinstance(node, ast.Call):
            name = self.name(node.func)
            if name in ('tempfile.gettempdir', 'tempfile.gettempdirb'):
                return True
            if name in ('tempfile.mkdtemp', 'tempfile.mkstemp', 'tempfile.TemporaryDirectory', 'tempfile.NamedTemporaryFile'):
                return False
            args = [self.value(x, env, depth + 1) for x in node.args]
            if name in ('os.path.join', 'os.path.abspath', 'os.path.realpath', 'os.path.normpath', 'pathlib.Path', 'Path', 'str', 'bytes', 'glob.glob', 'glob.iglob', 'sorted', 'list', 'iter', 'tuple'):
                return any(args)
            if isinstance(node.func, ast.Attribute) and node.func.attr in ('glob', 'rglob', 'iterdir', 'joinpath', 'resolve', 'absolute'):
                return self.value(node.func.value, env, depth + 1)
            fn = self.functions.get(name)
            if fn:
                local = dict(env)
                params = fn.args.posonlyargs + fn.args.args
                for p, arg in zip(params, args):
                    local[p.arg] = arg
                for kw in node.keywords:
                    if kw.arg:
                        local[kw.arg] = self.value(kw.value, env, depth + 1)
                # Only simple, direct returns are summarized. No target code runs.
                return any(self.value(s.value, local, depth + 1) for s in fn.body if isinstance(s, ast.Return))
            return False
        if isinstance(node, (ast.BinOp, ast.JoinedStr, ast.FormattedValue, ast.Subscript, ast.IfExp)):
            return any(self.value(x, env, depth + 1) for x in ast.iter_child_nodes(node))
        return False

    def inspect(self, node, env):
        if isinstance(node, ast.Call):
            name = self.name(node.func)
            target = None
            if name in ('os.unlink', 'os.remove', 'os.rmdir', 'shutil.rmtree'):
                target = node.args[0] if node.args else next((k.value for k in node.keywords if k.arg in ('path', 'filename')), None)
            elif isinstance(node.func, ast.Attribute) and node.func.attr in ('unlink', 'rmdir'):
                target = node.func.value
            if target is not None and self.value(target, env):
                key = (node.lineno, node.col_offset)
                self.findings[key] = dict(path=self.filename, line=node.lineno, column=node.col_offset + 1,
                    rule='TCA001', message='Deletion derives from the shared tempfile root; verify exclusive ownership or use TemporaryDirectory.')
        for child in ast.iter_child_nodes(node):
            self.inspect(child, env)

    @staticmethod
    def bind(target, value, env):
        if isinstance(target, ast.Name):
            env[target.id] = value
        elif isinstance(target, (ast.Tuple, ast.List)):
            for n in target.elts:
                Analyzer.bind(n, value, env)

    def block(self, statements, env):
        for n in statements:
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            if isinstance(n, (ast.Assign, ast.AnnAssign)):
                self.inspect(n.value, env) if n.value else None
                value = self.value(n.value, env)
                for t in n.targets if isinstance(n, ast.Assign) else [n.target]:
                    self.bind(t, value, env)
            elif isinstance(n, (ast.For, ast.AsyncFor)):
                self.inspect(n.iter, env)
                local = dict(env)
                self.bind(n.target, self.value(n.iter, env), local)
                self.block(n.body, local)
                self.block(n.orelse, local)
                for k, v in local.items():
                    env[k] = env.get(k, False) or v
            elif isinstance(n, (ast.With, ast.AsyncWith)):
                local = dict(env)
                for item in n.items:
                    self.inspect(item.context_expr, env)
                    self.bind(item.optional_vars, self.value(item.context_expr, env), local)
                self.block(n.body, local)
                env.update(local)
            elif isinstance(n, ast.If):
                self.inspect(n.test, env)
                left, right = dict(env), dict(env)
                self.block(n.body, left)
                self.block(n.orelse, right)
                for k in left.keys() | right.keys():
                    env[k] = left.get(k, False) or right.get(k, False)
            elif isinstance(n, (ast.Try, ast.TryStar)):
                start = dict(env)
                normal = self.block(n.body, dict(start))
                normal = self.block(n.orelse, normal)
                # An exception may happen before or after any assignment.
                exception = {k: start.get(k, False) or normal.get(k, False)
                             for k in start.keys() | normal.keys()}
                branches = [normal, exception]
                for handler in n.handlers:
                    branches.append(self.block(handler.body, dict(exception)))
                for branch in branches:
                    for key, value in branch.items():
                        env[key] = env.get(key, False) or value
                self.block(n.finalbody, env)
            elif isinstance(n, ast.While):
                self.inspect(n.test, env)
                after = self.block(n.body, dict(env))
                # Keep the zero-iteration path as well as the body path.
                for key, value in after.items():
                    env[key] = env.get(key, False) or value
                self.block(n.orelse, env)
            else:
                self.inspect(n, env)
        return env

    def run(self):
        globals_ = self.block(self.tree.body, {})
        for fn in self.functions.values():
            env = dict(globals_)
            for p in fn.args.posonlyargs + fn.args.args + fn.args.kwonlyargs:
                env[p.arg] = False
            self.block(fn.body, env)
        return [self.findings[k] for k in sorted(self.findings)]


def audit(source, filename='<string>'):
    return Analyzer(ast.parse(source, filename=filename), filename).run()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('paths', nargs='+', type=Path)
    parser.add_argument('--json', action='store_true', dest='as_json')
    args = parser.parse_args(argv)
    findings, errors, files = [], [], set()
    for path in args.paths:
        absolute = path.absolute()
        if any(part.is_symlink() for part in (absolute, *absolute.parents)):
            errors.append(dict(path=str(path), message='Symlink input or ancestor is not scanned'))
        elif path.is_dir():
            def walk_error(exc):
                errors.append(dict(path=exc.filename or str(path), message=type(exc).__name__))
            for directory, dirs, names in os.walk(path, onerror=walk_error, followlinks=False):
                dirs[:] = [name for name in dirs if name not in ('.git', '.venv', '__pycache__')
                           and not (Path(directory) / name).is_symlink()]
                for name in names:
                    candidate = Path(directory) / name
                    if not name.endswith('.py') or candidate.is_symlink():
                        continue
                    if candidate.is_file():
                        files.add(candidate)
                    else:
                        errors.append(dict(path=str(candidate), message='Input is not a regular file'))
        elif path.is_file():
            files.add(path)
        else:
            errors.append(dict(path=str(path), message='Input does not exist or is not a regular file'))
    for path in sorted(files):
        try:
            with tokenize.open(path) as handle:
                findings.extend(audit(handle.read(), str(path)))
        except (OSError, UnicodeError, SyntaxError, ValueError, RecursionError) as exc:
            # Do not echo source text from SyntaxError; it may contain secrets.
            errors.append(dict(path=str(path), message=type(exc).__name__))
    result = dict(version=VERSION, files_scanned=len(files), findings=findings, errors=errors,
                  complete=not errors)
    if args.as_json:
        print(json.dumps(result, indent=2))
    else:
        for f in findings:
            print(f"{f['path']}:{f['line']}:{f['column']}: {f['rule']} {f['message']}")
        for e in errors:
            print(f"{e['path']}: {e['message']}", file=sys.stderr)
        print(f'{len(files)} files; {len(findings)} findings; {len(errors)} errors')
    return 2 if errors else 1 if findings else 0


if __name__ == '__main__':
    sys.exit(main())
