import argparse
import ast
import os
import sys
from pathlib import Path


SKIP_DIR_NAMES = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "env",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    ".mypy_cache",
    ".tox",
    ".nox",
    "node_modules",
}

MAX_FILE_BYTES = 1024 * 1024
REQUESTS_METHODS = {"get", "post", "put", "patch", "delete", "head", "options", "request"}
LEAK_KEYWORDS = ("credential", "api_key", "apikey", "secret", "token", "password", "passwd")
LOGGER_METHODS = {"debug", "info", "warning", "warn", "error", "exception", "critical", "log"}
MAX_WARNINGS = 100


def relative_path(path: Path, base: Path) -> str:
    return path.relative_to(base).as_posix()


def should_scan_file(path: Path) -> bool:
    if path.suffix != ".py":
        return False
    try:
        return path.stat().st_size <= MAX_FILE_BYTES
    except OSError:
        return False


def dotted_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = dotted_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return ""


def source_snippet(source: str, node: ast.AST) -> str:
    snippet = ast.get_source_segment(source, node) or ""
    return " ".join(snippet.strip().split())[:180]


def contains_leak_keyword(value: str) -> bool:
    normalized = value.lower()
    return any(keyword in normalized for keyword in LEAK_KEYWORDS)


def expression_contains_secret_value(node: ast.AST) -> bool:
    if isinstance(node, ast.Name):
        return contains_leak_keyword(node.id)
    if isinstance(node, ast.Attribute):
        return contains_leak_keyword(node.attr) or expression_contains_secret_value(node.value)
    if isinstance(node, ast.Call):
        return any(expression_contains_secret_value(arg) for arg in node.args) or any(
            expression_contains_secret_value(keyword.value) for keyword in node.keywords
        )
    if isinstance(node, ast.keyword):
        return expression_contains_secret_value(node.value)

    return any(expression_contains_secret_value(child) for child in ast.iter_child_nodes(node))


def node_text_contains_secret(node: ast.AST) -> bool:
    return expression_contains_secret_value(node)


def has_timeout_keyword(node: ast.Call) -> bool:
    return any(keyword.arg == "timeout" for keyword in node.keywords)


def is_logging_call(node: ast.Call) -> bool:
    if not isinstance(node.func, ast.Attribute):
        return False
    if node.func.attr not in LOGGER_METHODS:
        return False
    target = dotted_name(node.func.value).lower()
    return target in {"logging", "logger", "log"} or target.endswith(".logger") or target.endswith(".log")


def is_exception_raise(node: ast.Raise) -> bool:
    return node.exc is not None


class SafetyVisitor(ast.NodeVisitor):
    def __init__(self, source: str, rel_path: str) -> None:
        self.source = source
        self.rel_path = rel_path
        self.warnings: list[str] = []
        self.requests_modules = {"requests"}
        self.requests_functions: set[str] = set()

    def add_warning(self, line_number: int, message: str, node: ast.AST) -> None:
        snippet = source_snippet(self.source, node)
        detail = f"{self.rel_path}:{line_number}: {message}"
        if snippet:
            detail = f"{detail}: {snippet}"
        self.warnings.append(detail)

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            if alias.name == "requests":
                self.requests_modules.add(alias.asname or alias.name)

        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module == "requests":
            for alias in node.names:
                if alias.name in REQUESTS_METHODS:
                    self.requests_functions.add(alias.asname or alias.name)

        self.generic_visit(node)

    def is_requests_call(self, node: ast.Call) -> bool:
        if isinstance(node.func, ast.Attribute):
            return dotted_name(node.func.value) in self.requests_modules and node.func.attr in REQUESTS_METHODS
        if isinstance(node.func, ast.Name):
            return node.func.id in self.requests_functions
        return False

    def visit_Call(self, node: ast.Call) -> None:
        if self.is_requests_call(node) and not has_timeout_keyword(node):
            self.add_warning(node.lineno, "requests call may be missing timeout", node)

        if is_logging_call(node) and node_text_contains_secret(node):
            self.add_warning(node.lineno, "log call may expose credential-like values", node)

        self.generic_visit(node)

    def visit_Raise(self, node: ast.Raise) -> None:
        if is_exception_raise(node) and node_text_contains_secret(node):
            self.add_warning(node.lineno, "raised exception may expose credential-like values", node)

        self.generic_visit(node)

    def visit_Return(self, node: ast.Return) -> None:
        if node.value is not None and node_text_contains_secret(node.value):
            self.add_warning(node.lineno, "return value may expose credential-like values", node)

        self.generic_visit(node)

    def visit_Yield(self, node: ast.Yield) -> None:
        if node.value is not None and node_text_contains_secret(node.value):
            self.add_warning(node.lineno, "yield value may expose credential-like values", node)

        self.generic_visit(node)


def scan_file(path: Path, base: Path) -> list[str]:
    try:
        source = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        source = path.read_text(encoding="utf-8", errors="ignore")

    rel_path = relative_path(path, base)
    try:
        tree = ast.parse(source, filename=rel_path)
    except SyntaxError as err:
        return [f"{rel_path}:{err.lineno or 1}: could not parse Python file for safety warnings: {err.msg}"]

    visitor = SafetyVisitor(source, rel_path)
    visitor.visit(tree)
    return visitor.warnings


def scan_package(directory: Path) -> list[str]:
    warnings: list[str] = []

    for root, dirs, files in os.walk(directory):
        dirs[:] = [dirname for dirname in dirs if dirname not in SKIP_DIR_NAMES]
        root_path = Path(root)

        for filename in files:
            path = root_path / filename
            if not should_scan_file(path):
                continue
            warnings.extend(scan_file(path, directory))
            if len(warnings) >= MAX_WARNINGS:
                warnings.append(f"warning limit reached; showing first {MAX_WARNINGS} Python safety warnings")
                return warnings[: MAX_WARNINGS + 1]

    return warnings


def write_report(path: str | None, lines: list[str]) -> None:
    if not path:
        return
    with open(path, "w", encoding="utf-8") as f:
        for line in lines:
            f.write(line + "\n")


def print_report(title: str, lines: list[str]) -> None:
    if not lines:
        return
    print(title)
    for line in lines:
        print(f"- {line}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Warn about Python network timeout and credential leak patterns.")
    parser.add_argument("-d", "--directory", required=True, help="The unpacked plugin package directory")
    parser.add_argument("--warning-file", help="Optional file path for review warnings")
    args = parser.parse_args()

    directory = Path(args.directory)
    if not directory.is_dir():
        print(f"Package directory not found: {directory}")
        sys.exit(1)

    warnings = scan_package(directory)
    write_report(args.warning_file, warnings)
    print_report("Python safety warnings:", warnings)
    print("Python safety warning check passed")


if __name__ == "__main__":
    main()
