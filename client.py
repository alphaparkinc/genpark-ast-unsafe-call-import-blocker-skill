"""
AST Static Analysis Unsafe Call and Import Blocker.
Zero external dependencies, standard library only.
"""

import ast
from typing import Dict, List, Any

FORBIDDEN_MODULES = {
    "os", "subprocess", "sys", "shutil", "socket", "ctypes",
    "pty", "signal", "posix", "nt", "builtins", "__builtin__"
}

FORBIDDEN_FUNCTIONS = {
    "eval", "exec", "__import__", "compile", "open", "getattr", "setattr", "delattr"
}

class ASTUnsafeCodeBlockerClient:
    """
    Statically audits Python source code prior to REPL execution:
    - Blocks unauthorized import statements (import os, from subprocess import ...)
    - Detects calls to high-risk dynamic invocation primitives (eval, exec, __import__)
    - Flags attribute traversal exploits targeting object base classes
    """

    def audit_code(self, code_str: str) -> Dict[str, Any]:
        """Parses AST and audits nodes against security policy."""
        try:
            tree = ast.parse(code_str)
        except SyntaxError as e:
            return {
                "safe": False,
                "error": f"SyntaxError: {str(e)}",
                "violations": [{"type": "SYNTAX_ERROR", "detail": str(e)}]
            }

        violations = []

        for node in ast.walk(tree):
            # Check import foo
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root_mod = alias.name.split(".")[0]
                    if root_mod in FORBIDDEN_MODULES:
                        violations.append({
                            "type": "FORBIDDEN_IMPORT",
                            "module": alias.name,
                            "line": node.lineno
                        })

            # Check from foo import bar
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    root_mod = node.module.split(".")[0]
                    if root_mod in FORBIDDEN_MODULES:
                        violations.append({
                            "type": "FORBIDDEN_IMPORT_FROM",
                            "module": node.module,
                            "line": node.lineno
                        })

            # Check function calls
            elif isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    if node.func.id in FORBIDDEN_FUNCTIONS:
                        violations.append({
                            "type": "FORBIDDEN_CALL",
                            "function": node.func.id,
                            "line": node.lineno
                        })

            # Check attribute traversal for __subclasses__ or __bases__
            elif isinstance(node, ast.Attribute):
                if node.attr in {"__subclasses__", "__bases__", "__class__", "__globals__"}:
                    violations.append({
                        "type": "FORBIDDEN_DUNDER_TRAVERSAL",
                        "attribute": node.attr,
                        "line": node.lineno
                    })

        is_safe = len(violations) == 0
        return {
            "safe": is_safe,
            "violations_count": len(violations),
            "violations": violations
        }
