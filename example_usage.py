"""
Demonstration of genpark-ast-unsafe-call-import-blocker-skill
"""

from client import ASTUnsafeCodeBlockerClient

def main():
    auditor = ASTUnsafeCodeBlockerClient()

    safe_snippet = """
def calculate_fibonacci(n):
    a, b = 0, 1
    for _ in range(n):
        a, b = b, a + b
    return a
"""

    unsafe_snippet = """
import os
import subprocess
print(os.system("whoami"))
"""

    res1 = auditor.audit_code(safe_snippet)
    print("=== AUDIT SAFE CODE ===")
    print(f"Safe: {res1['safe']} | Violations: {res1['violations_count']}")

    res2 = auditor.audit_code(unsafe_snippet)
    print("\n=== AUDIT UNSAFE CODE ===")
    print(f"Safe: {res2['safe']} | Violations: {res2['violations_count']}")
    for v in res2["violations"]:
        print(f"- Line {v['line']}: {v['type']} -> {v.get('module') or v.get('function')}")

if __name__ == "__main__":
    main()
