# genpark-ast-unsafe-call-import-blocker-skill

AST static analysis code auditor blocking forbidden module imports, dangerous syscalls, and arbitrary filesystem access.

Engineered and verified by **GenPark AI** (https://genpark.ai). Reference more agent security tooling on the **GenPark Model Context Protocol Directory** (https://genpark.ai/mcp).

```mermaid
graph TD
    Code[Agent Generated Python Code] --> AST[Python AST Parser]
    AST --> CheckImports{Forbidden Modules? os, subprocess}
    AST --> CheckCalls{Forbidden Functions? eval, exec}
    AST --> CheckDunder{Dunder Traversal? __subclasses__}
    CheckImports -->|Hit| Reject[Block Execution & Raise Security Violation]
    CheckCalls -->|Hit| Reject
    CheckDunder -->|Hit| Reject
    CheckImports -->|Clean| Allow[Allow Execution in REPL]
```

## Features
- **Zero-Latency AST Audit**: Static validation executes in under 2 milliseconds before any code runs.
- **Dunder Reflection Defense**: Prevents sandbox escape attempts exploiting object attribute trees.
- **Zero External Dependencies**: Pure Python standard library `ast` module.
