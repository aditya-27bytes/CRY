"""AST-based Taint and Dataflow Analysis for Python and JavaScript/TypeScript.

Traces variable flow from untrusted Sources (request.args, req.query, argv)
through assignments and sanitizers to dangerous Sinks (exec, eval, system, sql).
"""

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class TaintResult:
    """Outcome of taint analysis for a flagged code location."""

    is_tainted: bool
    confidence: float
    source: str | None = None
    sink: str | None = None
    sanitizer: str | None = None
    is_literal_constant: bool = False
    dataflow_chain: list[str] = field(default_factory=list)
    explanation: str = ""


# Known source identifiers
TAINTED_SOURCES: set[str] = {
    "request.args",
    "request.form",
    "request.values",
    "request.json",
    "request.get",
    "request.post",
    "req.args",
    "req.query",
    "req.params",
    "req.body",
    "req.headers",
    "req.get",
    "req.post",
    "sys.argv",
    "user_input",
    "raw_input",
}

# Known sanitization functions
SANITIZERS: set[str] = {
    "int",
    "float",
    "bool",
    "str.isalnum",
    "shlex.quote",
    "html.escape",
    "escape",
    "dompurify.sanitize",
    "encodeuricomponent",
    "validator.escape",
    "escape_string",
    "parameterized",
}


class PythonTaintVisitor(ast.NodeVisitor):
    """AST visitor to trace taint sources through variable assignments to sinks."""

    def __init__(self, target_line: int) -> None:
        self.target_line = target_line
        self.tainted_vars: dict[str, str] = {}  # var_name -> source_expr
        self.sanitized_vars: set[str] = set()
        self.sink_found: bool = False
        self.taint_result: TaintResult | None = None

    def visit_Assign(self, node: ast.Assign) -> None:
        """Track variable assignments."""
        value_repr = ast.unparse(node.value) if hasattr(ast, "unparse") else ""
        is_src = any(src in value_repr.lower() for src in TAINTED_SOURCES)

        # Check if value passed through a sanitizer
        is_san = any(san in value_repr.lower() for san in SANITIZERS)

        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id
                if is_san:
                    self.sanitized_vars.add(var_name)
                    if var_name in self.tainted_vars:
                        del self.tainted_vars[var_name]
                elif is_src:
                    self.tainted_vars[var_name] = value_repr
                else:
                    # Propagate taint if right-hand side uses an already tainted variable
                    for t_var, t_src in list(self.tainted_vars.items()):
                        if re.search(rf"\b{re.escape(t_var)}\b", value_repr):
                            self.tainted_vars[var_name] = f"{t_var} (from {t_src})"
                            break

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        """Inspect calls at the target line."""
        if getattr(node, "lineno", None) == self.target_line:
            call_name = ast.unparse(node.func) if hasattr(ast, "unparse") else ""
            args_repr = [ast.unparse(a) for a in node.args] if hasattr(ast, "unparse") else []

            # Check if all arguments are pure literal constants
            all_constants = all(isinstance(a, ast.Constant) for a in node.args)
            if all_constants and node.args:
                self.taint_result = TaintResult(
                    is_tainted=False,
                    confidence=0.15,
                    is_literal_constant=True,
                    sink=call_name,
                    explanation="Arguments are static string/number literals with no variable concatenation.",
                )
                return

            # Check if arguments use sanitized variables
            for arg_str in args_repr:
                for san_var in self.sanitized_vars:
                    if re.search(rf"\b{re.escape(san_var)}\b", arg_str):
                        self.taint_result = TaintResult(
                            is_tainted=False,
                            confidence=0.20,
                            sanitizer=san_var,
                            sink=call_name,
                            explanation=f"Argument is sanitized via {san_var}.",
                        )
                        return

            # Check if arguments use tainted variables or direct sources
            for arg_str in args_repr:
                for t_var, t_src in self.tainted_vars.items():
                    if re.search(rf"\b{re.escape(t_var)}\b", arg_str):
                        self.taint_result = TaintResult(
                            is_tainted=True,
                            confidence=0.98,
                            source=t_src,
                            sink=call_name,
                            dataflow_chain=[t_src, f"{t_var} -> {call_name}"],
                            explanation=f"Untrusted input from '{t_src}' flows directly into sink '{call_name}'.",
                        )
                        return

                for src in TAINTED_SOURCES:
                    if src in arg_str.lower():
                        self.taint_result = TaintResult(
                            is_tainted=True,
                            confidence=0.99,
                            source=src,
                            sink=call_name,
                            dataflow_chain=[src, call_name],
                            explanation=f"Untrusted source '{src}' is passed directly to sink '{call_name}'.",
                        )
                        return

        self.generic_visit(node)


def analyze_taint_in_python(file_path: Path, target_line: int) -> TaintResult | None:
    """Analyze Python file AST to verify taint flow at target_line."""
    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
        tree = ast.parse(content)
        visitor = PythonTaintVisitor(target_line)
        visitor.visit(tree)
        return visitor.taint_result
    except Exception:
        return None


def analyze_taint_in_javascript(content: str, target_line: int) -> TaintResult | None:
    """Regex-structural dataflow analysis for JS/TS route handlers and sinks."""
    lines = content.splitlines()
    if target_line < 1 or target_line > len(lines):
        return None

    target_content = lines[target_line - 1]

    # Look back up to 20 lines to find variable source assignments
    start_idx = max(0, target_line - 20)
    preceding_lines = lines[start_idx : target_line - 1]

    tainted_map: dict[str, str] = {}
    sanitized_vars: set[str] = set()

    for p_line in preceding_lines:
        line_clean = p_line.strip()
        # Look for: const x = req.query.y
        m = re.search(
            r"(?:const|let|var)\s+([a-zA-Z0-9_$]+)\s*=\s*(req\.(?:query|params|body)[a-zA-Z0-9_$.?\[\]]*)",
            line_clean,
        )
        if m:
            tainted_map[m.group(1)] = m.group(2)

        # Look for sanitization e.g. DOMPurify.sanitize, parseInt, validator
        m_san = re.search(
            r"(?:const|let|var)\s+([a-zA-Z0-9_$]+)\s*=\s*(?:DOMPurify\.sanitize|parseInt|Number|encodeURIComponent)\s*\(",
            line_clean,
        )
        if m_san:
            sanitized_vars.add(m_san.group(1))

    # Check if target line uses a sanitized variable
    for s_var in sanitized_vars:
        if re.search(rf"\b{re.escape(s_var)}\b", target_content):
            return TaintResult(
                is_tainted=False,
                confidence=0.25,
                sanitizer=s_var,
                explanation=f"JavaScript/TypeScript variable '{s_var}' was sanitized before execution.",
            )

    # Check if target line uses tainted variable
    for t_var, t_src in tainted_map.items():
        if re.search(rf"\b{re.escape(t_var)}\b", target_content):
            return TaintResult(
                is_tainted=True,
                confidence=0.96,
                source=t_src,
                dataflow_chain=[t_src, f"{t_var} -> line {target_line}"],
                explanation=f"Untrusted request parameter '{t_src}' flows into '{t_var}' on line {target_line}.",
            )

    # Check for direct req.query / req.params on the target line itself
    m_direct = re.search(r"(req\.(?:query|params|body)(?:\.[a-zA-Z0-9_$]+)?)", target_content)
    if m_direct:
        return TaintResult(
            is_tainted=True,
            confidence=0.98,
            source=m_direct.group(1),
            dataflow_chain=[m_direct.group(1), f"sink at line {target_line}"],
            explanation=f"Direct usage of unvalidated '{m_direct.group(1)}' at sink.",
        )

    return None
