"""Context Graph builder: extracts structural scope, security middleware, and AST dataflow."""

import ast
import re
from dataclasses import dataclass
from pathlib import Path

from cry.scanners.taint import TaintResult, analyze_taint_in_javascript, analyze_taint_in_python


@dataclass
class ContextGraph:
    """Enriched code context graph for an individual finding."""

    file_path: str
    target_line: int
    enclosing_function: str | None = None
    route_decorator: str | None = None
    security_imports: list[str] | None = None
    taint_analysis: TaintResult | None = None

    def format_for_llm_prompt(self) -> str:
        """Format the structural context graph into a concise section for the LLM."""
        sections = []
        if self.enclosing_function:
            sections.append(f"Function Scope: {self.enclosing_function}")
        if self.route_decorator:
            sections.append(f"Route/Endpoint: {self.route_decorator}")
        if self.security_imports:
            sections.append(f"Security Libraries Present: {', '.join(self.security_imports)}")
        if self.taint_analysis:
            if self.taint_analysis.is_tainted:
                chain = " -> ".join(self.taint_analysis.dataflow_chain) or "Direct"
                sections.append(
                    f"AST Dataflow (CONFIRMED TAINT, confidence={self.taint_analysis.confidence:.2f}): {chain}"
                )
            elif self.taint_analysis.is_literal_constant:
                sections.append(
                    f"AST Dataflow (BENIGN CONSTANT, confidence={self.taint_analysis.confidence:.2f}): {self.taint_analysis.explanation}"
                )
            elif self.taint_analysis.sanitizer:
                sections.append(
                    f"AST Dataflow (SANITIZED, confidence={self.taint_analysis.confidence:.2f}): {self.taint_analysis.explanation}"
                )

        return "\n".join(sections) if sections else "No special AST graph available."


def build_context_graph(
    base_dir: Path, file_path_str: str | None, line_num: int | None
) -> ContextGraph:
    """Analyze the file around line_num to construct a structural ContextGraph."""
    if not file_path_str or line_num is None:
        return ContextGraph(file_path=file_path_str or "", target_line=line_num or 0)

    p = Path(file_path_str)
    full_path = p if p.is_absolute() else base_dir / p
    if not full_path.is_file():
        return ContextGraph(file_path=file_path_str, target_line=line_num)

    ext = full_path.suffix.lower()
    try:
        content = full_path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ContextGraph(file_path=file_path_str, target_line=line_num)

    graph = ContextGraph(file_path=file_path_str, target_line=line_num)

    # 1. Detect Security Imports
    sec_libs = []
    for pattern in (
        "dompurify",
        "helmet",
        "csurf",
        "bcrypt",
        "argon2",
        "shlex",
        "secrets",
        "validator",
    ):
        if pattern in content.lower():
            sec_libs.append(pattern)
    if sec_libs:
        graph.security_imports = sec_libs

    # 2. Python AST extraction
    if ext == ".py":
        graph.taint_analysis = analyze_taint_in_python(full_path, line_num)
        try:
            tree = ast.parse(content)
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    start = getattr(node, "lineno", 0)
                    end = getattr(node, "end_lineno", start + 20)
                    if start <= line_num <= end:
                        graph.enclosing_function = f"def {node.name}({ast.unparse(node.args) if hasattr(ast, 'unparse') else '...'})"
                        if node.decorator_list:
                            decs = [
                                ast.unparse(d)
                                for d in node.decorator_list
                                if hasattr(ast, "unparse")
                            ]
                            graph.route_decorator = ", ".join(decs)
                        break
        except Exception:
            pass

    # 3. JavaScript / TypeScript analysis
    elif ext in {".ts", ".tsx", ".js", ".jsx"}:
        graph.taint_analysis = analyze_taint_in_javascript(content, line_num)
        lines = content.splitlines()
        # Find enclosing function
        for i in range(max(0, line_num - 25), line_num):
            line = lines[i].strip()
            if re.search(
                r"(?:function\s+([a-zA-Z0-9_$]+)|(?:export\s+)?const\s+([a-zA-Z0-9_$]+)\s*=\s*(?:async\s*)?\()",
                line,
            ):
                graph.enclosing_function = line
            if re.search(r"(?:app|router)\.(?:get|post|put|delete|use)\s*\(", line):
                graph.route_decorator = line

    return graph
