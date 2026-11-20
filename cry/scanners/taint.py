"""AST-based Taint and Dataflow Analysis for Python and JavaScript/TypeScript.

Traces variable flow from untrusted Sources (request.args, req.query, argv)
through assignments, concatenations, dicts/lists, and sanitizers to dangerous Sinks (exec, eval, system, sql, open).
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
    "request.args.get",
    "request.form",
    "request.form.get",
    "request.values",
    "request.values.get",
    "request.json",
    "request.get_json",
    "request.data",
    "request.params",
    "request.get",
    "request.post",
    "request.cookies",
    "request.headers",
    "req.args",
    "req.query",
    "req.params",
    "req.body",
    "req.headers",
    "req.cookies",
    "req.get",
    "req.post",
    "sys.argv",
    "user_input",
    "raw_input",
    "input",
}

# Known sanitization functions / transforms
SANITIZERS: set[str] = {
    "int",
    "float",
    "bool",
    "str.isalnum",
    "shlex.quote",
    "html.escape",
    "escape",
    "markupsafe.escape",
    "dompurify.sanitize",
    "encodeuricomponent",
    "validator.escape",
    "escape_string",
    "parameterized",
    "os.path.basename",
    "secure_filename",
    "pathlib.path.name",
}


class PythonTaintVisitor(ast.NodeVisitor):
    """AST visitor to trace taint sources through variable assignments to sinks."""

    def __init__(self, target_line: int) -> None:
        self.target_line = target_line
        self.tainted_vars: dict[str, str] = {}  # var_name -> source_expr
        self.sanitized_vars: set[str] = set()
        self.function_defs: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
        self.sink_found: bool = False
        self.taint_result: TaintResult | None = None

    def _is_source_expr(self, text: str) -> bool:
        t_low = text.lower()
        return any(src in t_low for src in TAINTED_SOURCES)

    def _is_sanitizer_expr(self, text: str) -> bool:
        t_low = text.lower()
        return any(san in t_low for san in SANITIZERS) or any(
            kw in t_low
            for kw in (
                "valid_url",
                "safe_url",
                "allowed_url",
                "allowlist",
                "whitelist",
                "is_valid",
                "is_safe",
                "is_allowed",
            )
        )

    def _eval_expr_taint(self, node: ast.AST | None) -> tuple[bool, str | None]:
        """Recursively evaluate if an AST expression is tainted."""
        if node is None:
            return False, None

        if isinstance(node, ast.Constant):
            return False, None

        if isinstance(node, ast.Name):
            if node.id in self.sanitized_vars:
                return False, None
            if node.id in self.tainted_vars:
                return True, self.tainted_vars[node.id]
            return False, None

        repr_str = ast.unparse(node) if hasattr(ast, "unparse") else ""
        if self._is_sanitizer_expr(repr_str):
            return False, None
        if self._is_source_expr(repr_str):
            return True, repr_str

        # Binary operations: + (concatenation), % (formatting)
        if isinstance(node, ast.BinOp):
            left_tainted, left_src = self._eval_expr_taint(node.left)
            if left_tainted:
                return True, left_src
            right_tainted, right_src = self._eval_expr_taint(node.right)
            if right_tainted:
                return True, right_src
            return False, None

        # F-strings: JoinedStr
        if isinstance(node, ast.JoinedStr):
            for val in node.values:
                if isinstance(val, ast.FormattedValue):
                    t, src = self._eval_expr_taint(val.value)
                    if t:
                        return True, src
            return False, None

        # Subscript: d["k"], items[0]
        if isinstance(node, ast.Subscript):
            val_tainted, val_src = self._eval_expr_taint(node.value)
            if val_tainted:
                return True, val_src
            sub_repr = ast.unparse(node) if hasattr(ast, "unparse") else ""
            if sub_repr in self.tainted_vars:
                return True, self.tainted_vars[sub_repr]
            return False, None

        # Dict literal: {"k": p}
        if isinstance(node, ast.Dict):
            for v in node.values:
                t, src = self._eval_expr_taint(v)
                if t:
                    return True, src
            return False, None

        # List / Tuple / Set literal: [p], (p,)
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            for elt in node.elts:
                t, src = self._eval_expr_taint(elt)
                if t:
                    return True, src
            return False, None

        # Method / function call: "".join(...), format(...), same-file functions
        if isinstance(node, ast.Call):
            # Check if calling a same-file function
            if isinstance(node.func, ast.Name) and node.func.id in self.function_defs:
                fn_def = self.function_defs[node.func.id]
                for arg in node.args:
                    t, src = self._eval_expr_taint(arg)
                    if t:
                        for stmt in ast.walk(fn_def):
                            if isinstance(stmt, ast.Return) and stmt.value:
                                return True, f"{node.func.id}({src})"

            for arg in node.args:
                t, src = self._eval_expr_taint(arg)
                if t:
                    return True, src
            for kw in node.keywords:
                t, src = self._eval_expr_taint(kw.value)
                if t:
                    return True, src

            if isinstance(node.func, ast.Attribute):
                caller_tainted, caller_src = self._eval_expr_taint(node.func.value)
                if caller_tainted:
                    return True, caller_src

        # Attribute access: e.g. obj.prop
        if isinstance(node, ast.Attribute):
            val_tainted, val_src = self._eval_expr_taint(node.value)
            if val_tainted:
                return True, val_src

        return False, None

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.function_defs[node.name] = node
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.function_defs[node.name] = node
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        """Track variable assignments and propagate taint."""
        val_repr = ast.unparse(node.value) if hasattr(ast, "unparse") else ""
        is_san = self._is_sanitizer_expr(val_repr)
        is_tainted, taint_src = self._eval_expr_taint(node.value)

        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id
                if is_san:
                    self.sanitized_vars.add(var_name)
                    self.tainted_vars.pop(var_name, None)
                elif is_tainted and taint_src:
                    self.tainted_vars[var_name] = taint_src
                    self.sanitized_vars.discard(var_name)
                elif isinstance(node.value, ast.Constant):
                    self.tainted_vars.pop(var_name, None)

            elif isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name):
                # e.g. d["k"] = p
                container_name = target.value.id
                if is_tainted and taint_src:
                    self.tainted_vars[container_name] = taint_src
                    sub_key = ast.unparse(target) if hasattr(ast, "unparse") else ""
                    if sub_key:
                        self.tainted_vars[sub_key] = taint_src

        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        """Track annotated assignments e.g. x: str = request.args.get('id')."""
        if node.value:
            val_repr = ast.unparse(node.value) if hasattr(ast, "unparse") else ""
            is_san = self._is_sanitizer_expr(val_repr)
            is_tainted, taint_src = self._eval_expr_taint(node.value)
            if isinstance(node.target, ast.Name):
                var_name = node.target.id
                if is_san:
                    self.sanitized_vars.add(var_name)
                    self.tainted_vars.pop(var_name, None)
                elif is_tainted and taint_src:
                    self.tainted_vars[var_name] = taint_src
                    self.sanitized_vars.discard(var_name)
                elif isinstance(node.value, ast.Constant):
                    self.tainted_vars.pop(var_name, None)
        self.generic_visit(node)

    def visit_Expr(self, node: ast.Expr) -> None:
        """Track container mutations e.g. items.append(p)."""
        if (
            isinstance(node.value, ast.Call)
            and isinstance(node.value.func, ast.Attribute)
            and node.value.func.attr in ("append", "extend", "insert", "update", "add")
            and isinstance(node.value.func.value, ast.Name)
        ):
            c_name = node.value.func.value.id
            for arg in node.value.args:
                t, src = self._eval_expr_taint(arg)
                if t and src:
                    self.tainted_vars[c_name] = src
        self.generic_visit(node)

    def _handle_guard_check(self, test_node: ast.AST) -> None:
        """Extract variables validated by allowlists, type checks, or guard functions."""
        # 1. Compare: var in ALLOWED or var not in ALLOWED
        if isinstance(test_node, ast.Compare) and any(
            isinstance(op, (ast.In, ast.NotIn)) for op in test_node.ops
        ):
            if isinstance(test_node.left, ast.Name):
                self.sanitized_vars.add(test_node.left.id)
                self.tainted_vars.pop(test_node.left.id, None)
            for comp in test_node.comparators:
                if (
                    isinstance(comp, ast.Name)
                    and any(
                        kw in comp.id.lower()
                        for kw in ("allow", "white", "valid", "safe", "trusted")
                    )
                    and isinstance(test_node.left, ast.Name)
                ):
                    self.sanitized_vars.add(test_node.left.id)
                    self.tainted_vars.pop(test_node.left.id, None)

        # 2. Call or UnaryOp(Not, Call): e.g. if is_valid_url(url): or if not is_valid_url(url):
        call_node: ast.Call | None = None
        if isinstance(test_node, ast.Call):
            call_node = test_node
        elif (
            isinstance(test_node, ast.UnaryOp)
            and isinstance(test_node.op, ast.Not)
            and isinstance(test_node.operand, ast.Call)
        ):
            call_node = test_node.operand

        if call_node:
            func_name = ast.unparse(call_node.func).lower() if hasattr(ast, "unparse") else ""
            if any(
                kw in func_name
                for kw in ("valid", "safe", "allow", "check", "whitelist", "allowlist", "trusted")
            ):
                for arg in call_node.args:
                    if isinstance(arg, ast.Name):
                        self.sanitized_vars.add(arg.id)
                        self.tainted_vars.pop(arg.id, None)

    def visit_If(self, node: ast.If) -> None:
        """Recognize allowlist checks e.g. if uid in ALLOWED_IDS: or if not is_valid_url(url):"""
        self._handle_guard_check(node.test)
        self.generic_visit(node)

    def visit_Assert(self, node: ast.Assert) -> None:
        """Recognize assert allowlist checks e.g. assert uid in ALLOWED_IDS:"""
        self._handle_guard_check(node.test)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        """Inspect calls at the target line."""
        if getattr(node, "lineno", None) == self.target_line:
            call_name = ast.unparse(node.func) if hasattr(ast, "unparse") else ""
            args_repr = [ast.unparse(a) for a in node.args] if hasattr(ast, "unparse") else []
            for kw in node.keywords:
                args_repr.append(ast.unparse(kw.value))

            # 1. Check if all arguments are pure literal constants
            all_constants = all(isinstance(a, ast.Constant) for a in node.args)
            if all_constants and node.args and not node.keywords:
                self.taint_result = TaintResult(
                    is_tainted=False,
                    confidence=0.15,
                    is_literal_constant=True,
                    sink=call_name,
                    explanation="Arguments are static string/number literals with no variable concatenation.",
                )
                return

            # 2. Check if arguments use sanitized variables or sanitizer functions
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
                if self._is_sanitizer_expr(arg_str):
                    self.taint_result = TaintResult(
                        is_tainted=False,
                        confidence=0.20,
                        sanitizer=arg_str,
                        sink=call_name,
                        explanation=f"Argument is sanitized via {arg_str}.",
                    )
                    return

            # 3. Check AST expression taint for each argument
            for arg_node in node.args:
                t, src = self._eval_expr_taint(arg_node)
                if t and src:
                    self.taint_result = TaintResult(
                        is_tainted=True,
                        confidence=0.98,
                        source=src,
                        sink=call_name,
                        dataflow_chain=[src, f"{ast.unparse(arg_node)} -> {call_name}"],
                        explanation=f"Untrusted input from '{src}' flows into '{call_name}'.",
                    )
                    return

            for kw in node.keywords:
                t, src = self._eval_expr_taint(kw.value)
                if t and src:
                    self.taint_result = TaintResult(
                        is_tainted=True,
                        confidence=0.98,
                        source=src,
                        sink=call_name,
                        dataflow_chain=[src, f"{kw.arg}={ast.unparse(kw.value)} -> {call_name}"],
                        explanation=f"Untrusted input from '{src}' flows into '{call_name}'.",
                    )
                    return

            # 4. Fallback string matching on arguments against tainted_vars
            for arg_str in args_repr:
                for t_var, t_src in self.tainted_vars.items():
                    if re.search(rf"\b{re.escape(t_var)}\b", arg_str) or t_var in arg_str:
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
    """Enhanced regex-structural dataflow analysis for JS/TS route handlers and sinks."""
    lines = content.splitlines()
    if target_line < 1 or target_line > len(lines):
        return None

    target_content = lines[target_line - 1]

    # Look back up to 50 lines to find variable source assignments
    start_idx = max(0, target_line - 50)
    preceding_lines = lines[start_idx : target_line - 1]

    tainted_map: dict[str, str] = {}
    sanitized_vars: set[str] = set()

    js_sanitizers = (
        "dompurify.sanitize",
        "parseint",
        "parsefloat",
        "number",
        "encodeuricomponent",
        "validator.escape",
        "escape",
    )

    for p_line in preceding_lines:
        line_clean = p_line.strip()
        if not line_clean or line_clean.startswith(("//", "/*", "*")):
            continue

        # 1. Sanitization: const clean = parseInt(req.query.id) or DOMPurify.sanitize(...)
        m_san = re.search(
            r"(?:const|let|var)\s+([a-zA-Z0-9_$]+)\s*=\s*(?:DOMPurify\.sanitize|parseInt|parseFloat|Number|encodeURIComponent|validator\.escape|escape)\s*\(",
            line_clean,
            re.IGNORECASE,
        )
        if m_san:
            san_var = m_san.group(1)
            sanitized_vars.add(san_var)
            tainted_map.pop(san_var, None)
            continue

        # 2. Direct request source: const x = req.query.y or req.body['z'] or req.params.p
        m_src = re.search(
            r"(?:const|let|var)\s+([a-zA-Z0-9_$]+)\s*=\s*(req\.(?:query|params|body|headers)[a-zA-Z0-9_$.?\[\]'\"]*)",
            line_clean,
        )
        if m_src:
            tainted_map[m_src.group(1)] = m_src.group(2)
            sanitized_vars.discard(m_src.group(1))
            continue

        # 3. Destructuring: const { id, name } = req.query
        m_destruct = re.search(
            r"(?:const|let|var)\s+\{([^}]+)\}\s*=\s*(req\.(?:query|params|body))",
            line_clean,
        )
        if m_destruct:
            fields = [f.strip() for f in m_destruct.group(1).split(",")]
            for field in fields:
                field_name = field.split(":")[0].strip()
                if field_name:
                    tainted_map[field_name] = f"{m_destruct.group(2)}.{field_name}"
            continue

        # 4. Taint propagation through concatenation, template literals, objects, or aliases
        for t_var, t_src in list(tainted_map.items()):
            pattern = rf"\b{re.escape(t_var)}\b"
            if re.search(pattern, line_clean):
                # Assignment target: const q = ...
                m_assign = re.search(
                    r"(?:const|let|var)\s+([a-zA-Z0-9_$]+)\s*=\s*(.+)",
                    line_clean,
                )
                if m_assign:
                    lhs = m_assign.group(1)
                    rhs = m_assign.group(2)
                    if any(san in rhs.lower() for san in js_sanitizers):
                        sanitized_vars.add(lhs)
                        tainted_map.pop(lhs, None)
                    else:
                        tainted_map[lhs] = f"{t_var} (from {t_src})"
                        sanitized_vars.discard(lhs)

                # Object/property assignment: d.k = p or d["k"] = p
                m_prop = re.search(
                    r"([a-zA-Z0-9_$]+)(?:\.[a-zA-Z0-9_$]+|\[['\"][a-zA-Z0-9_$]+['\"]\])\s*=\s*(.+)",
                    line_clean,
                )
                if m_prop:
                    obj_name = m_prop.group(1)
                    tainted_map[obj_name] = f"{t_var} (from {t_src})"

        # 5. Allowlist & guard validation checks in JS/TS
        # e.g. if (!isValidUrl(url)), if (ALLOWED_HOSTS.includes(url)), if (!whitelist.includes(url))
        for t_var in list(tainted_map.keys()):
            guard_patterns = (
                rf"""(?:isValid|isSafe|validate|isAllowed|check|validator\.isURL|isURL)[a-zA-Z0-9_$]*\s*\(\s*[^)]*\b{re.escape(t_var)}\b""",
                rf"""(?:allowed|whitelist|allowlist|trusted)[a-zA-Z0-9_$]*\.(?:includes|indexOf|has)\s*\([^)]*\b{re.escape(t_var)}\b""",
                rf"""\b{re.escape(t_var)}\b\s*===\s*['"]""",
            )
            if any(re.search(pat, line_clean, re.IGNORECASE) for pat in guard_patterns):
                sanitized_vars.add(t_var)
                tainted_map.pop(t_var, None)

        m_guard = re.search(
            r"""(?:isValid|isSafe|validate|isAllowed|check|validator\.isURL|isURL)[a-zA-Z0-9_$]*\s*\(\s*([a-zA-Z0-9_$]+)""",
            line_clean,
            re.IGNORECASE,
        )
        if m_guard:
            g_var = m_guard.group(1)
            sanitized_vars.add(g_var)
            tainted_map.pop(g_var, None)

        m_allow = re.search(
            r"""(?:allowed|whitelist|allowlist|trusted)[a-zA-Z0-9_$]*\.(?:includes|indexOf|has)\s*\(\s*([a-zA-Z0-9_$]+)""",
            line_clean,
            re.IGNORECASE,
        )
        if m_allow:
            a_var = m_allow.group(1)
            sanitized_vars.add(a_var)
            tainted_map.pop(a_var, None)

    # Target line evaluation
    # Check if target line uses a sanitized variable
    for s_var in sanitized_vars:
        if re.search(rf"\b{re.escape(s_var)}\b", target_content):
            return TaintResult(
                is_tainted=False,
                confidence=0.20,
                sanitizer=s_var,
                explanation=f"JavaScript/TypeScript variable '{s_var}' was sanitized before execution.",
            )

    # Check if target line has pure constant string passed to sink
    if re.search(
        r"""\b(?:eval|exec|execute|query|raw|open|fs\.[a-zA-Z0-9]+)\s*\(\s*['"][^'"]*['"]\s*\)""",
        target_content,
    ) and not re.search(r"""\+|\$\{|\breq\.""", target_content):
        return TaintResult(
            is_tainted=False,
            confidence=0.15,
            is_literal_constant=True,
            explanation="Static string literal with no variable concatenation.",
        )

    # Check if target line uses tainted variable or object property
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
    m_direct = re.search(
        r"(req\.(?:query|params|body)(?:\.[a-zA-Z0-9_$]+|\[['\"][a-zA-Z0-9_$]+['\"]\])?)",
        target_content,
    )
    if m_direct:
        return TaintResult(
            is_tainted=True,
            confidence=0.98,
            source=m_direct.group(1),
            dataflow_chain=[m_direct.group(1), f"sink at line {target_line}"],
            explanation=f"Direct usage of unvalidated '{m_direct.group(1)}' at sink.",
        )

    return None
