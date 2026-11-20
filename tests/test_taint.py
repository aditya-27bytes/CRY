"""Unit tests for Step 3: Closing the taint gaps (concatenation, f-strings, format, dicts/lists, sanitizers)."""

import tempfile
from pathlib import Path

from cry.scanners.sast import scan_file
from cry.scanners.taint import analyze_taint_in_javascript, analyze_taint_in_python


def test_python_case_a_sql_concat_alias_flagged() -> None:
    """uid = request.args.get('id'); q = 'SELECT * FROM u WHERE id=' + uid; cursor.execute(q) MUST be flagged."""
    with tempfile.TemporaryDirectory() as td:
        py_file = Path(td) / "app.py"
        py_file.write_text(
            "import os\n"
            "def get_user():\n"
            '    uid = request.args.get("id")\n'
            '    q = "SELECT * FROM u WHERE id=" + uid\n'
            "    cursor.execute(q)\n",
            encoding="utf-8",
        )

        res = analyze_taint_in_python(py_file, 5)
        assert res is not None
        assert res.is_tainted is True
        assert "cursor.execute" in (res.sink or "")

        findings = scan_file(py_file, Path(td))
        assert len(findings) >= 1
        sqli_findings = [f for f in findings if f.category.value == "INJECTION"]
        assert len(sqli_findings) >= 1
        assert any("SQL Injection" in f.title for f in sqli_findings)


def test_python_case_b_dict_subscript_path_traversal_flagged() -> None:
    """p = request.args.get('p'); d = {'k': p}; open(d['k']) MUST be flagged."""
    with tempfile.TemporaryDirectory() as td:
        py_file = Path(td) / "app.py"
        py_file.write_text(
            "import os\n"
            "def read_user_file():\n"
            '    p = request.args.get("p")\n'
            '    d = {"k": p}\n'
            '    open(d["k"])\n',
            encoding="utf-8",
        )

        res = analyze_taint_in_python(py_file, 5)
        assert res is not None
        assert res.is_tainted is True
        assert "open" in (res.sink or "")

        findings = scan_file(py_file, Path(td))
        assert len(findings) >= 1
        path_findings = [f for f in findings if "Path Traversal" in f.title]
        assert len(path_findings) >= 1


def test_python_string_format_variants() -> None:
    """Verify taint propagation across f-strings, str.format, %, and join."""
    with tempfile.TemporaryDirectory() as td:
        py_file = Path(td) / "formats.py"
        py_file.write_text(
            "def test_formats():\n"
            '    val = request.args.get("val")\n'
            '    f_str = f"SELECT * FROM t WHERE col = {val}"\n'
            "    cursor.execute(f_str)\n"
            '    fmt_str = "SELECT * FROM t WHERE col = {}".format(val)\n'
            "    cursor.execute(fmt_str)\n"
            '    pct_str = "SELECT * FROM t WHERE col = %s" % val\n'
            "    cursor.execute(pct_str)\n"
            '    join_str = "".join(["SELECT * FROM t WHERE col = ", val])\n'
            "    cursor.execute(join_str)\n",
            encoding="utf-8",
        )

        for line_no in (4, 6, 8, 10):
            res = analyze_taint_in_python(py_file, line_no)
            assert res is not None, f"Expected taint result at line {line_no}"
            assert res.is_tainted is True, f"Expected line {line_no} to be tainted"


def test_python_dict_and_list_subscripts() -> None:
    """Verify taint propagation through dict mutations, list mutations, and item access."""
    with tempfile.TemporaryDirectory() as td:
        py_file = Path(td) / "collections_test.py"
        py_file.write_text(
            "import os\n"
            "def run_ops():\n"
            '    cmd = request.args.get("cmd")\n'
            "    items = []\n"
            "    items.append(cmd)\n"
            "    os.system(items[0])\n"
            "    d = {}\n"
            '    d["action"] = cmd\n'
            '    os.system(d["action"])\n',
            encoding="utf-8",
        )

        res_list = analyze_taint_in_python(py_file, 6)
        assert res_list is not None
        assert res_list.is_tainted is True

        res_dict = analyze_taint_in_python(py_file, 9)
        assert res_dict is not None
        assert res_dict.is_tainted is True


def test_python_local_alias_and_same_file_function() -> None:
    """Verify alias propagation and same-file function return tracking."""
    with tempfile.TemporaryDirectory() as td:
        py_file = Path(td) / "alias.py"
        py_file.write_text(
            "import os\n"
            "def identity(x):\n"
            "    return x\n"
            "def runner():\n"
            '    orig = request.args.get("x")\n'
            "    alias = orig\n"
            "    os.system(alias)\n"
            "    func_res = identity(orig)\n"
            "    os.system(func_res)\n",
            encoding="utf-8",
        )

        res_alias = analyze_taint_in_python(py_file, 7)
        assert res_alias is not None
        assert res_alias.is_tainted is True

        res_func = analyze_taint_in_python(py_file, 9)
        assert res_func is not None
        assert res_func.is_tainted is True


def test_python_sanitizers_clear_taint() -> None:
    """shlex.quote, int(), float(), and allowlist checks must clear taint and not trigger blockers."""
    with tempfile.TemporaryDirectory() as td:
        py_file = Path(td) / "safe_sanitizers.py"
        py_file.write_text(
            "import os, shlex\n"
            "ALLOWED = ['safe1', 'safe2']\n"
            "def safe_runner():\n"
            '    raw_id = request.args.get("id")\n'
            "    clean_id = int(raw_id)\n"
            '    cursor.execute("SELECT * FROM u WHERE id=" + str(clean_id))\n'
            '    raw_cmd = request.args.get("cmd")\n'
            "    clean_cmd = shlex.quote(raw_cmd)\n"
            '    os.system("echo " + clean_cmd)\n'
            '    allow_val = request.args.get("val")\n'
            "    if allow_val in ALLOWED:\n"
            '        cursor.execute("SELECT * FROM u WHERE val=" + allow_val)\n',
            encoding="utf-8",
        )

        # Lines with sanitized arguments must not be flagged as tainted
        res_int = analyze_taint_in_python(py_file, 6)
        assert res_int is not None
        assert res_int.is_tainted is False

        res_shlex = analyze_taint_in_python(py_file, 9)
        assert res_shlex is not None
        assert res_shlex.is_tainted is False

        res_allow = analyze_taint_in_python(py_file, 12)
        assert res_allow is not None
        assert res_allow.is_tainted is False


def test_javascript_taint_concatenation_and_template_literals() -> None:
    """JS structural dataflow must trace concatenation, template literals, and property access."""
    # 1. String concatenation into SQL query
    js_code_concat = """
    app.get('/user', (req, res) => {
        const uid = req.query.id;
        const q = "SELECT * FROM users WHERE id = " + uid;
        db.query(q);
    });
    """
    res_concat = analyze_taint_in_javascript(js_code_concat, 5)
    assert res_concat is not None
    assert res_concat.is_tainted is True

    # 2. Template literal into query
    js_code_template = """
    app.get('/search', (req, res) => {
        const term = req.query.q;
        const q = `SELECT * FROM items WHERE name = ${term}`;
        db.query(q);
    });
    """
    res_temp = analyze_taint_in_javascript(js_code_template, 5)
    assert res_temp is not None
    assert res_temp.is_tainted is True

    # 3. Object property into fs.readFile
    js_code_obj = """
    app.get('/file', (req, res) => {
        const p = req.query.p;
        const d = { k: p };
        fs.readFile(d.k);
    });
    """
    res_obj = analyze_taint_in_javascript(js_code_obj, 5)
    assert res_obj is not None
    assert res_obj.is_tainted is True


def test_javascript_sanitizers_clear_taint() -> None:
    """DOMPurify.sanitize, parseInt, and Number in JS must clear taint."""
    js_code = """
    app.get('/safe', (req, res) => {
        const rawId = req.query.id;
        const cleanId = parseInt(rawId);
        db.query("SELECT * FROM u WHERE id = " + cleanId);
        const rawName = req.query.name;
        const cleanName = DOMPurify.sanitize(rawName);
        res.send(cleanName);
    });
    """
    res_int = analyze_taint_in_javascript(js_code, 5)
    assert res_int is not None
    assert res_int.is_tainted is False

    res_dom = analyze_taint_in_javascript(js_code, 8)
    assert res_dom is not None
    assert res_dom.is_tainted is False
