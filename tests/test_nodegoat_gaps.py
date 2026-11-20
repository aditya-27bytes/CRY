"""Unit tests verifying resolution of OWASP NodeGoat detection gaps: NoSQL and SSRF."""

from pathlib import Path

from cry.models import Severity
from cry.scanners.network import scan_file_network
from cry.scanners.sast import scan_file


def test_nodegoat_allocations_dao_vulnerable_where_concat_flagged(tmp_path: Path) -> None:
    """Ensure allocations-dao.js $where string concatenation is caught as NoSQL injection."""
    sample_file = tmp_path / "allocations-dao.js"
    sample_file.write_text(
        """function AllocationsDAO(db) {
    const allocations = db.collection("allocations");

    this.getByUserIdAndThreshold = function(userId, threshold, callback) {
        // Vulnerable: using $where with string concatenation
        allocations.find({ $where: "this.userId == '" + userId + "' && this.stocks > '" + threshold + "'" }).toArray(callback);
    };
}
module.exports = AllocationsDAO;
""",
        encoding="utf-8",
    )

    findings = scan_file(sample_file, tmp_path)
    assert len(findings) >= 1
    nosql_findings = [f for f in findings if f.cwe_id == "CWE-943"]
    assert len(nosql_findings) >= 1
    assert any("NoSQL" in f.title or "$where" in f.title for f in nosql_findings)
    assert any(f.severity == Severity.CRITICAL for f in nosql_findings)


def test_nodegoat_allocations_dao_vulnerable_where_template_literal_flagged(
    tmp_path: Path,
) -> None:
    """Ensure allocations-dao.js $where template literal is caught as NoSQL injection."""
    sample_file = tmp_path / "allocations-dao-template.js"
    sample_file.write_text(
        """function AllocationsDAO(db) {
    const allocations = db.collection("allocations");

    this.getByUserIdAndThreshold = function(userId, threshold, callback) {
        // Vulnerable: using $where with template strings
        const query = { $where: `this.userId == '${userId}' && this.stocks > '${threshold}'` };
        allocations.find(query).toArray(callback);
    };
}
module.exports = AllocationsDAO;
""",
        encoding="utf-8",
    )

    findings = scan_file(sample_file, tmp_path)
    assert len(findings) >= 1
    nosql_findings = [f for f in findings if f.cwe_id == "CWE-943"]
    assert len(nosql_findings) >= 1
    assert any(f.severity == Severity.CRITICAL for f in nosql_findings)


def test_nodegoat_allocations_dao_safe_equality_matcher_not_flagged(tmp_path: Path) -> None:
    """Ensure safe allocations query using standard equality matchers ({ userId: parsedInt }) is NOT flagged."""
    sample_file = tmp_path / "allocations-dao-safe.js"
    sample_file.write_text(
        """function AllocationsDAO(db) {
    const allocations = db.collection("allocations");

    this.getByUserIdAndThreshold = function(userId, threshold, callback) {
        // Safe: standard equality matchers with parsed numeric threshold
        const parsedUserId = parseInt(userId, 10);
        const parsedThreshold = Number(threshold);
        allocations.find({ userId: parsedUserId, stocks: { $gt: parsedThreshold } }).toArray(callback);
    };
}
module.exports = AllocationsDAO;
""",
        encoding="utf-8",
    )

    findings = scan_file(sample_file, tmp_path)
    # The safe variant must not produce any NoSQL or injection findings
    assert not any(f.cwe_id == "CWE-943" for f in findings)


def test_nodegoat_research_vulnerable_needle_ssrf_flagged(tmp_path: Path) -> None:
    """Ensure research.js unvalidated URL passed to needle.get is caught as SSRF."""
    sample_file = tmp_path / "research.js"
    sample_file.write_text(
        """const needle = require("needle");

function ResearchHandler() {
    this.displayResearch = function(req, res) {
        const url = req.query.url + req.query.symbol;
        return needle.get(url, function(error, newResponse, body) {
            if (!error && newResponse.statusCode === 200) {
                res.write(body);
            }
            res.end();
        });
    };
}

module.exports = ResearchHandler;
""",
        encoding="utf-8",
    )

    # SAST scanner detection
    sast_findings = scan_file(sample_file, tmp_path)
    ssrf_sast = [f for f in sast_findings if f.cwe_id == "CWE-918"]
    assert len(ssrf_sast) >= 1
    assert any("SSRF" in f.title for f in ssrf_sast)
    assert any(f.severity == Severity.CRITICAL for f in ssrf_sast)

    # Network code pattern scanner detection
    net_findings = scan_file_network(sample_file, tmp_path)
    ssrf_net = [f for f in net_findings if f.cwe_id == "CWE-918"]
    assert len(ssrf_net) >= 1


def test_nodegoat_research_safe_allowlist_not_flagged(tmp_path: Path) -> None:
    """Ensure research route with an allowlist check is NOT flagged as SSRF."""
    sample_file = tmp_path / "research-safe.js"
    sample_file.write_text(
        """const needle = require("needle");

const ALLOWED_HOSTS = ["api.marketdata.com", "finance.yahoo.com"];

function isValidUrl(rawUrl) {
    try {
        const parsed = new URL(rawUrl);
        return ALLOWED_HOSTS.includes(parsed.hostname);
    } catch {
        return false;
    }
}

function ResearchHandler() {
    this.displayResearch = function(req, res) {
        const url = req.query.url + req.query.symbol;
        if (!isValidUrl(url)) {
            return res.status(400).send("Invalid target URL");
        }
        return needle.get(url, function(error, newResponse, body) {
            if (!error && newResponse.statusCode === 200) {
                res.write(body);
            }
            res.end();
        });
    };
}

module.exports = ResearchHandler;
""",
        encoding="utf-8",
    )

    # Neither SAST nor Network scanner should flag the allowlist-guarded code
    sast_findings = scan_file(sample_file, tmp_path)
    assert not any(f.cwe_id == "CWE-918" for f in sast_findings)

    net_findings = scan_file_network(sample_file, tmp_path)
    assert not any(f.cwe_id == "CWE-918" for f in net_findings)


def test_python_nosql_vulnerable_and_safe(tmp_path: Path) -> None:
    """Ensure Python pymongo $where injection is caught and safe equality matcher is clean."""
    vuln_file = tmp_path / "mongo_vuln.py"
    vuln_file.write_text(
        """def find_user_allocations(db, request):
    uid = request.args.get("id")
    threshold = request.args.get("threshold")
    return db.allocations.find({"$where": f"this.userId == '{uid}' && this.stocks > {threshold}"})
""",
        encoding="utf-8",
    )
    vuln_findings = scan_file(vuln_file, tmp_path)
    assert any(f.cwe_id == "CWE-943" for f in vuln_findings)

    safe_file = tmp_path / "mongo_safe.py"
    safe_file.write_text(
        """def find_user_allocations(db, request):
    uid = int(request.args.get("id"))
    threshold = float(request.args.get("threshold"))
    return db.allocations.find({"userId": uid, "stocks": {"$gt": threshold}})
""",
        encoding="utf-8",
    )
    safe_findings = scan_file(safe_file, tmp_path)
    assert not any(f.cwe_id == "CWE-943" for f in safe_findings)


def test_python_ssrf_vulnerable_and_safe_requests_and_httpx(tmp_path: Path) -> None:
    """Ensure requests/httpx SSRF with untrusted input is flagged, and allowlisted/static is safe."""
    # 1. Vulnerable requests
    vuln_requests = tmp_path / "vuln_requests.py"
    vuln_requests.write_text(
        """import requests

def proxy(request):
    url = request.args.get("url")
    return requests.get(url, timeout=5).text
""",
        encoding="utf-8",
    )
    r_findings = scan_file(vuln_requests, tmp_path)
    assert any(f.cwe_id == "CWE-918" for f in r_findings)

    # 2. Safe requests with allowlist
    safe_requests = tmp_path / "safe_requests.py"
    safe_requests.write_text(
        """import requests

ALLOWED_DOMAINS = {"api.example.com", "data.example.com"}

def proxy(request):
    url = request.args.get("url")
    if url in ALLOWED_DOMAINS:
        return requests.get(url, timeout=5).text
    return "Forbidden", 403
""",
        encoding="utf-8",
    )
    sr_findings = scan_file(safe_requests, tmp_path)
    assert not any(f.cwe_id == "CWE-918" for f in sr_findings)

    # 3. Vulnerable httpx
    vuln_httpx = tmp_path / "vuln_httpx.py"
    vuln_httpx.write_text(
        """import httpx

def fetch_data(request):
    target = request.GET.get("target")
    return httpx.get(target).text
""",
        encoding="utf-8",
    )
    h_findings = scan_file(vuln_httpx, tmp_path)
    assert any(f.cwe_id == "CWE-918" for f in h_findings)

    # 4. Safe static literal URL
    safe_static = tmp_path / "safe_static.py"
    safe_static.write_text(
        """import httpx

def get_status():
    return httpx.get("https://api.github.com/status").text
""",
        encoding="utf-8",
    )
    static_findings = scan_file(safe_static, tmp_path)
    assert not any(f.cwe_id == "CWE-918" for f in static_findings)
