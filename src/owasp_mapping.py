"""
src/owasp_mapping.py

Static reference data for the OWASP Top 10:2025 (released November 2025,
finalized January 2026). This is awareness/reference content only -- no
payloads, no exploit code. It is indexed alongside MITRE ATT&CK techniques
in the RAG store so the LLM can reason about which category a given
finding belongs to, and it is used by the reporting phase to attach a
standard name, description, and remediation guidance to each finding the
LLM reports.

The LLM decides what to test and how; this module only supplies the
taxonomy and remediation language it should reason against.
"""

from typing import Dict, List

OWASP_TOP_10_2025: Dict[str, Dict] = {
    "A01:2025": {
        "name": "Broken Access Control",
        "rank": 1,
        "description": (
            "Failures to properly enforce what an authenticated or "
            "unauthenticated user is allowed to do or access. Includes "
            "insecure direct object references (IDOR), path traversal, "
            "privilege escalation, missing function-level access control, "
            "and server-side request forgery (SSRF), which was folded "
            "into this category in the 2025 edition."
        ),
        "example_indicators": [
            "Accessing another user's resource by changing an ID parameter",
            "Reaching an admin function without an admin session",
            "A server-side component fetching an attacker-supplied URL",
            "Directory or file paths reachable outside the intended root",
        ],
        "remediation": (
            "Enforce authorization on every request server-side, deny by "
            "default, use indirect object references, and validate/allow-list "
            "any server-side outbound requests to prevent SSRF."
        ),
        "related_mitre_tactics": ["privilege-escalation", "initial-access", "collection"],
    },
    "A02:2025": {
        "name": "Security Misconfiguration",
        "rank": 2,
        "description": (
            "Missing hardening, default credentials, verbose error messages, "
            "unnecessary features enabled, permissive cloud/storage settings, "
            "or missing security headers."
        ),
        "example_indicators": [
            "Missing Content-Security-Policy, X-Frame-Options, HSTS, etc.",
            "Default admin credentials still active",
            "Stack traces or debug information returned to the client",
            "Directory listing enabled",
        ],
        "remediation": (
            "Harden configurations, remove default accounts, disable verbose "
            "errors in production, and apply a repeatable, automated "
            "configuration baseline."
        ),
        "related_mitre_tactics": ["discovery", "defense-evasion"],
    },
    "A03:2025": {
        "name": "Software Supply Chain Failures",
        "rank": 3,
        "description": (
            "Risks introduced through third-party components, dependencies, "
            "build pipelines, and distribution channels, including "
            "outdated/vulnerable libraries, typosquatting, and compromised "
            "build or CI/CD infrastructure."
        ),
        "example_indicators": [
            "JavaScript or server framework versions with known CVEs",
            "Exposed CI/CD configuration or build artifacts",
            "Third-party scripts loaded without integrity checks",
        ],
        "remediation": (
            "Maintain a software bill of materials (SBOM), pin and verify "
            "dependency versions, and monitor upstream packages for "
            "compromise."
        ),
        "related_mitre_tactics": ["initial-access", "persistence"],
    },
    "A04:2025": {
        "name": "Cryptographic Failures",
        "rank": 4,
        "description": (
            "Weak or missing encryption in transit or at rest, poor key "
            "management, use of deprecated algorithms, or exposure of "
            "sensitive data due to inadequate cryptographic controls."
        ),
        "example_indicators": [
            "Sensitive data transmitted over plain HTTP",
            "Weak TLS configuration or expired certificates",
            "Secrets or keys embedded in source or responses",
        ],
        "remediation": (
            "Enforce TLS everywhere, use modern algorithms and key lengths, "
            "and keep secrets out of source code and client-visible output."
        ),
        "related_mitre_tactics": ["credential-access", "collection"],
    },
    "A05:2025": {
        "name": "Injection",
        "rank": 5,
        "description": (
            "Untrusted input alters the behavior of an interpreter, "
            "including SQL, NoSQL, OS command, LDAP, and template "
            "injection (SSTI)."
        ),
        "example_indicators": [
            "Database error messages returned after unusual input",
            "Application behavior changes based on injected control "
            "characters or template syntax",
            "Command execution artifacts appearing in a response",
        ],
        "remediation": (
            "Use parameterized queries/prepared statements, avoid "
            "evaluating templates with user-controlled data, and validate "
            "and encode all untrusted input."
        ),
        "related_mitre_tactics": ["execution", "initial-access"],
    },
    "A06:2025": {
        "name": "Insecure Design",
        "rank": 6,
        "description": (
            "Missing or ineffective security controls at the architecture "
            "level -- issues that cannot be fixed by patching code alone "
            "because the design itself lacks a control."
        ),
        "example_indicators": [
            "Business logic that can be abused (e.g., unlimited password "
            "reset attempts, negative quantity purchases)",
            "No rate limiting on sensitive operations",
        ],
        "remediation": (
            "Apply threat modeling during design, use secure design "
            "patterns, and add explicit resource/rate limits on sensitive "
            "operations."
        ),
        "related_mitre_tactics": ["initial-access", "impact"],
    },
    "A07:2025": {
        "name": "Authentication Failures",
        "rank": 7,
        "description": (
            "Weaknesses in identity verification and session handling, "
            "including weak password policy, credential stuffing "
            "susceptibility, and improper session management."
        ),
        "example_indicators": [
            "Successful login with common or default credentials",
            "Session tokens that do not expire or are predictable",
            "No account lockout or throttling after repeated failed logins",
        ],
        "remediation": (
            "Enforce strong password policy, multi-factor authentication, "
            "secure session/token handling, and throttle authentication "
            "attempts."
        ),
        "related_mitre_tactics": ["credential-access", "initial-access"],
    },
    "A08:2025": {
        "name": "Software or Data Integrity Failures",
        "rank": 8,
        "description": (
            "Code or data is trusted without verifying its integrity, "
            "including insecure deserialization, unsigned auto-updates, "
            "and unverified third-party plugins/CDNs."
        ),
        "example_indicators": [
            "Serialized objects accepted from the client and deserialized "
            "without validation",
            "Update or plugin mechanisms with no signature verification",
        ],
        "remediation": (
            "Verify signatures on updates and artifacts, avoid "
            "deserializing untrusted data, and only load third-party code "
            "from vetted sources."
        ),
        "related_mitre_tactics": ["execution", "persistence"],
    },
    "A09:2025": {
        "name": "Security Logging and Alerting Failures",
        "rank": 9,
        "description": (
            "Insufficient logging, monitoring, or alerting that delays or "
            "prevents detection of an ongoing attack or breach."
        ),
        "example_indicators": [
            "No audit trail for authentication or authorization events",
            "Errors and security-relevant events are not logged",
        ],
        "remediation": (
            "Centralize logging, log authentication/authorization "
            "decisions, and configure alerting on anomalous activity."
        ),
        "related_mitre_tactics": ["defense-evasion"],
    },
    "A10:2025": {
        "name": "Mishandling of Exceptional Conditions",
        "rank": 10,
        "description": (
            "Improper error handling, logic flaws in failure paths, and "
            "insecure failure states that can expose sensitive data or "
            "cause denial of service. New category in the 2025 edition."
        ),
        "example_indicators": [
            "Unhandled exceptions returning stack traces or internal state",
            "A failed check that fails open instead of failing closed",
        ],
        "remediation": (
            "Handle all error paths explicitly, fail closed on security "
            "checks, and avoid leaking internal state in error responses."
        ),
        "related_mitre_tactics": ["defense-evasion", "impact"],
    },
}


def as_rag_documents() -> List[Dict]:
    """
    Format the OWASP Top 10:2025 categories as RAG-indexable documents,
    in the same shape as MITRE technique dicts, so they can be merged
    into the same retrieval corpus.
    """
    docs = []
    for owasp_id, info in OWASP_TOP_10_2025.items():
        docs.append({
            "id": owasp_id,
            "name": info["name"],
            "description": info["description"],
            "tactics": info["related_mitre_tactics"],
            "source_type": "owasp_top10_2025",
        })
    return docs


def find_category_by_keyword(text: str) -> str:
    """
    Best-effort classification of a free-text finding description into an
    OWASP Top 10:2025 category, used only as a fallback when the LLM does
    not supply an explicit owasp_category on a recorded finding.
    """
    text_lower = text.lower()
    keyword_map = {
        "A05:2025": ["sql injection", "sqli", "ssti", "template injection",
                     "command injection", "os command", "nosql injection", "ldap injection"],
        "A01:2025": ["idor", "access control", "privilege escalation", "ssrf",
                     "path traversal", "directory traversal", "unauthorized access"],
        "A07:2025": ["credential", "brute force", "authentication", "login",
                     "session", "password"],
        "A02:2025": ["security header", "misconfiguration", "default credential",
                     "directory listing", "debug", "stack trace", "verbose error"],
        "A04:2025": ["tls", "certificate", "encryption", "cryptograph", "plaintext",
                     "secret exposed", "api key", "hardcoded key"],
        "A08:2025": ["deserialization", "unsigned update", "integrity check",
                     "untrusted plugin"],
        "A03:2025": ["outdated component", "vulnerable dependency", "supply chain",
                     "cve"],
        "A09:2025": ["logging", "alerting", "monitoring"],
        "A10:2025": ["stack trace", "unhandled exception", "error handling"],
        "A06:2025": ["business logic", "rate limit", "insecure design"],
    }
    for owasp_id, keywords in keyword_map.items():
        if any(kw in text_lower for kw in keywords):
            return owasp_id
    return "Unclassified"
