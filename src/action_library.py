"""
src/action_library.py

Exposes only generic, protocol-level actions: HTTP GET and POST,
full request/response introspection, and neutral wordlist/file helpers.
No scripted vulnerability tests – all reasoning belongs to the LLM.
"""
import logging
import os
import time
from typing import Dict, List, Optional, Any

import requests

from src import scope

logger = logging.getLogger(__name__)

USER_AGENT = "Nemesis-RedTeam-Agent/2.0 (authorized-security-test)"
DEFAULT_REQUEST_DELAY = 0.3
DEFAULT_MAX_REQUESTS = 500
MAX_BODY_PREVIEW_CHARS = 3000

# Expanded search directories for wordlists (including your ~/wordlists)
WORDLIST_SEARCH_DIRS = [
    "wordlists",
    os.path.join("data", "wordlists"),
    os.path.expanduser("~/wordlists/seclists"),           # your main directory
]


class RequestBudgetExceeded(Exception):
    pass


class ActionLibrary:
    def __init__(self, request_delay: float = DEFAULT_REQUEST_DELAY,
                 max_requests: int = DEFAULT_MAX_REQUESTS):
        # Only GET and POST actions are provided
        self.actions = {
            "http_get": self._http_get,
            "http_post": self._http_post,
            "read_wordlist": self._read_wordlist,
            "list_wordlists": self._list_wordlists,
            "record_finding": self._record_finding,
        }
        self.request_delay = request_delay
        self.max_requests = max_requests
        self.request_count = 0
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": USER_AGENT})
        self.recorded_findings: List[Dict] = []

    def list_actions(self):
        return list(self.actions.keys())

    def execute(self, action_name: str, **kwargs):
        if action_name not in self.actions:
            raise ValueError(f"Unknown action: {action_name}")
        return self.actions[action_name](**kwargs)

    # ------------------------------------------------------------------
    # Centralized HTTP transport (scope + budget enforced)
    # ------------------------------------------------------------------
    def _request(self, method: str, url: str, **kwargs) -> Any:
        if not scope.confirm_authorized(url):
            raise scope.ScopeViolation(
                f"'{url}' is not an authorized target. Refusing to send traffic."
            )
        if self.request_count >= self.max_requests:
            raise RequestBudgetExceeded(
                f"Hit the {self.max_requests}-request budget for this run."
            )
        kwargs.setdefault("timeout", 10)
        try:
            resp = self.session.request(method, url, **kwargs)
            self.request_count += 1
            time.sleep(self.request_delay)
            return resp
        except requests.RequestException as e:
            logger.debug(f"Request failed: {method} {url} -> {e}")
            self.request_count += 1
            time.sleep(self.request_delay)
            return None

    # ------------------------------------------------------------------
    # Response formatting – full request/response detail for LLM analysis
    # ------------------------------------------------------------------
    def _format_exchange(self, method: str, url: str,
                         req_headers: Optional[Dict], req_params: Optional[Dict],
                         req_body: Any, resp) -> str:
        if resp is None:
            return (
                f"METHOD: {method}\nURL: {url}\n"
                f"RESULT: Request failed (connection error, timeout, or DNS failure)."
            )

        body = resp.text
        truncated = len(body) > MAX_BODY_PREVIEW_CHARS
        body_preview = body[:MAX_BODY_PREVIEW_CHARS] if truncated else body

        try:
            cookies = resp.cookies.get_dict()
        except Exception:
            cookies = {}

        redirect_chain = [r.url for r in resp.history] if resp.history else []

        lines = [
            f"METHOD: {method}",
            f"URL: {url}",
            f"REQUEST HEADERS: {dict(req_headers) if req_headers else '(session defaults only)'}",
            f"REQUEST QUERY PARAMS: {req_params if req_params else '(none)'}",
            f"REQUEST BODY: {req_body if req_body else '(none)'}",
            "---",
            f"RESPONSE STATUS: {resp.status_code} {resp.reason}",
            f"RESPONSE TIME: {resp.elapsed.total_seconds():.3f}s",
            f"REDIRECT CHAIN: {redirect_chain if redirect_chain else '(none)'}",
            f"RESPONSE HEADERS: {dict(resp.headers)}",
            f"RESPONSE COOKIES: {cookies if cookies else '(none)'}",
            f"RESPONSE BODY LENGTH: {len(body)} bytes",
            f"RESPONSE BODY{' (truncated to ' + str(MAX_BODY_PREVIEW_CHARS) + ' chars)' if truncated else ''}:",
            body_preview,
        ]
        return "\n".join(lines)

    def _run_http(self, method: str, url: str, headers: Optional[Dict] = None,
                  params: Optional[Dict] = None, data: Optional[Dict] = None,
                  json_body: Optional[Dict] = None, cookies: Optional[Dict] = None) -> str:
        try:
            resp = self._request(
                method, url, headers=headers, params=params,
                data=data, json=json_body, cookies=cookies,
            )
        except scope.ScopeViolation as e:
            return f"REFUSED: {e}"
        except RequestBudgetExceeded as e:
            return f"BUDGET EXCEEDED: {e}"

        body_sent = json_body if json_body is not None else data
        return self._format_exchange(method, url, headers, params, body_sent, resp)

    # ------------------------------------------------------------------
    # HTTP GET and POST actions (only these are exposed)
    # ------------------------------------------------------------------
    def _http_get(self, url: str, headers: Optional[Dict] = None,
                  params: Optional[Dict] = None, cookies: Optional[Dict] = None) -> str:
        return self._run_http("GET", url, headers=headers, params=params, cookies=cookies)

    def _http_post(self, url: str, headers: Optional[Dict] = None,
                   params: Optional[Dict] = None, data: Optional[Dict] = None,
                   json_body: Optional[Dict] = None, cookies: Optional[Dict] = None) -> str:
        return self._run_http("POST", url, headers=headers, params=params,
                              data=data, json_body=json_body, cookies=cookies)

    # ------------------------------------------------------------------
    # Wordlist utilities – read‑only, no network traffic
    # ------------------------------------------------------------------
    def _resolve_wordlist_path(self, wordlist_name: str) -> Optional[str]:
        if os.path.exists(wordlist_name):
            return wordlist_name
        for directory in WORDLIST_SEARCH_DIRS:
            candidate = os.path.join(directory, wordlist_name)
            if os.path.exists(candidate):
                return candidate
        return None

    def _list_wordlists(self) -> str:
        """
        List all wordlist files found in the search directories.
        Shows relative paths so the LLM can choose appropriate ones.
        """
        found = []
        for directory in WORDLIST_SEARCH_DIRS:
            if os.path.isdir(directory):
                for root, dirs, files in os.walk(directory):
                    dirs[:] = [d for d in dirs if not d.startswith('.')]
                    for fname in files:
                        if fname.endswith(('.txt', '.lst', '.dict')):
                            full = os.path.join(root, fname)
                            rel = os.path.relpath(full, directory)
                            found.append(rel)
        if not found:
            return ("No wordlist files found. Place text files under one of:\n"
                    + "\n".join(WORDLIST_SEARCH_DIRS))
        return "Available wordlists (relative paths):\n- " + "\n- ".join(sorted(found))

    def _read_wordlist(self, wordlist_name: str, limit: int = 200,
                       offset: int = 0) -> str:
        """
        Read up to `limit` lines from a wordlist file, starting at `offset`.
        The LLM uses this to obtain candidate values and then issues its own
        http_* calls to test them.
        """
        path = self._resolve_wordlist_path(wordlist_name)
        if not path:
            return (f"Wordlist '{wordlist_name}' not found. "
                    f"Call list_wordlists to see what is available.")
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                all_lines = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        except Exception as e:
            return f"Failed to read wordlist '{path}': {e}"

        chunk = all_lines[offset:offset + limit]
        if not chunk:
            return f"No entries in '{path}' at offset {offset}."
        return (f"Read {len(chunk)} entries from '{path}' "
                f"(offset {offset}, {len(all_lines)} total lines):\n" +
                "\n".join(chunk))

    # ------------------------------------------------------------------
    # Finding recorder – LLM calls this explicitly after analysis
    # ------------------------------------------------------------------
    def _record_finding(self, url: str, owasp_category: str, technique_id: str,
                        description: str, evidence: str, severity: str = "Medium") -> str:
        finding = {
            "url": url,
            "owasp_category": owasp_category,
            "technique_id": technique_id,
            "description": description,
            "evidence": evidence,
            "severity": severity,
        }
        self.recorded_findings.append(finding)
        logger.info(f"Finding recorded: [{owasp_category}] {description} at {url}")
        return (f"Finding recorded: [{severity}] [{owasp_category}] {description} "
                f"at {url} (technique: {technique_id or 'n/a'})")
