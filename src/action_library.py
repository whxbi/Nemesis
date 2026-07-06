"""
src/action_library.py

This module exposes only generic, protocol-level actions: HTTP requests
(GET/POST/PUT/PATCH/DELETE, plus a fully generic http_request), full
request/response introspection, and a couple of neutral file/utility
helpers (reading a wordlist, listing available wordlists, recording a
finding). There is no scripted vulnerability testing logic here --
no payload lists, no automatic crawler, no "test for SQLi/XSS/SSTI"
functions. All reasoning about what to send, where to send it, and how
to interpret the response belongs to the LLM in src/agent.py.

The only non-negotiable safety control implemented at this layer is:
  1. Scope authorization (src/scope.py) -- every request is checked
     against the operator-confirmed target list before it is sent.
  2. A request budget -- an upper bound on total requests per run, to
     keep an autonomous session bounded.

Everything else -- what to test, which OWASP Top 10:2025 category it
maps to, which MITRE ATT&CK technique it resembles, what payload to
send -- is decided by the LLM at runtime.
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

WORDLIST_SEARCH_DIRS = [
    "wordlists",
    os.path.join("data", "wordlists"),
    os.path.expanduser("~/wordlists"),
    os.path.expanduser("~/.wordlists"),
]

class RequestBudgetExceeded(Exception):
    """Raised when a run has hit its total request budget."""
    pass


class ActionLibrary:
    def __init__(self, request_delay: float = DEFAULT_REQUEST_DELAY,
                 max_requests: int = DEFAULT_MAX_REQUESTS):
        self.actions = {
            "http_get": self._http_get,
            "http_post": self._http_post,
            "http_put": self._http_put,
            "http_patch": self._http_patch,
            "http_delete": self._http_delete,
            "http_request": self._http_request,
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
    # Centralized HTTP transport. This is the single choke point where
    # scope authorization and the request budget are enforced, no matter
    # which HTTP verb the LLM asked for.
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
    # Response formatting -- always returns full request/response detail
    # so the LLM has everything it needs to make its own determination
    # about whether the target is vulnerable.
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
    # HTTP verb actions -- thin, uniform wrappers over _run_http.
    # The LLM supplies whatever headers/params/body it decides to send;
    # no payload is generated by this module.
    # ------------------------------------------------------------------
    def _http_get(self, url: str, headers: Optional[Dict] = None,
                   params: Optional[Dict] = None, cookies: Optional[Dict] = None) -> str:
        return self._run_http("GET", url, headers=headers, params=params, cookies=cookies)

    def _http_post(self, url: str, headers: Optional[Dict] = None,
                    params: Optional[Dict] = None, data: Optional[Dict] = None,
                    json_body: Optional[Dict] = None, cookies: Optional[Dict] = None) -> str:
        return self._run_http("POST", url, headers=headers, params=params,
                               data=data, json_body=json_body, cookies=cookies)

    def _http_put(self, url: str, headers: Optional[Dict] = None,
                   params: Optional[Dict] = None, data: Optional[Dict] = None,
                   json_body: Optional[Dict] = None, cookies: Optional[Dict] = None) -> str:
        return self._run_http("PUT", url, headers=headers, params=params,
                               data=data, json_body=json_body, cookies=cookies)

    def _http_patch(self, url: str, headers: Optional[Dict] = None,
                     params: Optional[Dict] = None, data: Optional[Dict] = None,
                     json_body: Optional[Dict] = None, cookies: Optional[Dict] = None) -> str:
        return self._run_http("PATCH", url, headers=headers, params=params,
                               data=data, json_body=json_body, cookies=cookies)

    def _http_delete(self, url: str, headers: Optional[Dict] = None,
                      params: Optional[Dict] = None, cookies: Optional[Dict] = None) -> str:
        return self._run_http("DELETE", url, headers=headers, params=params, cookies=cookies)

    def _http_request(self, url: str, method: str = "GET", headers: Optional[Dict] = None,
                       params: Optional[Dict] = None, data: Optional[Dict] = None,
                       json_body: Optional[Dict] = None, cookies: Optional[Dict] = None) -> str:
        """Fully generic request for any HTTP method (HEAD, OPTIONS, TRACE, etc.)."""
        return self._run_http(method.upper(), url, headers=headers, params=params,
                               data=data, json_body=json_body, cookies=cookies)

    # ------------------------------------------------------------------
    # Neutral utilities -- these do not send network traffic and do not
    # embody any attack technique. They exist so the LLM can compose its
    # own enumeration or credential-testing strategy using the HTTP
    # actions above, rather than the tool doing it automatically.
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
        found = []
        for directory in WORDLIST_SEARCH_DIRS:
            if os.path.isdir(directory):
                for root, dirs, files in os.walk(directory):
                    # Skip hidden directories
                    dirs[:] = [d for d in dirs if not d.startswith('.')]
                    for fname in files:
                        if fname.endswith('.txt') or fname.endswith('.lst') or fname.endswith('.dict'):
                            full = os.path.join(root, fname)
                            # Show relative path from base directory
                            rel = os.path.relpath(full, directory) if not full.startswith('/') else full
                            found.append(rel)
        if not found:
            return ("No wordlist files found. Place text files under ./wordlists or ~/wordlists.")
        return "Available wordlists (relative paths):\n- " + "\n- ".join(sorted(found))

    def _read_wordlist(self, wordlist_name: str, limit: int = 200,
                        offset: int = 0) -> str:
        """
        Read up to `limit` lines from a wordlist file, starting at `offset`.
        The LLM uses this to obtain candidate values (paths, usernames,
        passwords) and then issues its own http_get/http_post calls to
        test them -- this function does not send any network traffic.
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

    def _record_finding(self, url: str, owasp_category: str, technique_id: str,
                         description: str, evidence: str, severity: str = "Medium") -> str:
        """
        The LLM calls this explicitly once it has determined, from the
        evidence in an http_* response, that a target is vulnerable. This
        is a structured logging action, not a test -- the LLM has already
        done the actual analysis by the time it calls this.

        owasp_category: one of the OWASP Top 10:2025 IDs, e.g. "A05:2025"
        technique_id: a MITRE ATT&CK technique ID if applicable, e.g. "T1190"
        severity: "Critical" | "High" | "Medium" | "Low" | "Informational"
        """
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
