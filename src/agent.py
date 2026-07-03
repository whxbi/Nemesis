import json
import re
import logging
import os
import ollama
from typing import List, Dict
from src.validation import ActionStep
from src.action_library import ActionLibrary

logger = logging.getLogger(__name__)

class RedTeamAgent:
    def __init__(self, techniques, atomic_tests, graph, retriever, actions):
        self.techniques = techniques
        self.atomic_tests = atomic_tests
        self.graph = graph
        self.retriever = retriever
        self.actions = actions
        self.model = os.getenv("OLLAMA_MODEL", "mistral")
        self.execution_history = []
        self.findings = []

    def run(self, goal: str) -> str:
        logger.info(f"Agent received goal: {goal}")
        if any(phrase in goal.lower() for phrase in ["find any vulnerability", "full scan", "comprehensive scan"]):
            return self._run_full_scan(goal)
        else:
            return self._run_planned_scan(goal)

    def _run_full_scan(self, goal: str) -> str:
        """Automatically crawl and recursively scan the target domain for all vulnerabilities."""
        import re
        url_match = re.search(r'(https?://[^\s"\']+)', goal)
        if not url_match:
            return "Could not find a target URL in your goal. Please specify a URL like 'https://vulnbank.org'."
        base_url = url_match.group(1).strip().strip('"').strip("'")

        # Use the new crawler (depth 3, max 50 pages)
        result = self.actions.execute("crawl_and_scan", base_url=base_url, max_depth=3, max_pages=50)
        return result

    def _run_planned_scan(self, goal: str) -> str:
        relevant_techs = self.retriever.retrieve(goal, top_k=15)
        logger.info(f"Retrieved {len(relevant_techs)} techniques.")
        plan = self._plan(goal, relevant_techs)
        logger.info(f"Initial plan: {plan}")
        refined_plan = self._reflect(plan)
        logger.info(f"Refined plan: {refined_plan}")
        execution_results = self._execute(refined_plan)
        report = self._generate_report(goal, execution_results)
        return report

    def _plan(self, goal: str, techniques: List[Dict]) -> Dict:
        tech_text = "\n".join([f"- {t['id']}: {t['name']} - {t['description']}" for t in techniques])
        prompt = f"""
You are an autonomous red team agent. Your goal is: {goal}

Available techniques (with IDs, names, and descriptions):
{tech_text}

You have a library of atomic actions with these parameters:
- send_http_request: requires url (string), method (GET/POST), optional data (dict)
- test_sql_injection: requires url (string), parameter_to_test (string, e.g., 'username', 'id', 'email', 'password')
- test_xss: requires url (string), parameter_to_test (string)
- test_ssti: requires url (string), parameter_to_test (string)
- test_idor: requires base_url (string), resource_path (string), id_param (string)
- test_privilege_escalation: requires base_url (string)
- directory_bruteforce: requires base_url (string)
- check_headers: requires url (string)
- test_credential_bruteforce: requires login_url (string), username_field (string), password_field (string)
- log_vulnerability: requires url (string), parameter_to_test (string), type (string), evidence (string)

Create a step-by-step plan to achieve the goal. For each step, specify:
- action_name: one of the atomic actions
- parameters: dictionary with the required parameters
- critical: boolean (True if requires human approval)

Output ONLY a valid JSON array of steps, e.g.:
[
  {{"action_name": "send_http_request", "parameters": {{"url": "https://vulnbank.org", "method": "GET"}}, "critical": false}},
  {{"action_name": "test_sql_injection", "parameters": {{"url": "https://vulnbank.org/login", "parameter_to_test": "username"}}, "critical": true}}
]
"""
        response = ollama.chat(model=self.model, messages=[{"role": "user", "content": prompt}])
        content = response['message']['content'].strip()
        json_match = re.search(r'\[\s*\{.*\}\s*\]', content, re.DOTALL)
        if json_match:
            json_str = json_match.group(0)
            try:
                plan = json.loads(json_str)
                return plan
            except json.JSONDecodeError:
                pass
        logger.warning("Failed to parse LLM JSON, using fallback plan.")
        return [
            {"action_name": "send_http_request", "parameters": {"url": "https://vulnbank.org", "method": "GET"}, "critical": False},
            {"action_name": "test_sql_injection", "parameters": {"url": "https://vulnbank.org/login", "parameter_to_test": "username"}, "critical": True}
        ]

    def _reflect(self, plan: List[Dict]) -> List[Dict]:
        prompt = f"""
You previously created this plan:
{json.dumps(plan, indent=2)}

Critically review the plan. Identify any logical flaws, missing steps, or unnecessary actions.
Propose an improved plan. Output only the improved JSON array of steps.
"""
        response = ollama.chat(model=self.model, messages=[{"role": "user", "content": prompt}])
        content = response['message']['content'].strip()
        json_match = re.search(r'\[\s*\{.*\}\s*\]', content, re.DOTALL)
        if json_match:
            json_str = json_match.group(0)
            try:
                refined = json.loads(json_str)
                return refined
            except json.JSONDecodeError:
                pass
        logger.warning("Reflection failed, using original plan.")
        return plan

    def _execute(self, plan: List[Dict]) -> List[Dict]:
        results = []
        for step in plan:
            action_name = step.get("action_name")
            params = step.get("parameters", {})
            critical = step.get("critical", False)

            if action_name == "test_sql_injection" and not params.get("parameter_to_test"):
                print(f"\n⚠️ Missing 'parameter_to_test' for {action_name}.")
                param = input("Enter parameter to test (e.g., username, id): ").strip()
                if param:
                    params["parameter_to_test"] = param
                else:
                    results.append({"step": step, "status": "failed", "error": "No parameter provided"})
                    continue

            try:
                validated = ActionStep(action_name=action_name, parameters=params, critical=critical)
            except Exception as e:
                logger.error(f"Step validation failed: {e}")
                results.append({"step": step, "status": "invalid", "error": str(e)})
                continue

            if validated.critical:
                print(f"\n⚠️ CRITICAL ACTION: {action_name} with params {params}")
                approval = input("Approve? (y/n): ").strip().lower()
                if approval != 'y':
                    logger.info(f"Action {action_name} blocked by user.")
                    results.append({"step": step, "status": "blocked", "reason": "user declined"})
                    continue

            try:
                result = self.actions.execute(action_name, **params)
                logger.info(f"Executed {action_name}: {result}")
                results.append({"step": step, "status": "success", "result": result})
                if "detected" in result or "vulnerability" in result or "found" in result:
                    self.findings.append(result)
            except Exception as e:
                logger.error(f"Action {action_name} failed: {e}")
                results.append({"step": step, "status": "failed", "error": str(e)})

        self.execution_history.extend(results)
        return results

    def _generate_report(self, goal: str, findings_or_results: List) -> str:
        if all(isinstance(x, str) for x in findings_or_results):
            report = f"# 🛡️ Security Assessment Report\n\n"
            report += f"**Goal:** {goal}\n\n"
            report += "## 🔍 Findings\n\n"
            vulnerabilities = []
            for finding in findings_or_results:
                if "No" in finding and "found" in finding:
                    continue
                if any(kw in finding.lower() for kw in ["detected", "vulnerability", "found", "discovered", "accessible"]):
                    if "No" in finding and "found" in finding:
                        continue
                    vulnerabilities.append(finding)
            if vulnerabilities:
                for vuln in vulnerabilities:
                    if "SQL Injection" in vuln:
                        report += f"### ⚠️ {vuln}\n\n"
                    elif "XSS" in vuln:
                        report += f"### 🛡️ {vuln}\n\n"
                    elif "SSTI" in vuln:
                        report += f"### 🧪 {vuln}\n\n"
                    elif "IDOR" in vuln:
                        report += f"### 🔑 {vuln}\n\n"
                    elif "Privilege escalation" in vuln or "accessible admin" in vuln:
                        report += f"### ⬆️ {vuln}\n\n"
                    elif "Missing security headers" in vuln:
                        report += f"### 🔒 {vuln}\n\n"
                    elif "Credentials found" in vuln:
                        report += f"### 🔐 {vuln}\n\n"
                    else:
                        report += f"- {vuln}\n"
            else:
                report += "No critical vulnerabilities found in the automated scan.\n\n"

            report += "\n## 📊 Summary\n"
            report += f"Total checks performed: {len(findings_or_results)}\n"
            report += f"Vulnerabilities found: {len(vulnerabilities)}\n"
            report += "For detailed evidence, please review the full log above (the 'Result:' lines).\n"
            return report
        else:
            success = any(r.get("status") == "success" for r in findings_or_results)
            report = f"Goal: {goal}\n\nExecution log:\n"
            for r in findings_or_results:
                report += f"- {r}\n"
            report += f"\nOverall status: {'PARTIAL SUCCESS' if success else 'FAILED'}"
            return report
