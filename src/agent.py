"""
src/agent.py — LLM‑driven, uses Mistral, strict prompt with composite actions.
"""
import json
import re
import logging
import os
import time
from datetime import datetime
from typing import List, Dict, Optional

import ollama

from src.validation import ActionStep
from src.action_library import ActionLibrary
from src.memory import EpisodicMemory
from src import scope

logger = logging.getLogger(__name__)

ALWAYS_CRITICAL = {
    "test_credential_bruteforce",
    "full_scan",
    "test_privilege_escalation",
}

MAX_PLAN_RETRIES = 3


class AgentPlanningError(Exception):
    pass


class RedTeamAgent:
    def __init__(self, techniques, atomic_tests, graph, retriever, actions: Optional[ActionLibrary] = None):
        self.techniques = techniques
        self.atomic_tests = atomic_tests
        self.graph = graph
        self.retriever = retriever
        self.actions = actions or ActionLibrary()
        self.model = os.getenv("OLLAMA_MODEL", "mistral")
        self.execution_history = []
        self.findings = []
        self.memory = EpisodicMemory()
        self.start_time = time.time()

    def run(self, goal: str) -> str:
        logger.info(f"Agent received goal: {goal}")
        try:
            if any(phrase in goal.lower() for phrase in
                   ["full scan", "find any vulnerability", "comprehensive scan"]):
                return self._run_full_scan(goal)
            return self._run_planned_scan(goal)
        except AgentPlanningError as e:
            return f"Could not complete the run: {e}"

    def _extract_target(self, goal: str) -> Optional[str]:
        match = re.search(r'(https?://[^\s"\']+)', goal)
        return match.group(1).strip().strip('"').strip("'") if match else None

    def _run_full_scan(self, goal: str) -> str:
        base_url = self._extract_target(goal)
        if not base_url:
            return "Could not find a target URL in your goal."
        result = self.actions.execute("full_scan", base_url=base_url, max_depth=3, max_pages=50)
        self.memory.record_run(goal, base_url, [{"step": {"action_name": "full_scan"},
                                                   "status": "success", "result": result}])
        return result

    def _run_planned_scan(self, goal: str) -> str:
        target = self._extract_target(goal)
        if target and not scope.confirm_authorized(target):
            return f"Refused: '{target}' not authorized."

        relevant_techs = self.retriever.retrieve(goal, top_k=15)
        logger.info(f"Retrieved {len(relevant_techs)} techniques.")
        memory_context = self.memory.format_for_prompt(goal, top_k=3)

        # Pass target to plan
        plan = self._plan(goal, relevant_techs, memory_context, target=target)
        logger.info(f"Initial plan: {plan}")

        # Force‑replace any URL with the real target
        plan = self._sanitize_plan(plan, target)

        # Skip reflection for speed
        # refined_plan = self._reflect(plan)
        execution_results = self._execute(plan)
        report = self._generate_report(goal, execution_results)
        self.memory.record_run(goal, target, execution_results)
        return report

    def _sanitize_plan(self, plan: List[Dict], target: str) -> List[Dict]:
        """
        Replace any hardcoded URL (e.g., vulnbank.org) with the actual target.
        """
        if not target:
            return plan
        replacements = {
            "https://vulnbank.org": target,
            "http://vulnbank.org": target,
            "vulnbank.org": target,
            "example.com": target,
            "https://example.com": target,
        }
        for step in plan:
            params = step.get("parameters", {})
            for key, value in params.items():
                if isinstance(value, str):
                    for old, new in replacements.items():
                        if old in value:
                            params[key] = value.replace(old, new)
                elif isinstance(value, dict):
                    for subkey, subvalue in value.items():
                        if isinstance(subvalue, str):
                            for old, new in replacements.items():
                                if old in subvalue:
                                    value[subkey] = subvalue.replace(old, new)
        return plan

    def _call_llm_for_json_array(self, prompt: str, what: str) -> List[Dict]:
        last_error = ""
        for attempt in range(1, MAX_PLAN_RETRIES + 1):
            response = ollama.chat(model=self.model, messages=[{"role": "user", "content": prompt}])
            content = response["message"]["content"].strip()
            json_match = re.search(r'\[\s*\{.*\}\s*\]', content, re.DOTALL)
            if json_match:
                try:
                    return json.loads(json_match.group(0))
                except json.JSONDecodeError as e:
                    last_error = str(e)
            else:
                last_error = "no JSON array found"
            logger.warning(f"{what} attempt {attempt}/{MAX_PLAN_RETRIES} failed: {last_error}")
            prompt += "\n\nRespond with ONLY a valid JSON array, no prose, no markdown fences."
        raise AgentPlanningError(f"Failed to produce valid {what} after {MAX_PLAN_RETRIES} attempts.")

    def _plan(self, goal: str, techniques: List[Dict], memory_context: str = "", target: Optional[str] = None) -> List[Dict]:
        tech_text = "\n".join([f"- {t['id']}: {t['name']} - {t['description']}" for t in techniques])

        if not target:
            target = self._extract_target(goal)

        target_instruction = ""
        if target:
            target_instruction = f"""
**IMPORTANT – YOUR TARGET IS: {target}**
You MUST use this exact domain for all URLs, base_urls, and login_urls.
Do NOT use "vulnbank.org", "example.com", or any other domain.
All actions must be scoped to: {target}
"""

        prompt = f"""
You are an autonomous red team agent. Your goal is: {goal}

{target_instruction}

Available techniques (for context, but you don't need to use them directly):
{tech_text}
{memory_context}

You have a library of atomic actions. These are the ONLY actions you may use.
For each action, you MUST use the EXACT parameters listed below.
Do NOT add any extra parameters, and do NOT invent new actions.

Actions and their EXACT parameters:
- send_http_request: {{"url": string, "method": string (GET/POST)}}  (optional: "data": dict)
- test_sql_injection: {{"url": string, "parameter_to_test": string, "method": string (GET/POST, default GET)}}
- test_xss: {{"url": string, "parameter_to_test": string, "method": string (GET/POST, default GET)}}
- test_ssti: {{"url": string, "parameter_to_test": string, "method": string (GET/POST, default GET)}}
- test_idor: {{"base_url": string, "resource_path": string, "id_param": string}}
- test_privilege_escalation: {{"base_url": string}}
- directory_bruteforce: {{"base_url": string, "wordlist_path": string (optional)}}
- check_headers: {{"url": string}}
- check_robots_txt: {{"base_url": string}}
- test_credential_bruteforce: {{"login_url": string, "username_field": string, "password_field": string, "password_wordlist": string (optional), "username_list": list (optional)}}
- log_vulnerability: {{"url": string, "parameter_to_test": string, "type": string, "evidence": string}}
- scan_sqli_all_paths: {{"base_url": string, "wordlist_path": string (optional), "params_to_test": list (optional)}}
- scan_xss_all_paths: {{"base_url": string, "wordlist_path": string (optional), "params_to_test": list (optional)}}
- scan_ssti_all_paths: {{"base_url": string, "wordlist_path": string (optional), "params_to_test": list (optional)}}
- full_scan: {{"base_url": string}}

CRITICAL INSTRUCTIONS:
- Your target is: {target if target else "extract from goal"}
- For every action that needs a URL (url, base_url, login_url), you MUST use the target domain.
- Do NOT use placeholder domains like "example.com" or "vulnbank.org".
- All subpaths should be relative to the target domain.

Create a step-by-step plan to achieve the goal. For each step:
- action_name: exact action name
- parameters: dictionary with ONLY the parameters listed above, using the target URL
- critical: boolean (true if action could cause harm)

Output ONLY a valid JSON array of steps.
"""
        return self._call_llm_for_json_array(prompt, "plan")

    def _reflect(self, plan: List[Dict]) -> List[Dict]:
        prompt = f"""
You previously created this plan:
{json.dumps(plan, indent=2)}

Critically review the plan. Identify any logical flaws, missing steps, or unnecessary actions.
Propose an improved plan. Output only the improved JSON array of steps.

IMPORTANT: Use ONLY the actions and parameters listed in the original prompt.
Do NOT add any new actions or parameters.
"""
        try:
            return self._call_llm_for_json_array(prompt, "reflection")
        except AgentPlanningError as e:
            logger.warning(f"Reflection failed ({e}); proceeding with original plan.")
            return plan

    def _execute(self, plan: List[Dict]) -> List[Dict]:
        results = []
        for step in plan:
            action_name = step.get("action_name")
            params = step.get("parameters", {})
            critical = bool(step.get("critical", False)) or action_name in ALWAYS_CRITICAL

            if action_name == "test_sql_injection" and not params.get("parameter_to_test"):
                print(f"\n⚠ Missing 'parameter_to_test' for {action_name}.")
                param = input("Enter parameter to test: ").strip()
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
                print(f"\n⚠ CRITICAL ACTION: {action_name} with params {params}")
                approval = input("Approve? (y/n): ").strip().lower()
                if approval != 'y':
                    logger.info(f"Action {action_name} blocked.")
                    results.append({"step": step, "status": "blocked", "reason": "user declined"})
                    continue

            try:
                result = self.actions.execute(action_name, **params)
                logger.info(f"Executed {action_name}: {result}")
                results.append({"step": step, "status": "success", "result": result})
                if isinstance(result, str) and any(kw in result for kw in ("detected", "vulnerability", "found")):
                    self.findings.append(result)
            except Exception as e:
                logger.error(f"Action {action_name} failed: {e}")
                results.append({"step": step, "status": "failed", "error": str(e)})

        self.execution_history.extend(results)
        return results

    def _generate_report(self, goal: str, findings_or_results: List) -> str:
        # Calculate duration
        duration = time.time() - self.start_time
        mins, secs = divmod(int(duration), 60)
        duration_str = f"{mins}m {secs}s"

        target = self._extract_target(goal) or "unspecified"

        if all(isinstance(x, str) for x in findings_or_results):
            all_findings = findings_or_results
            logs = []
        else:
            all_findings = []
            logs = []
            for item in findings_or_results:
                if isinstance(item, dict):
                    if item.get("status") == "success":
                        result = item.get("result", "")
                        if result and any(kw in result for kw in ("detected", "vulnerability", "found")):
                            all_findings.append(result)
                    logs.append(item)

        vuln_categories = {
            "SQL Injection": [],
            "XSS": [],
            "SSTI": [],
            "IDOR": [],
            "Privilege Escalation": [],
            "Security Headers": [],
            "Credentials": [],
            "Other": [],
        }

        for finding in all_findings:
            if "SQL Injection" in finding:
                vuln_categories["SQL Injection"].append(finding)
            elif "XSS" in finding:
                vuln_categories["XSS"].append(finding)
            elif "SSTI" in finding:
                vuln_categories["SSTI"].append(finding)
            elif "IDOR" in finding:
                vuln_categories["IDOR"].append(finding)
            elif "Privilege escalation" in finding or "accessible admin" in finding:
                vuln_categories["Privilege Escalation"].append(finding)
            elif "Missing security headers" in finding:
                vuln_categories["Security Headers"].append(finding)
            elif "Credentials found" in finding:
                vuln_categories["Credentials"].append(finding)
            else:
                vuln_categories["Other"].append(finding)

        total_findings = len(all_findings)
        critical_findings = sum(1 for f in all_findings if "SQL Injection" in f or "SSTI" in f or "Privilege Escalation" in f)

        if critical_findings > 0:
            risk = "🔴 High"
        elif total_findings > 0:
            risk = "🟡 Medium"
        else:
            risk = "🟢 Low"

        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        report = f"""
# 🛡 Security Assessment Report

**Target:** `{target}`
**Date:** {now}
**Duration:** {duration_str}
**Risk Level:** {risk}

---

## 📊 Executive Summary

- Total checks performed: {len(findings_or_results)}
- Vulnerabilities found: {total_findings}
- Critical issues: {critical_findings}

---

## 🔍 Detailed Findings
"""

        has_findings = False
        for category, items in vuln_categories.items():
            if items:
                has_findings = True
                if category == "SQL Injection":
                    severity = "🔴 High"
                elif category == "SSTI":
                    severity = "🔴 High"
                elif category == "Privilege Escalation":
                    severity = "🔴 High"
                elif category == "XSS":
                    severity = "🟡 Medium"
                elif category == "IDOR":
                    severity = "🟡 Medium"
                elif category == "Credentials":
                    severity = "🔴 High"
                elif category == "Security Headers":
                    severity = "🟠 Low"
                else:
                    severity = "🟡 Medium"

                report += f"\n### {category} ({severity})\n"
                for finding in items:
                    report += f"- {finding}\n"

        if not has_findings:
            report += "\n✅ No critical vulnerabilities were detected during the scan. However, review the action log for complete context.\n"

        if logs:
            report += "\n## 📋 Action Log\n\n"
            report += "| Action | Status | Details |\n"
            report += "|--------|--------|--------|\n"
            for entry in logs:
                step = entry.get("step", {})
                action = step.get("action_name", "unknown")
                status = entry.get("status", "unknown")
                if status == "success":
                    result = entry.get("result", "")[:80].replace("\n", " ")
                elif status == "failed":
                    result = entry.get("error", "error")
                elif status == "blocked":
                    result = "Blocked by user"
                else:
                    result = status
                report += f"| {action} | {status} | {result} |\n"

        report += "\n## 💡 Recommendations\n\n"
        if critical_findings > 0:
            report += "- **Immediate action required:** Address critical vulnerabilities (SQLi, SSTI, privilege escalation) as top priority.\n"
            if "SQL Injection" in vuln_categories and vuln_categories["SQL Injection"]:
                report += "  - Use parameterized queries and input validation to prevent SQL injection.\n"
            if "SSTI" in vuln_categories and vuln_categories["SSTI"]:
                report += "  - Sanitize user inputs and avoid evaluating templates with user-controlled data.\n"
            if "Privilege Escalation" in vuln_categories and vuln_categories["Privilege Escalation"]:
                report += "  - Restrict access to admin endpoints and enforce role-based access control.\n"
        if "XSS" in vuln_categories and vuln_categories["XSS"]:
            report += "- Implement output encoding and Content Security Policy (CSP) to mitigate XSS.\n"
        if "Security Headers" in vuln_categories and vuln_categories["Security Headers"]:
            report += "- Add missing security headers (X-Frame-Options, X-XSS-Protection, CSP, HSTS).\n"
        if "Credentials" in vuln_categories and vuln_categories["Credentials"]:
            report += "- Enforce strong password policies and consider multi-factor authentication.\n"
        if total_findings == 0:
            report += "- No vulnerabilities found, but continue regular security assessments.\n"

        report += "\n---\n*Report generated by Nemesis Red-Team Agent (prototype)*"
        return report
