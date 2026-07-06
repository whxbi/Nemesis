"""
src/agent.py

RedTeamAgent runs an assessment as a sequence of specialized LLM phases,
mirroring the multi-agent roles described in the project design
document (Commander, Reconnaissance, Planning, Exploitation, Adaptation,
Reporting). All phases run on the same local model (Ollama Mistral --
unchanged from before); "multi-agent" here means multiple distinct
prompts/responsibilities orchestrated in sequence by this class, not
multiple separate model instances.

Every decision about *what* to test, *which* payload to send, and
*whether* a response indicates a vulnerability is made by the LLM. This
module only:
  - orchestrates the phase sequence,
  - retrieves relevant MITRE ATT&CK / OWASP Top 10:2025 / atomic-test
    context for the LLM to reason over,
  - validates and executes the actions the LLM chooses,
  - assembles the final report from what the LLM explicitly recorded.

There is no scripted "if goal contains X do Y" vulnerability logic and
no automatic crawler. The one fixed control that is NOT delegated to
the LLM is scope authorization (src/scope.py) -- which domains may be
tested at all is a human decision, made explicitly, once per domain.
"""
import json
import re
import logging
import os
import time
from datetime import datetime
from typing import List, Dict, Optional, Any

import ollama

from src.validation import ActionStep
from src.action_library import ActionLibrary
from src.memory import EpisodicMemory
from src.owasp_mapping import OWASP_TOP_10_2025, find_category_by_keyword
from src import scope

logger = logging.getLogger(__name__)

MAX_LLM_RETRIES = 3
MAX_RECON_STEPS = 12
MAX_ADAPTATION_ROUNDS = 2


class AgentPlanningError(Exception):
    pass


class RedTeamAgent:
    def __init__(self, techniques, atomic_tests, graph, retriever,
                 actions: Optional[ActionLibrary] = None):
        self.techniques = techniques
        self.atomic_tests = atomic_tests
        self.graph = graph
        self.retriever = retriever
        self.actions = actions or ActionLibrary()
        self.model = os.getenv("OLLAMA_MODEL", "mistral")
        self.execution_history: List[Dict] = []
        self.memory = EpisodicMemory()
        self.start_time = time.time()

    # ------------------------------------------------------------------
    # Extract target URL from goal
    # ------------------------------------------------------------------
    def _extract_target(self, goal: str) -> Optional[str]:
        match = re.search(r'(https?://[^\s"\']+)', goal)
        return match.group(1).strip().strip('"').strip("'") if match else None

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------
    def run(self, goal: str) -> str:
        logger.info(f"Agent received goal: {goal}")
        target = self._extract_target(goal)
        if not target:
            return ("No target URL was found in the goal. Provide a goal that "
                    "includes the full target URL, e.g. "
                    "'Assess https://target.example.com for injection flaws.'")

        if not scope.confirm_authorized(target):
            return f"Refused: '{target}' is not an authorized target."

        try:
            directive = self._commander_phase(goal, target)
            logger.info(f"Commander directive: {directive}")

            recon_findings = self._recon_phase(directive, target)
            logger.info("Reconnaissance phase complete.")

            memory_context = self.memory.format_for_prompt(goal, top_k=3)
            plan = self._planning_phase(directive, target, recon_findings, memory_context)
            logger.info(f"Initial exploitation plan: {plan}")

            results = self._execute(plan)

            for round_num in range(1, MAX_ADAPTATION_ROUNDS + 1):
                if not self._needs_adaptation(directive, results):
                    break
                logger.info(f"Adaptation round {round_num}: revising plan.")
                revised_plan = self._adaptation_phase(directive, target, results)
                if not revised_plan:
                    break
                results.extend(self._execute(revised_plan))

            report = self._reporting_phase(goal, target, directive, recon_findings, results)
            self.memory.record_run(goal, target, results)
            return report

        except AgentPlanningError as e:
            return f"Could not complete the run: {e}"

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------
    def _call_llm_json(self, prompt: str, what: str, expect_array: bool = True) -> Any:
        pattern = r'\[\s*\{.*\}\s*\]' if expect_array else r'\{.*\}'
        last_error = ""
        for attempt in range(1, MAX_LLM_RETRIES + 1):
            response = ollama.chat(model=self.model, messages=[{"role": "user", "content": prompt}])
            content = response["message"]["content"].strip()
            # Remove markdown fences
            content = re.sub(r'```(?:json)?\s*', '', content)
            content = re.sub(r'```\s*$', '', content)
            # Try to parse the whole content first
            try:
                parsed = json.loads(content)
                if expect_array and isinstance(parsed, list):
                    return parsed
                elif not expect_array and isinstance(parsed, dict):
                    return parsed
            except json.JSONDecodeError:
                pass
            # Fallback to regex extraction
            json_match = re.search(pattern, content, re.DOTALL)
            if json_match:
                try:
                    return json.loads(json_match.group(0))
                except json.JSONDecodeError as e:
                    last_error = str(e)
            else:
                last_error = "no JSON found in model output"
            logger.warning(f"{what} attempt {attempt}/{MAX_LLM_RETRIES} failed: {last_error}")
            prompt += "\n\nYour response must be ONLY valid JSON, no extra text, no markdown."
        raise AgentPlanningError(f"Failed to produce valid {what} after {MAX_LLM_RETRIES} attempts.")

    # ------------------------------------------------------------------
    # Phase 1: Commander -- interprets the operator's goal into an
    # explicit, unambiguous directive that every later phase must honor
    # literally. This is where instruction precision is enforced: if the
    # operator asked for one category or one path, the directive says so
    # and nothing downstream is allowed to broaden it.
    # ------------------------------------------------------------------
    def _commander_phase(self, goal: str, target: str) -> Dict:
        owasp_list = "\n".join(
            f"- {oid}: {info['name']}" for oid, info in OWASP_TOP_10_2025.items()
        )
        prompt = f"""
You are the Commander component of an authorized security assessment
platform. Your only job is to translate the operator's instruction into
a precise, literal directive. You do not test anything yourself.

Operator's goal: "{goal}"
Confirmed target: {target}

OWASP Top 10:2025 categories (for reference):
{owasp_list}

Interpret the goal literally. Do not broaden it beyond what was asked.
Examples:
- "full scan" / "find any vulnerabilities" / "comprehensive assessment"
  -> scope_mode "full", focus_owasp_categories ["ALL"]
- "find SQL injection" / "check for injection flaws"
  -> scope_mode "targeted", focus_owasp_categories ["A05:2025"]
- "find vulnerabilities on /login"
  -> focus_paths ["/login"], everything else stays as broad or narrow
     as the rest of the sentence indicates
- "check authentication" / "brute force credentials"
  -> focus_owasp_categories ["A07:2025"]
- "check headers" / "misconfiguration"
  -> focus_owasp_categories ["A02:2025"]

Respond with ONLY a JSON object of this exact shape:
{{
  "target": "{target}",
  "objective_summary": "<one sentence, your own words>",
  "scope_mode": "full" or "targeted",
  "focus_owasp_categories": ["A05:2025"] or ["ALL"],
  "focus_paths": ["/login"] or ["ALL"],
  "notes": "<anything else the operator specified that later phases must respect>"
}}
"""
        directive = self._call_llm_json(prompt, "commander directive", expect_array=False)
        directive.setdefault("target", target)
        directive.setdefault("scope_mode", "targeted")
        directive.setdefault("focus_owasp_categories", ["ALL"])
        directive.setdefault("focus_paths", ["ALL"])
        return directive

    # ------------------------------------------------------------------
    # Phase 2: Reconnaissance -- read-only enumeration. The LLM decides
    # what to look at (using http_get, read_wordlist, list_wordlists
    # only); nothing here is scripted.
    # ------------------------------------------------------------------
    def _recon_phase(self, directive: Dict, target: str) -> str:
        prompt = f"""
You are the Reconnaissance component of an authorized security
assessment. You may only use read-only actions: http_get,
read_wordlist, list_wordlists.

Directive from the Commander:
{json.dumps(directive, indent=2)}

Plan up to {MAX_RECON_STEPS} reconnaissance steps to understand the
target ({target}) before any testing begins: what pages/endpoints
exist, what forms or parameters they expose, what technologies or
headers are visible, and what wordlists might be useful for later
enumeration. Respect focus_paths if it is not ["ALL"].

Available actions:
- http_get: {{"url": string, "headers": object (optional), "params": object (optional), "cookies": object (optional)}}
- read_wordlist: {{"wordlist_name": string, "limit": int (optional), "offset": int (optional)}}
- list_wordlists: {{}}

Respond with ONLY a JSON array of steps, each shaped as:
{{"action_name": "...", "parameters": {{...}}, "critical": false}}
"""
        seclists_guide = """
KNOWLEDGE ABOUT SECLISTS (wordlist structure):
- Fuzzing/          → payloads for fuzzing (SQLi, XSS, SSTI, etc.)
  - SQLi/           → SQL injection payloads (Generic-SQLi.txt, MySQL-SQLi.txt, etc.)
  - XSS/            → Cross-site scripting payloads
  - SSTI/           → Server-side template injection payloads
  - Directory/      → directory brute-force (common.txt, etc.)
- Passwords/        → password wordlists (rockyou.txt, weakpass_4.txt, etc.)
- Usernames/        → username lists (common.txt, etc.)
- Discovery/        → discovery lists (web-content, etc.)
- Web-Shells/       → webshell payloads
When choosing a wordlist, pick the appropriate category based on the test type.
For SQL injection tests, use Fuzzing/SQLi/ files.
For credential brute-force, use Passwords/ files.
"""
        prompt += seclists_guide
        try:
            steps = self._call_llm_json(prompt, "recon plan", expect_array=True)
        except AgentPlanningError as e:
            logger.warning(f"Recon planning failed ({e}); continuing with no recon.")
            return "Reconnaissance phase produced no plan; proceeding without prior enumeration."

        results = self._execute(steps)
        lines = ["RECONNAISSANCE FINDINGS:"]
        for r in results:
            step = r.get("step", {})
            lines.append(f"[{step.get('action_name')}] status={r.get('status')}")
            if r.get("status") == "success":
                lines.append(str(r.get("result"))[:1200])
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Phase 3: Planning -- builds the exploitation plan using recon
    # findings plus retrieved MITRE ATT&CK / atomic-test / OWASP context,
    # strictly scoped by the Commander's directive.
    # ------------------------------------------------------------------
    def _planning_phase(self, directive: Dict, target: str, recon_findings: str,
                         memory_context: str) -> List[Dict]:
        query = directive.get("objective_summary", "") + " " + " ".join(
            directive.get("focus_owasp_categories", [])
        )
        grouped = self.retriever.retrieve_grouped(query, top_k=15)

        mitre_text = "\n".join(
            f"- {d['ref_id']}: {d['name']}" for d in grouped.get("mitre_attack", [])
        ) or "(none retrieved)"
        atomic_text = "\n".join(
            f"- {d['ref_id']}: {d['name']}" for d in grouped.get("atomic_test", [])
        ) or "(none retrieved)"
        owasp_text = "\n".join(
            f"- {d['ref_id']}: {d['name']}" for d in grouped.get("owasp_top10_2025", [])
        ) or "(none retrieved)"

        prompt = f"""
You are the Planning and Exploitation component of an authorized
security assessment. You design and execute your own tests -- there is
no library of pre-built vulnerability checks. You decide what payloads,
headers, and bodies to send, based on your own knowledge of how each
class of vulnerability manifests.

Commander directive (follow literally -- do not broaden scope beyond
what it specifies):
{json.dumps(directive, indent=2)}

Target: {target}

{recon_findings}

Relevant MITRE ATT&CK techniques:
{mitre_text}

Relevant Atomic Red Team test concepts (for inspiration on technique
procedure, not literal payloads):
{atomic_text}

Relevant OWASP Top 10:2025 categories:
{owasp_text}

{memory_context}

INSTRUCTION PRECISION RULES:
- If scope_mode is "targeted" and focus_owasp_categories lists specific
  categories, test ONLY those categories. Do not also probe unrelated
  categories "just in case".
- If focus_paths is not ["ALL"], test ONLY those paths.
- If scope_mode is "full", cover a representative test across all ten
  OWASP Top 10:2025 categories where the recon findings make a category
  applicable.
- Do not let the memory context above cause you to broaden scope beyond
  what the current directive specifies.

You have these actions available (the only ones that exist):
- http_get: {{"url": string, "headers": object (optional), "params": object (optional), "cookies": object (optional)}}
- http_post: {{"url": string, "headers": object (optional), "params": object (optional), "data": object (optional), "json_body": object (optional), "cookies": object (optional)}}
- http_put: same shape as http_post
- http_patch: same shape as http_post
- http_delete: {{"url": string, "headers": object (optional), "params": object (optional), "cookies": object (optional)}}
- http_request: {{"url": string, "method": string, "headers": object (optional), "params": object (optional), "data": object (optional), "json_body": object (optional), "cookies": object (optional)}}
- read_wordlist: {{"wordlist_name": string, "limit": int (optional), "offset": int (optional)}}
- list_wordlists: {{}}
- record_finding: {{"url": string, "owasp_category": string, "technique_id": string, "description": string, "evidence": string, "severity": string}}

For every parameter, header, or body value you send, YOU choose the
value -- craft the actual test payload yourself based on your own
security knowledge of the relevant category. After sending a request
and reading its response, if you conclude the target is vulnerable,
add a record_finding step immediately after it with your reasoning as
the "evidence" and the correct owasp_category / technique_id.

All URLs must use the confirmed target: {target}. Never invent or use
a placeholder domain.

Respond with ONLY a JSON array of steps:
{{"action_name": "...", "parameters": {{...}}, "critical": false}}
"""

        # ---- Injection hint: force SQLi payloads if injection is in scope ----
        if "A05:2025" in directive.get("focus_owasp_categories", []):
            injection_hint = """
IMPORTANT: For injection tests, you MUST send test payloads in parameters (e.g., ' OR '1'='1,
' UNION SELECT NULL--, etc.) and inspect the response for errors or anomalies.
Record a finding only if the response indicates a vulnerability (e.g., SQL error,
unexpected behavior). Do NOT record findings without sending a payload first.
"""
        else:
            injection_hint = ""

        prompt += injection_hint

        return self._call_llm_json(prompt, "exploitation plan", expect_array=True)

    # ------------------------------------------------------------------
    # Phase 4: Execution
    # ------------------------------------------------------------------
    def _execute(self, plan: List[Dict]) -> List[Dict]:
        results = []
        for step in plan:
            action_name = step.get("action_name")
            params = step.get("parameters", {}) or {}

            try:
                ActionStep(action_name=action_name, parameters=params,
                           critical=bool(step.get("critical", False)))
            except Exception as e:
                logger.error(f"Step validation failed: {e}")
                results.append({"step": step, "status": "invalid", "error": str(e)})
                continue

            try:
                result = self.actions.execute(action_name, **params)
                logger.info(f"Executed {action_name} -> {str(result)[:200]}")
                results.append({"step": step, "status": "success", "result": result})
            except scope.ScopeViolation as e:
                results.append({"step": step, "status": "refused", "error": str(e)})
            except Exception as e:
                logger.error(f"Action {action_name} failed: {e}")
                results.append({"step": step, "status": "failed", "error": str(e)})

        self.execution_history.extend(results)
        return results

    # ------------------------------------------------------------------
    # Phase 5: Adaptation -- if steps failed for correctable reasons, or
    # a "full" scan yielded no findings at all despite successful
    # requests, ask the LLM to reconsider its approach once or twice
    # more, still bounded by the same directive.
    # ------------------------------------------------------------------
    def _needs_adaptation(self, directive: Dict, results: List[Dict]) -> bool:
        failed = [r for r in results if r.get("status") in ("failed", "invalid")]
        has_any_success = any(r.get("status") == "success" for r in results)
        no_findings_yet = len(self.actions.recorded_findings) == 0
        if failed and has_any_success:
            return True
        if directive.get("scope_mode") == "full" and no_findings_yet and has_any_success:
            return True
        return False

    def _adaptation_phase(self, directive: Dict, target: str, results: List[Dict]) -> List[Dict]:
        failures = [
            {"action": r["step"].get("action_name"),
             "parameters": r["step"].get("parameters"),
             "error": r.get("error")}
            for r in results if r.get("status") in ("failed", "invalid")
        ]
        prompt = f"""
You are reviewing the results of the exploitation phase of an
authorized security assessment against {target}.

Directive (still binding -- do not broaden scope):
{json.dumps(directive, indent=2)}

Steps that failed or were rejected:
{json.dumps(failures, indent=2) if failures else "(none -- all steps executed, but no findings were recorded yet)"}

Findings recorded so far: {len(self.actions.recorded_findings)}

Propose a revised, small set of follow-up steps: fix any parameter
mistakes that caused failures, and/or try different payloads or
parameters for categories the directive requires covering. Do not
repeat a step that already failed with the exact same parameters.

Use only the same actions as before (http_get, http_post, http_put,
http_patch, http_delete, http_request, read_wordlist, list_wordlists,
record_finding). All URLs must use {target}.

Respond with ONLY a JSON array of steps, or an empty array [] if no
further useful action can be taken.
"""
        try:
            return self._call_llm_json(prompt, "adaptation plan", expect_array=True)
        except AgentPlanningError as e:
            logger.warning(f"Adaptation planning failed ({e}); stopping adaptation.")
            return []

    # ------------------------------------------------------------------
    # Phase 6: Reporting -- deterministic, professional assembly of
    # everything the LLM explicitly recorded via record_finding, grouped
    # by OWASP Top 10:2025 category, plus a short LLM-written executive
    # narrative. No emojis, no decorative symbols.
    # ------------------------------------------------------------------
    def _executive_narrative(self, goal: str, target: str, findings: List[Dict]) -> str:
        summary_input = [
            {"owasp_category": f.get("owasp_category"), "severity": f.get("severity"),
             "description": f.get("description")}
            for f in findings
        ]
        prompt = f"""
Write a concise, professional executive summary (3-5 sentences, plain
prose, no bullet points, no markdown headers, no emojis or symbols) for
a security assessment report.

Assessment goal: "{goal}"
Target: {target}
Findings (structured): {json.dumps(summary_input)}

Write only the paragraph text, nothing else.
"""
        try:
            response = ollama.chat(model=self.model, messages=[{"role": "user", "content": prompt}])
            text = response["message"]["content"].strip()
            return text if text else "No executive summary could be generated."
        except Exception as e:
            logger.warning(f"Executive narrative generation failed: {e}")
            return ("An executive summary could not be generated automatically. "
                    "See the detailed findings and action log below.")

    def _reporting_phase(self, goal: str, target: str, directive: Dict,
                         recon_findings: str, results: List[Dict]) -> str:
        duration = time.time() - self.start_time
        mins, secs = divmod(int(duration), 60)
        duration_str = f"{mins}m {secs}s"
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        findings = self.actions.recorded_findings

        # Normalize / backfill category if the LLM omitted or mis-typed one
        normalized_findings = []
        for f in findings:
            category = f.get("owasp_category") or ""
            if category not in OWASP_TOP_10_2025:
                category = find_category_by_keyword(f.get("description", "") + " " + f.get("evidence", ""))
            normalized_findings.append({**f, "owasp_category": category})

        severity_rank = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Informational": 0}
        highest_severity = max(
            (severity_rank.get(f.get("severity", "Medium"), 2) for f in normalized_findings),
            default=-1,
        )
        if highest_severity >= 4:
            risk = "Critical"
        elif highest_severity >= 3:
            risk = "High"
        elif highest_severity >= 2:
            risk = "Medium"
        elif highest_severity >= 0:
            risk = "Low"
        else:
            risk = "No findings recorded"

        executive_summary = self._executive_narrative(goal, target, normalized_findings)

        by_category: Dict[str, List[Dict]] = {}
        for f in normalized_findings:
            by_category.setdefault(f["owasp_category"], []).append(f)

        report_lines = [
            "SECURITY ASSESSMENT REPORT",
            "",
            f"Target: {target}",
            f"Date: {now}",
            f"Duration: {duration_str}",
            f"Overall Risk Level: {risk}",
            f"Assessment Scope: {directive.get('scope_mode', 'targeted')} "
            f"({', '.join(directive.get('focus_owasp_categories', ['ALL']))})",
            "",
            "EXECUTIVE SUMMARY",
            executive_summary,
            "",
            "FINDINGS SUMMARY",
            f"Total requests sent: {self.actions.request_count}",
            f"Total findings recorded: {len(normalized_findings)}",
            "",
        ]

        if not normalized_findings:
            report_lines.append(
                "No vulnerabilities were recorded during this assessment. This "
                "does not guarantee the target is free of vulnerabilities -- it "
                "reflects only what was tested in this run. Review the action "
                "log below for what was actually attempted."
            )
        else:
            report_lines.append("DETAILED FINDINGS (grouped by OWASP Top 10:2025 category)")
            report_lines.append("")
            for category_id in sorted(by_category.keys()):
                items = by_category[category_id]
                category_info = OWASP_TOP_10_2025.get(category_id)
                if category_info:
                    heading = f"{category_id} - {category_info['name']}"
                else:
                    heading = category_id
                report_lines.append(heading)
                report_lines.append("-" * len(heading))
                for item in items:
                    report_lines.append(f"URL: {item.get('url')}")
                    report_lines.append(f"Severity: {item.get('severity', 'Medium')}")
                    if item.get("technique_id"):
                        report_lines.append(f"MITRE ATT&CK technique: {item.get('technique_id')}")
                    report_lines.append(f"Description: {item.get('description')}")
                    report_lines.append(f"Evidence: {item.get('evidence')}")
                    if category_info:
                        report_lines.append(f"Recommended remediation: {category_info['remediation']}")
                    report_lines.append("")

        report_lines.append("ACTION LOG")
        report_lines.append("Action | Status | Details")
        for entry in results:
            step = entry.get("step", {})
            action = step.get("action_name", "unknown")
            status = entry.get("status", "unknown")
            if status == "success":
                detail = str(entry.get("result", ""))[:120].replace("\n", " ")
            else:
                detail = str(entry.get("error", status))
            report_lines.append(f"{action} | {status} | {detail}")

        report_lines.append("")
        report_lines.append("Report generated by the Nemesis autonomous assessment platform.")

        return "\n".join(report_lines)
