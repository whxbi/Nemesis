"""
src/validation.py — patched.

The original ActionStep accepted any string as action_name — an invalid
or hallucinated action name would pass validation here and only fail
later, inside ActionLibrary.execute()'s ValueError. Not wrong exactly,
just a validation layer that wasn't actually validating the one field
most likely to be wrong. Now it checks against the real registry.
"""
from pydantic import BaseModel, Field, field_validator
from typing import Dict, Any

# Kept as a plain list (not an import of ActionLibrary) to avoid a circular
# import between validation.py and action_library.py. Update this if you
# add/rename actions in ActionLibrary.actions.

KNOWN_ACTIONS = {
    "send_http_request", "crawl_and_scan", "test_sql_injection", "test_xss",
    "test_ssti", "test_idor", "test_privilege_escalation", "directory_bruteforce",
    "check_headers", "test_credential_bruteforce", "analyze_source_for_secrets",
    "log_vulnerability", "check_robots_txt",
    "full_scan", "scan_sqli_all_paths", "scan_xss_all_paths", "scan_ssti_all_paths",
}
class ActionStep(BaseModel):
    action_name: str
    parameters: Dict[str, Any] = Field(default_factory=dict)
    critical: bool = False

    @field_validator("action_name")
    @classmethod
    def action_must_be_known(cls, v: str) -> str:
        if v not in KNOWN_ACTIONS:
            raise ValueError(
                f"'{v}' is not a registered action. Known actions: {sorted(KNOWN_ACTIONS)}"
            )
        return v
