# src/validation.py

from pydantic import BaseModel, Field, field_validator
from typing import Dict, Any
import re

ACTION_REGISTRY = {
    "http_get": {
        "required": ["url"],
        "optional": ["headers", "params", "cookies"],
    },
    "http_post": {
        "required": ["url"],
        "optional": ["headers", "params", "data", "json_body", "cookies"],
    },
    "read_wordlist": {
        "required": ["wordlist_name"],
        "optional": ["limit", "offset"],
    },
    "list_wordlists": {
        "required": [],
        "optional": [],
    },
    "record_finding": {
        "required": ["url", "owasp_category", "technique_id", "description", "evidence"],
        "optional": ["severity"],
    },
}

KNOWN_ACTIONS = set(ACTION_REGISTRY.keys())

def _is_valid_url(url: str) -> bool:
    if not isinstance(url, str):
        return False
    if not url.startswith(("http://", "https://")):
        return False
    if len(url) <= 8:
        return False
    return bool(re.match(r'^https?://[^\s"\'<>]+$', url))

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


    @field_validator("parameters")
    @classmethod
    def validate_parameters(cls, params: Dict[str, Any], info) -> Dict[str, Any]:
        action_name = info.data.get("action_name")
        if not action_name or action_name not in ACTION_REGISTRY:
            return params

        registry = ACTION_REGISTRY[action_name]
        required_params = registry.get("required", [])
        optional_params = registry.get("optional", [])
        allowed = set(required_params) | set(optional_params)

        missing = [p for p in required_params if p not in params]
        if missing:
            raise ValueError(
                f"Action '{action_name}' missing required parameters: {missing}. "
                f"Required: {required_params}. Got: {list(params.keys())}"
            )

        unknown = [p for p in params.keys() if p not in allowed]
        if unknown:
            raise ValueError(
                f"Action '{action_name}' has unknown parameters: {unknown}. "
                f"Allowed: {sorted(allowed)}"
            )

        if "url" in params and isinstance(params["url"], str):
            if not _is_valid_url(params["url"]):
                raise ValueError(
                    f"Parameter 'url' is not a valid http(s) URL: '{params['url']}'"
                )

        return params
