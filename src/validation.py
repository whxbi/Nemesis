from pydantic import BaseModel, Field
from typing import Dict, Any

class ActionStep(BaseModel):
    action_name: str
    parameters: Dict[str, Any] = Field(default_factory=dict)
    critical: bool = False
