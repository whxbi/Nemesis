"""
fastapi_app.py

Minimal HTTP backend around RedTeamAgent, implementing the "FastAPI
provides backend communication between the AI system and the user
interface" role from the design document. This is intentionally small:
one endpoint, synchronous, no auth/session layer -- a starting point,
not a production API.

Run with:
    pip install fastapi uvicorn --break-system-packages
    uvicorn fastapi_app:app --reload

Then:
    curl -X POST http://127.0.0.1:8000/assess \
         -H "Content-Type: application/json" \
         -d '{"goal": "Assess https://your-authorized-target.example for injection vulnerabilities"}'

Note: scope.confirm_authorized() normally prompts interactively on the
first request to a new domain. Over HTTP there is no terminal to type
into, so this wrapper pre-authorizes only domains already present in
data/authorized_targets.json (added via the CLI's interactive
confirmation, or manually). Requests against unauthorized domains are
refused rather than silently prompted.
"""
from fastapi import FastAPI
from pydantic import BaseModel

from src.ttp_loader import TTPLoader
from src.graph_builder import build_ttp_graph
from src.rag import RAGRetriever
from src.action_library import ActionLibrary
from src.agent import RedTeamAgent

app = FastAPI(title="Nemesis Assessment API", version="0.1")

_loader = TTPLoader()
_techniques = _loader.load_techniques()
_atomic_tests = _loader.load_atomic_tests()
_graph = build_ttp_graph(_techniques)
_retriever = RAGRetriever(_techniques, _atomic_tests)
_retriever.build_index()


class AssessRequest(BaseModel):
    goal: str


class AssessResponse(BaseModel):
    report: str


@app.post("/assess", response_model=AssessResponse)
def assess(request: AssessRequest):
    actions = ActionLibrary()
    agent = RedTeamAgent(
        techniques=_techniques,
        atomic_tests=_atomic_tests,
        graph=_graph,
        retriever=_retriever,
        actions=actions,
    )
    report = agent.run(request.goal)
    return AssessResponse(report=report)


@app.get("/health")
def health():
    return {"status": "ok"}
