"""
src/memory.py — persistent learning across runs.

This is the "learn from everything it did previously" feature.

IMPORTANT — what this is NOT: it does not retrain/fine-tune the Ollama
model's weights. Retraining a local model after every run needs GPU
infrastructure, curated datasets, and real ML-ops discipline — doing it
casually after every single prompt would degrade the model over time
(catastrophic forgetting), not improve it.

What this IS: an episodic memory store. After every run, we write a short
structured summary of what happened (goal, target, which actions worked,
which failed, what was found). Before every new run, we pull the most
relevant past summaries and hand them to the LLM as context: "here's what
you learned last time you tried something like this." The model's weights
never change — its *prompt* gets smarter over time instead. This is the
standard way agent frameworks implement "memory" and it's far more
reliable than actual retraining for a project this size.

Storage is two-layer, same pattern as your existing rag.py:
  1. data/memory/episodes.jsonl   — append-only, human-readable, source of truth
  2. Chroma collection "episodes" — vector index over episode summaries,
     so retrieval is semantic ("SQLi against login forms" will match past
     episodes about SQLi even if the wording differs)

Both live next to your existing data/chroma_db, so no new dependency and
no new setup step.
"""
import json
import os
import time
import uuid
from typing import Dict, List, Optional

import chromadb
from chromadb.utils import embedding_functions

DATA_DIR = "data"
MEMORY_DIR = os.path.join(DATA_DIR, "memory")
EPISODES_FILE = os.path.join(MEMORY_DIR, "episodes.jsonl")
CHROMA_DIR = os.path.join(DATA_DIR, "chroma_db")
COLLECTION_NAME = "episodes"


class EpisodicMemory:
    def __init__(self):
        os.makedirs(MEMORY_DIR, exist_ok=True)
        self.embedding_fn = embedding_functions.SentenceTransformerEmbeddingFunction(
            model_name="all-MiniLM-L6-v2"
        )
        self.client = chromadb.PersistentClient(path=CHROMA_DIR)
        self.collection = self.client.get_or_create_collection(
            COLLECTION_NAME, embedding_function=self.embedding_fn
        )

    # ---------------------------------------------------------------
    # Writing memory (call this once, at the end of a run)
    # ---------------------------------------------------------------
    def record_run(self, goal: str, target: Optional[str], results: List[Dict]) -> str:
        """
        Summarizes a completed run's action results into a short episode
        and stores it. Returns the episode's id.

        `results` is the list agent.py builds in _execute():
        [{"step": {...}, "status": "success"/"failed"/"refused"/"invalid",
          "result": "...", "error": "..."}]
        """
        episode_id = str(uuid.uuid4())[:8]
        summary = self._summarize(goal, target, results)
        record = {
            "id": episode_id,
            "ts": time.time(),
            "goal": goal,
            "target": target,
            "summary": summary,
            "action_count": len(results),
        }
        with open(EPISODES_FILE, "a") as f:
            f.write(json.dumps(record) + "\n")

        self.collection.upsert(
            ids=[episode_id],
            documents=[f"Goal: {goal}\n{summary}"],
            metadatas=[{"goal": goal, "target": target or "", "ts": record["ts"]}],
        )
        return episode_id

    def _summarize(self, goal: str, target: Optional[str], results: List[Dict]) -> str:
        """
        Rule-based summary — deliberately NOT another LLM call. An LLM
        summarizing its own run risks hallucinating a cleaner story than
        what actually happened. Reading the structured status fields
        directly is slower to write but always accurate.
        """
        succeeded, failed, refused, invalid = [], [], [], []
        for r in results:
            action = r.get("step", {}).get("action_name", "?")
            status = r.get("status")
            if status == "success":
                outcome = str(r.get("result", ""))[:160]
                succeeded.append(f"{action} -> {outcome}")
            elif status == "failed":
                failed.append(f"{action} ({r.get('error', 'unknown error')})")
            elif status == "refused":
                refused.append(action)
            elif status == "invalid":
                invalid.append(action)

        lines = [f"Target: {target or 'unspecified'}"]
        if succeeded:
            lines.append("Worked: " + "; ".join(succeeded))
        if failed:
            lines.append("Failed: " + "; ".join(failed))
        if refused:
            lines.append("Refused (out of scope): " + ", ".join(refused))
        if invalid:
            lines.append("Rejected as invalid: " + ", ".join(invalid))
        return "\n".join(lines)

    # ---------------------------------------------------------------
    # Reading memory (call this before planning a new run)
    # ---------------------------------------------------------------
    def retrieve_relevant(self, goal: str, top_k: int = 3) -> List[str]:
        """
        Returns up to top_k past episode summaries relevant to a new goal,
        formatted as ready-to-paste prompt text. Empty list on first run —
        that's expected and fine, there's nothing to learn from yet.
        """
        if self.collection.count() == 0:
            return []
        results = self.collection.query(
            query_texts=[goal],
            n_results=min(top_k, self.collection.count()),
            include=["documents", "metadatas"],
        )
        return results["documents"][0] if results["documents"] else []

    def format_for_prompt(self, goal: str, top_k: int = 3) -> str:
        """Convenience wrapper: memory as a ready-to-insert prompt block."""
        episodes = self.retrieve_relevant(goal, top_k)
        if not episodes:
            return ""
        block = "\n\n".join(f"Past run:\n{ep}" for ep in episodes)
        return (
            "\n\nLESSONS FROM PREVIOUS RUNS (use these to avoid repeating "
            "failed approaches and to prioritize what has worked before -- "
            "but never let this broaden the scope of the CURRENT directive):\n"
            f"{block}\n"
        )

    def all_episodes(self) -> List[Dict]:
        """Read back the full durable log — useful for a report/CLI view."""
        if not os.path.exists(EPISODES_FILE):
            return []
        out = []
        with open(EPISODES_FILE) as f:
            for line in f:
                line = line.strip()
                if line:
                    out.append(json.loads(line))
        return out
