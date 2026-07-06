"""
main.py

Entry point for the Nemesis autonomous assessment agent. Loads MITRE
ATT&CK techniques and Atomic Red Team test data, builds the combined
knowledge base (MITRE + atomic tests + OWASP Top 10:2025), and hands
control to RedTeamAgent, which runs the full Commander -> Recon ->
Planning -> Exploitation -> Adaptation -> Reporting pipeline for
whatever goal the operator provides.
"""
import logging
import os
os.environ["HF_HUB_DISABLE_SYMLINKS_WARNING"] = "1"
os.environ["TQDM_DISABLE"] = "1"
import logging
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("huggingface_hub").setLevel(logging.WARNING)
from src.ttp_loader import TTPLoader
from src.graph_builder import build_ttp_graph
from src.rag import RAGRetriever
from src.action_library import ActionLibrary
from src.agent import RedTeamAgent

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)


def main():
    print("=" * 70)
    print("Nemesis - autonomous red-team assessment platform (prototype)")
    print("Only test systems you own or are explicitly authorized to test.")
    print("=" * 70)

    loader = TTPLoader()
    techniques = loader.load_techniques()
    atomic_tests = loader.load_atomic_tests()
    graph = build_ttp_graph(techniques)

    retriever = RAGRetriever(techniques, atomic_tests)
    retriever.build_index()

    actions = ActionLibrary()
    agent = RedTeamAgent(
        techniques=techniques,
        atomic_tests=atomic_tests,
        graph=graph,
        retriever=retriever,
        actions=actions,
    )

    goal = input(
        "\nEnter your assessment goal, including the full target URL "
        "(e.g. 'Assess https://your-authorized-target.example for "
        "injection vulnerabilities'): "
    ).strip()

    if not goal:
        print("No goal entered. Nothing to do. Run again with a goal.")
        return

    result = agent.run(goal)
    print("\n" + result)


if __name__ == "__main__":
    main()
