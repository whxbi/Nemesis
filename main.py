"""
main.py — patched.

Fix from the review: the old default goal, used whenever you hit Enter
with no input, was "Perform a credential dumping attack on a Windows
domain controller." Two problems with that: (1) nothing in
action_library.py does credential dumping or touches Windows/AD at all
— it's a web-app scanner (SQLi/XSS/SSTI/IDOR/directory brute-force) — so
the phrase didn't match any real capability here, it looks like leftover
boilerplate; (2) a silent default that reads as a live attack instruction
is exactly the kind of thing worth removing on principle, matched
capability or not. Now a goal is required — no attack-flavored fallback.
"""
import logging
import os

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
    print("Nemesis — autonomous red-team agent (prototype)")
    print("Only test systems you own or are explicitly authorized to test.")
    print("=" * 70)

    loader = TTPLoader()
    techniques = loader.load_techniques()
    atomic_tests = loader.load_atomic_tests()
    graph = build_ttp_graph(techniques)

    retriever = RAGRetriever(techniques)
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
        "\nEnter your red team goal (e.g. 'Find vulnerabilities on "
        "https://vulnbank.org'): "
    ).strip()

    if not goal:
        print("No goal entered — nothing to do. Run again with a goal.")
        return

    result = agent.run(goal)
    print("\n" + result)


if __name__ == "__main__":
    main()
