import logging
import os
from src.agent import RedTeamAgent
from src.ttp_loader import TTPLoader
from src.rag import RAGRetriever
from src.action_library import ActionLibrary
from src.graph_builder import build_ttp_graph

# Create logs folder
os.makedirs("logs", exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("logs/agent.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def main():
    print("\n=== Nemesis Prototype ===\n")
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
        actions=actions
    )

    goal = input("Enter your red team goal: ").strip()
    if not goal:
        goal = "Perform a credential dumping attack on a Windows domain controller."

    result = agent.run(goal)
    print("\n=== Final Report ===")
    print(result)

if __name__ == "__main__":
    main()
