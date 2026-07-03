import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src.ttp_loader import TTPLoader

if __name__ == "__main__":
    loader = TTPLoader()
    techniques = loader.load_techniques()
    tests = loader.load_atomic_tests()
    print(f"Data ready: {len(techniques)} techniques, {len(tests)} atomic tests.")
