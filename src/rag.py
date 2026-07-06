"""
src/rag.py

Retrieval layer used by the planning phase. Indexes three knowledge
sources into one ChromaDB collection so a single semantic query returns
a mix of relevant material:

  1. MITRE ATT&CK techniques (from src/ttp_loader.py)
  2. Atomic Red Team test procedures for those techniques (also loaded
     by ttp_loader.py, previously fetched but never actually used by
     the agent -- now indexed and retrievable)
  3. OWASP Top 10:2025 categories (from src/owasp_mapping.py)

Each document carries a `source_type` in its metadata so the planning
prompt can present them to the LLM under clear headings.

Chroma is used here as the vector store. If a Qdrant instance is
available in your deployment, this class can be pointed at Qdrant
instead by swapping the client construction below -- the retrieval
interface (`retrieve`) does not need to change.
"""
import os
from typing import List, Dict

import chromadb

from src.owasp_mapping import as_rag_documents as owasp_rag_documents

CHROMA_DIR = "data/chroma_db"


class RAGRetriever:
    def __init__(self, techniques: List[Dict], atomic_tests: Dict[str, List[Dict]] = None):
        self.techniques = techniques
        self.atomic_tests = atomic_tests or {}
        self.client = chromadb.PersistentClient(path=CHROMA_DIR)
        self.collection_name = "knowledge_base"
        self.collection = self.client.get_or_create_collection(self.collection_name)

    def build_index(self):
        if self.collection.count() > 0:
            print("Knowledge base index already exists, skipping build.")
            return

        print("Building knowledge base index (MITRE ATT&CK + atomic tests + OWASP Top 10:2025)...")
        ids, documents, metadatas = [], [], []
        doc_counter = 0

        # 1. MITRE ATT&CK techniques
        for tech in self.techniques:
            documents.append(f"{tech['id']} - {tech['name']}: {tech['description']}")
            ids.append(f"mitre_{doc_counter}")
            metadatas.append({
                "source_type": "mitre_attack",
                "ref_id": tech["id"],
                "name": tech["name"],
            })
            doc_counter += 1

        # 2. Atomic Red Team test procedures, linked to their technique ID
        for tech_id, entries in self.atomic_tests.items():
            atomic_tests_list = entries.get("atomic_tests", []) if isinstance(entries, dict) else []
            for atomic_test in atomic_tests_list:
                name = atomic_test.get("name", "")
                description = atomic_test.get("description", "")
                if not (name or description):
                    continue
                documents.append(f"Atomic test for {tech_id} - {name}: {description}")
                ids.append(f"atomic_{doc_counter}")
                metadatas.append({
                    "source_type": "atomic_test",
                    "ref_id": tech_id,
                    "name": name,
                })
                doc_counter += 1

        # 3. OWASP Top 10:2025 categories
        for owasp_doc in owasp_rag_documents():
            documents.append(f"{owasp_doc['id']} - {owasp_doc['name']}: {owasp_doc['description']}")
            ids.append(f"owasp_{doc_counter}")
            metadatas.append({
                "source_type": "owasp_top10_2025",
                "ref_id": owasp_doc["id"],
                "name": owasp_doc["name"],
            })
            doc_counter += 1

        self.collection.add(ids=ids, documents=documents, metadatas=metadatas)
        print(f"Indexed {len(documents)} documents "
              f"({len(self.techniques)} MITRE techniques, "
              f"{doc_counter - len(self.techniques) - 10} atomic tests, "
              f"10 OWASP Top 10:2025 categories).")

    def retrieve(self, query: str, top_k: int = 15) -> List[Dict]:
        """
        Returns a mixed list of retrieved documents, each tagged with
        source_type so the caller can group them (MITRE technique,
        atomic test, or OWASP category) when building the planning
        prompt.
        """
        results = self.collection.query(
            query_texts=[query],
            n_results=top_k,
            include=["metadatas", "documents", "distances"],
        )
        retrieved = []
        if not results["metadatas"] or not results["metadatas"][0]:
            return retrieved
        for meta, doc in zip(results["metadatas"][0], results["documents"][0]):
            retrieved.append({
                "source_type": meta.get("source_type"),
                "ref_id": meta.get("ref_id"),
                "name": meta.get("name"),
                "text": doc,
            })
        return retrieved

    def retrieve_grouped(self, query: str, top_k: int = 15) -> Dict[str, List[Dict]]:
        """Convenience wrapper: same retrieval, grouped by source_type."""
        grouped: Dict[str, List[Dict]] = {
            "mitre_attack": [],
            "atomic_test": [],
            "owasp_top10_2025": [],
        }
        for item in self.retrieve(query, top_k):
            key = item.get("source_type")
            if key in grouped:
                grouped[key].append(item)
        return grouped
