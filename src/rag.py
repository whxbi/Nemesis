"""
src/rag.py — Chroma-based retrieval for MITRE ATT&CK, Atomic tests, OWASP.
"""
import os
from typing import List, Dict

import chromadb
from chromadb.utils import embedding_functions

from src.owasp_mapping import as_rag_documents as owasp_rag_documents

CHROMA_DIR = "data/chroma_db"

class RAGRetriever:
    def __init__(self, techniques: List[Dict], atomic_tests: Dict[str, List[Dict]] = None):
        self.techniques = techniques
        self.atomic_tests = atomic_tests or {}
        self.embedding_fn = embedding_functions.SentenceTransformerEmbeddingFunction(
            model_name="all-MiniLM-L6-v2"
        )
        self.client = chromadb.PersistentClient(path=CHROMA_DIR)
        self.collection_name = "knowledge_base"

        # Delete old collection to avoid embedding function conflict
        try:
            self.client.delete_collection(self.collection_name)
        except:
            pass

        # Create fresh collection with our embedding function
        self.collection = self.client.create_collection(
            self.collection_name,
            embedding_function=self.embedding_fn
        )

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

        # 2. Atomic Red Team tests
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

        # 3. OWASP Top 10:2025
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
        print(f"Indexed {len(documents)} documents.")

    def retrieve(self, query: str, top_k: int = 15) -> List[Dict]:
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
        grouped = {"mitre_attack": [], "atomic_test": [], "owasp_top10_2025": []}
        for item in self.retrieve(query, top_k):
            key = item.get("source_type")
            if key in grouped:
                grouped[key].append(item)
        return grouped
