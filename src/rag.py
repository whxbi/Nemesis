"""
src/rag.py — patched.

Fix: removed explicit embedding_function when getting/creating the
collection. The collection already exists with the default embedding
function (same model), and passing a new one causes a conflict.
"""
import os
from typing import List, Dict

import chromadb

CHROMA_DIR = "data/chroma_db"


class RAGRetriever:
    def __init__(self, techniques: List[Dict]):
        self.techniques = techniques
        self.client = chromadb.PersistentClient(path=CHROMA_DIR)
        self.collection_name = "techniques"
        # Do NOT pass embedding_function here – use whatever is persisted
        self.collection = self.client.get_or_create_collection(self.collection_name)

    def build_index(self):
        if self.collection.count() > 0:
            print("RAG index already exists, skipping build.")
            return

        print("Building RAG index...")
        ids, documents, metadatas = [], [], []
        for i, tech in enumerate(self.techniques):
            documents.append(f"{tech['id']} - {tech['name']}: {tech['description']}")
            ids.append(str(i))
            metadatas.append({"id": tech['id'], "name": tech['name']})

        # The collection's own embedding function handles this automatically
        self.collection.add(ids=ids, documents=documents, metadatas=metadatas)
        print(f"Indexed {len(self.techniques)} techniques.")

    def retrieve(self, query: str, top_k: int = 5) -> List[Dict]:
        results = self.collection.query(
            query_texts=[query],
            n_results=top_k,
            include=["metadatas", "documents", "distances"],
        )
        retrieved = []
        for meta in results["metadatas"][0]:
            tech_id = meta["id"]
            tech = next((t for t in self.techniques if t["id"] == tech_id), None)
            if tech:
                retrieved.append(tech)
        return retrieved
