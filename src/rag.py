import chromadb
from chromadb.utils import embedding_functions
from sentence_transformers import SentenceTransformer
from typing import List, Dict
import os

CHROMA_DIR = "data/chroma_db"

class RAGRetriever:
    def __init__(self, techniques: List[Dict]):
        self.techniques = techniques
        self.model = SentenceTransformer('all-MiniLM-L6-v2')
        self.client = chromadb.PersistentClient(path=CHROMA_DIR)
        self.collection_name = "techniques"
        self._ensure_collection()
    
    def _ensure_collection(self):
        try:
            self.collection = self.client.get_collection(self.collection_name)
        except:
            self.collection = self.client.create_collection(self.collection_name)
    
    def build_index(self):
        if self.collection.count() > 0:
            print("RAG index already exists, skipping build.")
            return
        
        print("Building RAG index...")
        ids = []
        documents = []
        metadatas = []
        for i, tech in enumerate(self.techniques):
            doc = f"{tech['id']} - {tech['name']}: {tech['description']}"
            ids.append(str(i))
            documents.append(doc)
            metadatas.append({"id": tech['id'], "name": tech['name']})
        
        self.embedding_fn = embedding_functions.SentenceTransformerEmbeddingFunction(model_name="all-MiniLM-L6-v2")
        
        self.collection.add(
            ids=ids,
            documents=documents,
            metadatas=metadatas,
            embeddings=self.embedding_fn(documents)
        )
        print(f"Indexed {len(self.techniques)} techniques.")
    
    def retrieve(self, query: str, top_k: int = 5) -> List[Dict]:
        results = self.collection.query(
            query_texts=[query],
            n_results=top_k,
            include=["metadatas", "documents", "distances"]
        )
        retrieved = []
        for idx, meta in enumerate(results['metadatas'][0]):
            tech_id = meta['id']
            tech = next((t for t in self.techniques if t['id'] == tech_id), None)
            if tech:
                retrieved.append(tech)
        return retrieved
