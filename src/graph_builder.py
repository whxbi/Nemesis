import networkx as nx
from typing import List, Dict


def build_ttp_graph(techniques: List[Dict]) -> nx.Graph:
    G = nx.Graph()
    for tech in techniques:
        G.add_node(tech['id'], name=tech['name'], tactics=tech.get('tactics', []))

    for i, t1 in enumerate(techniques):
        for j, t2 in enumerate(techniques):
            if i >= j:
                continue
            common = set(t1.get('tactics', [])) & set(t2.get('tactics', []))
            if common:
                G.add_edge(t1['id'], t2['id'], weight=len(common))
    return G
