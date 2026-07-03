import json
import os
import yaml
import requests
from typing import List, Dict

DATA_DIR = "data"
ATOMIC_DIR = os.path.join(DATA_DIR, "atomic_tests")
TECHNIQUES_FILE = os.path.join(DATA_DIR, "techniques.json")

class TTPLoader:
    def __init__(self):
        os.makedirs(DATA_DIR, exist_ok=True)
        os.makedirs(ATOMIC_DIR, exist_ok=True)
    
    def load_techniques(self) -> List[Dict]:
        if os.path.exists(TECHNIQUES_FILE):
            with open(TECHNIQUES_FILE, 'r') as f:
                return json.load(f)
        else:
            return self._fetch_mitre_techniques()
    
    def _fetch_mitre_techniques(self) -> List[Dict]:
        print("Fetching MITRE ATT&CK Enterprise techniques...")
        url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()
        techniques = []
        for obj in data['objects']:
            if obj['type'] == 'attack-pattern':
                tech = {
                    'id': obj.get('external_references', [{}])[0].get('external_id', ''),
                    'name': obj.get('name', ''),
                    'description': obj.get('description', ''),
                    'platforms': obj.get('x_mitre_platforms', []),
                    'tactics': [p['phase_name'] for p in obj.get('kill_chain_phases', []) if p.get('kill_chain_name') == 'mitre-attack']
                }
                if tech['id']:
                    techniques.append(tech)
        with open(TECHNIQUES_FILE, 'w') as f:
            json.dump(techniques, f, indent=2)
        print(f"Fetched {len(techniques)} techniques.")
        return techniques
    
    def load_atomic_tests(self) -> Dict[str, List[Dict]]:
        if not os.listdir(ATOMIC_DIR):
            self._fetch_atomic_tests()
        tests = {}
        for yaml_file in os.listdir(ATOMIC_DIR):
            if yaml_file.endswith('.yaml'):
                with open(os.path.join(ATOMIC_DIR, yaml_file), 'r') as f:
                    try:
                        data = yaml.safe_load(f)
                        if data:
                            tests.update(data)
                    except Exception as e:
                        print(f"Error loading {yaml_file}: {e}")
        return tests
    
    def _fetch_atomic_tests(self):
        print("Downloading Atomic Red Team tests (subset)...")
        sample_tests = {
            "T1059.001": "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1059.001/T1059.001.yaml",
            "T1003.001": "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1003.001/T1003.001.yaml",
        }
        for tech_id, url in sample_tests.items():
            try:
                resp = requests.get(url)
                resp.raise_for_status()
                with open(os.path.join(ATOMIC_DIR, f"{tech_id}.yaml"), 'w') as f:
                    f.write(resp.text)
                print(f"Downloaded {tech_id}")
            except Exception as e:
                print(f"Failed to download {tech_id}: {e}")
