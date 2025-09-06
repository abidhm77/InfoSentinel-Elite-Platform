from stix2 import MemoryStore, Filter
import json
from datetime import datetime

class AttackMapper:
    def __init__(self, stix_client):
        self.attack_data = stix_client.get_attack_enterprise()
        self.memory_store = MemoryStore(stix_data=self.attack_data)
        self.technique_cache = self._build_technique_cache()

    def _build_technique_cache(self):
        """Create fast lookup cache for ATT&CK techniques"""
        return {t['external_references'][0]['external_id']: t 
                for t in self.attack_data if t['type'] == 'attack-pattern'}

    def map_techniques(self, observed_ttps, min_confidence=70):
        """Map observed TTPs to ATT&CK techniques with STIX pattern correlation"""
        matched = []
        stix_patterns = self._parse_stix_indicators(observed_ttps)
        
        for tactic in observed_ttps.keys():
            for technique in self.technique_cache.values():
                if tactic in [phase['phase_name'] for phase in technique.get('kill_chain_phases', [])]:
                    correlation = self._correlate_stix_patterns(
                        technique['pattern'], 
                        stix_patterns
                    )
                    if correlation['score'] >= min_confidence:
                        matched.append({
                            'technique': technique,
                            'tactic': tactic,
                            'confidence': correlation['score'],
                            'detection_coverage': self._calculate_detection_coverage(technique)
                        })
        return self._prioritize_matches(matched)

    def generate_navigator_layer(self, matched_techniques, layer_name='Detection Coverage'):
        """Generate MITRE Navigator layer JSON with detection coverage visualization"""
        return {
            'name': layer_name,
            'version': '4.4',
            'domain': 'enterprise-attack',
            'description': 'Automated detection coverage analysis',
            'techniques': [{
                'techniqueID': t['technique']['external_references'][0]['external_id'],
                'score': t['confidence'],
                'metadata': [{
                    'name': 'Detection Coverage',
                    'value': f"{t['detection_coverage']}%"
                }]
            } for t in matched_techniques],
            'gradient': {
                'colors': ['#ff6666', '#ffe766', '#8ec843'],
                'minValue': 0,
                'maxValue': 100
            }
        }

    def save_navigator_layer(self, layer_json, output_path='layer.json'):
        """Save generated layer to JSON file with validation"""
        with open(output_path, 'w') as f:
            json.dump(layer_json, f, indent=2)

    def _calculate_confidence(self, indicators):
        # Implement confidence scoring logic based on IOC prevalence
        return max(min(len(indicators) * 20, 100), min_confidence)