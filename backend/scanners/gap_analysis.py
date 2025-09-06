class DetectionGapAnalyzer:
    def __init__(self, ttp_mapper, siem_client):
        self.ttp_mapper = ttp_mapper
        self.siem_client = siem_client
        self.coverage_metrics = {
            'techniques': {'detected': 0, 'total': 0},
            'tactics': {'detected': 0, 'total': 0},
            'platforms': {'windows': 0, 'linux': 0, 'macos': 0}
        }

    def calculate_coverage(self):
        """Calculate detection coverage across ATT&CK matrix"""
        attack_techniques = self.ttp_mapper.get_all_techniques()
        detected = self.siem_client.get_detected_techniques()

        self.coverage_metrics['techniques']['total'] = len(attack_techniques)
        self.coverage_metrics['techniques']['detected'] = len(
            [t for t in attack_techniques if t['id'] in detected]
        )

        return {
            'technique_coverage': self._calculate_percentage('techniques'),
            'tactic_coverage': self._calculate_percentage('tactics'),
            'platform_coverage': self._platform_distribution()
        }

    def generate_gap_report(self, min_severity=3):
        """Generate actionable gap report with MITRE Navigator layer"""
        gaps = []
        for technique in self.ttp_mapper.get_all_techniques():
            if not self.siem_client.has_detection(technique['id']):
                if technique['severity'] >= min_severity:
                    gaps.append({
                        'technique_id': technique['id'],
                        'name': technique['name'],
                        'tactics': technique['tactics'],
                        'severity': technique['severity'],
                        'recommended_sensors': self._recommend_sensors(technique)
                    })
        return self._format_navigator_layer(gaps)

    def _recommend_sensors(self, technique):
        """Return recommended sensors based on ATT&CK technique"""
        sensor_map = {
            'windows': ['Sysmon', 'Windows Event Logs', 'EDR'],
            'linux': ['Auditd', 'Osquery', 'FIM'],
            'network': ['Zeek', 'Suricata', 'NetFlow']
        }
        return sensor_map.get(technique.get('platform', 'windows'), [])

    def _format_navigator_layer(self, gaps):
        """Generate MITRE Navigator compatible JSON layer"""
        return {
            'name': 'Detection Coverage Gaps',
            'versions': {'attack': '13', 'navigator': '4.8'},
            'techniques': [{
                'techniqueID': gap['technique_id'],
                'color': '#ff6666',
                'comment': f"Missing detection for {gap['name']}. Recommended sensors: {', '.join(gap['recommended_sensors'])}"
            } for gap in gaps]
        }

    def _calculate_percentage(self, category):
        return (self.coverage_metrics[category]['detected'] / 
                self.coverage_metrics[category]['total']) * 100 if self.coverage_metrics[category]['total'] > 0 else 0

    def _platform_distribution(self):
        total = sum(self.coverage_metrics['platforms'].values())
        return {k: (v/total)*100 for k, v in self.coverage_metrics['platforms'].items()} if total > 0 else {}