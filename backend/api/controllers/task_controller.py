"""
Task Controller for cybersecurity task status tracking
"""
from flask_restful import Resource
from flask import jsonify

class TaskController(Resource):
    def get(self):
        """
        Get current status of all cybersecurity tasks
        """
        return jsonify({
            "tasks": [
                {
                    "id": "adversary-emulation",
                    "name": "Adversary Emulation Engine",
                    "status": "in_progress",
                    "priority": "high",
                    "description": "Core emulation engine integrating MITRE ATT&CK STIX data"
                },
                {
                    "id": "stix-integration",
                    "name": "STIX/TAXII Integration",
                    "status": "pending",
                    "priority": "high",
                    "description": "MITRE CTI feed synchronization client implementation"
                },
                {
                    "id": "ttp-mapping",
                    "name": "ATT&CK Mapping",
                    "status": "pending",
                    "priority": "high",
                    "description": "Automated technique mapping with Navigator visualization"
                }
            ]
        })