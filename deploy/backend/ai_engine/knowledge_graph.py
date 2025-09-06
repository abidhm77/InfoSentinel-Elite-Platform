"""
Knowledge Graph for Attack Patterns and Techniques

This module implements a graph-based representation of attack patterns,
vulnerabilities, and their relationships to support AI-driven penetration testing.
"""

import networkx as nx
import json
import os
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple, Set

class AttackKnowledgeGraph:
    """
    A knowledge graph implementation for modeling attack patterns, techniques,
    vulnerabilities, and their relationships to support AI-driven penetration testing.
    """
    
    def __init__(self):
        """Initialize the knowledge graph."""
        self.graph = nx.DiGraph()
        self.load_initial_data()
        
    def load_initial_data(self):
        """Load initial MITRE ATT&CK and OWASP data into the graph."""
        # Add OWASP Top 10 nodes
        owasp_categories = [
            {"id": "A01:2021", "name": "Broken Access Control", 
             "description": "Access control enforces policy such that users cannot act outside of their intended permissions."},
            {"id": "A02:2021", "name": "Cryptographic Failures", 
             "description": "Failures related to cryptography which often lead to sensitive data exposure or system compromise."},
            {"id": "A03:2021", "name": "Injection", 
             "description": "Injection flaws, such as SQL, NoSQL, OS, and LDAP injection occur when untrusted data is sent to an interpreter."},
            {"id": "A04:2021", "name": "Insecure Design", 
             "description": "Insecure design refers to flaws in the design that cannot be fixed by proper implementation."},
            {"id": "A05:2021", "name": "Security Misconfiguration", 
             "description": "Security misconfiguration is the most commonly seen issue, often the result of insecure default configurations."},
            {"id": "A06:2021", "name": "Vulnerable and Outdated Components", 
             "description": "Components, such as libraries, frameworks, and other software modules, run with the same privileges as the application."},
            {"id": "A07:2021", "name": "Identification and Authentication Failures", 
             "description": "Authentication failures can allow attackers to assume other users' identities."},
            {"id": "A08:2021", "name": "Software and Data Integrity Failures", 
             "description": "Software and data integrity failures relate to code and infrastructure that does not protect against integrity violations."},
            {"id": "A09:2021", "name": "Security Logging and Monitoring Failures", 
             "description": "This category helps detect, escalate, and respond to active breaches."},
            {"id": "A10:2021", "name": "Server-Side Request Forgery", 
             "description": "SSRF flaws occur whenever a web application is fetching a remote resource without validating the user-supplied URL."}
        ]
        
        for category in owasp_categories:
            self.add_node(
                node_id=category["id"],
                node_type="vulnerability_category",
                properties={
                    "name": category["name"],
                    "description": category["description"],
                    "framework": "OWASP Top 10"
                }
            )
        
        # Add some common vulnerabilities and link to OWASP categories
        vulnerabilities = [
            {
                "id": "CVE-2021-44228", 
                "name": "Log4Shell", 
                "description": "Remote code execution vulnerability in Apache Log4j",
                "categories": ["A03:2021", "A06:2021"],
                "cwe": "CWE-502"
            },
            {
                "id": "CVE-2021-26084", 
                "name": "Confluence OGNL Injection", 
                "description": "OGNL injection in Atlassian Confluence Server",
                "categories": ["A03:2021"],
                "cwe": "CWE-917"
            },
            {
                "id": "CVE-2021-34473", 
                "name": "ProxyShell", 
                "description": "Microsoft Exchange Server remote code execution vulnerability",
                "categories": ["A01:2021", "A05:2021"],
                "cwe": "CWE-269"
            }
        ]
        
        for vuln in vulnerabilities:
            self.add_node(
                node_id=vuln["id"],
                node_type="vulnerability",
                properties={
                    "name": vuln["name"],
                    "description": vuln["description"],
                    "cwe": vuln["cwe"]
                }
            )
            
            # Link vulnerability to its OWASP categories
            for category_id in vuln["categories"]:
                self.add_edge(
                    source_id=vuln["id"],
                    target_id=category_id,
                    edge_type="belongs_to",
                    properties={"confidence": 0.9}
                )
        
        # Add attack techniques
        techniques = [
            {
                "id": "T1190", 
                "name": "Exploit Public-Facing Application", 
                "description": "Adversaries may attempt to exploit vulnerabilities in public-facing applications.",
                "vulnerabilities": ["CVE-2021-44228", "CVE-2021-26084", "CVE-2021-34473"],
                "tactics": ["initial_access"]
            },
            {
                "id": "T1059", 
                "name": "Command and Scripting Interpreter", 
                "description": "Adversaries may abuse command and script interpreters to execute commands.",
                "vulnerabilities": ["CVE-2021-44228"],
                "tactics": ["execution"]
            },
            {
                "id": "T1210", 
                "name": "Exploitation of Remote Services", 
                "description": "Adversaries may exploit remote services to gain unauthorized access to systems.",
                "vulnerabilities": ["CVE-2021-34473"],
                "tactics": ["lateral_movement"]
            }
        ]
        
        for technique in techniques:
            self.add_node(
                node_id=technique["id"],
                node_type="attack_technique",
                properties={
                    "name": technique["name"],
                    "description": technique["description"],
                    "tactics": technique["tactics"],
                    "framework": "MITRE ATT&CK"
                }
            )
            
            # Link technique to vulnerabilities it can exploit
            for vuln_id in technique["vulnerabilities"]:
                self.add_edge(
                    source_id=technique["id"],
                    target_id=vuln_id,
                    edge_type="exploits",
                    properties={"confidence": 0.85}
                )
    
    def add_node(self, node_id: str, node_type: str, properties: Dict[str, Any]) -> None:
        """
        Add a node to the knowledge graph.
        
        Args:
            node_id: Unique identifier for the node
            node_type: Type of the node (e.g., vulnerability, technique)
            properties: Dictionary of node properties
        """
        properties["type"] = node_type
        properties["last_updated"] = datetime.now().isoformat()
        self.graph.add_node(node_id, **properties)
    
    def add_edge(self, source_id: str, target_id: str, edge_type: str, properties: Dict[str, Any]) -> None:
        """
        Add an edge between two nodes in the knowledge graph.
        
        Args:
            source_id: ID of the source node
            target_id: ID of the target node
            edge_type: Type of relationship
            properties: Dictionary of edge properties
        """
        properties["type"] = edge_type
        properties["last_updated"] = datetime.now().isoformat()
        self.graph.add_edge(source_id, target_id, **properties)
    
    def get_related_nodes(self, node_id: str, edge_type: Optional[str] = None) -> List[Tuple[str, Dict[str, Any]]]:
        """
        Get nodes related to the specified node.
        
        Args:
            node_id: ID of the node to find relationships for
            edge_type: Optional filter for specific relationship types
            
        Returns:
            List of tuples containing related node IDs and their properties
        """
        related_nodes = []
        
        # Check outgoing edges
        for _, target, data in self.graph.out_edges(node_id, data=True):
            if edge_type is None or data.get("type") == edge_type:
                target_data = self.graph.nodes[target]
                related_nodes.append((target, target_data))
        
        # Check incoming edges
        for source, _, data in self.graph.in_edges(node_id, data=True):
            if edge_type is None or data.get("type") == edge_type:
                source_data = self.graph.nodes[source]
                related_nodes.append((source, source_data))
                
        return related_nodes
    
    def find_attack_paths(self, source_type: str, target_type: str, max_depth: int = 3) -> List[List[str]]:
        """
        Find possible attack paths between node types.
        
        Args:
            source_type: Type of the source nodes
            target_type: Type of the target nodes
            max_depth: Maximum path length to consider
            
        Returns:
            List of attack paths (each path is a list of node IDs)
        """
        source_nodes = [n for n, data in self.graph.nodes(data=True) 
                       if data.get("type") == source_type]
        target_nodes = [n for n, data in self.graph.nodes(data=True) 
                       if data.get("type") == target_type]
        
        all_paths = []
        for source in source_nodes:
            for target in target_nodes:
                try:
                    paths = list(nx.all_simple_paths(self.graph, source, target, cutoff=max_depth))
                    all_paths.extend(paths)
                except nx.NetworkXNoPath:
                    continue
        
        return all_paths
    
    def suggest_exploits(self, vulnerability_id: str) -> List[Dict[str, Any]]:
        """
        Suggest possible exploit techniques for a given vulnerability.
        
        Args:
            vulnerability_id: ID of the vulnerability
            
        Returns:
            List of attack techniques that can exploit the vulnerability
        """
        exploits = []
        
        for source, _, data in self.graph.in_edges(vulnerability_id, data=True):
            if data.get("type") == "exploits":
                source_data = self.graph.nodes[source]
                if source_data.get("type") == "attack_technique":
                    exploits.append({
                        "id": source,
                        "name": source_data.get("name"),
                        "description": source_data.get("description"),
                        "confidence": data.get("confidence", 0.0)
                    })
        
        return sorted(exploits, key=lambda x: x.get("confidence", 0), reverse=True)
    
    def export_to_json(self, filepath: str) -> None:
        """
        Export the knowledge graph to a JSON file.
        
        Args:
            filepath: Path to save the JSON file
        """
        data = nx.node_link_data(self.graph)
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
    
    def import_from_json(self, filepath: str) -> None:
        """
        Import a knowledge graph from a JSON file.
        
        Args:
            filepath: Path to the JSON file
        """
        if os.path.exists(filepath):
            with open(filepath, 'r') as f:
                data = json.load(f)
                self.graph = nx.node_link_graph(data)
    
    def get_vulnerability_statistics(self) -> Dict[str, int]:
        """
        Get statistics about vulnerabilities in the knowledge graph.
        
        Returns:
            Dictionary with vulnerability statistics
        """
        stats = {
            "total_vulnerabilities": 0,
            "by_category": {},
            "by_cwe": {}
        }
        
        for node_id, data in self.graph.nodes(data=True):
            if data.get("type") == "vulnerability":
                stats["total_vulnerabilities"] += 1
                
                # Get categories for this vulnerability
                categories = []
                for _, target, edge_data in self.graph.out_edges(node_id, data=True):
                    if edge_data.get("type") == "belongs_to":
                        target_data = self.graph.nodes[target]
                        if target_data.get("type") == "vulnerability_category":
                            categories.append(target_data.get("name"))
                
                # Update category counts
                for category in categories:
                    if category in stats["by_category"]:
                        stats["by_category"][category] += 1
                    else:
                        stats["by_category"][category] = 1
                
                # Update CWE counts
                cwe = data.get("cwe")
                if cwe:
                    if cwe in stats["by_cwe"]:
                        stats["by_cwe"][cwe] += 1
                    else:
                        stats["by_cwe"][cwe] = 1
        
        return stats


# Example usage
if __name__ == "__main__":
    # Create a knowledge graph
    kg = AttackKnowledgeGraph()
    
    # Get related nodes for Log4Shell vulnerability
    related = kg.get_related_nodes("CVE-2021-44228")
    print(f"Nodes related to Log4Shell: {len(related)}")
    
    # Find attack paths
    paths = kg.find_attack_paths("attack_technique", "vulnerability_category")
    print(f"Found {len(paths)} attack paths")
    
    # Get exploit suggestions
    exploits = kg.suggest_exploits("CVE-2021-44228")
    print(f"Suggested exploits for Log4Shell: {len(exploits)}")
    
    # Export the graph
    kg.export_to_json("attack_knowledge_graph.json")