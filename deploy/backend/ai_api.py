"""
AI Penetration Testing API

This module provides API endpoints for accessing the advanced AI-driven
penetration testing capabilities.
"""

from flask import Blueprint, request, jsonify
import json
import os
import sys

# Add the current directory to the path so we can import the ai_engine
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import AI components
try:
    from ai_engine.knowledge_graph import AttackKnowledgeGraph
    from ai_engine.reinforcement_learning import AttackPathEnvironment, QAgent
    from ai_engine.payload_generator import PayloadGenerator
except ImportError as e:
    print(f"Warning: Could not import AI engine components: {e}")

# Create Blueprint
ai_api = Blueprint('ai_api', __name__)

# Initialize AI components
knowledge_graph = AttackKnowledgeGraph()
payload_generator = PayloadGenerator()

@ai_api.route('/api/ai/attack_path', methods=['POST'])
def generate_attack_path():
    """Generate an optimal attack path for a target."""
    data = request.json
    
    if not data or 'target_config' not in data:
        return jsonify({'error': 'Missing target configuration'}), 400
    
    try:
        # Create environment with target configuration
        env = AttackPathEnvironment(knowledge_graph, data['target_config'])
        
        # Create and train agent
        agent = QAgent(env)
        agent.train(num_episodes=100)  # Quick training for demo
        
        # Get optimal attack path
        initial_observation = env.reset()
        optimal_path = agent.get_optimal_attack_path(initial_observation)
        
        return jsonify({
            'status': 'success',
            'attack_path': optimal_path,
            'target': data['target_config']['name']
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@ai_api.route('/api/ai/generate_payload', methods=['POST'])
def generate_custom_payload():
    """Generate a custom payload for a specific vulnerability."""
    data = request.json
    
    if not data or 'vulnerability_type' not in data or 'target_info' not in data:
        return jsonify({'error': 'Missing required parameters'}), 400
    
    try:
        # Generate payload
        payload_data = payload_generator.generate_payload(
            data['vulnerability_type'],
            data['target_info'],
            data.get('evasion_profile')
        )
        
        return jsonify({
            'status': 'success',
            'payload': payload_data
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@ai_api.route('/api/ai/vulnerability_analysis', methods=['POST'])
def analyze_vulnerabilities():
    """Analyze vulnerabilities and suggest exploits."""
    data = request.json
    
    if not data or 'vulnerability_id' not in data:
        return jsonify({'error': 'Missing vulnerability ID'}), 400
    
    try:
        # Get exploit suggestions
        exploits = knowledge_graph.suggest_exploits(data['vulnerability_id'])
        
        # Get related nodes
        related_nodes = knowledge_graph.get_related_nodes(data['vulnerability_id'])
        related_data = [{'id': node_id, 'properties': props} for node_id, props in related_nodes]
        
        return jsonify({
            'status': 'success',
            'vulnerability_id': data['vulnerability_id'],
            'suggested_exploits': exploits,
            'related_entities': related_data
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@ai_api.route('/api/ai/knowledge_graph_stats', methods=['GET'])
def get_knowledge_graph_stats():
    """Get statistics about the knowledge graph."""
    try:
        # Get vulnerability statistics
        stats = knowledge_graph.get_vulnerability_statistics()
        
        return jsonify({
            'status': 'success',
            'statistics': stats
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Demo endpoint with sample data
@ai_api.route('/api/ai/demo', methods=['GET'])
def get_demo_data():
    """Get demo data for the AI capabilities."""
    try:
        # Sample target configuration
        target_config = {
            "name": "Example Corp Web Server",
            "exposed_services": ["http", "https", "ssh"],
            "all_services": ["http", "https", "ssh", "mysql", "smb", "ldap"],
            "vulnerabilities": ["CVE-2021-44228", "CVE-2021-26084"],
            "security_level": "medium",
            "monitoring_level": "medium",
            "objective": "admin_access"
        }
        
        # Sample target info for payload generation
        target_info = {
            "database_tables": ["users", "products", "orders"],
            "database_columns": ["id", "username", "password", "email"],
            "error_messages": "visible",
            "query_timeout": 10,
            "callback_url": "https://attacker.example.com/collect",
            "callback_ip": "192.168.1.100",
            "callback_port": 4444,
            "internal_ip": "10.0.0.1",
            "security_level": "medium",
            "waf_type": "modsecurity",
            "content_security_policy": False,
            "prepared_statements": False,
            "input_sanitization": True
        }
        
        # Sample evasion profile
        evasion_profile = {
            "waf_bypass": True,
            "ids_evasion": True,
            "sandbox_evasion": False
        }
        
        # Generate SQL injection payload
        sql_payload = payload_generator.generate_payload("sql_injection", target_info, evasion_profile)
        
        # Get exploit suggestions for Log4Shell
        exploits = knowledge_graph.suggest_exploits("CVE-2021-44228")
        
        return jsonify({
            'status': 'success',
            'demo_data': {
                'target_config': target_config,
                'target_info': target_info,
                'evasion_profile': evasion_profile,
                'sample_payload': sql_payload,
                'sample_exploits': exploits
            }
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500