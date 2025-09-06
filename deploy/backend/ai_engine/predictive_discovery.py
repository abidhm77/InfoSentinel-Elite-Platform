"""
Predictive Vulnerability Discovery System

This module implements an AI-driven system that can identify potential vulnerabilities
in software before they are publicly disclosed, using pattern analysis, code archaeology,
and machine learning techniques.
"""

import os
import re
import json
import hashlib
import numpy as np
from datetime import datetime
from collections import defaultdict
import networkx as nx

try:
    from .knowledge_graph import AttackKnowledgeGraph
except ImportError:
    print("Warning: Unable to import AttackKnowledgeGraph. Some functionality may be limited.")


class PredictiveVulnerabilityDiscovery:
    """
    A system that predicts potential vulnerabilities in code before they are publicly disclosed.
    Uses pattern analysis, historical vulnerability data, and machine learning to identify
    code patterns that may indicate security weaknesses.
    """

    def __init__(self):
        self.vulnerability_patterns = self._load_vulnerability_patterns()
        self.historical_data = self._load_historical_data()
        self.knowledge_graph = self._initialize_knowledge_graph()
        self.confidence_threshold = 0.65
        self.discovered_vulnerabilities = []
        
    def _load_vulnerability_patterns(self):
        """Load known vulnerability patterns from database or default to built-in patterns."""
        # In a production system, these would be loaded from a database
        # that's regularly updated with new patterns
        return {
            "sql_injection": [
                r"(?i)(?:execute|exec)\s*\(\s*(?:[\"']|\$[a-zA-Z0-9_]+)\s*\+",
                r"(?i)(?:SELECT|INSERT|UPDATE|DELETE|CREATE|ALTER|DROP).*\+\s*(?:[\"']|\$[a-zA-Z0-9_]+)",
                r"(?i)(?:SELECT|INSERT|UPDATE|DELETE|CREATE|ALTER|DROP).*\$_(?:GET|POST|REQUEST|COOKIE)",
            ],
            "xss": [
                r"(?i)document\.write\s*\(\s*(?:[\"']|\$[a-zA-Z0-9_]+)\s*\+",
                r"(?i)\.innerHTML\s*=\s*(?:[\"']|\$[a-zA-Z0-9_]+)",
                r"(?i)eval\s*\(\s*(?:[\"']|\$[a-zA-Z0-9_]+)\s*\)",
            ],
            "path_traversal": [
                r"(?i)(?:include|require|include_once|require_once)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)",
                r"(?i)fopen\s*\(\s*(?:[\"']|\$[a-zA-Z0-9_]+)\s*,",
                r"(?i)file_get_contents\s*\(\s*(?:[\"']|\$[a-zA-Z0-9_]+)\s*\)",
            ],
            "command_injection": [
                r"(?i)(?:system|exec|passthru|shell_exec|popen|proc_open|pcntl_exec)\s*\(\s*(?:[\"']|\$[a-zA-Z0-9_]+)",
                r"(?i)(?:`|\||\|\||&&)\s*(?:[\"']|\$[a-zA-Z0-9_]+)",
            ],
            "insecure_deserialization": [
                r"(?i)(?:unserialize|json_decode)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)",
                r"(?i)(?:yaml_parse|simplexml_load_string)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)",
            ],
            "memory_corruption": [
                r"(?i)memcpy\s*\(\s*[^,]+,\s*[^,]+,\s*(?:[^)]+\+|\d+\s*\*)",
                r"(?i)strcpy\s*\(\s*[^,]+,\s*[^)]+\)",
                r"(?i)strncpy\s*\(\s*[^,]+,\s*[^,]+,\s*(?:[^)]+\+|\d+\s*\*)",
            ],
            "race_condition": [
                r"(?i)(?:mkdir|unlink|file_exists|is_dir|is_file)\s*\(\s*(?:[\"']|\$[a-zA-Z0-9_]+)\s*\).*(?:mkdir|unlink|file_put_contents|fopen)",
                r"(?i)(?:flock|sem_acquire)\s*\(\s*(?:[\"']|\$[a-zA-Z0-9_]+)\s*\)",
            ],
            "crypto_weakness": [
                r"(?i)(?:md5|sha1)\s*\(\s*(?:[\"']|\$[a-zA-Z0-9_]+)\s*\)",
                r"(?i)(?:DES|RC4|ECB)\s*\(",
                r"(?i)random\s*\(\s*\)",
            ],
            "zero_day_indicators": [
                # Patterns that might indicate novel vulnerability classes
                r"(?i)(?:custom_(?:parser|decoder|encoder))\s*\(\s*(?:[\"']|\$[a-zA-Z0-9_]+)\s*\)",
                r"(?i)(?:unsafe|insecure|dangerous)_(?:function|method|operation)",
                r"(?i)(?:bypass|avoid|skip)_(?:validation|sanitization|check)",
            ]
        }
        
    def _load_historical_data(self):
        """Load historical vulnerability data for pattern analysis."""
        # In a production system, this would load from a database of historical vulnerabilities
        return {
            "cve_patterns": {
                "CVE-2021-44228": {  # Log4j
                    "patterns": [
                        r"(?i)jndi:ldap",
                        r"(?i)log4j.*\.lookup\(",
                    ],
                    "severity": "critical",
                    "discovery_date": "2021-12-09",
                    "similar_code_indicators": [
                        "string interpolation in logging",
                        "JNDI lookups",
                        "deserialization of user input"
                    ]
                },
                "CVE-2022-22965": {  # Spring4Shell
                    "patterns": [
                        r"(?i)class\.module\.classLoader",
                        r"(?i)org\.springframework\.validation\.BeanPropertyBindingResult",
                    ],
                    "severity": "critical",
                    "discovery_date": "2022-03-30",
                    "similar_code_indicators": [
                        "parameter binding",
                        "class property access",
                        "reflection-based property access"
                    ]
                },
                "CVE-2023-23397": {  # Microsoft Outlook
                    "patterns": [
                        r"(?i)net\.pipe:",
                        r"(?i)\\\\\\\\",
                    ],
                    "severity": "critical",
                    "discovery_date": "2023-03-14",
                    "similar_code_indicators": [
                        "UNC path handling",
                        "authentication token processing",
                        "message parsing without validation"
                    ]
                }
            },
            "vulnerability_evolution": {
                "sql_injection": {
                    "first_seen": "1998",
                    "evolution_stages": [
                        "Basic string concatenation",
                        "Numeric parameter manipulation",
                        "Second-order injection",
                        "Blind injection techniques",
                        "ORM-based injections"
                    ],
                    "future_prediction": "AI-context aware injections that adapt to database schema"
                },
                "xss": {
                    "first_seen": "2000",
                    "evolution_stages": [
                        "Basic script injection",
                        "DOM-based XSS",
                        "Stored XSS",
                        "CSP bypass techniques",
                        "Template injection"
                    ],
                    "future_prediction": "Framework-specific rendering engine exploits"
                }
            }
        }
    
    def _initialize_knowledge_graph(self):
        """Initialize the knowledge graph for vulnerability relationships."""
        try:
            graph = AttackKnowledgeGraph()
            # Add additional nodes and relationships specific to predictive discovery
            return graph
        except:
            # Fallback to a simple graph if the import failed
            graph = nx.DiGraph()
            # Add some basic nodes and edges
            graph.add_node("SQL Injection", type="vulnerability_class")
            graph.add_node("XSS", type="vulnerability_class")
            graph.add_node("Command Injection", type="vulnerability_class")
            
            graph.add_node("Input Validation", type="security_control")
            graph.add_node("Parameterized Queries", type="security_control")
            graph.add_node("Output Encoding", type="security_control")
            
            graph.add_edge("Input Validation", "SQL Injection", relationship="mitigates")
            graph.add_edge("Parameterized Queries", "SQL Injection", relationship="mitigates")
            graph.add_edge("Output Encoding", "XSS", relationship="mitigates")
            
            return graph
    
    def analyze_code_snippet(self, code, language="unknown", context=None):
        """
        Analyze a code snippet for potential vulnerabilities.
        
        Args:
            code (str): The code snippet to analyze
            language (str): The programming language of the code
            context (dict): Additional context about the code (e.g., function name, file path)
            
        Returns:
            list: Discovered potential vulnerabilities with confidence scores
        """
        results = []
        
        # Check for known vulnerability patterns
        for vuln_type, patterns in self.vulnerability_patterns.items():
            for pattern in patterns:
                matches = re.finditer(pattern, code)
                for match in matches:
                    # Calculate confidence based on pattern match and context
                    confidence = self._calculate_confidence(
                        vuln_type, match.group(), code, language, context
                    )
                    
                    if confidence >= self.confidence_threshold:
                        results.append({
                            "type": vuln_type,
                            "pattern": pattern,
                            "matched_code": match.group(),
                            "line_number": code[:match.start()].count('\n') + 1,
                            "confidence": confidence,
                            "discovery_date": datetime.now().isoformat(),
                            "potential_cve": self._generate_potential_cve_id(vuln_type, match.group()),
                            "remediation_suggestions": self._generate_remediation(vuln_type, match.group(), language)
                        })
        
        # Check for novel patterns that might indicate zero-day vulnerabilities
        novel_patterns = self._identify_novel_patterns(code, language)
        results.extend(novel_patterns)
        
        # Update discovered vulnerabilities list
        self.discovered_vulnerabilities.extend(results)
        
        return results
    
    def analyze_codebase(self, directory_path, file_extensions=None, exclude_dirs=None):
        """
        Analyze an entire codebase for potential vulnerabilities.
        
        Args:
            directory_path (str): Path to the codebase directory
            file_extensions (list): List of file extensions to analyze
            exclude_dirs (list): List of directories to exclude
            
        Returns:
            dict: Summary of discovered potential vulnerabilities
        """
        if file_extensions is None:
            file_extensions = ['.py', '.js', '.php', '.java', '.cs', '.go', '.rb']
        
        if exclude_dirs is None:
            exclude_dirs = ['node_modules', 'venv', '.git', '__pycache__', 'dist', 'build']
        
        results = {
            "scan_date": datetime.now().isoformat(),
            "total_files_analyzed": 0,
            "total_vulnerabilities_found": 0,
            "vulnerabilities_by_type": defaultdict(int),
            "vulnerabilities_by_confidence": defaultdict(int),
            "high_confidence_vulnerabilities": [],
            "potential_zero_days": [],
            "files_with_vulnerabilities": defaultdict(list)
        }
        
        for root, dirs, files in os.walk(directory_path):
            # Skip excluded directories
            dirs[:] = [d for d in dirs if d not in exclude_dirs]
            
            for file in files:
                if any(file.endswith(ext) for ext in file_extensions):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            code = f.read()
                        
                        # Determine language from file extension
                        language = file.split('.')[-1]
                        
                        # Provide context for better analysis
                        context = {
                            "file_path": file_path,
                            "file_name": file,
                            "directory": root
                        }
                        
                        # Analyze the file
                        vulnerabilities = self.analyze_code_snippet(code, language, context)
                        
                        # Update results
                        results["total_files_analyzed"] += 1
                        results["total_vulnerabilities_found"] += len(vulnerabilities)
                        
                        for vuln in vulnerabilities:
                            results["vulnerabilities_by_type"][vuln["type"]] += 1
                            confidence_level = self._get_confidence_level(vuln["confidence"])
                            results["vulnerabilities_by_confidence"][confidence_level] += 1
                            
                            if confidence_level == "high":
                                results["high_confidence_vulnerabilities"].append(vuln)
                            
                            if vuln["type"] == "zero_day_indicators":
                                results["potential_zero_days"].append(vuln)
                            
                            results["files_with_vulnerabilities"][file_path].append(vuln)
                    
                    except Exception as e:
                        print(f"Error analyzing {file_path}: {str(e)}")
        
        return results
    
    def _calculate_confidence(self, vuln_type, matched_code, full_code, language, context=None):
        """
        Calculate confidence score for a potential vulnerability.
        
        Args:
            vuln_type (str): Type of vulnerability
            matched_code (str): The code that matched the pattern
            full_code (str): The full code snippet
            language (str): The programming language
            context (dict): Additional context
            
        Returns:
            float: Confidence score between 0 and 1
        """
        # Base confidence from pattern match
        base_confidence = 0.7
        
        # Adjust based on language-specific factors
        language_multiplier = {
            "php": 1.1,  # PHP has historically had more injection vulnerabilities
            "js": 1.05,  # JavaScript has many XSS opportunities
            "py": 0.95,  # Python has some built-in protections
            "java": 0.9,  # Java has stronger type checking
            "go": 0.85,  # Go has good security by default
            "unknown": 1.0
        }.get(language.lower(), 1.0)
        
        # Adjust based on context clues
        context_score = 0
        if context:
            # Check if file path contains security-sensitive directories
            sensitive_dirs = ["auth", "login", "admin", "payment", "user", "account"]
            if any(d in context.get("file_path", "").lower() for d in sensitive_dirs):
                context_score += 0.1
            
            # Check if file name indicates security-sensitive functionality
            sensitive_files = ["auth", "login", "admin", "payment", "user", "account", "password", "credential"]
            if any(s in context.get("file_name", "").lower() for s in sensitive_files):
                context_score += 0.1
        
        # Check for sanitization or validation nearby
        sanitization_patterns = [
            r"(?i)(?:sanitize|validate|escape|filter|clean)",
            r"(?i)prepared\s*statement",
            r"(?i)parameterized\s*query",
            r"(?i)input\s*validation"
        ]
        
        # If sanitization is found near the vulnerability, reduce confidence
        sanitization_found = any(re.search(pattern, full_code) for pattern in sanitization_patterns)
        sanitization_modifier = 0.7 if sanitization_found else 1.0
        
        # Calculate final confidence
        confidence = base_confidence * language_multiplier + context_score
        confidence *= sanitization_modifier
        
        # Ensure confidence is between 0 and 1
        return max(0.0, min(1.0, confidence))
    
    def _get_confidence_level(self, confidence_score):
        """Convert numerical confidence to categorical level."""
        if confidence_score >= 0.8:
            return "high"
        elif confidence_score >= 0.6:
            return "medium"
        else:
            return "low"
    
    def _generate_potential_cve_id(self, vuln_type, code_snippet):
        """Generate a potential CVE-like ID for tracking the vulnerability."""
        # Create a hash of the vulnerability type and code snippet
        hash_input = f"{vuln_type}:{code_snippet}"
        hash_value = hashlib.md5(hash_input.encode()).hexdigest()[:8]
        
        # Format as a potential CVE ID with current year
        year = datetime.now().year
        return f"POTENTIAL-{year}-{hash_value}"
    
    def _generate_remediation(self, vuln_type, matched_code, language):
        """Generate remediation suggestions based on vulnerability type and language."""
        remediation_strategies = {
            "sql_injection": {
                "general": "Use parameterized queries or prepared statements instead of string concatenation.",
                "python": "Use SQLAlchemy ORM or parameterized queries with placeholders.",
                "php": "Use PDO prepared statements with bound parameters.",
                "java": "Use PreparedStatement with parameterized queries.",
                "js": "Use parameterized queries with libraries like Sequelize or Knex."
            },
            "xss": {
                "general": "Sanitize and validate all user inputs. Use context-appropriate output encoding.",
                "python": "Use frameworks like Django with auto-escaping or libraries like MarkupSafe.",
                "php": "Use htmlspecialchars() or htmlentities() for output encoding.",
                "java": "Use OWASP Java Encoder or Spring's HtmlUtils.htmlEscape().",
                "js": "Use DOMPurify for sanitization and avoid innerHTML when possible."
            },
            "command_injection": {
                "general": "Avoid passing user input to system commands. Use allowlists for permitted values.",
                "python": "Use subprocess module with shell=False and pass arguments as a list.",
                "php": "Use escapeshellarg() and escapeshellcmd() functions.",
                "java": "Use ProcessBuilder with arguments as separate list items.",
                "js": "Use child_process.execFile() instead of exec() and avoid shell option."
            }
        }
        
        # Get language-specific remediation if available, otherwise use general
        vuln_remediation = remediation_strategies.get(vuln_type, {"general": "Review and validate all user inputs."})
        specific_remediation = vuln_remediation.get(language.lower(), vuln_remediation["general"])
        
        return {
            "description": specific_remediation,
            "code_example": self._get_remediation_example(vuln_type, language.lower()),
            "security_resources": [
                "OWASP Cheat Sheet Series",
                "SANS Security Guidelines",
                f"{language.capitalize()} Security Best Practices"
            ]
        }
    
    def _get_remediation_example(self, vuln_type, language):
        """Get a code example for remediation."""
        examples = {
            "sql_injection": {
                "python": """
# Unsafe:
query = "SELECT * FROM users WHERE username = '" + username + "'"

# Safe:
query = "SELECT * FROM users WHERE username = %s"
cursor.execute(query, (username,))
""",
                "php": """
// Unsafe:
$query = "SELECT * FROM users WHERE username = '" . $username . "'";

// Safe:
$stmt = $pdo->prepare("SELECT * FROM users WHERE username = ?");
$stmt->execute([$username]);
""",
                "js": """
// Unsafe:
const query = `SELECT * FROM users WHERE username = '${username}'`;

// Safe:
const query = 'SELECT * FROM users WHERE username = ?';
db.query(query, [username]);
"""
            },
            "xss": {
                "python": """
# Unsafe:
response.write("<p>" + user_input + "</p>")

# Safe:
from markupsafe import escape
response.write("<p>" + escape(user_input) + "</p>")
""",
                "php": """
// Unsafe:
echo "<p>" . $user_input . "</p>";

// Safe:
echo "<p>" . htmlspecialchars($user_input, ENT_QUOTES, 'UTF-8') . "</p>";
""",
                "js": """
// Unsafe:
element.innerHTML = userInput;

// Safe:
import DOMPurify from 'dompurify';
element.textContent = userInput; // For plain text
// OR for HTML content:
element.innerHTML = DOMPurify.sanitize(userInput);
"""
            }
        }
        
        return examples.get(vuln_type, {}).get(language, "No specific example available for this language.")
    
    def _identify_novel_patterns(self, code, language):
        """
        Identify potentially novel vulnerability patterns that might indicate zero-days.
        
        This uses more advanced heuristics and pattern analysis to find code that doesn't
        match known vulnerability patterns but exhibits suspicious characteristics.
        """
        results = []
        
        # Check for unusual combinations of risky functions
        risky_functions = {
            "memory": ["malloc", "alloc", "realloc", "memcpy", "strcpy", "memmove"],
            "system": ["system", "exec", "popen", "spawn", "fork", "createProcess"],
            "parsing": ["parse", "decode", "deserialize", "fromJson", "fromXml", "unmarshal"],
            "crypto": ["encrypt", "decrypt", "hash", "random", "generateKey"]
        }
        
        # Look for unusual combinations of risky functions
        for category1, funcs1 in risky_functions.items():
            for category2, funcs2 in risky_functions.items():
                if category1 != category2:
                    for func1 in funcs1:
                        for func2 in funcs2:
                            pattern = r"(?i)(?:{0}.*{1}|{1}.*{0})".format(func1, func2)
                            matches = re.finditer(pattern, code)
                            
                            for match in matches:
                                # Calculate confidence for novel pattern
                                confidence = 0.6  # Start with lower confidence for novel patterns
                                
                                # Increase confidence if pattern is in a security-sensitive context
                                if re.search(r"(?i)(?:auth|login|password|secure|crypt|token)", code):
                                    confidence += 0.1
                                
                                # Increase confidence if user input is involved
                                if re.search(r"(?i)(?:input|request|param|arg|argv|user|client)", code):
                                    confidence += 0.1
                                
                                if confidence >= self.confidence_threshold:
                                    results.append({
                                        "type": "zero_day_indicators",
                                        "pattern": f"Unusual combination of {func1} and {func2}",
                                        "matched_code": match.group(),
                                        "line_number": code[:match.start()].count('\n') + 1,
                                        "confidence": confidence,
                                        "discovery_date": datetime.now().isoformat(),
                                        "potential_cve": self._generate_potential_cve_id("zero_day", match.group()),
                                        "remediation_suggestions": {
                                            "description": f"Review the use of {func1} and {func2} together, as this combination may introduce security risks.",
                                            "security_resources": [
                                                "OWASP Code Review Guide",
                                                "SANS Secure Coding Practices"
                                            ]
                                        }
                                    })
        
        # Look for code patterns similar to historical zero-days
        for cve_id, cve_data in self.historical_data["cve_patterns"].items():
            for pattern in cve_data["patterns"]:
                matches = re.finditer(pattern, code)
                for match in matches:
                    confidence = 0.7  # Higher confidence for patterns similar to known CVEs
                    
                    results.append({
                        "type": "historical_pattern_match",
                        "related_cve": cve_id,
                        "pattern": pattern,
                        "matched_code": match.group(),
                        "line_number": code[:match.start()].count('\n') + 1,
                        "confidence": confidence,
                        "discovery_date": datetime.now().isoformat(),
                        "potential_cve": self._generate_potential_cve_id("historical", match.group()),
                        "remediation_suggestions": {
                            "description": f"This code pattern is similar to the vulnerability described in {cve_id}. Review and refactor accordingly.",
                            "security_resources": [
                                f"CVE Details: {cve_id}",
                                "NIST National Vulnerability Database",
                                "MITRE CVE Database"
                            ]
                        }
                    })
        
        return results
    
    def predict_future_vulnerabilities(self):
        """
        Predict future vulnerability classes based on historical trends and current patterns.
        
        Returns:
            list: Predicted future vulnerability classes with confidence scores
        """
        predictions = []
        
        # Analyze historical vulnerability evolution
        for vuln_type, data in self.historical_data["vulnerability_evolution"].items():
            evolution_stages = data["evolution_stages"]
            future_prediction = data["future_prediction"]
            
            predictions.append({
                "vulnerability_type": vuln_type,
                "current_stage": evolution_stages[-1],
                "predicted_next_stage": future_prediction,
                "confidence": 0.7,
                "estimated_timeframe": "6-12 months",
                "potential_impact": "high",
                "detection_strategies": [
                    "Monitor for new code patterns combining current stage techniques with AI/ML components",
                    "Track research papers and conference presentations on related topics",
                    "Analyze open source frameworks for emerging security patterns"
                ]
            })
        
        # Add predictions for emerging technology areas
        emerging_predictions = [
            {
                "vulnerability_type": "ai_model_poisoning",
                "description": "Vulnerabilities in machine learning pipelines allowing model corruption",
                "confidence": 0.8,
                "estimated_timeframe": "3-6 months",
                "potential_impact": "critical",
                "detection_strategies": [
                    "Analyze ML training pipelines for input validation",
                    "Monitor for unusual patterns in model training data sources",
                    "Check for integrity verification in model deployment workflows"
                ]
            },
            {
                "vulnerability_type": "quantum_algorithm_weaknesses",
                "description": "Cryptographic vulnerabilities exposed by advances in quantum computing",
                "confidence": 0.6,
                "estimated_timeframe": "18-24 months",
                "potential_impact": "critical",
                "detection_strategies": [
                    "Identify systems using vulnerable cryptographic algorithms",
                    "Monitor for quantum-resistant algorithm implementation issues",
                    "Track quantum computing capability advancements"
                ]
            }
        ]
        
        predictions.extend(emerging_predictions)
        return predictions
    
    def export_results(self, format="json"):
        """Export discovered vulnerabilities in the specified format."""
        if format == "json":
            return json.dumps({
                "discovered_vulnerabilities": self.discovered_vulnerabilities,
                "scan_date": datetime.now().isoformat(),
                "total_vulnerabilities": len(self.discovered_vulnerabilities)
            }, indent=2)
        else:
            # Could implement other formats like CSV, HTML, etc.
            return "Unsupported format"


# Example usage
if __name__ == "__main__":
    # Create the predictive vulnerability discovery system
    pvd = PredictiveVulnerabilityDiscovery()
    
    # Analyze a code snippet
    code_snippet = """
    def process_user_data(request):
        user_id = request.GET.get('id')
        query = "SELECT * FROM users WHERE id = " + user_id
        cursor.execute(query)
        
        user_input = request.POST.get('comment')
        html = "<div>" + user_input + "</div>"
        return html
    """
    
    results = pvd.analyze_code_snippet(code_snippet, language="python")
    print(json.dumps(results, indent=2))
    
    # Predict future vulnerabilities
    future_vulns = pvd.predict_future_vulnerabilities()
    print(json.dumps(future_vulns, indent=2))