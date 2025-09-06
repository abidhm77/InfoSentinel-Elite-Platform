"""Real-time security monitoring and threat detection system."""
import asyncio
import json
import time
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
import websockets
import requests
from collections import defaultdict, deque

from database.db import get_db

@dataclass
class SecurityEvent:
    """Represents a security event."""
    event_id: str
    timestamp: datetime
    event_type: str
    severity: str
    source: str
    target: str
    description: str
    details: Dict[str, Any]
    threat_score: float
    status: str = "new"
    
class ThreatDetectionEngine:
    """AI-powered threat detection engine."""
    
    def __init__(self):
        self.threat_patterns = self._load_threat_patterns()
        self.baseline_metrics = {}
        self.anomaly_threshold = 2.0  # Standard deviations
        
    def analyze_event(self, event_data: Dict[str, Any]) -> Optional[SecurityEvent]:
        """Analyze event for potential threats."""
        threat_score = 0.0
        threat_indicators = []
        
        # Pattern-based detection
        for pattern_name, pattern in self.threat_patterns.items():
            if self._matches_pattern(event_data, pattern):
                threat_score += pattern["score"]
                threat_indicators.append(pattern_name)
        
        # Anomaly detection
        anomaly_score = self._detect_anomalies(event_data)
        threat_score += anomaly_score
        
        # Behavioral analysis
        behavioral_score = self._analyze_behavior(event_data)
        threat_score += behavioral_score
        
        if threat_score > 5.0:  # Threshold for security event
            severity = self._calculate_severity(threat_score)
            
            return SecurityEvent(
                event_id=f"evt_{int(time.time())}_{hash(str(event_data)) % 10000}",
                timestamp=datetime.utcnow(),
                event_type=self._classify_event_type(threat_indicators),
                severity=severity,
                source=event_data.get("source_ip", "unknown"),
                target=event_data.get("target", "unknown"),
                description=self._generate_description(threat_indicators, threat_score),
                details={
                    "threat_score": threat_score,
                    "indicators": threat_indicators,
                    "raw_event": event_data
                },
                threat_score=threat_score
            )
        
        return None
    
    def _load_threat_patterns(self) -> Dict[str, Dict[str, Any]]:
        """Load threat detection patterns."""
        return {
            "sql_injection_attempt": {
                "patterns": ["union select", "' or 1=1", "drop table", "exec(", "xp_cmdshell"],
                "score": 8.0,
                "category": "injection"
            },
            "xss_attempt": {
                "patterns": ["<script>", "javascript:", "onerror=", "onload=", "alert("],
                "score": 7.0,
                "category": "xss"
            },
            "directory_traversal": {
                "patterns": ["../", "..\\\\", "%2e%2e%2f", "....//"],
                "score": 6.0,
                "category": "traversal"
            },
            "command_injection": {
                "patterns": ["; cat ", "| nc ", "&& wget", "; curl", "$(whoami)"],
                "score": 9.0,
                "category": "command_injection"
            },
            "brute_force_login": {
                "patterns": ["failed login", "authentication failed", "invalid credentials"],
                "score": 5.0,
                "category": "brute_force",
                "frequency_threshold": 10  # 10 attempts in time window
            },
            "port_scan": {
                "patterns": ["connection refused", "port scan", "syn flood"],
                "score": 4.0,
                "category": "reconnaissance"
            },
            "malware_signature": {
                "patterns": ["malware detected", "virus found", "trojan", "backdoor"],
                "score": 10.0,
                "category": "malware"
            },
            "data_exfiltration": {
                "patterns": ["large data transfer", "unusual upload", "sensitive file access"],
                "score": 8.5,
                "category": "exfiltration"
            }
        }
    
    def _matches_pattern(self, event_data: Dict[str, Any], pattern: Dict[str, Any]) -> bool:
        """Check if event matches threat pattern."""
        event_text = json.dumps(event_data).lower()
        
        for pattern_text in pattern["patterns"]:
            if pattern_text.lower() in event_text:
                return True
        
        return False
    
    def _detect_anomalies(self, event_data: Dict[str, Any]) -> float:
        """Detect anomalies in event data."""
        anomaly_score = 0.0
        
        # Check for unusual request sizes
        request_size = event_data.get("request_size", 0)
        if request_size > 100000:  # Large request
            anomaly_score += 2.0
        
        # Check for unusual response times
        response_time = event_data.get("response_time", 0)
        if response_time > 10000:  # Very slow response
            anomaly_score += 1.5
        
        # Check for unusual user agents
        user_agent = event_data.get("user_agent", "")
        if any(suspicious in user_agent.lower() for suspicious in ["bot", "crawler", "scanner"]):
            anomaly_score += 1.0
        
        return anomaly_score
    
    def _analyze_behavior(self, event_data: Dict[str, Any]) -> float:
        """Analyze behavioral patterns."""
        behavioral_score = 0.0
        
        # Check for rapid successive requests
        source_ip = event_data.get("source_ip")
        if source_ip:
            recent_requests = self._get_recent_requests(source_ip)
            if len(recent_requests) > 50:  # More than 50 requests in last minute
                behavioral_score += 3.0
        
        # Check for access to sensitive endpoints
        endpoint = event_data.get("endpoint", "")
        sensitive_endpoints = ["/admin", "/config", "/backup", "/database", "/.env"]
        if any(sensitive in endpoint for sensitive in sensitive_endpoints):
            behavioral_score += 2.0
        
        return behavioral_score
    
    def _get_recent_requests(self, source_ip: str) -> List[Dict]:
        """Get recent requests from source IP."""
        # This would query the database for recent requests
        # For now, return empty list
        return []
    
    def _calculate_severity(self, threat_score: float) -> str:
        """Calculate severity based on threat score."""
        if threat_score >= 9.0:
            return "critical"
        elif threat_score >= 7.0:
            return "high"
        elif threat_score >= 5.0:
            return "medium"
        else:
            return "low"
    
    def _classify_event_type(self, indicators: List[str]) -> str:
        """Classify event type based on indicators."""
        if not indicators:
            return "anomaly"
        
        # Map indicators to event types
        type_mapping = {
            "sql_injection_attempt": "injection_attack",
            "xss_attempt": "xss_attack",
            "command_injection": "command_injection",
            "brute_force_login": "brute_force",
            "port_scan": "reconnaissance",
            "malware_signature": "malware",
            "data_exfiltration": "data_breach"
        }
        
        return type_mapping.get(indicators[0], "security_event")
    
    def _generate_description(self, indicators: List[str], threat_score: float) -> str:
        """Generate human-readable description."""
        if not indicators:
            return f"Anomalous activity detected (threat score: {threat_score:.1f})"
        
        primary_indicator = indicators[0].replace("_", " ").title()
        return f"{primary_indicator} detected (threat score: {threat_score:.1f})"

class RealTimeMonitor:
    """Real-time security monitoring system."""
    
    def __init__(self):
        self.threat_engine = ThreatDetectionEngine()
        self.active_monitors = {}
        self.event_queue = deque(maxlen=10000)
        self.alert_thresholds = {
            "critical": 0,  # Immediate alert
            "high": 3,      # Alert after 3 events
            "medium": 10,   # Alert after 10 events
            "low": 50       # Alert after 50 events
        }
        self.alert_counts = defaultdict(int)
        self.websocket_clients = set()
        self.monitoring_active = False
        
    async def start_monitoring(self, target: str, monitor_config: Dict[str, Any] = None):
        """Start real-time monitoring for target."""
        if monitor_config is None:
            monitor_config = self._get_default_config()
        
        monitor_id = f"monitor_{target}_{int(time.time())}"
        
        self.active_monitors[monitor_id] = {
            "target": target,
            "config": monitor_config,
            "start_time": datetime.utcnow(),
            "status": "active",
            "events_detected": 0,
            "alerts_generated": 0
        }
        
        # Start monitoring tasks
        self.monitoring_active = True
        
        # Start different monitoring components
        tasks = [
            asyncio.create_task(self._monitor_network_traffic(monitor_id, target)),
            asyncio.create_task(self._monitor_web_requests(monitor_id, target)),
            asyncio.create_task(self._monitor_system_logs(monitor_id, target)),
            asyncio.create_task(self._monitor_file_integrity(monitor_id, target)),
            asyncio.create_task(self._process_event_queue()),
            asyncio.create_task(self._websocket_server())
        ]
        
        try:
            await asyncio.gather(*tasks)
        except Exception as e:
            print(f"Monitoring error: {e}")
        finally:
            self.monitoring_active = False
    
    async def _monitor_network_traffic(self, monitor_id: str, target: str):
        """Monitor network traffic for suspicious activity."""
        while self.monitoring_active:
            try:
                # Simulate network traffic monitoring
                # In real implementation, this would integrate with network monitoring tools
                await asyncio.sleep(5)
                
                # Generate sample network events
                if time.time() % 30 < 5:  # Simulate periodic events
                    event_data = {
                        "source": "network_monitor",
                        "target": target,
                        "source_ip": "192.168.1.100",
                        "destination_port": 80,
                        "protocol": "TCP",
                        "packet_size": 1500,
                        "timestamp": datetime.utcnow().isoformat()
                    }
                    
                    await self._process_event(monitor_id, event_data)
                    
            except Exception as e:
                print(f"Network monitoring error: {e}")
                await asyncio.sleep(10)
    
    async def _monitor_web_requests(self, monitor_id: str, target: str):
        """Monitor web requests for attacks."""
        while self.monitoring_active:
            try:
                # Simulate web request monitoring
                await asyncio.sleep(3)
                
                # Generate sample web events
                if time.time() % 20 < 3:  # Simulate periodic events
                    suspicious_requests = [
                        "/admin/config.php?id=1' OR 1=1--",
                        "/search?q=<script>alert('xss')</script>",
                        "/files/../../../etc/passwd",
                        "/login.php (failed login attempt)"
                    ]
                    
                    import random
                    request = random.choice(suspicious_requests)
                    
                    event_data = {
                        "source": "web_monitor",
                        "target": target,
                        "source_ip": f"192.168.1.{random.randint(100, 200)}",
                        "endpoint": request,
                        "method": "GET",
                        "user_agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)",
                        "response_code": random.choice([200, 403, 404, 500]),
                        "timestamp": datetime.utcnow().isoformat()
                    }
                    
                    await self._process_event(monitor_id, event_data)
                    
            except Exception as e:
                print(f"Web monitoring error: {e}")
                await asyncio.sleep(10)
    
    async def _monitor_system_logs(self, monitor_id: str, target: str):
        """Monitor system logs for security events."""
        while self.monitoring_active:
            try:
                # Simulate system log monitoring
                await asyncio.sleep(7)
                
                # Generate sample system events
                if time.time() % 40 < 7:  # Simulate periodic events
                    log_events = [
                        "Failed login attempt for user admin",
                        "Unusual process execution detected",
                        "File modification in system directory",
                        "Network connection to suspicious IP",
                        "Privilege escalation attempt detected"
                    ]
                    
                    import random
                    log_message = random.choice(log_events)
                    
                    event_data = {
                        "source": "system_monitor",
                        "target": target,
                        "log_level": "WARNING",
                        "message": log_message,
                        "process": "security_monitor",
                        "timestamp": datetime.utcnow().isoformat()
                    }
                    
                    await self._process_event(monitor_id, event_data)
                    
            except Exception as e:
                print(f"System monitoring error: {e}")
                await asyncio.sleep(10)
    
    async def _monitor_file_integrity(self, monitor_id: str, target: str):
        """Monitor file integrity for unauthorized changes."""
        while self.monitoring_active:
            try:
                # Simulate file integrity monitoring
                await asyncio.sleep(15)
                
                # Generate sample file integrity events
                if time.time() % 60 < 15:  # Simulate periodic events
                    import random
                    if random.random() < 0.3:  # 30% chance of file change event
                        event_data = {
                            "source": "file_monitor",
                            "target": target,
                            "file_path": "/etc/passwd",
                            "change_type": "modification",
                            "old_hash": "abc123def456",
                            "new_hash": "def456ghi789",
                            "timestamp": datetime.utcnow().isoformat()
                        }
                        
                        await self._process_event(monitor_id, event_data)
                        
            except Exception as e:
                print(f"File monitoring error: {e}")
                await asyncio.sleep(10)
    
    async def _process_event(self, monitor_id: str, event_data: Dict[str, Any]):
        """Process incoming security event."""
        # Analyze event for threats
        security_event = self.threat_engine.analyze_event(event_data)
        
        if security_event:
            # Add to event queue
            self.event_queue.append(security_event)
            
            # Update monitor statistics
            if monitor_id in self.active_monitors:
                self.active_monitors[monitor_id]["events_detected"] += 1
            
            # Check alert thresholds
            await self._check_alert_thresholds(security_event)
            
            # Broadcast to WebSocket clients
            await self._broadcast_event(security_event)
            
            # Save to database
            await self._save_security_event(security_event)
    
    async def _process_event_queue(self):
        """Process events from the queue."""
        while self.monitoring_active:
            try:
                if self.event_queue:
                    # Process correlation analysis
                    await self._correlate_events()
                    
                    # Clean old events
                    await self._cleanup_old_events()
                
                await asyncio.sleep(10)
                
            except Exception as e:
                print(f"Event processing error: {e}")
                await asyncio.sleep(5)
    
    async def _correlate_events(self):
        """Correlate events to identify attack patterns."""
        # Group events by source IP and time window
        time_window = timedelta(minutes=5)
        current_time = datetime.utcnow()
        
        recent_events = [e for e in self.event_queue 
                        if current_time - e.timestamp < time_window]
        
        # Group by source IP
        events_by_source = defaultdict(list)
        for event in recent_events:
            events_by_source[event.source].append(event)
        
        # Check for attack patterns
        for source_ip, events in events_by_source.items():
            if len(events) >= 5:  # Multiple events from same source
                # Create correlation event
                correlation_event = SecurityEvent(
                    event_id=f"corr_{int(time.time())}_{hash(source_ip) % 10000}",
                    timestamp=current_time,
                    event_type="coordinated_attack",
                    severity="high",
                    source=source_ip,
                    target="multiple",
                    description=f"Coordinated attack detected from {source_ip} ({len(events)} events)",
                    details={
                        "correlated_events": [e.event_id for e in events],
                        "attack_duration": str(max(e.timestamp for e in events) - min(e.timestamp for e in events)),
                        "event_types": list(set(e.event_type for e in events))
                    },
                    threat_score=sum(e.threat_score for e in events) / len(events) + 2.0
                )
                
                self.event_queue.append(correlation_event)
                await self._broadcast_event(correlation_event)
    
    async def _check_alert_thresholds(self, security_event: SecurityEvent):
        """Check if alert thresholds are met."""
        severity = security_event.severity
        self.alert_counts[severity] += 1
        
        threshold = self.alert_thresholds.get(severity, 10)
        
        if self.alert_counts[severity] >= threshold:
            await self._generate_alert(security_event, self.alert_counts[severity])
            self.alert_counts[severity] = 0  # Reset counter
    
    async def _generate_alert(self, security_event: SecurityEvent, event_count: int):
        """Generate security alert."""
        alert = {
            "alert_id": f"alert_{int(time.time())}",
            "timestamp": datetime.utcnow().isoformat(),
            "severity": security_event.severity,
            "title": f"{security_event.severity.title()} Security Alert",
            "description": f"{event_count} {security_event.severity} security events detected",
            "triggering_event": asdict(security_event),
            "recommended_actions": self._get_recommended_actions(security_event)
        }
        
        # Save alert to database
        db = get_db()
        db.security_alerts.insert_one(alert)
        
        # Broadcast alert
        await self._broadcast_alert(alert)
        
        print(f"SECURITY ALERT: {alert['title']} - {alert['description']}")
    
    def _get_recommended_actions(self, security_event: SecurityEvent) -> List[str]:
        """Get recommended actions for security event."""
        actions = {
            "injection_attack": [
                "Block source IP immediately",
                "Review application input validation",
                "Check database logs for compromise",
                "Update WAF rules"
            ],
            "brute_force": [
                "Implement account lockout policies",
                "Enable multi-factor authentication",
                "Block source IP",
                "Review authentication logs"
            ],
            "malware": [
                "Isolate affected systems",
                "Run full antivirus scan",
                "Check for lateral movement",
                "Review file integrity"
            ],
            "data_breach": [
                "Activate incident response plan",
                "Preserve evidence",
                "Notify stakeholders",
                "Assess data exposure"
            ]
        }
        
        return actions.get(security_event.event_type, [
            "Investigate the security event",
            "Review system logs",
            "Consider blocking source if malicious"
        ])
    
    async def _broadcast_event(self, security_event: SecurityEvent):
        """Broadcast security event to WebSocket clients."""
        if self.websocket_clients:
            message = {
                "type": "security_event",
                "data": asdict(security_event)
            }
            
            # Convert datetime to string for JSON serialization
            message["data"]["timestamp"] = security_event.timestamp.isoformat()
            
            disconnected_clients = set()
            for client in self.websocket_clients:
                try:
                    await client.send(json.dumps(message))
                except websockets.exceptions.ConnectionClosed:
                    disconnected_clients.add(client)
            
            # Remove disconnected clients
            self.websocket_clients -= disconnected_clients
    
    async def _broadcast_alert(self, alert: Dict[str, Any]):
        """Broadcast security alert to WebSocket clients."""
        if self.websocket_clients:
            message = {
                "type": "security_alert",
                "data": alert
            }
            
            disconnected_clients = set()
            for client in self.websocket_clients:
                try:
                    await client.send(json.dumps(message))
                except websockets.exceptions.ConnectionClosed:
                    disconnected_clients.add(client)
            
            # Remove disconnected clients
            self.websocket_clients -= disconnected_clients
    
    async def _websocket_server(self):
        """WebSocket server for real-time updates."""
        async def handle_client(websocket, path):
            self.websocket_clients.add(websocket)
            try:
                await websocket.wait_closed()
            finally:
                self.websocket_clients.discard(websocket)
        
        try:
            server = await websockets.serve(handle_client, "localhost", 8765)
            await server.wait_closed()
        except Exception as e:
            print(f"WebSocket server error: {e}")
    
    async def _save_security_event(self, security_event: SecurityEvent):
        """Save security event to database."""
        try:
            db = get_db()
            event_dict = asdict(security_event)
            event_dict["timestamp"] = security_event.timestamp.isoformat()
            db.security_events.insert_one(event_dict)
        except Exception as e:
            print(f"Error saving security event: {e}")
    
    async def _cleanup_old_events(self):
        """Clean up old events from memory."""
        cutoff_time = datetime.utcnow() - timedelta(hours=1)
        
        # Remove events older than 1 hour from queue
        while self.event_queue and self.event_queue[0].timestamp < cutoff_time:
            self.event_queue.popleft()
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default monitoring configuration."""
        return {
            "network_monitoring": True,
            "web_monitoring": True,
            "system_monitoring": True,
            "file_monitoring": True,
            "alert_email": "security@company.com",
            "alert_webhook": None,
            "monitoring_interval": 5,
            "retention_days": 30
        }
    
    def get_monitoring_status(self) -> Dict[str, Any]:
        """Get current monitoring status."""
        return {
            "active_monitors": len(self.active_monitors),
            "monitoring_active": self.monitoring_active,
            "events_in_queue": len(self.event_queue),
            "websocket_clients": len(self.websocket_clients),
            "alert_counts": dict(self.alert_counts),
            "monitors": self.active_monitors
        }
    
    def stop_monitoring(self, monitor_id: str = None):
        """Stop monitoring for specific monitor or all monitors."""
        if monitor_id:
            if monitor_id in self.active_monitors:
                self.active_monitors[monitor_id]["status"] = "stopped"
                self.active_monitors[monitor_id]["end_time"] = datetime.utcnow()
        else:
            self.monitoring_active = False
            for monitor in self.active_monitors.values():
                monitor["status"] = "stopped"
                monitor["end_time"] = datetime.utcnow()

# Global monitor instance
real_time_monitor = RealTimeMonitor()

def start_monitoring_service():
    """Start the monitoring service."""
    def run_monitor():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        # Start monitoring for default target
        loop.run_until_complete(
            real_time_monitor.start_monitoring("default_target")
        )
    
    monitor_thread = threading.Thread(target=run_monitor)
    monitor_thread.daemon = True
    monitor_thread.start()
    
    return monitor_thread