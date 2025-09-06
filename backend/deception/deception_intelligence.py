#!/usr/bin/env python3
"""
Deception Intelligence Engine Module

Provides advanced threat intelligence gathering and analysis capabilities
based on deception technology interactions. Correlates attacker behaviors,
identifies TTPs, and generates actionable intelligence.
"""

import os
import json
import uuid
import logging
import datetime
from enum import Enum
from typing import Dict, List, Optional, Union, Any, Set, Tuple
from dataclasses import dataclass, field


class ThreatActorType(Enum):
    """Types of threat actors that might interact with deception assets"""
    UNKNOWN = "unknown"
    OPPORTUNISTIC = "opportunistic"  # Random, non-targeted attackers
    APT = "apt"  # Advanced Persistent Threat
    INSIDER = "insider"  # Insider threat
    HACKTIVIST = "hacktivist"  # Politically motivated
    CRIMINAL = "criminal"  # Financially motivated
    NATION_STATE = "nation_state"  # State-sponsored


class TTPCategory(Enum):
    """Categories of Tactics, Techniques, and Procedures"""
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    EXFILTRATION = "exfiltration"
    COMMAND_AND_CONTROL = "command_and_control"
    IMPACT = "impact"


class ConfidenceLevel(Enum):
    """Confidence levels for intelligence assessments"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    VERY_HIGH = "very_high"


@dataclass
class MITREAttackTechnique:
    """Representation of a MITRE ATT&CK technique"""
    technique_id: str  # e.g., T1110
    name: str
    url: str
    description: str
    sub_technique_id: Optional[str] = None  # e.g., T1110.001
    tactic: Optional[str] = None
    platforms: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "technique_id": self.technique_id,
            "name": self.name,
            "url": self.url,
            "description": self.description,
            "sub_technique_id": self.sub_technique_id,
            "tactic": self.tactic,
            "platforms": self.platforms
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'MITREAttackTechnique':
        """Create from dictionary"""
        return cls(
            technique_id=data["technique_id"],
            name=data["name"],
            url=data["url"],
            description=data["description"],
            sub_technique_id=data.get("sub_technique_id"),
            tactic=data.get("tactic"),
            platforms=data.get("platforms", [])
        )


@dataclass
class DeceptionEvent:
    """Represents an interaction with a deception asset"""
    id: str
    timestamp: datetime.datetime
    asset_id: str
    asset_type: str  # honeypot, honeytoken, etc.
    source_ip: Optional[str] = None
    user_agent: Optional[str] = None
    username: Optional[str] = None
    event_type: str = "access"
    details: Dict[str, Any] = field(default_factory=dict)
    raw_data: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "asset_id": self.asset_id,
            "asset_type": self.asset_type,
            "source_ip": self.source_ip,
            "user_agent": self.user_agent,
            "username": self.username,
            "event_type": self.event_type,
            "details": self.details,
            "raw_data": self.raw_data
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'DeceptionEvent':
        """Create from dictionary"""
        return cls(
            id=data["id"],
            timestamp=datetime.datetime.fromisoformat(data["timestamp"]),
            asset_id=data["asset_id"],
            asset_type=data["asset_type"],
            source_ip=data.get("source_ip"),
            user_agent=data.get("user_agent"),
            username=data.get("username"),
            event_type=data.get("event_type", "access"),
            details=data.get("details", {}),
            raw_data=data.get("raw_data")
        )


@dataclass
class ThreatIndicator:
    """Represents an indicator of compromise or threat"""
    id: str
    indicator_type: str  # ip, domain, hash, url, etc.
    value: str
    confidence: ConfidenceLevel
    created_at: datetime.datetime
    updated_at: datetime.datetime
    first_seen: datetime.datetime
    last_seen: datetime.datetime
    source: str
    description: str = ""
    tags: List[str] = field(default_factory=list)
    related_events: List[str] = field(default_factory=list)  # Event IDs
    ttp_categories: List[TTPCategory] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)  # Technique IDs
    false_positive: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "id": self.id,
            "indicator_type": self.indicator_type,
            "value": self.value,
            "confidence": self.confidence.value,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "source": self.source,
            "description": self.description,
            "tags": self.tags,
            "related_events": self.related_events,
            "ttp_categories": [cat.value for cat in self.ttp_categories],
            "mitre_techniques": self.mitre_techniques,
            "false_positive": self.false_positive
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ThreatIndicator':
        """Create from dictionary"""
        return cls(
            id=data["id"],
            indicator_type=data["indicator_type"],
            value=data["value"],
            confidence=ConfidenceLevel(data["confidence"]),
            created_at=datetime.datetime.fromisoformat(data["created_at"]),
            updated_at=datetime.datetime.fromisoformat(data["updated_at"]),
            first_seen=datetime.datetime.fromisoformat(data["first_seen"]),
            last_seen=datetime.datetime.fromisoformat(data["last_seen"]),
            source=data["source"],
            description=data.get("description", ""),
            tags=data.get("tags", []),
            related_events=data.get("related_events", []),
            ttp_categories=[TTPCategory(cat) for cat in data.get("ttp_categories", [])],
            mitre_techniques=data.get("mitre_techniques", []),
            false_positive=data.get("false_positive", False)
        )


@dataclass
class ThreatCampaign:
    """Represents a collection of related threat activities"""
    id: str
    name: str
    description: str
    created_at: datetime.datetime
    updated_at: datetime.datetime
    first_activity: datetime.datetime
    last_activity: datetime.datetime
    status: str  # active, closed, etc.
    confidence: ConfidenceLevel
    actor_type: ThreatActorType
    indicators: List[str] = field(default_factory=list)  # Indicator IDs
    events: List[str] = field(default_factory=list)  # Event IDs
    ttp_categories: List[TTPCategory] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)  # Technique IDs
    tags: List[str] = field(default_factory=list)
    notes: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "first_activity": self.first_activity.isoformat(),
            "last_activity": self.last_activity.isoformat(),
            "status": self.status,
            "confidence": self.confidence.value,
            "actor_type": self.actor_type.value,
            "indicators": self.indicators,
            "events": self.events,
            "ttp_categories": [cat.value for cat in self.ttp_categories],
            "mitre_techniques": self.mitre_techniques,
            "tags": self.tags,
            "notes": self.notes
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ThreatCampaign':
        """Create from dictionary"""
        return cls(
            id=data["id"],
            name=data["name"],
            description=data["description"],
            created_at=datetime.datetime.fromisoformat(data["created_at"]),
            updated_at=datetime.datetime.fromisoformat(data["updated_at"]),
            first_activity=datetime.datetime.fromisoformat(data["first_activity"]),
            last_activity=datetime.datetime.fromisoformat(data["last_activity"]),
            status=data["status"],
            confidence=ConfidenceLevel(data["confidence"]),
            actor_type=ThreatActorType(data["actor_type"]),
            indicators=data.get("indicators", []),
            events=data.get("events", []),
            ttp_categories=[TTPCategory(cat) for cat in data.get("ttp_categories", [])],
            mitre_techniques=data.get("mitre_techniques", []),
            tags=data.get("tags", []),
            notes=data.get("notes", "")
        )


class DeceptionIntelligenceEngine:
    """Engine for gathering and analyzing threat intelligence from deception assets"""
    
    def __init__(self, config_path: Optional[str] = None, mitre_data_path: Optional[str] = None):
        self.logger = logging.getLogger("deception_intelligence")
        self.events: Dict[str, DeceptionEvent] = {}
        self.indicators: Dict[str, ThreatIndicator] = {}
        self.campaigns: Dict[str, ThreatCampaign] = {}
        self.mitre_techniques: Dict[str, MITREAttackTechnique] = {}
        self.config_path = config_path
        self.mitre_data_path = mitre_data_path
        
        # Load MITRE ATT&CK data if available
        if mitre_data_path and os.path.exists(mitre_data_path):
            self.load_mitre_data()
        
        # Load existing intelligence data if available
        if config_path and os.path.exists(config_path):
            self.load_state()
    
    def record_event(self, event: DeceptionEvent) -> str:
        """Record a new deception event"""
        if not event.id:
            event.id = str(uuid.uuid4())
            
        self.events[event.id] = event
        self.logger.info(f"Recorded deception event {event.id} from asset {event.asset_id}")
        
        # Process the event for intelligence
        self.process_event(event)
        
        # Save state
        self.save_state()
        return event.id
    
    def process_event(self, event: DeceptionEvent) -> None:
        """Process an event to extract intelligence"""
        # Extract potential indicators
        self._extract_indicators(event)
        
        # Correlate with existing campaigns
        self._correlate_with_campaigns(event)
        
        # Identify TTPs
        self._identify_ttps(event)
    
    def _extract_indicators(self, event: DeceptionEvent) -> List[str]:
        """Extract indicators from an event"""
        indicator_ids = []
        
        # Extract IP address
        if event.source_ip:
            indicator_id = self._create_or_update_indicator(
                indicator_type="ip",
                value=event.source_ip,
                confidence=ConfidenceLevel.MEDIUM,
                source=f"deception:{event.asset_type}",
                event_id=event.id
            )
            if indicator_id:
                indicator_ids.append(indicator_id)
        
        # Extract other indicators from details
        if "domain" in event.details:
            indicator_id = self._create_or_update_indicator(
                indicator_type="domain",
                value=event.details["domain"],
                confidence=ConfidenceLevel.MEDIUM,
                source=f"deception:{event.asset_type}",
                event_id=event.id
            )
            if indicator_id:
                indicator_ids.append(indicator_id)
        
        if "url" in event.details:
            indicator_id = self._create_or_update_indicator(
                indicator_type="url",
                value=event.details["url"],
                confidence=ConfidenceLevel.MEDIUM,
                source=f"deception:{event.asset_type}",
                event_id=event.id
            )
            if indicator_id:
                indicator_ids.append(indicator_id)
        
        if "hash" in event.details:
            indicator_id = self._create_or_update_indicator(
                indicator_type="hash",
                value=event.details["hash"],
                confidence=ConfidenceLevel.HIGH,
                source=f"deception:{event.asset_type}",
                event_id=event.id
            )
            if indicator_id:
                indicator_ids.append(indicator_id)
        
        return indicator_ids
    
    def _create_or_update_indicator(self, indicator_type: str, value: str, 
                                  confidence: ConfidenceLevel, source: str,
                                  event_id: str) -> Optional[str]:
        """Create a new indicator or update an existing one"""
        # Check if indicator already exists
        existing_id = None
        for id, indicator in self.indicators.items():
            if indicator.indicator_type == indicator_type and indicator.value == value:
                existing_id = id
                break
        
        now = datetime.datetime.now()
        
        if existing_id:
            # Update existing indicator
            indicator = self.indicators[existing_id]
            indicator.last_seen = now
            indicator.updated_at = now
            
            # Update confidence if higher
            if confidence.value > indicator.confidence.value:
                indicator.confidence = confidence
            
            # Add event ID if not already present
            if event_id not in indicator.related_events:
                indicator.related_events.append(event_id)
                
            return existing_id
        else:
            # Create new indicator
            indicator_id = str(uuid.uuid4())
            indicator = ThreatIndicator(
                id=indicator_id,
                indicator_type=indicator_type,
                value=value,
                confidence=confidence,
                created_at=now,
                updated_at=now,
                first_seen=now,
                last_seen=now,
                source=source,
                related_events=[event_id]
            )
            
            self.indicators[indicator_id] = indicator
            self.logger.info(f"Created new {indicator_type} indicator: {value}")
            return indicator_id
    
    def _correlate_with_campaigns(self, event: DeceptionEvent) -> None:
        """Correlate an event with existing campaigns"""
        # Find indicators related to this event
        related_indicators = []
        for id, indicator in self.indicators.items():
            if event.id in indicator.related_events:
                related_indicators.append(id)
        
        # Find campaigns that share indicators
        matching_campaigns = set()
        for id, campaign in self.campaigns.items():
            # Check if any indicators match
            if any(ind_id in campaign.indicators for ind_id in related_indicators):
                matching_campaigns.add(id)
            
            # Check if source IP matches any campaign events
            if event.source_ip:
                for event_id in campaign.events:
                    if event_id in self.events and self.events[event_id].source_ip == event.source_ip:
                        matching_campaigns.add(id)
                        break
        
        # Update matching campaigns
        for campaign_id in matching_campaigns:
            campaign = self.campaigns[campaign_id]
            
            # Add event to campaign
            if event.id not in campaign.events:
                campaign.events.append(event.id)
            
            # Add indicators to campaign
            for indicator_id in related_indicators:
                if indicator_id not in campaign.indicators:
                    campaign.indicators.append(indicator_id)
            
            # Update campaign timestamps
            campaign.updated_at = datetime.datetime.now()
            if event.timestamp > campaign.last_activity:
                campaign.last_activity = event.timestamp
            elif event.timestamp < campaign.first_activity:
                campaign.first_activity = event.timestamp
    
    def _identify_ttps(self, event: DeceptionEvent) -> List[Tuple[TTPCategory, str]]:
        """Identify TTPs from an event"""
        ttps = []
        
        # Map event types to TTP categories
        event_type_mapping = {
            "login_attempt": (TTPCategory.CREDENTIAL_ACCESS, "T1110"),  # Brute Force
            "command_execution": (TTPCategory.EXECUTION, "T1059"),  # Command and Scripting Interpreter
            "file_access": (TTPCategory.COLLECTION, "T1005"),  # Data from Local System
            "data_exfiltration": (TTPCategory.EXFILTRATION, "T1048"),  # Exfiltration Over Alternative Protocol
            "network_scan": (TTPCategory.DISCOVERY, "T1046"),  # Network Service Scanning
            "privilege_escalation": (TTPCategory.PRIVILEGE_ESCALATION, "T1068"),  # Exploitation for Privilege Escalation
            "lateral_movement": (TTPCategory.LATERAL_MOVEMENT, "T1021")  # Remote Services
        }
        
        # Check event type
        if event.event_type in event_type_mapping:
            category, technique_id = event_type_mapping[event.event_type]
            ttps.append((category, technique_id))
        
        # Check event details for additional TTPs
        if "commands" in event.details:
            commands = event.details["commands"]
            if any(cmd for cmd in commands if "wget" in cmd or "curl" in cmd):
                ttps.append((TTPCategory.COMMAND_AND_CONTROL, "T1105"))  # Ingress Tool Transfer
        
        if "files_accessed" in event.details:
            ttps.append((TTPCategory.COLLECTION, "T1005"))  # Data from Local System
        
        if "persistence_mechanism" in event.details:
            ttps.append((TTPCategory.PERSISTENCE, "T1136"))  # Create Account
        
        # Update indicators with identified TTPs
        for indicator_id in self._extract_indicators(event):
            indicator = self.indicators[indicator_id]
            for category, technique_id in ttps:
                if category not in indicator.ttp_categories:
                    indicator.ttp_categories.append(category)
                if technique_id not in indicator.mitre_techniques:
                    indicator.mitre_techniques.append(technique_id)
        
        return ttps
    
    def create_campaign(self, name: str, description: str, 
                       actor_type: ThreatActorType = ThreatActorType.UNKNOWN,
                       confidence: ConfidenceLevel = ConfidenceLevel.MEDIUM) -> str:
        """Create a new threat campaign"""
        now = datetime.datetime.now()
        campaign_id = str(uuid.uuid4())
        
        campaign = ThreatCampaign(
            id=campaign_id,
            name=name,
            description=description,
            created_at=now,
            updated_at=now,
            first_activity=now,
            last_activity=now,
            status="active",
            confidence=confidence,
            actor_type=actor_type
        )
        
        self.campaigns[campaign_id] = campaign
        self.logger.info(f"Created new threat campaign: {name}")
        self.save_state()
        return campaign_id
    
    def add_event_to_campaign(self, campaign_id: str, event_id: str) -> bool:
        """Add an event to a campaign"""
        if campaign_id not in self.campaigns or event_id not in self.events:
            return False
        
        campaign = self.campaigns[campaign_id]
        event = self.events[event_id]
        
        # Add event to campaign
        if event_id not in campaign.events:
            campaign.events.append(event_id)
        
        # Update campaign timestamps
        campaign.updated_at = datetime.datetime.now()
        if event.timestamp > campaign.last_activity:
            campaign.last_activity = event.timestamp
        elif event.timestamp < campaign.first_activity:
            campaign.first_activity = event.timestamp
        
        # Add related indicators to campaign
        for indicator_id, indicator in self.indicators.items():
            if event_id in indicator.related_events and indicator_id not in campaign.indicators:
                campaign.indicators.append(indicator_id)
        
        self.save_state()
        return True
    
    def get_event(self, event_id: str) -> Optional[DeceptionEvent]:
        """Get an event by ID"""
        return self.events.get(event_id)
    
    def get_indicator(self, indicator_id: str) -> Optional[ThreatIndicator]:
        """Get an indicator by ID"""
        return self.indicators.get(indicator_id)
    
    def get_campaign(self, campaign_id: str) -> Optional[ThreatCampaign]:
        """Get a campaign by ID"""
        return self.campaigns.get(campaign_id)
    
    def list_events(self, asset_id: Optional[str] = None, 
                   start_time: Optional[datetime.datetime] = None,
                   end_time: Optional[datetime.datetime] = None) -> List[DeceptionEvent]:
        """List events with optional filtering"""
        results = list(self.events.values())
        
        if asset_id:
            results = [e for e in results if e.asset_id == asset_id]
        
        if start_time:
            results = [e for e in results if e.timestamp >= start_time]
        
        if end_time:
            results = [e for e in results if e.timestamp <= end_time]
            
        return sorted(results, key=lambda e: e.timestamp, reverse=True)
    
    def list_indicators(self, indicator_type: Optional[str] = None,
                       confidence: Optional[ConfidenceLevel] = None) -> List[ThreatIndicator]:
        """List indicators with optional filtering"""
        results = list(self.indicators.values())
        
        if indicator_type:
            results = [i for i in results if i.indicator_type == indicator_type]
        
        if confidence:
            results = [i for i in results if i.confidence == confidence]
            
        return sorted(results, key=lambda i: i.last_seen, reverse=True)
    
    def list_campaigns(self, status: Optional[str] = None,
                      actor_type: Optional[ThreatActorType] = None) -> List[ThreatCampaign]:
        """List campaigns with optional filtering"""
        results = list(self.campaigns.values())
        
        if status:
            results = [c for c in results if c.status == status]
        
        if actor_type:
            results = [c for c in results if c.actor_type == actor_type]
            
        return sorted(results, key=lambda c: c.last_activity, reverse=True)
    
    def get_mitre_technique(self, technique_id: str) -> Optional[MITREAttackTechnique]:
        """Get a MITRE ATT&CK technique by ID"""
        return self.mitre_techniques.get(technique_id)
    
    def load_mitre_data(self) -> bool:
        """Load MITRE ATT&CK data from file"""
        if not self.mitre_data_path or not os.path.exists(self.mitre_data_path):
            return False
        
        try:
            with open(self.mitre_data_path, 'r') as f:
                data = json.load(f)
            
            self.mitre_techniques = {}
            for technique_data in data.get("techniques", []):
                technique = MITREAttackTechnique.from_dict(technique_data)
                self.mitre_techniques[technique.technique_id] = technique
                
                # Also index by sub-technique ID if present
                if technique.sub_technique_id:
                    self.mitre_techniques[technique.sub_technique_id] = technique
                
            self.logger.info(f"Loaded {len(self.mitre_techniques)} MITRE ATT&CK techniques")
            return True
        except Exception as e:
            self.logger.error(f"Failed to load MITRE data: {str(e)}")
            return False
    
    def save_state(self) -> bool:
        """Save engine state to disk"""
        if not self.config_path:
            return False
        
        data = {
            "events": {id: event.to_dict() for id, event in self.events.items()},
            "indicators": {id: indicator.to_dict() for id, indicator in self.indicators.items()},
            "campaigns": {id: campaign.to_dict() for id, campaign in self.campaigns.items()}
        }
        
        try:
            with open(self.config_path, 'w') as f:
                json.dump(data, f, indent=2)
            return True
        except Exception as e:
            self.logger.error(f"Failed to save state: {str(e)}")
            return False
    
    def load_state(self) -> bool:
        """Load engine state from disk"""
        if not self.config_path or not os.path.exists(self.config_path):
            return False
        
        try:
            with open(self.config_path, 'r') as f:
                data = json.load(f)
            
            # Load events
            self.events = {}
            for id, event_data in data.get("events", {}).items():
                self.events[id] = DeceptionEvent.from_dict(event_data)
            
            # Load indicators
            self.indicators = {}
            for id, indicator_data in data.get("indicators", {}).items():
                self.indicators[id] = ThreatIndicator.from_dict(indicator_data)
            
            # Load campaigns
            self.campaigns = {}
            for id, campaign_data in data.get("campaigns", {}).items():
                self.campaigns[id] = ThreatCampaign.from_dict(campaign_data)
                
            self.logger.info(f"Loaded {len(self.events)} events, {len(self.indicators)} indicators, and {len(self.campaigns)} campaigns")
            return True
        except Exception as e:
            self.logger.error(f"Failed to load state: {str(e)}")
            return False
    
    def generate_intelligence_report(self, campaign_id: Optional[str] = None,
                                   start_time: Optional[datetime.datetime] = None,
                                   end_time: Optional[datetime.datetime] = None) -> Dict[str, Any]:
        """Generate an intelligence report"""
        now = datetime.datetime.now()
        report = {
            "generated_at": now.isoformat(),
            "period": {
                "start": start_time.isoformat() if start_time else None,
                "end": end_time.isoformat() if end_time else now.isoformat()
            },
            "summary": {},
            "campaigns": [],
            "indicators": [],
            "ttps": [],
            "recommendations": []
        }
        
        # Filter events by time period
        filtered_events = self.list_events(start_time=start_time, end_time=end_time)
        
        # If campaign ID is provided, filter to just that campaign
        if campaign_id and campaign_id in self.campaigns:
            campaign = self.campaigns[campaign_id]
            report["campaign_focus"] = {
                "id": campaign.id,
                "name": campaign.name,
                "description": campaign.description,
                "first_activity": campaign.first_activity.isoformat(),
                "last_activity": campaign.last_activity.isoformat(),
                "status": campaign.status,
                "actor_type": campaign.actor_type.value
            }
            
            # Filter events to just this campaign
            filtered_events = [e for e in filtered_events if e.id in campaign.events]
            
            # Add campaign indicators
            for indicator_id in campaign.indicators:
                if indicator_id in self.indicators:
                    indicator = self.indicators[indicator_id]
                    report["indicators"].append({
                        "id": indicator.id,
                        "type": indicator.indicator_type,
                        "value": indicator.value,
                        "confidence": indicator.confidence.value,
                        "first_seen": indicator.first_seen.isoformat(),
                        "last_seen": indicator.last_seen.isoformat()
                    })
            
            # Add campaign TTPs
            ttp_counts = {}
            for technique_id in campaign.mitre_techniques:
                if technique_id in self.mitre_techniques:
                    technique = self.mitre_techniques[technique_id]
                    ttp_counts[technique_id] = ttp_counts.get(technique_id, 0) + 1
                    
            for technique_id, count in sorted(ttp_counts.items(), key=lambda x: x[1], reverse=True):
                technique = self.mitre_techniques[technique_id]
                report["ttps"].append({
                    "technique_id": technique.technique_id,
                    "name": technique.name,
                    "count": count,
                    "description": technique.description
                })
        else:
            # Summarize all campaigns in the time period
            active_campaigns = []
            for campaign in self.campaigns.values():
                # Check if campaign was active in the time period
                if start_time and campaign.last_activity < start_time:
                    continue
                if end_time and campaign.first_activity > end_time:
                    continue
                    
                active_campaigns.append({
                    "id": campaign.id,
                    "name": campaign.name,
                    "first_activity": campaign.first_activity.isoformat(),
                    "last_activity": campaign.last_activity.isoformat(),
                    "status": campaign.status,
                    "actor_type": campaign.actor_type.value,
                    "event_count": len(campaign.events),
                    "indicator_count": len(campaign.indicators)
                })
                
            report["campaigns"] = active_campaigns
            
            # Add top indicators
            top_indicators = sorted(
                [i for i in self.indicators.values() if any(e in filtered_events for e in i.related_events)],
                key=lambda i: i.confidence.value + "-" + i.last_seen.isoformat(),
                reverse=True
            )[:10]
            
            for indicator in top_indicators:
                report["indicators"].append({
                    "id": indicator.id,
                    "type": indicator.indicator_type,
                    "value": indicator.value,
                    "confidence": indicator.confidence.value,
                    "first_seen": indicator.first_seen.isoformat(),
                    "last_seen": indicator.last_seen.isoformat()
                })
            
            # Add top TTPs
            ttp_counts = {}
            for indicator in self.indicators.values():
                if any(e in filtered_events for e in indicator.related_events):
                    for technique_id in indicator.mitre_techniques:
                        if technique_id in self.mitre_techniques:
                            ttp_counts[technique_id] = ttp_counts.get(technique_id, 0) + 1
                            
            for technique_id, count in sorted(ttp_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
                if technique_id in self.mitre_techniques:
                    technique = self.mitre_techniques[technique_id]
                    report["ttps"].append({
                        "technique_id": technique.technique_id,
                        "name": technique.name,
                        "count": count,
                        "description": technique.description
                    })
        
        # Generate summary statistics
        report["summary"] = {
            "event_count": len(filtered_events),
            "unique_source_ips": len(set(e.source_ip for e in filtered_events if e.source_ip)),
            "unique_assets_triggered": len(set(e.asset_id for e in filtered_events)),
            "most_targeted_asset": self._get_most_targeted_asset(filtered_events),
            "most_active_source": self._get_most_active_source(filtered_events)
        }
        
        # Generate recommendations based on observed TTPs
        report["recommendations"] = self._generate_recommendations(report["ttps"])
        
        return report
    
    def _get_most_targeted_asset(self, events: List[DeceptionEvent]) -> Dict[str, Any]:
        """Get the most targeted asset from a list of events"""
        asset_counts = {}
        for event in events:
            asset_counts[event.asset_id] = asset_counts.get(event.asset_id, 0) + 1
            
        if not asset_counts:
            return {"asset_id": None, "count": 0}
            
        most_targeted = max(asset_counts.items(), key=lambda x: x[1])
        return {"asset_id": most_targeted[0], "count": most_targeted[1]}
    
    def _get_most_active_source(self, events: List[DeceptionEvent]) -> Dict[str, Any]:
        """Get the most active source from a list of events"""
        source_counts = {}
        for event in events:
            if event.source_ip:
                source_counts[event.source_ip] = source_counts.get(event.source_ip, 0) + 1
                
        if not source_counts:
            return {"source_ip": None, "count": 0}
                
        most_active = max(source_counts.items(), key=lambda x: x[1])
        return {"source_ip": most_active[0], "count": most_active[1]}
    
    def _generate_recommendations(self, ttps: List[Dict[str, Any]]) -> List[str]:
        """Generate recommendations based on observed TTPs"""
        recommendations = []
        
        # Map technique IDs to recommendations
        recommendation_map = {
            "T1110": "Implement account lockout policies and multi-factor authentication to mitigate brute force attacks.",
            "T1059": "Restrict command-line interface access and implement application whitelisting.",
            "T1005": "Implement proper access controls and encrypt sensitive data at rest.",
            "T1048": "Monitor for unusual outbound network traffic and implement data loss prevention solutions.",
            "T1046": "Implement network segmentation and restrict unnecessary services.",
            "T1068": "Keep systems patched and implement principle of least privilege.",
            "T1021": "Restrict remote service access and implement network segmentation.",
            "T1105": "Block unnecessary file download utilities and monitor for suspicious downloads."
        }
        
        # Add recommendations based on observed TTPs
        for ttp in ttps:
            technique_id = ttp["technique_id"]
            if technique_id in recommendation_map and recommendation_map[technique_id] not in recommendations:
                recommendations.append(recommendation_map[technique_id])
        
        # Add general recommendations if we have few specific ones
        if len(recommendations) < 3:
            general_recommendations = [
                "Regularly review and update deception assets to maintain their effectiveness.",
                "Implement network segmentation to limit lateral movement opportunities.",
                "Ensure comprehensive logging and monitoring across the environment.",
                "Conduct regular security awareness training for all employees.",
                "Implement a robust patch management process for all systems and applications."
            ]
            
            for rec in general_recommendations:
                if rec not in recommendations:
                    recommendations.append(rec)
                    if len(recommendations) >= 5:
                        break
        
        return recommendations[:5]  # Limit to top 5 recommendations