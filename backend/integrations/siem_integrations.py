#!/usr/bin/env python3
"""
SIEM Integration Module for InfoSentinel Enterprise.
Provides integration with Splunk, ELK Stack, and other SIEM systems.
"""
import json
import logging
import requests
import asyncio
import aiohttp
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
from abc import ABC, abstractmethod
import base64
from urllib.parse import urljoin
from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk

logger = logging.getLogger(__name__)

class SIEMType(Enum):
    """Supported SIEM types."""
    SPLUNK = "splunk"
    ELASTICSEARCH = "elasticsearch"
    LOGSTASH = "logstash"
    KIBANA = "kibana"
    QRADAR = "qradar"
    ARCSIGHT = "arcsight"
    SENTINEL = "sentinel"
    CUSTOM = "custom"

class EventSeverity(Enum):
    """Event severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class EventCategory(Enum):
    """Event categories."""
    VULNERABILITY = "vulnerability"
    SCAN_RESULT = "scan_result"
    SECURITY_ALERT = "security_alert"
    COMPLIANCE_VIOLATION = "compliance_violation"
    THREAT_DETECTION = "threat_detection"
    SYSTEM_EVENT = "system_event"
    USER_ACTIVITY = "user_activity"

@dataclass
class SIEMEvent:
    """SIEM event data structure."""
    timestamp: datetime
    event_id: str
    source: str
    category: EventCategory
    severity: EventSeverity
    title: str
    description: str
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    user_id: Optional[str] = None
    asset_id: Optional[str] = None
    vulnerability_id: Optional[str] = None
    scan_id: Optional[str] = None
    raw_data: Optional[Dict] = None
    tags: Optional[List[str]] = None
    custom_fields: Optional[Dict] = None

@dataclass
class SIEMConfig:
    """SIEM configuration."""
    siem_type: SIEMType
    name: str
    host: str
    port: int
    username: str
    password: str
    api_key: Optional[str] = None
    index_name: Optional[str] = None
    ssl_enabled: bool = True
    verify_ssl: bool = True
    timeout: int = 30
    custom_headers: Optional[Dict] = None
    custom_params: Optional[Dict] = None

class BaseSIEMIntegration(ABC):
    """Base class for SIEM integrations."""
    
    def __init__(self, config: SIEMConfig):
        self.config = config
        self.session = None
    
    @abstractmethod
    async def connect(self) -> bool:
        """Establish connection to SIEM."""
        pass
    
    @abstractmethod
    async def send_event(self, event: SIEMEvent) -> bool:
        """Send single event to SIEM."""
        pass
    
    @abstractmethod
    async def send_events_batch(self, events: List[SIEMEvent]) -> Dict:
        """Send batch of events to SIEM."""
        pass
    
    @abstractmethod
    async def query_events(self, query: str, start_time: datetime, end_time: datetime) -> List[Dict]:
        """Query events from SIEM."""
        pass
    
    @abstractmethod
    async def test_connection(self) -> Dict:
        """Test SIEM connection."""
        pass
    
    def format_event(self, event: SIEMEvent) -> Dict:
        """Format event for SIEM."""
        formatted_event = {
            'timestamp': event.timestamp.isoformat(),
            'event_id': event.event_id,
            'source': event.source,
            'category': event.category.value,
            'severity': event.severity.value,
            'title': event.title,
            'description': event.description
        }
        
        # Add optional fields
        if event.source_ip:
            formatted_event['source_ip'] = event.source_ip
        if event.destination_ip:
            formatted_event['destination_ip'] = event.destination_ip
        if event.user_id:
            formatted_event['user_id'] = event.user_id
        if event.asset_id:
            formatted_event['asset_id'] = event.asset_id
        if event.vulnerability_id:
            formatted_event['vulnerability_id'] = event.vulnerability_id
        if event.scan_id:
            formatted_event['scan_id'] = event.scan_id
        if event.tags:
            formatted_event['tags'] = event.tags
        if event.custom_fields:
            formatted_event.update(event.custom_fields)
        if event.raw_data:
            formatted_event['raw_data'] = event.raw_data
        
        return formatted_event

class SplunkIntegration(BaseSIEMIntegration):
    """Splunk SIEM integration."""
    
    def __init__(self, config: SIEMConfig):
        super().__init__(config)
        self.base_url = f"{'https' if config.ssl_enabled else 'http'}://{config.host}:{config.port}"
        self.auth_token = None
    
    async def connect(self) -> bool:
        """Establish connection to Splunk."""
        try:
            # Authenticate with Splunk
            auth_url = urljoin(self.base_url, '/services/auth/login')
            
            auth_data = {
                'username': self.config.username,
                'password': self.config.password,
                'output_mode': 'json'
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    auth_url,
                    data=auth_data,
                    ssl=self.config.verify_ssl,
                    timeout=self.config.timeout
                ) as response:
                    if response.status == 200:
                        auth_response = await response.json()
                        self.auth_token = auth_response.get('sessionKey')
                        logger.info(f"Successfully connected to Splunk: {self.config.name}")
                        return True
                    else:
                        logger.error(f"Failed to authenticate with Splunk: {response.status}")
                        return False
        
        except Exception as e:
            logger.error(f"Error connecting to Splunk: {str(e)}")
            return False
    
    async def send_event(self, event: SIEMEvent) -> bool:
        """Send single event to Splunk."""
        try:
            if not self.auth_token:
                await self.connect()
            
            # Format event for Splunk
            formatted_event = self.format_event(event)
            
            # Send to Splunk HTTP Event Collector or via REST API
            if self.config.api_key:  # Use HEC
                return await self._send_via_hec(formatted_event)
            else:  # Use REST API
                return await self._send_via_rest(formatted_event)
        
        except Exception as e:
            logger.error(f"Error sending event to Splunk: {str(e)}")
            return False
    
    async def _send_via_hec(self, event_data: Dict) -> bool:
        """Send event via Splunk HTTP Event Collector."""
        try:
            hec_url = urljoin(self.base_url, '/services/collector/event')
            
            headers = {
                'Authorization': f'Splunk {self.config.api_key}',
                'Content-Type': 'application/json'
            }
            
            hec_event = {
                'time': event_data['timestamp'],
                'source': 'InfoSentinel',
                'sourcetype': f'infosec:{event_data["category"]}',
                'index': self.config.index_name or 'main',
                'event': event_data
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    hec_url,
                    json=hec_event,
                    headers=headers,
                    ssl=self.config.verify_ssl,
                    timeout=self.config.timeout
                ) as response:
                    return response.status == 200
        
        except Exception as e:
            logger.error(f"Error sending event via HEC: {str(e)}")
            return False
    
    async def _send_via_rest(self, event_data: Dict) -> bool:
        """Send event via Splunk REST API."""
        try:
            # This would implement REST API event submission
            # For now, return True as placeholder
            return True
        
        except Exception as e:
            logger.error(f"Error sending event via REST: {str(e)}")
            return False
    
    async def send_events_batch(self, events: List[SIEMEvent]) -> Dict:
        """Send batch of events to Splunk."""
        try:
            if not self.auth_token and not self.config.api_key:
                await self.connect()
            
            successful = 0
            failed = 0
            
            # Process events in batches
            batch_size = 100
            for i in range(0, len(events), batch_size):
                batch = events[i:i + batch_size]
                
                if self.config.api_key:
                    # Use HEC for batch
                    batch_data = []
                    for event in batch:
                        formatted_event = self.format_event(event)
                        hec_event = {
                            'time': formatted_event['timestamp'],
                            'source': 'InfoSentinel',
                            'sourcetype': f'infosec:{formatted_event["category"]}',
                            'index': self.config.index_name or 'main',
                            'event': formatted_event
                        }
                        batch_data.append(hec_event)
                    
                    if await self._send_batch_hec(batch_data):
                        successful += len(batch)
                    else:
                        failed += len(batch)
                else:
                    # Send individually via REST
                    for event in batch:
                        if await self.send_event(event):
                            successful += 1
                        else:
                            failed += 1
            
            return {
                'successful': successful,
                'failed': failed,
                'total': len(events)
            }
        
        except Exception as e:
            logger.error(f"Error sending batch events to Splunk: {str(e)}")
            return {
                'successful': 0,
                'failed': len(events),
                'total': len(events),
                'error': str(e)
            }
    
    async def _send_batch_hec(self, batch_data: List[Dict]) -> bool:
        """Send batch via HEC."""
        try:
            hec_url = urljoin(self.base_url, '/services/collector/event')
            
            headers = {
                'Authorization': f'Splunk {self.config.api_key}',
                'Content-Type': 'application/json'
            }
            
            # Send as newline-delimited JSON
            payload = '\n'.join([json.dumps(event) for event in batch_data])
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    hec_url,
                    data=payload,
                    headers=headers,
                    ssl=self.config.verify_ssl,
                    timeout=self.config.timeout
                ) as response:
                    return response.status == 200
        
        except Exception as e:
            logger.error(f"Error sending batch via HEC: {str(e)}")
            return False
    
    async def query_events(self, query: str, start_time: datetime, end_time: datetime) -> List[Dict]:
        """Query events from Splunk."""
        try:
            if not self.auth_token:
                await self.connect()
            
            search_url = urljoin(self.base_url, '/services/search/jobs')
            
            # Format time for Splunk
            earliest_time = start_time.strftime('%Y-%m-%dT%H:%M:%S')
            latest_time = end_time.strftime('%Y-%m-%dT%H:%M:%S')
            
            search_query = f'search {query} earliest={earliest_time} latest={latest_time}'
            
            headers = {
                'Authorization': f'Splunk {self.auth_token}',
                'Content-Type': 'application/x-www-form-urlencoded'
            }
            
            search_data = {
                'search': search_query,
                'output_mode': 'json',
                'exec_mode': 'blocking'
            }
            
            async with aiohttp.ClientSession() as session:
                # Submit search job
                async with session.post(
                    search_url,
                    data=search_data,
                    headers=headers,
                    ssl=self.config.verify_ssl,
                    timeout=self.config.timeout
                ) as response:
                    if response.status == 201:
                        job_response = await response.json()
                        job_id = job_response.get('sid')
                        
                        # Get search results
                        results_url = urljoin(self.base_url, f'/services/search/jobs/{job_id}/results')
                        
                        async with session.get(
                            results_url,
                            headers=headers,
                            params={'output_mode': 'json'},
                            ssl=self.config.verify_ssl,
                            timeout=self.config.timeout
                        ) as results_response:
                            if results_response.status == 200:
                                results_data = await results_response.json()
                                return results_data.get('results', [])
            
            return []
        
        except Exception as e:
            logger.error(f"Error querying Splunk: {str(e)}")
            return []
    
    async def test_connection(self) -> Dict:
        """Test Splunk connection."""
        try:
            connected = await self.connect()
            
            if connected:
                # Test with a simple search
                test_results = await self.query_events(
                    'index=* | head 1',
                    datetime.utcnow() - timedelta(minutes=5),
                    datetime.utcnow()
                )
                
                return {
                    'success': True,
                    'message': 'Successfully connected to Splunk',
                    'test_query_results': len(test_results)
                }
            else:
                return {
                    'success': False,
                    'message': 'Failed to connect to Splunk'
                }
        
        except Exception as e:
            return {
                'success': False,
                'message': f'Connection test failed: {str(e)}'
            }

class ElasticsearchIntegration(BaseSIEMIntegration):
    """Elasticsearch/ELK Stack integration."""
    
    def __init__(self, config: SIEMConfig):
        super().__init__(config)
        self.es_client = None
    
    async def connect(self) -> bool:
        """Establish connection to Elasticsearch."""
        try:
            # Configure Elasticsearch client
            es_config = {
                'hosts': [{'host': self.config.host, 'port': self.config.port}],
                'timeout': self.config.timeout,
                'use_ssl': self.config.ssl_enabled,
                'verify_certs': self.config.verify_ssl
            }
            
            # Add authentication
            if self.config.username and self.config.password:
                es_config['http_auth'] = (self.config.username, self.config.password)
            elif self.config.api_key:
                es_config['api_key'] = self.config.api_key
            
            self.es_client = Elasticsearch(**es_config)
            
            # Test connection
            if self.es_client.ping():
                logger.info(f"Successfully connected to Elasticsearch: {self.config.name}")
                return True
            else:
                logger.error("Failed to ping Elasticsearch")
                return False
        
        except Exception as e:
            logger.error(f"Error connecting to Elasticsearch: {str(e)}")
            return False
    
    async def send_event(self, event: SIEMEvent) -> bool:
        """Send single event to Elasticsearch."""
        try:
            if not self.es_client:
                await self.connect()
            
            # Format event for Elasticsearch
            formatted_event = self.format_event(event)
            
            # Determine index name
            index_name = self.config.index_name or f'infosec-{datetime.utcnow().strftime("%Y.%m.%d")}'
            
            # Index the document
            result = self.es_client.index(
                index=index_name,
                id=event.event_id,
                body=formatted_event
            )
            
            return result.get('result') in ['created', 'updated']
        
        except Exception as e:
            logger.error(f"Error sending event to Elasticsearch: {str(e)}")
            return False
    
    async def send_events_batch(self, events: List[SIEMEvent]) -> Dict:
        """Send batch of events to Elasticsearch."""
        try:
            if not self.es_client:
                await self.connect()
            
            # Prepare bulk data
            bulk_data = []
            index_name = self.config.index_name or f'infosec-{datetime.utcnow().strftime("%Y.%m.%d")}'
            
            for event in events:
                formatted_event = self.format_event(event)
                
                bulk_data.append({
                    '_index': index_name,
                    '_id': event.event_id,
                    '_source': formatted_event
                })
            
            # Execute bulk operation
            success_count, failed_items = bulk(
                self.es_client,
                bulk_data,
                chunk_size=100,
                request_timeout=self.config.timeout
            )
            
            return {
                'successful': success_count,
                'failed': len(failed_items),
                'total': len(events),
                'failed_items': failed_items
            }
        
        except Exception as e:
            logger.error(f"Error sending batch events to Elasticsearch: {str(e)}")
            return {
                'successful': 0,
                'failed': len(events),
                'total': len(events),
                'error': str(e)
            }
    
    async def query_events(self, query: str, start_time: datetime, end_time: datetime) -> List[Dict]:
        """Query events from Elasticsearch."""
        try:
            if not self.es_client:
                await self.connect()
            
            # Build Elasticsearch query
            es_query = {
                'query': {
                    'bool': {
                        'must': [
                            {
                                'query_string': {
                                    'query': query
                                }
                            },
                            {
                                'range': {
                                    'timestamp': {
                                        'gte': start_time.isoformat(),
                                        'lte': end_time.isoformat()
                                    }
                                }
                            }
                        ]
                    }
                },
                'sort': [
                    {'timestamp': {'order': 'desc'}}
                ],
                'size': 1000
            }
            
            # Execute search
            index_pattern = self.config.index_name or 'infosec-*'
            result = self.es_client.search(
                index=index_pattern,
                body=es_query
            )
            
            # Extract hits
            hits = result.get('hits', {}).get('hits', [])
            return [hit['_source'] for hit in hits]
        
        except Exception as e:
            logger.error(f"Error querying Elasticsearch: {str(e)}")
            return []
    
    async def test_connection(self) -> Dict:
        """Test Elasticsearch connection."""
        try:
            connected = await self.connect()
            
            if connected:
                # Get cluster info
                cluster_info = self.es_client.info()
                
                return {
                    'success': True,
                    'message': 'Successfully connected to Elasticsearch',
                    'cluster_name': cluster_info.get('cluster_name'),
                    'version': cluster_info.get('version', {}).get('number')
                }
            else:
                return {
                    'success': False,
                    'message': 'Failed to connect to Elasticsearch'
                }
        
        except Exception as e:
            return {
                'success': False,
                'message': f'Connection test failed: {str(e)}'
            }

class SIEMIntegrationManager:
    """Manager for SIEM integrations."""
    
    def __init__(self):
        self.integrations = {}
        self.event_queue = []
        self.batch_size = 100
        self.flush_interval = 60  # seconds
    
    def register_integration(self, name: str, integration: BaseSIEMIntegration):
        """Register a SIEM integration."""
        self.integrations[name] = integration
        logger.info(f"Registered SIEM integration: {name}")
    
    def create_integration(self, config: SIEMConfig) -> BaseSIEMIntegration:
        """Create SIEM integration based on type."""
        if config.siem_type == SIEMType.SPLUNK:
            return SplunkIntegration(config)
        elif config.siem_type == SIEMType.ELASTICSEARCH:
            return ElasticsearchIntegration(config)
        else:
            raise ValueError(f"Unsupported SIEM type: {config.siem_type}")
    
    async def send_event_to_all(self, event: SIEMEvent) -> Dict:
        """Send event to all registered SIEM integrations."""
        results = {}
        
        for name, integration in self.integrations.items():
            try:
                success = await integration.send_event(event)
                results[name] = {
                    'success': success,
                    'timestamp': datetime.utcnow().isoformat()
                }
            except Exception as e:
                results[name] = {
                    'success': False,
                    'error': str(e),
                    'timestamp': datetime.utcnow().isoformat()
                }
        
        return results
    
    async def send_vulnerability_event(self, vulnerability: Dict, scan_id: str = None) -> Dict:
        """Send vulnerability discovery event to SIEM."""
        event = SIEMEvent(
            timestamp=datetime.utcnow(),
            event_id=f"vuln_{vulnerability.get('_id', 'unknown')}",
            source="InfoSentinel",
            category=EventCategory.VULNERABILITY,
            severity=self._map_severity(vulnerability.get('severity', 'medium')),
            title=f"Vulnerability Detected: {vulnerability.get('title', 'Unknown')}",
            description=vulnerability.get('description', ''),
            source_ip=vulnerability.get('host'),
            vulnerability_id=str(vulnerability.get('_id')),
            scan_id=scan_id,
            tags=['vulnerability', 'security', vulnerability.get('severity', 'medium')],
            raw_data=vulnerability
        )
        
        return await self.send_event_to_all(event)
    
    async def send_scan_completion_event(self, scan_data: Dict) -> Dict:
        """Send scan completion event to SIEM."""
        vulnerability_count = scan_data.get('vulnerability_count', 0)
        
        # Determine severity based on findings
        if vulnerability_count > 10:
            severity = EventSeverity.HIGH
        elif vulnerability_count > 5:
            severity = EventSeverity.MEDIUM
        elif vulnerability_count > 0:
            severity = EventSeverity.LOW
        else:
            severity = EventSeverity.INFO
        
        event = SIEMEvent(
            timestamp=datetime.utcnow(),
            event_id=f"scan_{scan_data.get('_id', 'unknown')}",
            source="InfoSentinel",
            category=EventCategory.SCAN_RESULT,
            severity=severity,
            title=f"Security Scan Completed: {scan_data.get('target', 'Unknown Target')}",
            description=f"Scan completed with {vulnerability_count} vulnerabilities found",
            source_ip=scan_data.get('target'),
            scan_id=str(scan_data.get('_id')),
            tags=['scan', 'security_assessment', scan_data.get('scan_type', 'unknown')],
            custom_fields={
                'scan_type': scan_data.get('scan_type'),
                'vulnerability_count': vulnerability_count,
                'scan_duration': scan_data.get('duration'),
                'target': scan_data.get('target')
            },
            raw_data=scan_data
        )
        
        return await self.send_event_to_all(event)
    
    async def send_compliance_event(self, compliance_data: Dict) -> Dict:
        """Send compliance violation event to SIEM."""
        event = SIEMEvent(
            timestamp=datetime.utcnow(),
            event_id=f"compliance_{compliance_data.get('id', 'unknown')}",
            source="InfoSentinel",
            category=EventCategory.COMPLIANCE_VIOLATION,
            severity=self._map_severity(compliance_data.get('severity', 'medium')),
            title=f"Compliance Violation: {compliance_data.get('rule_name', 'Unknown Rule')}",
            description=compliance_data.get('description', ''),
            asset_id=compliance_data.get('asset_id'),
            tags=['compliance', compliance_data.get('framework', 'unknown')],
            custom_fields={
                'framework': compliance_data.get('framework'),
                'rule_id': compliance_data.get('rule_id'),
                'control_id': compliance_data.get('control_id')
            },
            raw_data=compliance_data
        )
        
        return await self.send_event_to_all(event)
    
    async def send_threat_intelligence_event(self, threat_data: Dict) -> Dict:
        """Send threat intelligence event to SIEM."""
        event = SIEMEvent(
            timestamp=datetime.utcnow(),
            event_id=f"threat_{threat_data.get('id', 'unknown')}",
            source="InfoSentinel",
            category=EventCategory.THREAT_DETECTION,
            severity=self._map_severity(threat_data.get('severity', 'medium')),
            title=f"Threat Detected: {threat_data.get('title', 'Unknown Threat')}",
            description=threat_data.get('description', ''),
            tags=['threat_intelligence', 'security_alert'],
            custom_fields={
                'threat_type': threat_data.get('threat_type'),
                'indicators': threat_data.get('indicators', []),
                'cve_ids': threat_data.get('cve_ids', [])
            },
            raw_data=threat_data
        )
        
        return await self.send_event_to_all(event)
    
    async def test_all_integrations(self) -> Dict:
        """Test all registered SIEM integrations."""
        results = {}
        
        for name, integration in self.integrations.items():
            try:
                test_result = await integration.test_connection()
                results[name] = test_result
            except Exception as e:
                results[name] = {
                    'success': False,
                    'message': f'Test failed: {str(e)}'
                }
        
        return results
    
    def _map_severity(self, severity_str: str) -> EventSeverity:
        """Map severity string to EventSeverity enum."""
        severity_mapping = {
            'critical': EventSeverity.CRITICAL,
            'high': EventSeverity.HIGH,
            'medium': EventSeverity.MEDIUM,
            'low': EventSeverity.LOW,
            'info': EventSeverity.INFO,
            'informational': EventSeverity.INFO
        }
        
        return severity_mapping.get(severity_str.lower(), EventSeverity.MEDIUM)
    
    async def flush_event_queue(self):
        """Flush queued events to SIEM systems."""
        if not self.event_queue:
            return
        
        events_to_send = self.event_queue[:self.batch_size]
        self.event_queue = self.event_queue[self.batch_size:]
        
        for name, integration in self.integrations.items():
            try:
                result = await integration.send_events_batch(events_to_send)
                logger.info(f"Sent {result.get('successful', 0)} events to {name}")
            except Exception as e:
                logger.error(f"Error sending batch to {name}: {str(e)}")
    
    def queue_event(self, event: SIEMEvent):
        """Queue event for batch processing."""
        self.event_queue.append(event)
        
        # Auto-flush if queue is full
        if len(self.event_queue) >= self.batch_size:
            asyncio.create_task(self.flush_event_queue())
    
    async def start_background_processing(self):
        """Start background event processing."""
        while True:
            try:
                await asyncio.sleep(self.flush_interval)
                await self.flush_event_queue()
            except Exception as e:
                logger.error(f"Error in background processing: {str(e)}")
    
    def get_integration_status(self) -> Dict:
        """Get status of all integrations."""
        status = {}
        
        for name, integration in self.integrations.items():
            status[name] = {
                'type': integration.config.siem_type.value,
                'host': integration.config.host,
                'port': integration.config.port,
                'ssl_enabled': integration.config.ssl_enabled,
                'connected': hasattr(integration, 'es_client') and integration.es_client is not None if isinstance(integration, ElasticsearchIntegration) else integration.auth_token is not None if isinstance(integration, SplunkIntegration) else False
            }
        
        return {
            'integrations': status,
            'queue_size': len(self.event_queue),
            'batch_size': self.batch_size,
            'flush_interval': self.flush_interval
        }

# Global SIEM manager instance
siem_manager = SIEMIntegrationManager()

# Convenience functions
async def send_vulnerability_to_siem(vulnerability: Dict, scan_id: str = None):
    """Send vulnerability event to all configured SIEM systems."""
    return await siem_manager.send_vulnerability_event(vulnerability, scan_id)

async def send_scan_completion_to_siem(scan_data: Dict):
    """Send scan completion event to all configured SIEM systems."""
    return await siem_manager.send_scan_completion_event(scan_data)

async def send_compliance_violation_to_siem(compliance_data: Dict):
    """Send compliance violation event to all configured SIEM systems."""
    return await siem_manager.send_compliance_event(compliance_data)

async def send_threat_intelligence_to_siem(threat_data: Dict):
    """Send threat intelligence event to all configured SIEM systems."""
    return await siem_manager.send_threat_intelligence_event(threat_data)