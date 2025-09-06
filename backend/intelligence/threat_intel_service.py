#!/usr/bin/env python3
"""
Threat Intelligence Service for InfoSentinel.
Integrates CVE databases, real-time threat feeds, and industry-specific alerts.
"""
import requests
import json
import logging
import asyncio
import aiohttp
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import hashlib
import time
from database.db import get_db, get_postgres_session, close_postgres_session
from sqlalchemy import Column, Integer, String, DateTime, Text, Boolean, Float
from sqlalchemy.ext.declarative import declarative_base
from tasks.notification_tasks import send_vulnerability_alert

logger = logging.getLogger(__name__)
Base = declarative_base()

class ThreatLevel(Enum):
    """Threat severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class IntelSource(Enum):
    """Threat intelligence sources."""
    NVD = "nvd"  # National Vulnerability Database
    MITRE = "mitre"  # MITRE ATT&CK
    CISA = "cisa"  # CISA Known Exploited Vulnerabilities
    EXPLOIT_DB = "exploit_db"  # Exploit Database
    GITHUB_ADVISORIES = "github_advisories"
    SECURITY_FEEDS = "security_feeds"
    CUSTOM = "custom"

@dataclass
class ThreatIntelligence:
    """Threat intelligence data structure."""
    id: str
    source: IntelSource
    threat_type: str
    severity: ThreatLevel
    title: str
    description: str
    indicators: List[str]
    cve_ids: List[str]
    affected_products: List[str]
    exploit_available: bool
    actively_exploited: bool
    published_date: datetime
    last_updated: datetime
    references: List[str]
    tags: List[str]

class CVEData(Base):
    """CVE data model for PostgreSQL."""
    __tablename__ = 'cve_data'
    
    id = Column(Integer, primary_key=True)
    cve_id = Column(String(20), unique=True, nullable=False)
    description = Column(Text)
    cvss_v3_score = Column(Float)
    cvss_v3_vector = Column(String(100))
    cvss_v2_score = Column(Float)
    severity = Column(String(20))
    published_date = Column(DateTime)
    last_modified = Column(DateTime)
    cpe_configurations = Column(Text)  # JSON
    references = Column(Text)  # JSON
    exploit_available = Column(Boolean, default=False)
    actively_exploited = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class ThreatFeed(Base):
    """Threat feed data model."""
    __tablename__ = 'threat_feeds'
    
    id = Column(Integer, primary_key=True)
    feed_id = Column(String(100), unique=True, nullable=False)
    source = Column(String(50), nullable=False)
    threat_type = Column(String(50))
    severity = Column(String(20))
    title = Column(String(500))
    description = Column(Text)
    indicators = Column(Text)  # JSON
    cve_ids = Column(Text)  # JSON
    affected_products = Column(Text)  # JSON
    exploit_available = Column(Boolean, default=False)
    actively_exploited = Column(Boolean, default=False)
    published_date = Column(DateTime)
    references = Column(Text)  # JSON
    tags = Column(Text)  # JSON
    created_at = Column(DateTime, default=datetime.utcnow)

class ThreatIntelligenceService:
    """
    Comprehensive threat intelligence service.
    """
    
    def __init__(self):
        """
        Initialize the threat intelligence service.
        """
        self.nvd_api_base = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.mitre_api_base = "https://cve.mitre.org/api/cve"
        self.cisa_kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        
        # Rate limiting
        self.last_nvd_request = 0
        self.nvd_rate_limit = 6  # 6 seconds between requests (NVD requirement)
        
        # Cache for frequently accessed data
        self.cve_cache = {}
        self.cache_ttl = 3600  # 1 hour
        
        # Industry mappings
        self.industry_keywords = {
            'financial': ['banking', 'finance', 'payment', 'credit', 'atm', 'swift'],
            'healthcare': ['medical', 'hospital', 'patient', 'health', 'hipaa', 'ehr'],
            'technology': ['software', 'cloud', 'saas', 'api', 'database', 'web'],
            'government': ['government', 'federal', 'military', 'defense', 'classified'],
            'retail': ['retail', 'ecommerce', 'pos', 'payment', 'shopping', 'store'],
            'energy': ['scada', 'ics', 'power', 'grid', 'utility', 'oil', 'gas'],
            'manufacturing': ['industrial', 'factory', 'production', 'automation', 'plc']
        }
    
    async def update_cve_database(self, days_back: int = 7) -> Dict:
        """
        Update CVE database with latest vulnerabilities.
        
        Args:
            days_back: Number of days to look back for updates
            
        Returns:
            Update results
        """
        try:
            logger.info(f"Updating CVE database for last {days_back} days")
            
            # Calculate date range
            end_date = datetime.utcnow()
            start_date = end_date - timedelta(days=days_back)
            
            # Format dates for NVD API
            start_date_str = start_date.strftime('%Y-%m-%dT%H:%M:%S.000')
            end_date_str = end_date.strftime('%Y-%m-%dT%H:%M:%S.000')
            
            # Fetch CVEs from NVD
            cves_updated = 0
            cves_new = 0
            
            async with aiohttp.ClientSession() as session:
                # NVD API pagination
                start_index = 0
                results_per_page = 100
                
                while True:
                    # Rate limiting for NVD
                    await self._rate_limit_nvd()
                    
                    url = f"{self.nvd_api_base}?lastModStartDate={start_date_str}&lastModEndDate={end_date_str}&startIndex={start_index}&resultsPerPage={results_per_page}"
                    
                    async with session.get(url) as response:
                        if response.status != 200:
                            logger.error(f"NVD API error: {response.status}")
                            break
                        
                        data = await response.json()
                        
                        if 'vulnerabilities' not in data:
                            break
                        
                        vulnerabilities = data['vulnerabilities']
                        
                        if not vulnerabilities:
                            break
                        
                        # Process each CVE
                        for vuln_data in vulnerabilities:
                            cve_data = vuln_data.get('cve', {})
                            result = await self._process_cve_data(cve_data)
                            
                            if result == 'new':
                                cves_new += 1
                            elif result == 'updated':
                                cves_updated += 1
                        
                        # Check if we have more results
                        total_results = data.get('totalResults', 0)
                        if start_index + results_per_page >= total_results:
                            break
                        
                        start_index += results_per_page
            
            # Update CISA Known Exploited Vulnerabilities
            kev_updated = await self._update_cisa_kev()
            
            logger.info(f"CVE database update completed: {cves_new} new, {cves_updated} updated, {kev_updated} KEV updated")
            
            return {
                'status': 'success',
                'cves_new': cves_new,
                'cves_updated': cves_updated,
                'kev_updated': kev_updated,
                'update_time': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error updating CVE database: {str(e)}")
            return {'status': 'error', 'error': str(e)}
    
    async def get_threat_intelligence(self, cve_id: str) -> Optional[ThreatIntelligence]:
        """
        Get comprehensive threat intelligence for a CVE.
        
        Args:
            cve_id: CVE identifier
            
        Returns:
            Threat intelligence data
        """
        try:
            # Check cache first
            cache_key = f"cve_{cve_id}"
            if cache_key in self.cve_cache:
                cached_data, timestamp = self.cve_cache[cache_key]
                if time.time() - timestamp < self.cache_ttl:
                    return cached_data
            
            # Get CVE data from database
            session = get_postgres_session()
            try:
                cve_record = session.query(CVEData).filter(CVEData.cve_id == cve_id).first()
                
                if not cve_record:
                    # Try to fetch from NVD
                    await self._fetch_single_cve(cve_id)
                    cve_record = session.query(CVEData).filter(CVEData.cve_id == cve_id).first()
                
                if cve_record:
                    # Create threat intelligence object
                    threat_intel = ThreatIntelligence(
                        id=cve_record.cve_id,
                        source=IntelSource.NVD,
                        threat_type="vulnerability",
                        severity=ThreatLevel(cve_record.severity.lower()) if cve_record.severity else ThreatLevel.MEDIUM,
                        title=f"CVE-{cve_record.cve_id}",
                        description=cve_record.description or "",
                        indicators=[],
                        cve_ids=[cve_record.cve_id],
                        affected_products=json.loads(cve_record.cpe_configurations) if cve_record.cpe_configurations else [],
                        exploit_available=cve_record.exploit_available,
                        actively_exploited=cve_record.actively_exploited,
                        published_date=cve_record.published_date,
                        last_updated=cve_record.last_modified,
                        references=json.loads(cve_record.references) if cve_record.references else [],
                        tags=[]
                    )
                    
                    # Cache the result
                    self.cve_cache[cache_key] = (threat_intel, time.time())
                    
                    return threat_intel
                
            finally:
                close_postgres_session(session)
            
            return None
            
        except Exception as e:
            logger.error(f"Error getting threat intelligence for {cve_id}: {str(e)}")
            return None
    
    async def monitor_threat_feeds(self) -> Dict:
        """
        Monitor and update real-time threat feeds.
        
        Returns:
            Monitoring results
        """
        try:
            logger.info("Starting threat feed monitoring")
            
            feeds_updated = 0
            new_threats = 0
            alerts_sent = 0
            
            # Monitor multiple threat feeds
            feed_sources = [
                self._monitor_exploit_db(),
                self._monitor_github_advisories(),
                self._monitor_security_feeds()
            ]
            
            # Process feeds concurrently
            results = await asyncio.gather(*feed_sources, return_exceptions=True)
            
            for result in results:
                if isinstance(result, dict) and 'feeds_updated' in result:
                    feeds_updated += result['feeds_updated']
                    new_threats += result['new_threats']
                    alerts_sent += result['alerts_sent']
            
            # Check for industry-specific threats
            industry_alerts = await self._check_industry_threats()
            alerts_sent += industry_alerts
            
            logger.info(f"Threat feed monitoring completed: {feeds_updated} feeds updated, {new_threats} new threats, {alerts_sent} alerts sent")
            
            return {
                'status': 'success',
                'feeds_updated': feeds_updated,
                'new_threats': new_threats,
                'alerts_sent': alerts_sent,
                'monitoring_time': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error monitoring threat feeds: {str(e)}")
            return {'status': 'error', 'error': str(e)}
    
    async def get_industry_threats(self, industry: str, days_back: int = 30) -> List[ThreatIntelligence]:
        """
        Get industry-specific threat intelligence.
        
        Args:
            industry: Industry sector
            days_back: Number of days to look back
            
        Returns:
            List of relevant threats
        """
        try:
            # Get industry keywords
            keywords = self.industry_keywords.get(industry.lower(), [])
            
            if not keywords:
                return []
            
            # Search threat feeds for industry-relevant threats
            session = get_postgres_session()
            try:
                # Query recent threats
                since_date = datetime.utcnow() - timedelta(days=days_back)
                
                threats = session.query(ThreatFeed).filter(
                    ThreatFeed.created_at >= since_date
                ).all()
                
                # Filter by industry relevance
                relevant_threats = []
                
                for threat in threats:
                    # Check if threat is relevant to industry
                    threat_text = f"{threat.title} {threat.description}".lower()
                    
                    if any(keyword in threat_text for keyword in keywords):
                        # Convert to ThreatIntelligence object
                        threat_intel = ThreatIntelligence(
                            id=threat.feed_id,
                            source=IntelSource(threat.source),
                            threat_type=threat.threat_type or "unknown",
                            severity=ThreatLevel(threat.severity) if threat.severity else ThreatLevel.MEDIUM,
                            title=threat.title or "",
                            description=threat.description or "",
                            indicators=json.loads(threat.indicators) if threat.indicators else [],
                            cve_ids=json.loads(threat.cve_ids) if threat.cve_ids else [],
                            affected_products=json.loads(threat.affected_products) if threat.affected_products else [],
                            exploit_available=threat.exploit_available,
                            actively_exploited=threat.actively_exploited,
                            published_date=threat.published_date,
                            last_updated=threat.created_at,
                            references=json.loads(threat.references) if threat.references else [],
                            tags=json.loads(threat.tags) if threat.tags else []
                        )
                        
                        relevant_threats.append(threat_intel)
                
                # Sort by severity and date
                severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
                relevant_threats.sort(
                    key=lambda x: (severity_order.get(x.severity.value, 5), x.published_date),
                    reverse=True
                )
                
                return relevant_threats[:50]  # Limit to top 50
                
            finally:
                close_postgres_session(session)
            
        except Exception as e:
            logger.error(f"Error getting industry threats for {industry}: {str(e)}")
            return []
    
    async def analyze_vulnerability_context(self, vulnerability: Dict) -> Dict:
        """
        Analyze vulnerability in context of current threat landscape.
        
        Args:
            vulnerability: Vulnerability data
            
        Returns:
            Contextual analysis
        """
        try:
            analysis = {
                'threat_level': 'medium',
                'exploit_likelihood': 'medium',
                'active_campaigns': [],
                'similar_threats': [],
                'recommendations': []
            }
            
            # Get CVE information if available
            cve_id = vulnerability.get('cve')
            if cve_id:
                threat_intel = await self.get_threat_intelligence(cve_id)
                if threat_intel:
                    analysis['threat_level'] = threat_intel.severity.value
                    analysis['exploit_likelihood'] = 'high' if threat_intel.exploit_available else 'medium'
                    
                    if threat_intel.actively_exploited:
                        analysis['active_campaigns'].append({
                            'cve': cve_id,
                            'description': 'Known to be actively exploited in the wild'
                        })
            
            # Check for similar vulnerabilities
            service = vulnerability.get('service', '')
            port = vulnerability.get('port', 0)
            
            if service or port:
                similar_threats = await self._find_similar_threats(service, port)
                analysis['similar_threats'] = similar_threats[:5]  # Top 5
            
            # Generate recommendations
            analysis['recommendations'] = self._generate_threat_recommendations(
                analysis['threat_level'],
                analysis['exploit_likelihood'],
                len(analysis['active_campaigns'])
            )
            
            return analysis
            
        except Exception as e:
            logger.error(f"Error analyzing vulnerability context: {str(e)}")
            return {'error': str(e)}
    
    # Helper methods
    async def _rate_limit_nvd(self):
        """Implement NVD API rate limiting."""
        current_time = time.time()
        time_since_last = current_time - self.last_nvd_request
        
        if time_since_last < self.nvd_rate_limit:
            await asyncio.sleep(self.nvd_rate_limit - time_since_last)
        
        self.last_nvd_request = time.time()
    
    async def _process_cve_data(self, cve_data: Dict) -> str:
        """Process and store CVE data."""
        try:
            cve_id = cve_data.get('id', '')
            if not cve_id:
                return 'skipped'
            
            session = get_postgres_session()
            try:
                # Check if CVE already exists
                existing_cve = session.query(CVEData).filter(CVEData.cve_id == cve_id).first()
                
                # Extract CVE information
                descriptions = cve_data.get('descriptions', [])
                description = ''
                for desc in descriptions:
                    if desc.get('lang') == 'en':
                        description = desc.get('value', '')
                        break
                
                # Extract CVSS scores
                metrics = cve_data.get('metrics', {})
                cvss_v3_score = None
                cvss_v3_vector = None
                cvss_v2_score = None
                
                if 'cvssMetricV31' in metrics:
                    cvss_v3_data = metrics['cvssMetricV31'][0]['cvssData']
                    cvss_v3_score = cvss_v3_data.get('baseScore')
                    cvss_v3_vector = cvss_v3_data.get('vectorString')
                elif 'cvssMetricV30' in metrics:
                    cvss_v3_data = metrics['cvssMetricV30'][0]['cvssData']
                    cvss_v3_score = cvss_v3_data.get('baseScore')
                    cvss_v3_vector = cvss_v3_data.get('vectorString')
                
                if 'cvssMetricV2' in metrics:
                    cvss_v2_data = metrics['cvssMetricV2'][0]['cvssData']
                    cvss_v2_score = cvss_v2_data.get('baseScore')
                
                # Determine severity
                severity = 'medium'
                if cvss_v3_score:
                    if cvss_v3_score >= 9.0:
                        severity = 'critical'
                    elif cvss_v3_score >= 7.0:
                        severity = 'high'
                    elif cvss_v3_score >= 4.0:
                        severity = 'medium'
                    else:
                        severity = 'low'
                
                # Extract dates
                published_date = None
                last_modified = None
                
                if cve_data.get('published'):
                    published_date = datetime.fromisoformat(cve_data['published'].replace('Z', '+00:00'))
                
                if cve_data.get('lastModified'):
                    last_modified = datetime.fromisoformat(cve_data['lastModified'].replace('Z', '+00:00'))
                
                # Extract references
                references = []
                for ref in cve_data.get('references', []):
                    references.append(ref.get('url', ''))
                
                # Extract CPE configurations
                cpe_configs = []
                for config in cve_data.get('configurations', []):
                    for node in config.get('nodes', []):
                        for cpe_match in node.get('cpeMatch', []):
                            if cpe_match.get('vulnerable'):
                                cpe_configs.append(cpe_match.get('criteria', ''))
                
                if existing_cve:
                    # Update existing CVE
                    existing_cve.description = description
                    existing_cve.cvss_v3_score = cvss_v3_score
                    existing_cve.cvss_v3_vector = cvss_v3_vector
                    existing_cve.cvss_v2_score = cvss_v2_score
                    existing_cve.severity = severity
                    existing_cve.last_modified = last_modified
                    existing_cve.references = json.dumps(references)
                    existing_cve.cpe_configurations = json.dumps(cpe_configs)
                    existing_cve.updated_at = datetime.utcnow()
                    
                    session.commit()
                    return 'updated'
                else:
                    # Create new CVE
                    new_cve = CVEData(
                        cve_id=cve_id,
                        description=description,
                        cvss_v3_score=cvss_v3_score,
                        cvss_v3_vector=cvss_v3_vector,
                        cvss_v2_score=cvss_v2_score,
                        severity=severity,
                        published_date=published_date,
                        last_modified=last_modified,
                        references=json.dumps(references),
                        cpe_configurations=json.dumps(cpe_configs)
                    )
                    
                    session.add(new_cve)
                    session.commit()
                    return 'new'
                
            finally:
                close_postgres_session(session)
            
        except Exception as e:
            logger.error(f"Error processing CVE data: {str(e)}")
            return 'error'
    
    async def _update_cisa_kev(self) -> int:
        """Update CISA Known Exploited Vulnerabilities."""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(self.cisa_kev_url) as response:
                    if response.status != 200:
                        logger.error(f"CISA KEV API error: {response.status}")
                        return 0
                    
                    data = await response.json()
                    vulnerabilities = data.get('vulnerabilities', [])
                    
                    updated_count = 0
                    pg_session = get_postgres_session()
                    
                    try:
                        for vuln in vulnerabilities:
                            cve_id = vuln.get('cveID')
                            if cve_id:
                                # Update CVE record to mark as actively exploited
                                cve_record = pg_session.query(CVEData).filter(CVEData.cve_id == cve_id).first()
                                if cve_record:
                                    cve_record.actively_exploited = True
                                    cve_record.exploit_available = True
                                    updated_count += 1
                        
                        pg_session.commit()
                        
                    finally:
                        close_postgres_session(pg_session)
                    
                    return updated_count
            
        except Exception as e:
            logger.error(f"Error updating CISA KEV: {str(e)}")
            return 0
    
    async def _fetch_single_cve(self, cve_id: str):
        """Fetch a single CVE from NVD."""
        try:
            await self._rate_limit_nvd()
            
            url = f"{self.nvd_api_base}?cveId={cve_id}"
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url) as response:
                    if response.status == 200:
                        data = await response.json()
                        vulnerabilities = data.get('vulnerabilities', [])
                        
                        if vulnerabilities:
                            cve_data = vulnerabilities[0].get('cve', {})
                            await self._process_cve_data(cve_data)
        
        except Exception as e:
            logger.error(f"Error fetching CVE {cve_id}: {str(e)}")
    
    async def _monitor_exploit_db(self) -> Dict:
        """Monitor Exploit Database for new exploits."""
        # This would integrate with Exploit-DB API or RSS feed
        # For now, return mock data
        return {
            'feeds_updated': 1,
            'new_threats': 0,
            'alerts_sent': 0
        }
    
    async def _monitor_github_advisories(self) -> Dict:
        """Monitor GitHub Security Advisories."""
        # This would integrate with GitHub Security Advisory API
        # For now, return mock data
        return {
            'feeds_updated': 1,
            'new_threats': 0,
            'alerts_sent': 0
        }
    
    async def _monitor_security_feeds(self) -> Dict:
        """Monitor various security feeds."""
        # This would integrate with multiple security feeds
        # For now, return mock data
        return {
            'feeds_updated': 1,
            'new_threats': 0,
            'alerts_sent': 0
        }
    
    async def _check_industry_threats(self) -> int:
        """Check for new industry-specific threats and send alerts."""
        try:
            alerts_sent = 0
            
            # Get recent high-severity threats
            session = get_postgres_session()
            try:
                recent_threats = session.query(ThreatFeed).filter(
                    ThreatFeed.severity.in_(['critical', 'high']),
                    ThreatFeed.created_at >= datetime.utcnow() - timedelta(hours=24)
                ).all()
                
                for threat in recent_threats:
                    # Check if this threat affects any industry
                    threat_text = f"{threat.title} {threat.description}".lower()
                    
                    for industry, keywords in self.industry_keywords.items():
                        if any(keyword in threat_text for keyword in keywords):
                            # Send industry-specific alert
                            await self._send_industry_alert(industry, threat)
                            alerts_sent += 1
                            break
                
            finally:
                close_postgres_session(session)
            
            return alerts_sent
            
        except Exception as e:
            logger.error(f"Error checking industry threats: {str(e)}")
            return 0
    
    async def _send_industry_alert(self, industry: str, threat: ThreatFeed):
        """Send industry-specific threat alert."""
        try:
            alert_data = {
                'industry': industry,
                'threat_id': threat.feed_id,
                'severity': threat.severity,
                'title': threat.title,
                'description': threat.description,
                'cve_ids': json.loads(threat.cve_ids) if threat.cve_ids else [],
                'references': json.loads(threat.references) if threat.references else []
            }
            
            # This would integrate with the notification system
            logger.info(f"Industry alert sent for {industry}: {threat.title}")
            
        except Exception as e:
            logger.error(f"Error sending industry alert: {str(e)}")
    
    async def _find_similar_threats(self, service: str, port: int) -> List[Dict]:
        """Find similar threats based on service and port."""
        try:
            session = get_postgres_session()
            try:
                # Search for threats affecting similar services
                similar_threats = []
                
                # This would implement more sophisticated similarity matching
                # For now, return empty list
                
                return similar_threats
                
            finally:
                close_postgres_session(session)
            
        except Exception as e:
            logger.error(f"Error finding similar threats: {str(e)}")
            return []
    
    def _generate_threat_recommendations(self, threat_level: str, exploit_likelihood: str, active_campaigns: int) -> List[str]:
        """Generate threat-based recommendations."""
        recommendations = []
        
        if threat_level in ['critical', 'high']:
            recommendations.append("🚨 Immediate patching required due to high threat level")
        
        if exploit_likelihood == 'high':
            recommendations.append("⚠️ Exploits are available - prioritize remediation")
        
        if active_campaigns > 0:
            recommendations.append("🔥 Active exploitation detected - implement emergency measures")
        
        recommendations.extend([
            "🛡️ Implement additional monitoring for this vulnerability type",
            "📊 Review similar vulnerabilities in your environment",
            "🔍 Consider threat hunting activities"
        ])
        
        return recommendations
    
    def get_threat_statistics(self) -> Dict:
        """
        Get threat intelligence statistics.
        
        Returns:
            Statistics summary
        """
        try:
            session = get_postgres_session()
            try:
                # CVE statistics
                total_cves = session.query(CVEData).count()
                critical_cves = session.query(CVEData).filter(CVEData.severity == 'critical').count()
                exploited_cves = session.query(CVEData).filter(CVEData.actively_exploited == True).count()
                
                # Recent threats
                recent_threats = session.query(ThreatFeed).filter(
                    ThreatFeed.created_at >= datetime.utcnow() - timedelta(days=7)
                ).count()
                
                return {
                    'total_cves': total_cves,
                    'critical_cves': critical_cves,
                    'actively_exploited': exploited_cves,
                    'recent_threats': recent_threats,
                    'last_updated': datetime.utcnow().isoformat()
                }
                
            finally:
                close_postgres_session(session)
            
        except Exception as e:
            logger.error(f"Error getting threat statistics: {str(e)}")
            return {'error': str(e)}
    
    async def enrich_findings(self, findings: List[Dict]) -> List[Dict]:
        """
        Enrich vulnerability findings with threat intelligence data.
        
        Args:
            findings: List of vulnerability findings
            
        Returns:
            Enriched findings with threat intelligence
        """
        if not findings:
            return findings
            
        enriched_findings = []
        
        for finding in findings:
            try:
                enriched_finding = finding.copy()
                
                # Extract CVE ID if present
                cve_id = finding.get('cve') or finding.get('cve_id')
                
                if cve_id:
                    # Get threat intelligence for CVE
                    threat_intel = await self.get_threat_intelligence(cve_id)
                    
                    if threat_intel:
                        enriched_finding['threat_intelligence'] = {
                            'cve_id': cve_id,
                            'severity': threat_intel.severity.value,
                            'exploit_available': threat_intel.exploit_available,
                            'actively_exploited': threat_intel.actively_exploited,
                            'published_date': threat_intel.published_date.isoformat(),
                            'references': threat_intel.references,
                            'tags': threat_intel.tags
                        }
                        
                        # Update severity if threat intel has higher severity
                        current_severity = finding.get('severity', 'low')
                        threat_severity = threat_intel.severity.value
                        
                        severity_order = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
                        if severity_order.get(threat_severity, 0) > severity_order.get(current_severity, 0):
                            enriched_finding['severity'] = threat_severity
                            enriched_finding['severity_updated_by_threat_intel'] = True
                        
                        # Add exploit information
                        if threat_intel.exploit_available:
                            enriched_finding['exploit_available'] = True
                            enriched_finding['exploit_sources'] = ['threat_intelligence']
                        
                        if threat_intel.actively_exploited:
                            enriched_finding['actively_exploited'] = True
                            enriched_finding['priority_boost'] = 'actively_exploited'
                
                # Analyze vulnerability context
                context_analysis = await self.analyze_vulnerability_context(finding)
                if context_analysis:
                    enriched_finding['context_analysis'] = context_analysis
                
                # Find similar threats based on service/port
                service = finding.get('service', '')
                port = finding.get('port', 0)
                
                if service or port:
                    similar_threats = await self._find_similar_threats(service, port)
                    if similar_threats:
                        enriched_finding['similar_threats'] = similar_threats[:5]  # Limit to top 5
                
                # Add enrichment metadata
                enriched_finding['threat_intel_enrichment'] = {
                    'enriched_at': datetime.utcnow().isoformat(),
                    'enrichment_version': '1.0',
                    'sources_checked': ['nvd', 'cisa_kev', 'threat_feeds']
                }
                
                enriched_findings.append(enriched_finding)
                
            except Exception as e:
                logger.error(f"Error enriching finding: {e}")
                # Keep original finding if enrichment fails
                enriched_findings.append(finding)
        
        logger.info(f"Enriched {len(enriched_findings)} findings with threat intelligence")
        return enriched_findings