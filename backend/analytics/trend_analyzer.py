#!/usr/bin/env python3
"""
Advanced vulnerability trend analysis engine for InfoSentinel.
Provides comprehensive analytics, risk scoring, and comparative security metrics.
"""
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional
import logging
import json
from dataclasses import dataclass
from enum import Enum
from collections import defaultdict
import statistics
from database.db import get_db, get_postgres_session, close_postgres_session
from sqlalchemy import text

logger = logging.getLogger(__name__)

class TrendPeriod(Enum):
    """Time periods for trend analysis."""
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"
    QUARTERLY = "quarterly"
    YEARLY = "yearly"

class MetricType(Enum):
    """Types of security metrics."""
    VULNERABILITY_COUNT = "vulnerability_count"
    SEVERITY_DISTRIBUTION = "severity_distribution"
    RISK_SCORE = "risk_score"
    REMEDIATION_TIME = "remediation_time"
    SCAN_FREQUENCY = "scan_frequency"
    COMPLIANCE_SCORE = "compliance_score"
    THREAT_EXPOSURE = "threat_exposure"

@dataclass
class TrendDataPoint:
    """Single data point in a trend analysis."""
    timestamp: datetime
    value: float
    metadata: Dict
    period: str

@dataclass
class SecurityPosture:
    """Security posture metrics for comparison."""
    overall_score: float
    vulnerability_density: float
    remediation_efficiency: float
    compliance_level: float
    threat_exposure_level: float
    improvement_rate: float

class VulnerabilityTrendAnalyzer:
    """
    Advanced vulnerability trend analysis and security posture analytics.
    """
    
    def __init__(self):
        """
        Initialize the trend analyzer.
        """
        self.risk_weights = {
            'critical': 10.0,
            'high': 7.5,
            'medium': 5.0,
            'low': 2.5,
            'info': 1.0
        }
        
        self.industry_benchmarks = {
            'financial': {'avg_vulns_per_scan': 15, 'avg_remediation_days': 7},
            'healthcare': {'avg_vulns_per_scan': 12, 'avg_remediation_days': 5},
            'technology': {'avg_vulns_per_scan': 20, 'avg_remediation_days': 3},
            'government': {'avg_vulns_per_scan': 8, 'avg_remediation_days': 14},
            'retail': {'avg_vulns_per_scan': 18, 'avg_remediation_days': 10}
        }
    
    def analyze_vulnerability_trends(self, period: TrendPeriod, start_date: Optional[datetime] = None, 
                                   end_date: Optional[datetime] = None) -> Dict:
        """
        Analyze vulnerability trends over specified period.
        
        Args:
            period: Time period for analysis
            start_date: Optional start date
            end_date: Optional end date
            
        Returns:
            Comprehensive trend analysis
        """
        try:
            # Set default date range if not provided
            if not end_date:
                end_date = datetime.utcnow()
            
            if not start_date:
                if period == TrendPeriod.DAILY:
                    start_date = end_date - timedelta(days=30)
                elif period == TrendPeriod.WEEKLY:
                    start_date = end_date - timedelta(weeks=12)
                elif period == TrendPeriod.MONTHLY:
                    start_date = end_date - timedelta(days=365)
                elif period == TrendPeriod.QUARTERLY:
                    start_date = end_date - timedelta(days=730)
                else:  # YEARLY
                    start_date = end_date - timedelta(days=1095)
            
            # Get vulnerability data
            vuln_trends = self._get_vulnerability_trends(period, start_date, end_date)
            
            # Get scan trends
            scan_trends = self._get_scan_trends(period, start_date, end_date)
            
            # Calculate risk trends
            risk_trends = self._calculate_risk_trends(period, start_date, end_date)
            
            # Calculate remediation trends
            remediation_trends = self._get_remediation_trends(period, start_date, end_date)
            
            # Generate insights
            insights = self._generate_trend_insights(vuln_trends, scan_trends, risk_trends, remediation_trends)
            
            # Calculate predictions
            predictions = self._generate_trend_predictions(vuln_trends, risk_trends)
            
            return {
                'period': period.value,
                'date_range': {
                    'start': start_date.isoformat(),
                    'end': end_date.isoformat()
                },
                'vulnerability_trends': vuln_trends,
                'scan_trends': scan_trends,
                'risk_trends': risk_trends,
                'remediation_trends': remediation_trends,
                'insights': insights,
                'predictions': predictions,
                'generated_at': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error analyzing vulnerability trends: {str(e)}")
            return {'error': str(e)}
    
    def calculate_security_posture(self, target_date: Optional[datetime] = None) -> SecurityPosture:
        """
        Calculate comprehensive security posture metrics.
        
        Args:
            target_date: Date for posture calculation (default: now)
            
        Returns:
            Security posture metrics
        """
        try:
            if not target_date:
                target_date = datetime.utcnow()
            
            # Calculate overall security score
            overall_score = self._calculate_overall_security_score(target_date)
            
            # Calculate vulnerability density
            vuln_density = self._calculate_vulnerability_density(target_date)
            
            # Calculate remediation efficiency
            remediation_efficiency = self._calculate_remediation_efficiency(target_date)
            
            # Calculate compliance level
            compliance_level = self._calculate_compliance_level(target_date)
            
            # Calculate threat exposure
            threat_exposure = self._calculate_threat_exposure_level(target_date)
            
            # Calculate improvement rate
            improvement_rate = self._calculate_improvement_rate(target_date)
            
            return SecurityPosture(
                overall_score=overall_score,
                vulnerability_density=vuln_density,
                remediation_efficiency=remediation_efficiency,
                compliance_level=compliance_level,
                threat_exposure_level=threat_exposure,
                improvement_rate=improvement_rate
            )
            
        except Exception as e:
            logger.error(f"Error calculating security posture: {str(e)}")
            return SecurityPosture(0.0, 0.0, 0.0, 0.0, 0.0, 0.0)
    
    def compare_security_posture(self, industry: str, organization_size: str = 'medium') -> Dict:
        """
        Compare security posture against industry benchmarks.
        
        Args:
            industry: Industry sector for comparison
            organization_size: Organization size (small, medium, large)
            
        Returns:
            Comparative analysis results
        """
        try:
            # Get current security posture
            current_posture = self.calculate_security_posture()
            
            # Get industry benchmarks
            benchmarks = self._get_industry_benchmarks(industry, organization_size)
            
            # Calculate comparative metrics
            comparison = {
                'current_posture': {
                    'overall_score': current_posture.overall_score,
                    'vulnerability_density': current_posture.vulnerability_density,
                    'remediation_efficiency': current_posture.remediation_efficiency,
                    'compliance_level': current_posture.compliance_level,
                    'threat_exposure': current_posture.threat_exposure_level
                },
                'industry_benchmarks': benchmarks,
                'comparative_analysis': {},
                'recommendations': []
            }
            
            # Compare each metric
            for metric, current_value in comparison['current_posture'].items():
                benchmark_value = benchmarks.get(metric, 0)
                
                if benchmark_value > 0:
                    percentage_diff = ((current_value - benchmark_value) / benchmark_value) * 100
                    
                    comparison['comparative_analysis'][metric] = {
                        'current': current_value,
                        'benchmark': benchmark_value,
                        'difference_percentage': round(percentage_diff, 2),
                        'status': 'above_average' if percentage_diff > 0 else 'below_average'
                    }
                    
                    # Generate recommendations
                    if percentage_diff < -10:  # More than 10% below benchmark
                        comparison['recommendations'].append(
                            f"Improve {metric.replace('_', ' ')}: currently {abs(percentage_diff):.1f}% below industry average"
                        )
            
            # Calculate overall ranking
            avg_performance = statistics.mean([
                comp['difference_percentage'] for comp in comparison['comparative_analysis'].values()
            ])
            
            if avg_performance > 20:
                ranking = 'excellent'
            elif avg_performance > 0:
                ranking = 'above_average'
            elif avg_performance > -20:
                ranking = 'average'
            else:
                ranking = 'needs_improvement'
            
            comparison['overall_ranking'] = ranking
            comparison['industry'] = industry
            comparison['organization_size'] = organization_size
            
            return comparison
            
        except Exception as e:
            logger.error(f"Error comparing security posture: {str(e)}")
            return {'error': str(e)}
    
    def generate_risk_score_algorithm(self, vulnerability_data: List[Dict]) -> Dict:
        """
        Generate advanced risk scores using multiple algorithms.
        
        Args:
            vulnerability_data: List of vulnerability dictionaries
            
        Returns:
            Risk scoring results
        """
        try:
            if not vulnerability_data:
                return {'error': 'No vulnerability data provided'}
            
            # Calculate different risk scoring algorithms
            cvss_scores = self._calculate_cvss_risk_scores(vulnerability_data)
            temporal_scores = self._calculate_temporal_risk_scores(vulnerability_data)
            environmental_scores = self._calculate_environmental_risk_scores(vulnerability_data)
            business_impact_scores = self._calculate_business_impact_scores(vulnerability_data)
            
            # Combine scores using weighted algorithm
            combined_scores = []
            for i, vuln in enumerate(vulnerability_data):
                combined_score = (
                    cvss_scores[i] * 0.3 +
                    temporal_scores[i] * 0.25 +
                    environmental_scores[i] * 0.25 +
                    business_impact_scores[i] * 0.2
                )
                combined_scores.append(combined_score)
            
            # Calculate aggregate metrics
            total_risk = sum(combined_scores)
            avg_risk = statistics.mean(combined_scores) if combined_scores else 0
            max_risk = max(combined_scores) if combined_scores else 0
            
            # Risk distribution
            risk_distribution = {
                'critical': len([s for s in combined_scores if s >= 9.0]),
                'high': len([s for s in combined_scores if 7.0 <= s < 9.0]),
                'medium': len([s for s in combined_scores if 4.0 <= s < 7.0]),
                'low': len([s for s in combined_scores if s < 4.0])
            }
            
            return {
                'algorithm_results': {
                    'cvss_scores': cvss_scores,
                    'temporal_scores': temporal_scores,
                    'environmental_scores': environmental_scores,
                    'business_impact_scores': business_impact_scores,
                    'combined_scores': combined_scores
                },
                'aggregate_metrics': {
                    'total_risk': round(total_risk, 2),
                    'average_risk': round(avg_risk, 2),
                    'maximum_risk': round(max_risk, 2),
                    'vulnerability_count': len(vulnerability_data)
                },
                'risk_distribution': risk_distribution,
                'risk_level': self._determine_overall_risk_level(avg_risk),
                'recommendations': self._generate_risk_recommendations(risk_distribution, avg_risk)
            }
            
        except Exception as e:
            logger.error(f"Error generating risk scores: {str(e)}")
            return {'error': str(e)}
    
    def _get_vulnerability_trends(self, period: TrendPeriod, start_date: datetime, end_date: datetime) -> Dict:
        """Get vulnerability trends data."""
        try:
            db = get_db()
            
            # Aggregate vulnerabilities by time period
            pipeline = [
                {
                    '$match': {
                        'created_at': {
                            '$gte': start_date,
                            '$lte': end_date
                        }
                    }
                },
                {
                    '$group': {
                        '_id': {
                            'year': {'$year': '$created_at'},
                            'month': {'$month': '$created_at'},
                            'day': {'$dayOfMonth': '$created_at'} if period == TrendPeriod.DAILY else None,
                            'week': {'$week': '$created_at'} if period == TrendPeriod.WEEKLY else None
                        },
                        'count': {'$sum': 1},
                        'severities': {'$push': '$severity'}
                    }
                },
                {'$sort': {'_id': 1}}
            ]
            
            # Remove None values from grouping
            pipeline[1]['$group']['_id'] = {k: v for k, v in pipeline[1]['$group']['_id'].items() if v is not None}
            
            results = list(db.vulnerabilities.aggregate(pipeline))
            
            # Process results into trend data
            trend_data = []
            severity_trends = defaultdict(list)
            
            for result in results:
                # Create timestamp based on period
                if period == TrendPeriod.DAILY:
                    timestamp = datetime(result['_id']['year'], result['_id']['month'], result['_id']['day'])
                elif period == TrendPeriod.WEEKLY:
                    timestamp = datetime(result['_id']['year'], 1, 1) + timedelta(weeks=result['_id']['week']-1)
                else:
                    timestamp = datetime(result['_id']['year'], result['_id']['month'], 1)
                
                trend_data.append({
                    'timestamp': timestamp.isoformat(),
                    'count': result['count'],
                    'severities': result['severities']
                })
                
                # Track severity trends
                severity_counts = defaultdict(int)
                for severity in result['severities']:
                    severity_counts[severity] += 1
                
                for severity, count in severity_counts.items():
                    severity_trends[severity].append({
                        'timestamp': timestamp.isoformat(),
                        'count': count
                    })
            
            return {
                'total_trends': trend_data,
                'severity_trends': dict(severity_trends),
                'summary': {
                    'total_vulnerabilities': sum(item['count'] for item in trend_data),
                    'average_per_period': statistics.mean([item['count'] for item in trend_data]) if trend_data else 0,
                    'peak_period': max(trend_data, key=lambda x: x['count']) if trend_data else None
                }
            }
            
        except Exception as e:
            logger.error(f"Error getting vulnerability trends: {str(e)}")
            return {'error': str(e)}
    
    def _get_scan_trends(self, period: TrendPeriod, start_date: datetime, end_date: datetime) -> Dict:
        """Get scan frequency and success trends."""
        try:
            db = get_db()
            
            # Get scan data
            scans = list(db.scans.find({
                'start_time': {
                    '$gte': start_date,
                    '$lte': end_date
                }
            }))
            
            # Group by time period
            scan_trends = defaultdict(lambda: {'total': 0, 'completed': 0, 'failed': 0})
            
            for scan in scans:
                # Determine period key
                scan_date = scan['start_time']
                if period == TrendPeriod.DAILY:
                    period_key = scan_date.strftime('%Y-%m-%d')
                elif period == TrendPeriod.WEEKLY:
                    period_key = scan_date.strftime('%Y-W%U')
                else:
                    period_key = scan_date.strftime('%Y-%m')
                
                scan_trends[period_key]['total'] += 1
                
                if scan.get('status') == 'completed':
                    scan_trends[period_key]['completed'] += 1
                elif scan.get('status') == 'failed':
                    scan_trends[period_key]['failed'] += 1
            
            # Convert to list format
            trend_data = []
            for period_key, data in sorted(scan_trends.items()):
                success_rate = (data['completed'] / data['total'] * 100) if data['total'] > 0 else 0
                
                trend_data.append({
                    'period': period_key,
                    'total_scans': data['total'],
                    'completed_scans': data['completed'],
                    'failed_scans': data['failed'],
                    'success_rate': round(success_rate, 2)
                })
            
            return {
                'scan_trends': trend_data,
                'summary': {
                    'total_scans': sum(item['total_scans'] for item in trend_data),
                    'average_success_rate': statistics.mean([item['success_rate'] for item in trend_data]) if trend_data else 0,
                    'scan_frequency': len(trend_data)
                }
            }
            
        except Exception as e:
            logger.error(f"Error getting scan trends: {str(e)}")
            return {'error': str(e)}
    
    def _calculate_risk_trends(self, period: TrendPeriod, start_date: datetime, end_date: datetime) -> Dict:
        """Calculate risk score trends over time."""
        try:
            db = get_db()
            
            # Get vulnerabilities with risk scores
            vulnerabilities = list(db.vulnerabilities.find({
                'created_at': {
                    '$gte': start_date,
                    '$lte': end_date
                }
            }))
            
            # Group by time period and calculate risk scores
            risk_trends = defaultdict(list)
            
            for vuln in vulnerabilities:
                # Determine period key
                vuln_date = vuln['created_at']
                if period == TrendPeriod.DAILY:
                    period_key = vuln_date.strftime('%Y-%m-%d')
                elif period == TrendPeriod.WEEKLY:
                    period_key = vuln_date.strftime('%Y-W%U')
                else:
                    period_key = vuln_date.strftime('%Y-%m')
                
                # Calculate risk score for this vulnerability
                severity = vuln.get('severity', 'low')
                risk_score = self.risk_weights.get(severity, 1.0)
                
                # Apply additional factors
                if vuln.get('cvss_score'):
                    risk_score = vuln['cvss_score']
                
                risk_trends[period_key].append(risk_score)
            
            # Calculate aggregate risk metrics per period
            trend_data = []
            for period_key, scores in sorted(risk_trends.items()):
                if scores:
                    trend_data.append({
                        'period': period_key,
                        'average_risk': round(statistics.mean(scores), 2),
                        'max_risk': round(max(scores), 2),
                        'total_risk': round(sum(scores), 2),
                        'vulnerability_count': len(scores)
                    })
            
            return {
                'risk_trends': trend_data,
                'summary': {
                    'average_risk_score': statistics.mean([item['average_risk'] for item in trend_data]) if trend_data else 0,
                    'peak_risk_period': max(trend_data, key=lambda x: x['max_risk']) if trend_data else None,
                    'total_risk_exposure': sum(item['total_risk'] for item in trend_data)
                }
            }
            
        except Exception as e:
            logger.error(f"Error calculating risk trends: {str(e)}")
            return {'error': str(e)}
    
    def _get_remediation_trends(self, period: TrendPeriod, start_date: datetime, end_date: datetime) -> Dict:
        """Get remediation time and efficiency trends."""
        try:
            db = get_db()
            
            # Get vulnerabilities with remediation data
            vulnerabilities = list(db.vulnerabilities.find({
                'created_at': {
                    '$gte': start_date,
                    '$lte': end_date
                },
                'status': {'$in': ['resolved', 'fixed', 'mitigated']}
            }))
            
            # Calculate remediation times
            remediation_trends = defaultdict(list)
            
            for vuln in vulnerabilities:
                if vuln.get('resolved_at'):
                    created_at = vuln['created_at']
                    resolved_at = vuln['resolved_at']
                    
                    # Calculate remediation time in days
                    remediation_time = (resolved_at - created_at).days
                    
                    # Determine period key
                    if period == TrendPeriod.DAILY:
                        period_key = created_at.strftime('%Y-%m-%d')
                    elif period == TrendPeriod.WEEKLY:
                        period_key = created_at.strftime('%Y-W%U')
                    else:
                        period_key = created_at.strftime('%Y-%m')
                    
                    remediation_trends[period_key].append(remediation_time)
            
            # Calculate metrics per period
            trend_data = []
            for period_key, times in sorted(remediation_trends.items()):
                if times:
                    trend_data.append({
                        'period': period_key,
                        'average_remediation_days': round(statistics.mean(times), 2),
                        'median_remediation_days': round(statistics.median(times), 2),
                        'max_remediation_days': max(times),
                        'vulnerabilities_resolved': len(times)
                    })
            
            return {
                'remediation_trends': trend_data,
                'summary': {
                    'average_remediation_time': statistics.mean([item['average_remediation_days'] for item in trend_data]) if trend_data else 0,
                    'total_vulnerabilities_resolved': sum(item['vulnerabilities_resolved'] for item in trend_data),
                    'fastest_remediation_period': min(trend_data, key=lambda x: x['average_remediation_days']) if trend_data else None
                }
            }
            
        except Exception as e:
            logger.error(f"Error getting remediation trends: {str(e)}")
            return {'error': str(e)}
    
    def _generate_trend_insights(self, vuln_trends: Dict, scan_trends: Dict, risk_trends: Dict, remediation_trends: Dict) -> List[str]:
        """Generate actionable insights from trend data."""
        insights = []
        
        try:
            # Vulnerability trend insights
            if vuln_trends.get('total_trends'):
                recent_count = vuln_trends['total_trends'][-1]['count'] if vuln_trends['total_trends'] else 0
                avg_count = vuln_trends['summary']['average_per_period']
                
                if recent_count > avg_count * 1.5:
                    insights.append(f"⚠️ Recent vulnerability discovery rate is {((recent_count/avg_count-1)*100):.0f}% above average")
                elif recent_count < avg_count * 0.5:
                    insights.append(f"✅ Recent vulnerability discovery rate is {((1-recent_count/avg_count)*100):.0f}% below average")
            
            # Scan trend insights
            if scan_trends.get('scan_trends'):
                avg_success_rate = scan_trends['summary']['average_success_rate']
                if avg_success_rate < 80:
                    insights.append(f"🔧 Scan success rate ({avg_success_rate:.1f}%) needs improvement")
                elif avg_success_rate > 95:
                    insights.append(f"🎯 Excellent scan success rate ({avg_success_rate:.1f}%)")
            
            # Risk trend insights
            if risk_trends.get('risk_trends'):
                risk_data = risk_trends['risk_trends']
                if len(risk_data) >= 2:
                    recent_risk = risk_data[-1]['average_risk']
                    previous_risk = risk_data[-2]['average_risk']
                    
                    if recent_risk > previous_risk * 1.2:
                        insights.append(f"📈 Risk level increasing: {((recent_risk/previous_risk-1)*100):.0f}% higher than previous period")
                    elif recent_risk < previous_risk * 0.8:
                        insights.append(f"📉 Risk level decreasing: {((1-recent_risk/previous_risk)*100):.0f}% lower than previous period")
            
            # Remediation trend insights
            if remediation_trends.get('remediation_trends'):
                avg_remediation = remediation_trends['summary']['average_remediation_time']
                if avg_remediation > 30:
                    insights.append(f"⏰ Average remediation time ({avg_remediation:.1f} days) exceeds recommended 30-day target")
                elif avg_remediation < 7:
                    insights.append(f"⚡ Excellent remediation speed: average {avg_remediation:.1f} days")
            
            # Add general insights if no specific ones found
            if not insights:
                insights.append("📊 Security metrics are within normal ranges")
                insights.append("🔍 Continue monitoring for emerging trends")
            
        except Exception as e:
            logger.error(f"Error generating insights: {str(e)}")
            insights.append("⚠️ Unable to generate insights due to data processing error")
        
        return insights
    
    def _generate_trend_predictions(self, vuln_trends: Dict, risk_trends: Dict) -> Dict:
        """Generate trend predictions using simple linear regression."""
        try:
            predictions = {}
            
            # Predict vulnerability count trend
            if vuln_trends.get('total_trends') and len(vuln_trends['total_trends']) >= 3:
                counts = [item['count'] for item in vuln_trends['total_trends'][-5:]]  # Last 5 periods
                trend_slope = (counts[-1] - counts[0]) / len(counts)
                
                next_period_prediction = max(0, counts[-1] + trend_slope)
                
                predictions['vulnerability_count'] = {
                    'next_period': round(next_period_prediction),
                    'trend': 'increasing' if trend_slope > 0 else 'decreasing',
                    'confidence': 'medium'
                }
            
            # Predict risk score trend
            if risk_trends.get('risk_trends') and len(risk_trends['risk_trends']) >= 3:
                risk_scores = [item['average_risk'] for item in risk_trends['risk_trends'][-5:]]
                risk_slope = (risk_scores[-1] - risk_scores[0]) / len(risk_scores)
                
                next_risk_prediction = max(0, risk_scores[-1] + risk_slope)
                
                predictions['risk_score'] = {
                    'next_period': round(next_risk_prediction, 2),
                    'trend': 'increasing' if risk_slope > 0 else 'decreasing',
                    'confidence': 'medium'
                }
            
            return predictions
            
        except Exception as e:
            logger.error(f"Error generating predictions: {str(e)}")
            return {'error': str(e)}
    
    # Additional helper methods for security posture calculation
    def _calculate_overall_security_score(self, target_date: datetime) -> float:
        """Calculate overall security score."""
        try:
            db = get_db()
            
            # Get recent vulnerabilities (last 30 days)
            recent_vulns = list(db.vulnerabilities.find({
                'created_at': {'$gte': target_date - timedelta(days=30)}
            }))
            
            if not recent_vulns:
                return 100.0  # Perfect score if no vulnerabilities
            
            # Calculate weighted score based on severity
            total_weight = 0
            for vuln in recent_vulns:
                severity = vuln.get('severity', 'low')
                total_weight += self.risk_weights.get(severity, 1.0)
            
            # Normalize to 0-100 scale (lower is better for vulnerabilities)
            max_possible_weight = len(recent_vulns) * 10.0  # Assuming all critical
            score = max(0, 100 - (total_weight / max_possible_weight * 100))
            
            return round(score, 2)
            
        except Exception as e:
            logger.error(f"Error calculating overall security score: {str(e)}")
            return 50.0  # Default middle score
    
    def _calculate_vulnerability_density(self, target_date: datetime) -> float:
        """Calculate vulnerability density (vulnerabilities per scan)."""
        try:
            db = get_db()
            
            # Get recent data
            recent_scans = db.scans.count_documents({
                'start_time': {'$gte': target_date - timedelta(days=30)}
            })
            
            recent_vulns = db.vulnerabilities.count_documents({
                'created_at': {'$gte': target_date - timedelta(days=30)}
            })
            
            if recent_scans == 0:
                return 0.0
            
            return round(recent_vulns / recent_scans, 2)
            
        except Exception as e:
            logger.error(f"Error calculating vulnerability density: {str(e)}")
            return 0.0
    
    def _calculate_remediation_efficiency(self, target_date: datetime) -> float:
        """Calculate remediation efficiency percentage."""
        try:
            db = get_db()
            
            # Get vulnerabilities from last 60 days
            old_vulns = list(db.vulnerabilities.find({
                'created_at': {'$gte': target_date - timedelta(days=60), '$lte': target_date - timedelta(days=30)}
            }))
            
            if not old_vulns:
                return 100.0  # Perfect if no old vulnerabilities
            
            # Count how many have been resolved
            resolved_count = len([v for v in old_vulns if v.get('status') in ['resolved', 'fixed', 'mitigated']])
            
            efficiency = (resolved_count / len(old_vulns)) * 100
            return round(efficiency, 2)
            
        except Exception as e:
            logger.error(f"Error calculating remediation efficiency: {str(e)}")
            return 50.0
    
    def _calculate_compliance_level(self, target_date: datetime) -> float:
        """Calculate compliance level based on recent scans."""
        try:
            # This would integrate with compliance scan results
            # For now, return a calculated value based on vulnerability severity distribution
            db = get_db()
            
            recent_vulns = list(db.vulnerabilities.find({
                'created_at': {'$gte': target_date - timedelta(days=30)}
            }))
            
            if not recent_vulns:
                return 100.0
            
            # Calculate compliance based on critical/high vulnerability ratio
            critical_high_count = len([v for v in recent_vulns if v.get('severity') in ['critical', 'high']])
            compliance_score = max(0, 100 - (critical_high_count / len(recent_vulns) * 100))
            
            return round(compliance_score, 2)
            
        except Exception as e:
            logger.error(f"Error calculating compliance level: {str(e)}")
            return 75.0
    
    def _calculate_threat_exposure_level(self, target_date: datetime) -> float:
        """Calculate threat exposure level."""
        try:
            db = get_db()
            
            # Get unresolved vulnerabilities
            unresolved_vulns = list(db.vulnerabilities.find({
                'status': {'$nin': ['resolved', 'fixed', 'mitigated']}
            }))
            
            if not unresolved_vulns:
                return 0.0  # No exposure
            
            # Calculate exposure based on age and severity
            total_exposure = 0
            for vuln in unresolved_vulns:
                age_days = (target_date - vuln['created_at']).days
                severity_weight = self.risk_weights.get(vuln.get('severity', 'low'), 1.0)
                
                # Exposure increases with age and severity
                exposure = severity_weight * (1 + age_days / 30)  # Increases by severity weight every 30 days
                total_exposure += exposure
            
            # Normalize to 0-100 scale
            max_exposure = len(unresolved_vulns) * 10 * 4  # Max if all critical and 120 days old
            exposure_level = min(100, (total_exposure / max_exposure) * 100)
            
            return round(exposure_level, 2)
            
        except Exception as e:
            logger.error(f"Error calculating threat exposure: {str(e)}")
            return 25.0
    
    def _calculate_improvement_rate(self, target_date: datetime) -> float:
        """Calculate security improvement rate over time."""
        try:
            # Compare current month vs previous month
            current_month_start = target_date.replace(day=1)
            previous_month_start = (current_month_start - timedelta(days=1)).replace(day=1)
            
            current_posture = self.calculate_security_posture(current_month_start)
            previous_posture = self.calculate_security_posture(previous_month_start)
            
            # Calculate improvement rate based on overall score
            if previous_posture.overall_score > 0:
                improvement = ((current_posture.overall_score - previous_posture.overall_score) / 
                             previous_posture.overall_score) * 100
            else:
                improvement = 0.0
            
            return round(improvement, 2)
            
        except Exception as e:
            logger.error(f"Error calculating improvement rate: {str(e)}")
            return 0.0
    
    def _get_industry_benchmarks(self, industry: str, organization_size: str) -> Dict:
        """Get industry benchmark data."""
        base_benchmarks = self.industry_benchmarks.get(industry, {
            'avg_vulns_per_scan': 15,
            'avg_remediation_days': 10
        })
        
        # Adjust for organization size
        size_multipliers = {
            'small': 0.7,
            'medium': 1.0,
            'large': 1.3
        }
        
        multiplier = size_multipliers.get(organization_size, 1.0)
        
        return {
            'overall_score': 75.0,
            'vulnerability_density': base_benchmarks['avg_vulns_per_scan'] * multiplier,
            'remediation_efficiency': 80.0,
            'compliance_level': 85.0,
            'threat_exposure': 20.0
        }
    
    # Risk scoring algorithm methods
    def _calculate_cvss_risk_scores(self, vulnerability_data: List[Dict]) -> List[float]:
        """Calculate CVSS-based risk scores."""
        scores = []
        for vuln in vulnerability_data:
            cvss_score = vuln.get('cvss_score', 0)
            if cvss_score > 0:
                scores.append(cvss_score)
            else:
                # Fallback to severity mapping
                severity = vuln.get('severity', 'low')
                scores.append(self.risk_weights.get(severity, 1.0))
        return scores
    
    def _calculate_temporal_risk_scores(self, vulnerability_data: List[Dict]) -> List[float]:
        """Calculate temporal risk scores based on age and exploit availability."""
        scores = []
        for vuln in vulnerability_data:
            base_score = vuln.get('cvss_score', self.risk_weights.get(vuln.get('severity', 'low'), 1.0))
            
            # Age factor
            if vuln.get('created_at'):
                age_days = (datetime.utcnow() - vuln['created_at']).days
                age_factor = min(1.5, 1 + age_days / 365)  # Increases over time, max 1.5x
            else:
                age_factor = 1.0
            
            # Exploit availability factor
            exploit_factor = 1.0
            if vuln.get('exploit_available'):
                exploit_factor = 1.3
            elif vuln.get('poc_available'):
                exploit_factor = 1.1
            
            temporal_score = base_score * age_factor * exploit_factor
            scores.append(min(10.0, temporal_score))  # Cap at 10
        
        return scores
    
    def _calculate_environmental_risk_scores(self, vulnerability_data: List[Dict]) -> List[float]:
        """Calculate environmental risk scores based on system context."""
        scores = []
        for vuln in vulnerability_data:
            base_score = vuln.get('cvss_score', self.risk_weights.get(vuln.get('severity', 'low'), 1.0))
            
            # Network exposure factor
            exposure_factor = 1.0
            if vuln.get('network_accessible'):
                exposure_factor = 1.4
            elif vuln.get('internet_facing'):
                exposure_factor = 1.6
            
            # Asset criticality factor
            criticality_factor = 1.0
            asset_criticality = vuln.get('asset_criticality', 'medium')
            if asset_criticality == 'critical':
                criticality_factor = 1.5
            elif asset_criticality == 'high':
                criticality_factor = 1.3
            elif asset_criticality == 'low':
                criticality_factor = 0.8
            
            environmental_score = base_score * exposure_factor * criticality_factor
            scores.append(min(10.0, environmental_score))
        
        return scores
    
    def _calculate_business_impact_scores(self, vulnerability_data: List[Dict]) -> List[float]:
        """Calculate business impact scores."""
        scores = []
        for vuln in vulnerability_data:
            base_score = vuln.get('cvss_score', self.risk_weights.get(vuln.get('severity', 'low'), 1.0))
            
            # Business impact factors
            impact_factor = 1.0
            
            # Data sensitivity
            if vuln.get('affects_sensitive_data'):
                impact_factor *= 1.4
            
            # Compliance requirements
            if vuln.get('compliance_relevant'):
                impact_factor *= 1.3
            
            # Service availability
            if vuln.get('affects_availability'):
                impact_factor *= 1.2
            
            business_score = base_score * impact_factor
            scores.append(min(10.0, business_score))
        
        return scores
    
    def _determine_overall_risk_level(self, avg_risk: float) -> str:
        """Determine overall risk level from average risk score."""
        if avg_risk >= 9.0:
            return 'critical'
        elif avg_risk >= 7.0:
            return 'high'
        elif avg_risk >= 4.0:
            return 'medium'
        elif avg_risk >= 1.0:
            return 'low'
        else:
            return 'minimal'
    
    def _generate_risk_recommendations(self, risk_distribution: Dict, avg_risk: float) -> List[str]:
        """Generate risk-based recommendations."""
        recommendations = []
        
        if risk_distribution['critical'] > 0:
            recommendations.append(f"🚨 Immediate action required: {risk_distribution['critical']} critical vulnerabilities")
        
        if risk_distribution['high'] > 5:
            recommendations.append(f"⚠️ High priority: {risk_distribution['high']} high-risk vulnerabilities need attention")
        
        if avg_risk > 7.0:
            recommendations.append("📈 Overall risk level is high - consider additional security measures")
        
        if risk_distribution['low'] > risk_distribution['high'] + risk_distribution['critical']:
            recommendations.append("✅ Most vulnerabilities are low risk - focus on prevention")
        
        recommendations.extend([
            "🔍 Implement continuous monitoring for new threats",
            "📊 Regular risk assessment reviews recommended",
            "🛡️ Consider implementing additional security controls"
        ])
        
        return recommendations