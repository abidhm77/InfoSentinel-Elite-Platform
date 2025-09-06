#!/usr/bin/env python3
"""
Comparative Security Posture Analytics for InfoSentinel.
Provides benchmarking, peer comparison, and security maturity assessment.
"""
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional
import logging
import json
import statistics
from dataclasses import dataclass
from enum import Enum
from database.db import get_db, get_postgres_session, close_postgres_session
from analytics.trend_analyzer import VulnerabilityTrendAnalyzer, SecurityPosture
from intelligence.threat_intel_service import ThreatIntelligenceService

logger = logging.getLogger(__name__)

class MaturityLevel(Enum):
    """Security maturity levels."""
    INITIAL = 1
    DEVELOPING = 2
    DEFINED = 3
    MANAGED = 4
    OPTIMIZING = 5

class BenchmarkCategory(Enum):
    """Benchmark categories for comparison."""
    VULNERABILITY_MANAGEMENT = "vulnerability_management"
    INCIDENT_RESPONSE = "incident_response"
    COMPLIANCE = "compliance"
    THREAT_DETECTION = "threat_detection"
    SECURITY_AWARENESS = "security_awareness"
    ACCESS_CONTROL = "access_control"
    DATA_PROTECTION = "data_protection"

@dataclass
class BenchmarkMetric:
    """Individual benchmark metric."""
    name: str
    category: BenchmarkCategory
    current_value: float
    benchmark_value: float
    percentile: float
    industry_average: float
    best_practice: float
    unit: str
    description: str

@dataclass
class SecurityMaturityAssessment:
    """Security maturity assessment results."""
    overall_level: MaturityLevel
    category_levels: Dict[BenchmarkCategory, MaturityLevel]
    strengths: List[str]
    weaknesses: List[str]
    recommendations: List[str]
    maturity_score: float

class SecurityPostureAnalytics:
    """
    Comprehensive security posture analytics and benchmarking.
    """
    
    def __init__(self):
        """
        Initialize the security posture analytics.
        """
        self.trend_analyzer = VulnerabilityTrendAnalyzer()
        self.threat_intel = ThreatIntelligenceService()
        
        # Industry benchmark data (would be loaded from external sources)
        self.industry_benchmarks = {
            'financial': {
                'vulnerability_density': 8.5,
                'mean_time_to_remediation': 5.2,
                'compliance_score': 92.0,
                'security_incidents_per_year': 2.1,
                'patch_coverage': 95.5,
                'security_training_completion': 98.0
            },
            'healthcare': {
                'vulnerability_density': 12.3,
                'mean_time_to_remediation': 7.8,
                'compliance_score': 88.5,
                'security_incidents_per_year': 3.2,
                'patch_coverage': 91.2,
                'security_training_completion': 94.5
            },
            'technology': {
                'vulnerability_density': 15.7,
                'mean_time_to_remediation': 3.1,
                'compliance_score': 85.2,
                'security_incidents_per_year': 4.8,
                'patch_coverage': 97.8,
                'security_training_completion': 96.2
            },
            'government': {
                'vulnerability_density': 6.2,
                'mean_time_to_remediation': 12.5,
                'compliance_score': 96.8,
                'security_incidents_per_year': 1.3,
                'patch_coverage': 98.9,
                'security_training_completion': 99.1
            },
            'retail': {
                'vulnerability_density': 18.9,
                'mean_time_to_remediation': 8.7,
                'compliance_score': 82.1,
                'security_incidents_per_year': 5.6,
                'patch_coverage': 89.3,
                'security_training_completion': 87.8
            }
        }
        
        # Organization size multipliers
        self.size_multipliers = {
            'small': {'vulnerability_density': 0.8, 'remediation_time': 1.3, 'compliance': 0.95},
            'medium': {'vulnerability_density': 1.0, 'remediation_time': 1.0, 'compliance': 1.0},
            'large': {'vulnerability_density': 1.2, 'remediation_time': 0.8, 'compliance': 1.05},
            'enterprise': {'vulnerability_density': 1.4, 'remediation_time': 0.6, 'compliance': 1.1}
        }
    
    async def generate_comprehensive_benchmark(self, industry: str, organization_size: str = 'medium', 
                                            include_peer_comparison: bool = True) -> Dict:
        """
        Generate comprehensive security posture benchmark.
        
        Args:
            industry: Industry sector
            organization_size: Organization size category
            include_peer_comparison: Whether to include peer comparison
            
        Returns:
            Comprehensive benchmark analysis
        """
        try:
            logger.info(f"Generating comprehensive benchmark for {industry} ({organization_size})")
            
            # Get current security posture
            current_posture = self.trend_analyzer.calculate_security_posture()
            
            # Calculate detailed metrics
            detailed_metrics = await self._calculate_detailed_metrics()
            
            # Get industry benchmarks
            industry_benchmarks = self._get_adjusted_benchmarks(industry, organization_size)
            
            # Create benchmark metrics
            benchmark_metrics = self._create_benchmark_metrics(detailed_metrics, industry_benchmarks)
            
            # Calculate percentiles
            percentiles = await self._calculate_percentiles(detailed_metrics, industry)
            
            # Generate maturity assessment
            maturity_assessment = self._assess_security_maturity(benchmark_metrics)
            
            # Peer comparison (if requested)
            peer_comparison = None
            if include_peer_comparison:
                peer_comparison = await self._generate_peer_comparison(industry, organization_size)
            
            # Generate recommendations
            recommendations = self._generate_benchmark_recommendations(benchmark_metrics, maturity_assessment)
            
            # Calculate overall score
            overall_score = self._calculate_overall_benchmark_score(benchmark_metrics)
            
            return {
                'organization_profile': {
                    'industry': industry,
                    'size': organization_size,
                    'assessment_date': datetime.utcnow().isoformat()
                },
                'current_posture': {
                    'overall_score': current_posture.overall_score,
                    'vulnerability_density': current_posture.vulnerability_density,
                    'remediation_efficiency': current_posture.remediation_efficiency,
                    'compliance_level': current_posture.compliance_level,
                    'threat_exposure': current_posture.threat_exposure_level
                },
                'benchmark_metrics': [metric.__dict__ for metric in benchmark_metrics],
                'percentiles': percentiles,
                'maturity_assessment': {
                    'overall_level': maturity_assessment.overall_level.name,
                    'maturity_score': maturity_assessment.maturity_score,
                    'category_levels': {cat.value: level.name for cat, level in maturity_assessment.category_levels.items()},
                    'strengths': maturity_assessment.strengths,
                    'weaknesses': maturity_assessment.weaknesses
                },
                'peer_comparison': peer_comparison,
                'recommendations': recommendations,
                'overall_benchmark_score': overall_score,
                'industry_ranking': self._determine_industry_ranking(overall_score)
            }
            
        except Exception as e:
            logger.error(f"Error generating comprehensive benchmark: {str(e)}")
            return {'error': str(e)}
    
    async def track_security_improvement(self, months_back: int = 12) -> Dict:
        """
        Track security improvement over time.
        
        Args:
            months_back: Number of months to analyze
            
        Returns:
            Security improvement tracking data
        """
        try:
            logger.info(f"Tracking security improvement over {months_back} months")
            
            # Get historical data points
            improvement_data = []
            
            for i in range(months_back):
                target_date = datetime.utcnow() - timedelta(days=30 * i)
                
                # Calculate posture for this date
                historical_posture = self.trend_analyzer.calculate_security_posture(target_date)
                
                improvement_data.append({
                    'date': target_date.isoformat(),
                    'overall_score': historical_posture.overall_score,
                    'vulnerability_density': historical_posture.vulnerability_density,
                    'remediation_efficiency': historical_posture.remediation_efficiency,
                    'compliance_level': historical_posture.compliance_level,
                    'threat_exposure': historical_posture.threat_exposure_level
                })
            
            # Reverse to get chronological order
            improvement_data.reverse()
            
            # Calculate trends
            trends = self._calculate_improvement_trends(improvement_data)
            
            # Identify significant changes
            significant_changes = self._identify_significant_changes(improvement_data)
            
            # Generate improvement insights
            insights = self._generate_improvement_insights(trends, significant_changes)
            
            return {
                'tracking_period': {
                    'months': months_back,
                    'start_date': improvement_data[0]['date'],
                    'end_date': improvement_data[-1]['date']
                },
                'historical_data': improvement_data,
                'trends': trends,
                'significant_changes': significant_changes,
                'insights': insights,
                'improvement_score': self._calculate_improvement_score(trends)
            }
            
        except Exception as e:
            logger.error(f"Error tracking security improvement: {str(e)}")
            return {'error': str(e)}
    
    async def generate_executive_dashboard(self, industry: str, organization_size: str) -> Dict:
        """
        Generate executive-level security dashboard.
        
        Args:
            industry: Industry sector
            organization_size: Organization size
            
        Returns:
            Executive dashboard data
        """
        try:
            logger.info("Generating executive security dashboard")
            
            # Get current posture
            current_posture = self.trend_analyzer.calculate_security_posture()
            
            # Get threat intelligence summary
            threat_stats = self.threat_intel.get_threat_statistics()
            
            # Calculate key metrics
            key_metrics = await self._calculate_executive_metrics()
            
            # Get industry comparison
            industry_comparison = self.trend_analyzer.compare_security_posture(industry, organization_size)
            
            # Generate risk summary
            risk_summary = await self._generate_risk_summary()
            
            # Calculate security ROI
            security_roi = self._calculate_security_roi()
            
            # Generate strategic recommendations
            strategic_recommendations = self._generate_strategic_recommendations(
                current_posture, industry_comparison, risk_summary
            )
            
            return {
                'executive_summary': {
                    'overall_security_score': current_posture.overall_score,
                    'industry_ranking': industry_comparison.get('overall_ranking', 'average'),
                    'risk_level': risk_summary.get('overall_risk_level', 'medium'),
                    'improvement_trend': current_posture.improvement_rate
                },
                'key_metrics': key_metrics,
                'threat_landscape': {
                    'active_threats': threat_stats.get('recent_threats', 0),
                    'critical_vulnerabilities': threat_stats.get('critical_cves', 0),
                    'exploited_vulnerabilities': threat_stats.get('actively_exploited', 0)
                },
                'industry_comparison': {
                    'ranking': industry_comparison.get('overall_ranking', 'average'),
                    'percentile': self._calculate_industry_percentile(current_posture.overall_score, industry),
                    'peer_performance': industry_comparison.get('comparative_analysis', {})
                },
                'risk_summary': risk_summary,
                'security_roi': security_roi,
                'strategic_recommendations': strategic_recommendations,
                'dashboard_generated': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error generating executive dashboard: {str(e)}")
            return {'error': str(e)}
    
    # Helper methods
    async def _calculate_detailed_metrics(self) -> Dict:
        """Calculate detailed security metrics."""
        try:
            db = get_db()
            
            # Time ranges
            now = datetime.utcnow()
            last_30_days = now - timedelta(days=30)
            last_90_days = now - timedelta(days=90)
            
            # Vulnerability metrics
            total_vulns = db.vulnerabilities.count_documents({})
            recent_vulns = db.vulnerabilities.count_documents({'created_at': {'$gte': last_30_days}})
            critical_vulns = db.vulnerabilities.count_documents({'severity': 'critical'})
            
            # Scan metrics
            total_scans = db.scans.count_documents({})
            successful_scans = db.scans.count_documents({'status': 'completed'})
            
            # Remediation metrics
            resolved_vulns = list(db.vulnerabilities.find({
                'status': {'$in': ['resolved', 'fixed', 'mitigated']},
                'resolved_at': {'$exists': True}
            }))
            
            # Calculate mean time to remediation
            remediation_times = []
            for vuln in resolved_vulns:
                if vuln.get('resolved_at') and vuln.get('created_at'):
                    time_diff = (vuln['resolved_at'] - vuln['created_at']).days
                    remediation_times.append(time_diff)
            
            mean_remediation_time = statistics.mean(remediation_times) if remediation_times else 0
            
            # Calculate vulnerability density
            vulnerability_density = recent_vulns / max(1, total_scans) if total_scans > 0 else 0
            
            # Calculate scan success rate
            scan_success_rate = (successful_scans / max(1, total_scans)) * 100 if total_scans > 0 else 0
            
            # Calculate patch coverage (simplified)
            patch_coverage = (len(resolved_vulns) / max(1, total_vulns)) * 100 if total_vulns > 0 else 100
            
            return {
                'vulnerability_density': vulnerability_density,
                'mean_time_to_remediation': mean_remediation_time,
                'scan_success_rate': scan_success_rate,
                'patch_coverage': patch_coverage,
                'critical_vulnerability_ratio': (critical_vulns / max(1, total_vulns)) * 100,
                'vulnerability_discovery_rate': recent_vulns / 30,  # per day
                'total_vulnerabilities': total_vulns,
                'total_scans': total_scans
            }
            
        except Exception as e:
            logger.error(f"Error calculating detailed metrics: {str(e)}")
            return {}
    
    def _get_adjusted_benchmarks(self, industry: str, organization_size: str) -> Dict:
        """Get industry benchmarks adjusted for organization size."""
        base_benchmarks = self.industry_benchmarks.get(industry, self.industry_benchmarks['technology'])
        size_multipliers = self.size_multipliers.get(organization_size, self.size_multipliers['medium'])
        
        adjusted_benchmarks = {}
        for metric, value in base_benchmarks.items():
            if 'vulnerability_density' in metric:
                adjusted_benchmarks[metric] = value * size_multipliers['vulnerability_density']
            elif 'remediation' in metric:
                adjusted_benchmarks[metric] = value * size_multipliers['remediation_time']
            elif 'compliance' in metric:
                adjusted_benchmarks[metric] = value * size_multipliers['compliance']
            else:
                adjusted_benchmarks[metric] = value
        
        return adjusted_benchmarks
    
    def _create_benchmark_metrics(self, current_metrics: Dict, benchmarks: Dict) -> List[BenchmarkMetric]:
        """Create benchmark metric objects."""
        metrics = []
        
        # Vulnerability density
        if 'vulnerability_density' in current_metrics and 'vulnerability_density' in benchmarks:
            metrics.append(BenchmarkMetric(
                name="Vulnerability Density",
                category=BenchmarkCategory.VULNERABILITY_MANAGEMENT,
                current_value=current_metrics['vulnerability_density'],
                benchmark_value=benchmarks['vulnerability_density'],
                percentile=self._calculate_percentile(current_metrics['vulnerability_density'], benchmarks['vulnerability_density']),
                industry_average=benchmarks['vulnerability_density'],
                best_practice=benchmarks['vulnerability_density'] * 0.5,
                unit="vulnerabilities per scan",
                description="Average number of vulnerabilities found per security scan"
            ))
        
        # Mean time to remediation
        if 'mean_time_to_remediation' in current_metrics and 'mean_time_to_remediation' in benchmarks:
            metrics.append(BenchmarkMetric(
                name="Mean Time to Remediation",
                category=BenchmarkCategory.VULNERABILITY_MANAGEMENT,
                current_value=current_metrics['mean_time_to_remediation'],
                benchmark_value=benchmarks['mean_time_to_remediation'],
                percentile=self._calculate_percentile(current_metrics['mean_time_to_remediation'], benchmarks['mean_time_to_remediation'], lower_is_better=True),
                industry_average=benchmarks['mean_time_to_remediation'],
                best_practice=benchmarks['mean_time_to_remediation'] * 0.5,
                unit="days",
                description="Average time to resolve identified vulnerabilities"
            ))
        
        # Patch coverage
        if 'patch_coverage' in current_metrics and 'patch_coverage' in benchmarks:
            metrics.append(BenchmarkMetric(
                name="Patch Coverage",
                category=BenchmarkCategory.VULNERABILITY_MANAGEMENT,
                current_value=current_metrics['patch_coverage'],
                benchmark_value=benchmarks['patch_coverage'],
                percentile=self._calculate_percentile(current_metrics['patch_coverage'], benchmarks['patch_coverage']),
                industry_average=benchmarks['patch_coverage'],
                best_practice=99.0,
                unit="percentage",
                description="Percentage of identified vulnerabilities that have been patched"
            ))
        
        return metrics
    
    def _calculate_percentile(self, current_value: float, benchmark_value: float, lower_is_better: bool = False) -> float:
        """Calculate percentile ranking."""
        if lower_is_better:
            if current_value <= benchmark_value * 0.5:
                return 95.0
            elif current_value <= benchmark_value * 0.75:
                return 80.0
            elif current_value <= benchmark_value:
                return 60.0
            elif current_value <= benchmark_value * 1.25:
                return 40.0
            else:
                return 20.0
        else:
            if current_value >= benchmark_value * 1.5:
                return 95.0
            elif current_value >= benchmark_value * 1.25:
                return 80.0
            elif current_value >= benchmark_value:
                return 60.0
            elif current_value >= benchmark_value * 0.75:
                return 40.0
            else:
                return 20.0
    
    async def _calculate_percentiles(self, metrics: Dict, industry: str) -> Dict:
        """Calculate percentile rankings for all metrics."""
        # This would typically query a database of peer organizations
        # For now, return calculated percentiles based on benchmarks
        return {
            'vulnerability_density': self._calculate_percentile(
                metrics.get('vulnerability_density', 0),
                self.industry_benchmarks.get(industry, {}).get('vulnerability_density', 10),
                lower_is_better=True
            ),
            'remediation_time': self._calculate_percentile(
                metrics.get('mean_time_to_remediation', 0),
                self.industry_benchmarks.get(industry, {}).get('mean_time_to_remediation', 7),
                lower_is_better=True
            ),
            'patch_coverage': self._calculate_percentile(
                metrics.get('patch_coverage', 0),
                self.industry_benchmarks.get(industry, {}).get('patch_coverage', 90)
            )
        }
    
    def _assess_security_maturity(self, benchmark_metrics: List[BenchmarkMetric]) -> SecurityMaturityAssessment:
        """Assess security maturity level."""
        # Calculate category scores
        category_scores = {}
        for category in BenchmarkCategory:
            category_metrics = [m for m in benchmark_metrics if m.category == category]
            if category_metrics:
                avg_percentile = statistics.mean([m.percentile for m in category_metrics])
                category_scores[category] = self._percentile_to_maturity_level(avg_percentile)
        
        # Calculate overall maturity
        if category_scores:
            avg_maturity = statistics.mean([level.value for level in category_scores.values()])
            overall_level = MaturityLevel(round(avg_maturity))
        else:
            overall_level = MaturityLevel.DEVELOPING
        
        # Identify strengths and weaknesses
        strengths = []
        weaknesses = []
        
        for metric in benchmark_metrics:
            if metric.percentile >= 80:
                strengths.append(f"{metric.name} (Top 20%)")
            elif metric.percentile <= 30:
                weaknesses.append(f"{metric.name} (Bottom 30%)")
        
        # Generate recommendations
        recommendations = self._generate_maturity_recommendations(category_scores, weaknesses)
        
        # Calculate maturity score
        maturity_score = (overall_level.value / 5.0) * 100
        
        return SecurityMaturityAssessment(
            overall_level=overall_level,
            category_levels=category_scores,
            strengths=strengths,
            weaknesses=weaknesses,
            recommendations=recommendations,
            maturity_score=maturity_score
        )
    
    def _percentile_to_maturity_level(self, percentile: float) -> MaturityLevel:
        """Convert percentile to maturity level."""
        if percentile >= 90:
            return MaturityLevel.OPTIMIZING
        elif percentile >= 70:
            return MaturityLevel.MANAGED
        elif percentile >= 50:
            return MaturityLevel.DEFINED
        elif percentile >= 30:
            return MaturityLevel.DEVELOPING
        else:
            return MaturityLevel.INITIAL
    
    async def _generate_peer_comparison(self, industry: str, organization_size: str) -> Dict:
        """Generate peer comparison data."""
        # This would typically query anonymized data from peer organizations
        # For now, return simulated peer comparison
        return {
            'peer_group_size': 150,
            'your_ranking': 45,
            'percentile': 70,
            'top_performers': {
                'vulnerability_density': 3.2,
                'remediation_time': 2.1,
                'compliance_score': 98.5
            },
            'peer_average': {
                'vulnerability_density': 12.8,
                'remediation_time': 8.3,
                'compliance_score': 87.2
            }
        }
    
    def _generate_benchmark_recommendations(self, metrics: List[BenchmarkMetric], maturity: SecurityMaturityAssessment) -> List[str]:
        """Generate benchmark-based recommendations."""
        recommendations = []
        
        # Metric-specific recommendations
        for metric in metrics:
            if metric.percentile < 50:
                if metric.name == "Vulnerability Density":
                    recommendations.append(f"🎯 Reduce vulnerability density: currently {metric.current_value:.1f}, target {metric.best_practice:.1f}")
                elif metric.name == "Mean Time to Remediation":
                    recommendations.append(f"⚡ Improve remediation speed: currently {metric.current_value:.1f} days, target {metric.best_practice:.1f} days")
                elif metric.name == "Patch Coverage":
                    recommendations.append(f"🔧 Increase patch coverage: currently {metric.current_value:.1f}%, target {metric.best_practice:.1f}%")
        
        # Maturity-based recommendations
        if maturity.overall_level.value < 3:
            recommendations.append("📋 Establish formal security policies and procedures")
            recommendations.append("🎓 Implement security awareness training program")
        
        if maturity.overall_level.value < 4:
            recommendations.append("📊 Implement security metrics and KPI tracking")
            recommendations.append("🔄 Establish continuous improvement processes")
        
        return recommendations
    
    def _calculate_overall_benchmark_score(self, metrics: List[BenchmarkMetric]) -> float:
        """Calculate overall benchmark score."""
        if not metrics:
            return 50.0
        
        # Weight different categories
        category_weights = {
            BenchmarkCategory.VULNERABILITY_MANAGEMENT: 0.4,
            BenchmarkCategory.COMPLIANCE: 0.2,
            BenchmarkCategory.THREAT_DETECTION: 0.2,
            BenchmarkCategory.INCIDENT_RESPONSE: 0.1,
            BenchmarkCategory.ACCESS_CONTROL: 0.1
        }
        
        weighted_score = 0
        total_weight = 0
        
        for category, weight in category_weights.items():
            category_metrics = [m for m in metrics if m.category == category]
            if category_metrics:
                category_score = statistics.mean([m.percentile for m in category_metrics])
                weighted_score += category_score * weight
                total_weight += weight
        
        return weighted_score / total_weight if total_weight > 0 else 50.0
    
    def _determine_industry_ranking(self, score: float) -> str:
        """Determine industry ranking based on score."""
        if score >= 90:
            return "Top 10%"
        elif score >= 75:
            return "Top 25%"
        elif score >= 50:
            return "Above Average"
        elif score >= 25:
            return "Below Average"
        else:
            return "Bottom 25%"
    
    def _calculate_improvement_trends(self, data: List[Dict]) -> Dict:
        """Calculate improvement trends from historical data."""
        trends = {}
        
        for metric in ['overall_score', 'vulnerability_density', 'remediation_efficiency', 'compliance_level']:
            values = [point[metric] for point in data if metric in point]
            
            if len(values) >= 2:
                # Calculate linear trend
                x = list(range(len(values)))
                slope = np.polyfit(x, values, 1)[0]
                
                trends[metric] = {
                    'slope': slope,
                    'direction': 'improving' if slope > 0 else 'declining' if slope < 0 else 'stable',
                    'change_rate': abs(slope),
                    'start_value': values[0],
                    'end_value': values[-1],
                    'total_change': values[-1] - values[0]
                }
        
        return trends
    
    def _identify_significant_changes(self, data: List[Dict]) -> List[Dict]:
        """Identify significant changes in security posture."""
        changes = []
        
        for i in range(1, len(data)):
            current = data[i]
            previous = data[i-1]
            
            for metric in ['overall_score', 'vulnerability_density', 'remediation_efficiency']:
                if metric in current and metric in previous:
                    change_percent = abs((current[metric] - previous[metric]) / previous[metric]) * 100
                    
                    if change_percent > 20:  # Significant change threshold
                        changes.append({
                            'date': current['date'],
                            'metric': metric,
                            'change_percent': change_percent,
                            'direction': 'increase' if current[metric] > previous[metric] else 'decrease',
                            'previous_value': previous[metric],
                            'current_value': current[metric]
                        })
        
        return changes
    
    def _generate_improvement_insights(self, trends: Dict, changes: List[Dict]) -> List[str]:
        """Generate insights from improvement tracking."""
        insights = []
        
        # Trend insights
        for metric, trend_data in trends.items():
            if trend_data['direction'] == 'improving':
                insights.append(f"📈 {metric.replace('_', ' ').title()} is improving at {trend_data['change_rate']:.2f} per month")
            elif trend_data['direction'] == 'declining':
                insights.append(f"📉 {metric.replace('_', ' ').title()} is declining at {trend_data['change_rate']:.2f} per month")
        
        # Significant change insights
        if changes:
            recent_changes = sorted(changes, key=lambda x: x['date'], reverse=True)[:3]
            for change in recent_changes:
                insights.append(f"⚡ Significant {change['direction']} in {change['metric'].replace('_', ' ')} ({change['change_percent']:.1f}%)")
        
        return insights
    
    def _calculate_improvement_score(self, trends: Dict) -> float:
        """Calculate overall improvement score."""
        if not trends:
            return 50.0
        
        improvement_scores = []
        
        for metric, trend_data in trends.items():
            if trend_data['direction'] == 'improving':
                improvement_scores.append(75 + min(25, trend_data['change_rate'] * 10))
            elif trend_data['direction'] == 'declining':
                improvement_scores.append(25 - min(25, trend_data['change_rate'] * 10))
            else:
                improvement_scores.append(50)
        
        return statistics.mean(improvement_scores)
    
    async def _calculate_executive_metrics(self) -> Dict:
        """Calculate key metrics for executive dashboard."""
        try:
            db = get_db()
            
            # Time ranges
            now = datetime.utcnow()
            last_30_days = now - timedelta(days=30)
            last_quarter = now - timedelta(days=90)
            
            # Key metrics
            total_assets = 100  # This would come from asset inventory
            critical_vulns = db.vulnerabilities.count_documents({'severity': 'critical'})
            high_vulns = db.vulnerabilities.count_documents({'severity': 'high'})
            
            # Recent incidents (simulated)
            security_incidents = 2
            
            # Compliance score (calculated)
            compliance_scans = db.scans.count_documents({'scan_type': 'compliance'})
            compliance_score = 85.5  # This would be calculated from compliance scan results
            
            return {
                'total_assets': total_assets,
                'critical_vulnerabilities': critical_vulns,
                'high_vulnerabilities': high_vulns,
                'security_incidents_30d': security_incidents,
                'compliance_score': compliance_score,
                'mean_time_to_detection': 4.2,  # hours
                'mean_time_to_response': 2.1,   # hours
                'security_training_completion': 94.5  # percentage
            }
            
        except Exception as e:
            logger.error(f"Error calculating executive metrics: {str(e)}")
            return {}
    
    async def _generate_risk_summary(self) -> Dict:
        """Generate risk summary for executive dashboard."""
        try:
            db = get_db()
            
            # Calculate risk levels
            critical_risks = db.vulnerabilities.count_documents({'severity': 'critical'})
            high_risks = db.vulnerabilities.count_documents({'severity': 'high'})
            medium_risks = db.vulnerabilities.count_documents({'severity': 'medium'})
            
            # Determine overall risk level
            if critical_risks > 0:
                overall_risk_level = 'critical'
            elif high_risks > 5:
                overall_risk_level = 'high'
            elif high_risks > 0 or medium_risks > 10:
                overall_risk_level = 'medium'
            else:
                overall_risk_level = 'low'
            
            return {
                'overall_risk_level': overall_risk_level,
                'critical_risks': critical_risks,
                'high_risks': high_risks,
                'medium_risks': medium_risks,
                'risk_trend': 'stable',  # This would be calculated from historical data
                'top_risk_categories': [
                    'Web Application Vulnerabilities',
                    'Network Security',
                    'Access Control'
                ]
            }
            
        except Exception as e:
            logger.error(f"Error generating risk summary: {str(e)}")
            return {'overall_risk_level': 'medium'}
    
    def _calculate_security_roi(self) -> Dict:
        """Calculate security return on investment."""
        # This would integrate with financial data
        # For now, return simulated ROI data
        return {
            'annual_security_investment': 250000,
            'estimated_risk_reduction': 1500000,
            'roi_percentage': 600,
            'payback_period_months': 8,
            'cost_per_vulnerability_prevented': 125
        }
    
    def _generate_strategic_recommendations(self, posture: SecurityPosture, comparison: Dict, risk_summary: Dict) -> List[str]:
        """Generate strategic recommendations for executives."""
        recommendations = []
        
        # Risk-based recommendations
        if risk_summary.get('overall_risk_level') in ['critical', 'high']:
            recommendations.append("🚨 Immediate investment in vulnerability remediation required")
        
        # Performance-based recommendations
        if posture.overall_score < 70:
            recommendations.append("📊 Consider increasing security budget and resources")
        
        # Industry comparison recommendations
        ranking = comparison.get('overall_ranking', 'average')
        if ranking in ['below_average', 'needs_improvement']:
            recommendations.append("🎯 Benchmark against industry leaders and implement best practices")
        
        # General strategic recommendations
        recommendations.extend([
            "🔄 Implement continuous security monitoring and improvement",
            "🎓 Invest in security awareness training for all employees",
            "🤝 Consider engaging external security experts for assessment",
            "📋 Develop comprehensive incident response and business continuity plans"
        ])
        
        return recommendations
    
    def _calculate_industry_percentile(self, score: float, industry: str) -> float:
        """Calculate industry percentile ranking."""
        # This would typically use real industry data
        # For now, return calculated percentile based on score
        if score >= 90:
            return 95
        elif score >= 80:
            return 80
        elif score >= 70:
            return 65
        elif score >= 60:
            return 50
        elif score >= 50:
            return 35
        else:
            return 20
    
    def _generate_maturity_recommendations(self, category_scores: Dict, weaknesses: List[str]) -> List[str]:
        """Generate maturity-based recommendations."""
        recommendations = []
        
        # Category-specific recommendations
        for category, level in category_scores.items():
            if level.value < 3:
                if category == BenchmarkCategory.VULNERABILITY_MANAGEMENT:
                    recommendations.append("🔧 Establish formal vulnerability management program")
                elif category == BenchmarkCategory.INCIDENT_RESPONSE:
                    recommendations.append("🚨 Develop comprehensive incident response procedures")
                elif category == BenchmarkCategory.COMPLIANCE:
                    recommendations.append("📋 Implement compliance monitoring and reporting")
        
        # Weakness-specific recommendations
        if weaknesses:
            recommendations.append(f"⚠️ Focus improvement efforts on: {', '.join(weaknesses[:3])}")
        
        return recommendations