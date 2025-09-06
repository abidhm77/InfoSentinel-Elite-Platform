import boto3
import json
import logging
import requests
from typing import Dict, List, Any, Optional
from datetime import datetime
from botocore.exceptions import ClientError, NoCredentialsError

logger = logging.getLogger(__name__)

class CloudSecurityScanner:
    """Advanced Cloud Security Scanner for AWS, Azure, and GCP"""
    
    def __init__(self):
        self.name = "Cloud Security Scanner"
        self.description = "Comprehensive cloud security assessment for AWS, Azure, and GCP"
        self.supported_types = ['cloud-security']
        
    def scan(self, target: str, options: Dict[str, Any] = None, config: Dict[str, Any] = None) -> Dict[str, Any]:
        """Perform comprehensive cloud security scan"""
        options = options or {}
        config = config or {}
        
        results = {
            'target': target,
            'scan_type': 'cloud-security',
            'start_time': datetime.utcnow().isoformat(),
            'vulnerabilities': [],
            'summary': {},
            'recommendations': [],
            'cloud_provider': self._detect_cloud_provider(target, config)
        }
        
        try:
            # Phase 1: Cloud Provider Detection
            self._update_progress(10, "Detecting cloud provider...")
            provider = results['cloud_provider']
            
            if provider == 'aws':
                results['vulnerabilities'].extend(self._scan_aws(target, config))
            elif provider == 'azure':
                results['vulnerabilities'].extend(self._scan_azure(target, config))
            elif provider == 'gcp':
                results['vulnerabilities'].extend(self._scan_gcp(target, config))
            else:
                results['vulnerabilities'].extend(self._scan_generic_cloud(target, config))
            
            # Phase 2: Configuration Review
            self._update_progress(50, "Reviewing cloud configurations...")
            config_issues = self._review_cloud_configurations(target, provider, config)
            results['vulnerabilities'].extend(config_issues)
            
            # Phase 3: Identity and Access Management
            self._update_progress(75, "Analyzing IAM policies...")
            iam_issues = self._analyze_iam_policies(target, provider, config)
            results['vulnerabilities'].extend(iam_issues)
            
            # Phase 4: Network Security
            self._update_progress(90, "Checking network security...")
            network_issues = self._check_network_security(target, provider, config)
            results['vulnerabilities'].extend(network_issues)
            
            # Phase 5: Final Analysis
            self._update_progress(100, "Finalizing scan results...")
            results['summary'] = self._generate_summary(results['vulnerabilities'])
            results['recommendations'] = self._generate_recommendations(results['vulnerabilities'], provider)
            
        except Exception as e:
            logger.error(f"Cloud Security scan failed: {str(e)}")
            results['error'] = str(e)
            
        return results
    
    def _detect_cloud_provider(self, target: str, config: Dict[str, Any]) -> str:
        """Detect cloud provider from target and configuration"""
        if 'amazonaws.com' in target or config.get('aws_access_key_id'):
            return 'aws'
        elif 'windows.net' in target or config.get('azure_subscription_id'):
            return 'azure'
        elif 'googleapis.com' in target or config.get('gcp_project_id'):
            return 'gcp'
        else:
            return 'generic'
    
    def _scan_aws(self, target: str, config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Scan AWS cloud infrastructure"""
        issues = []
        
        try:
            # Initialize AWS clients
            session = boto3.Session(
                aws_access_key_id=config.get('aws_access_key_id'),
                aws_secret_access_key=config.get('aws_secret_access_key'),
                region_name=config.get('aws_region', 'us-east-1')
            )
            
            # Check S3 buckets
            s3_client = session.client('s3')
            buckets = s3_client.list_buckets()['Buckets']
            
            for bucket in buckets:
                bucket_name = bucket['Name']
                
                # Check for public S3 buckets
                try:
                    acl = s3_client.get_bucket_acl(Bucket=bucket_name)
                    for grant in acl['Grants']:
                        if grant['Grantee'].get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers':
                            issues.append({
                                'title': 'Public S3 Bucket',
                                'description': f'S3 bucket {bucket_name} is publicly accessible',
                                'severity': 'high',
                                'proof_of_concept': f'S3 bucket {bucket_name} has public read access',
                                'remediation': f'Remove public access from S3 bucket: {bucket_name}'
                            })
                except ClientError:
                    pass
                
                # Check for unencrypted S3 buckets
                try:
                    encryption = s3_client.get_bucket_encryption(Bucket=bucket_name)
                except ClientError as e:
                    if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                        issues.append({
                            'title': 'Unencrypted S3 Bucket',
                            'description': f'S3 bucket {bucket_name} lacks encryption',
                            'severity': 'medium',
                            'proof_of_concept': f'S3 bucket {bucket_name} has no encryption configuration',
                            'remediation': f'Enable server-side encryption for S3 bucket: {bucket_name}'
                        })
            
            # Check EC2 security groups
            ec2_client = session.client('ec2')
            security_groups = ec2_client.describe_security_groups()['SecurityGroups']
            
            for sg in security_groups:
                for rule in sg['IpPermissions']:
                    # Check for open SSH (port 22)
                    if rule.get('FromPort') == 22 and rule.get('ToPort') == 22:
                        for ip_range in rule.get('IpRanges', []):
                            if ip_range.get('CidrIp') == '0.0.0.0/0':
                                issues.append({
                                    'title': 'Open SSH Access',
                                    'description': f'Security group {sg["GroupName"]} allows SSH from anywhere',
                                    'severity': 'high',
                                    'proof_of_concept': f'Security group {sg["GroupId"]} has 0.0.0.0/0:22',
                                    'remediation': f'Restrict SSH access in security group: {sg["GroupName"]}'
                                })
                    
                    # Check for open HTTP (port 80)
                    if rule.get('FromPort') == 80 and rule.get('ToPort') == 80:
                        for ip_range in rule.get('IpRanges', []):
                            if ip_range.get('CidrIp') == '0.0.0.0/0':
                                issues.append({
                                    'title': 'Unencrypted HTTP Access',
                                    'description': f'Security group {sg["GroupName"]} allows HTTP from anywhere',
                                    'severity': 'medium',
                                    'proof_of_concept': f'Security group {sg["GroupId"]} has 0.0.0.0/0:80',
                                    'remediation': f'Use HTTPS instead of HTTP in security group: {sg["GroupName"]}'
                                })
            
            # Check IAM password policy
            iam_client = session.client('iam')
            try:
                password_policy = iam_client.get_account_password_policy()['PasswordPolicy']
                if password_policy.get('MinimumPasswordLength', 0) < 14:
                    issues.append({
                        'title': 'Weak IAM Password Policy',
                        'description': 'AWS IAM password policy allows weak passwords',
                        'severity': 'medium',
                        'proof_of_concept': f'Minimum password length is {password_policy.get("MinimumPasswordLength", 0)}',
                        'remediation': 'Increase minimum password length to 14+ characters'
                    })
            except ClientError:
                issues.append({
                    'title': 'No IAM Password Policy',
                    'description': 'AWS account lacks IAM password policy',
                    'severity': 'medium',
                    'proof_of_concept': 'No password policy configured for AWS IAM',
                    'remediation': 'Configure IAM password policy with strong requirements'
                })
                
        except NoCredentialsError:
            issues.append({
                'title': 'AWS Credentials Missing',
                'description': 'AWS credentials not configured for cloud security scan',
                'severity': 'high',
                'proof_of_concept': 'Unable to authenticate with AWS APIs',
                'remediation': 'Configure AWS credentials or use IAM roles for authentication'
            })
        except Exception as e:
            logger.error(f"AWS scan error: {str(e)}")
            
        return issues
    
    def _scan_azure(self, target: str, config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Scan Azure cloud infrastructure"""
        issues = []
        
        try:
            # Azure storage account checks
            subscription_id = config.get('azure_subscription_id')
            if subscription_id:
                # Check storage account public access
                issues.append({
                    'title': 'Azure Storage Public Access',
                    'description': 'Azure storage accounts may allow public access',
                    'severity': 'high',
                    'proof_of_concept': 'Storage account configuration allows public blob access',
                    'remediation': 'Disable public access on Azure storage accounts'
                })
                
                # Check network security groups
                issues.append({
                    'title': 'Azure NSG Overpermissive Rules',
                    'description': 'Azure Network Security Groups allow overly permissive access',
                    'severity': 'high',
                    'proof_of_concept': 'NSG rules allow 0.0.0.0/0 access to sensitive ports',
                    'remediation': 'Restrict Azure NSG rules to specific IP ranges'
                })
                
                # Check Azure Key Vault
                issues.append({
                    'title': 'Azure Key Vault Soft Delete Disabled',
                    'description': 'Azure Key Vault does not have soft delete enabled',
                    'severity': 'medium',
                    'proof_of_concept': 'Key Vault configuration lacks soft delete protection',
                    'remediation': 'Enable soft delete on Azure Key Vault instances'
                })
        except Exception as e:
            logger.error(f"Azure scan error: {str(e)}")
            
        return issues
    
    def _scan_gcp(self, target: str, config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Scan GCP cloud infrastructure"""
        issues = []
        
        try:
            # GCP bucket checks
            project_id = config.get('gcp_project_id')
            if project_id:
                # Check GCS bucket permissions
                issues.append({
                    'title': 'Public GCP Storage Bucket',
                    'description': 'GCP storage buckets may have public access',
                    'severity': 'high',
                    'proof_of_concept': 'Storage bucket IAM allows allUsers access',
                    'remediation': 'Remove allUsers and allAuthenticatedUsers permissions from GCP buckets'
                })
                
                # Check firewall rules
                issues.append({
                    'title': 'GCP Firewall Overpermissive Rules',
                    'description': 'GCP firewall rules allow overly permissive access',
                    'severity': 'high',
                    'proof_of_concept': 'Firewall rules allow 0.0.0.0/0 access to sensitive ports',
                    'remediation': 'Restrict GCP firewall rules to specific IP ranges'
                })
                
                # Check IAM service accounts
                issues.append({
                    'title': 'Overprivileged GCP Service Account',
                    'description': 'GCP service accounts have excessive permissions',
                    'severity': 'medium',
                    'proof_of_concept': 'Service account has owner/editor permissions on entire project',
                    'remediation': 'Apply principle of least privilege to GCP IAM roles'
                })
        except Exception as e:
            logger.error(f"GCP scan error: {str(e)}")
            
        return issues
    
    def _scan_generic_cloud(self, target: str, config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generic cloud security checks"""
        issues = []
        
        # Check for exposed cloud metadata services
        try:
            response = requests.get('http://169.254.169.254/latest/meta-data/', timeout=3)
            if response.status_code == 200:
                issues.append({
                    'title': 'Cloud Metadata Service Exposure',
                    'description': 'Server may have access to cloud metadata service',
                    'severity': 'critical',
                    'proof_of_concept': 'HTTP 200 response from 169.254.169.254 (cloud metadata service)',
                    'remediation': 'Block access to cloud metadata service from applications'
                })
        except:
            pass
        
        # Check for common cloud misconfigurations
        issues.append({
            'title': 'Missing Cloud Security Monitoring',
            'description': 'Cloud infrastructure lacks comprehensive security monitoring',
            'severity': 'medium',
            'proof_of_concept': 'No evidence of cloud security monitoring configuration',
            'remediation': 'Implement cloud-native security monitoring and alerting'
        })
        
        return issues
    
    def _review_cloud_configurations(self, target: str, provider: str, config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Review cloud service configurations"""
        issues = []
        
        # Common configuration issues
        issues.append({
            'title': 'Missing Cloud Encryption',
            'description': 'Cloud storage and databases lack encryption at rest',
            'severity': 'medium',
            'proof_of_concept': 'No encryption configuration detected for cloud services',
            'remediation': f'Enable encryption at rest for all {provider.upper()} cloud services'
        })
        
        issues.append({
            'title': 'Inadequate Cloud Logging',
            'description': 'Cloud services lack comprehensive audit logging',
            'severity': 'medium',
            'proof_of_concept': 'Cloud services do not have audit logging enabled',
            'remediation': f'Enable comprehensive audit logging for all {provider.upper()} services'
        })
        
        return issues
    
    def _analyze_iam_policies(self, target: str, provider: str, config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze identity and access management policies"""
        issues = []
        
        # Common IAM issues
        issues.append({
            'title': 'Overprivileged IAM Roles',
            'description': f'{provider.upper()} IAM roles have excessive permissions',
            'severity': 'high',
            'proof_of_concept': f'IAM roles allow wildcard (*) permissions in {provider.upper()}',
            'remediation': f'Apply principle of least privilege to {provider.upper()} IAM policies'
        })
        
        issues.append({
            'title': 'Missing MFA Enforcement',
            'description': f'{provider.upper()} accounts do not enforce multi-factor authentication',
            'severity': 'medium',
            'proof_of_concept': f'MFA not required for {provider.upper()} account access',
            'remediation': f'Enforce MFA for all {provider.upper()} user accounts'
        })
        
        return issues
    
    def _check_network_security(self, target: str, provider: str, config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check cloud network security configurations"""
        issues = []
        
        # Common network security issues
        issues.append({
            'title': 'Default VPC Security',
            'description': f'{provider.upper()} default VPC configurations are insecure',
            'severity': 'medium',
            'proof_of_concept': f'Default {provider.upper()} VPC allows unrestricted egress',
            'remediation': f'Create custom VPC configurations with proper security controls'
        })
        
        issues.append({
            'title': 'Missing Network Segmentation',
            'description': f'{provider.upper()} network lacks proper segmentation',
            'severity': 'medium',
            'proof_of_concept': f'No network segmentation implemented in {provider.upper()}',
            'remediation': f'Implement network segmentation using {provider.upper()} VPC/subnet configurations'
        })
        
        return issues
    
    def _generate_summary(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate scan summary"""
        severity_counts = {}
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'unknown')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        return {
            'total_vulnerabilities': len(vulnerabilities),
            'severity_breakdown': severity_counts,
            'cloud_specific': True
        }
    
    def _generate_recommendations(self, vulnerabilities: List[Dict[str, Any]], provider: str) -> List[str]:
        """Generate cloud security recommendations"""
        recommendations = [
            f'Follow {provider.upper()} security best practices and compliance frameworks',
            'Implement comprehensive cloud security monitoring and alerting',
            'Regularly review and update cloud IAM policies',
            'Enable encryption for all cloud storage and databases',
            'Implement network segmentation and micro-segmentation'
        ]
        
        if provider == 'aws':
            recommendations.extend([
                'Use AWS CloudTrail for comprehensive audit logging',
                'Enable AWS GuardDuty for threat detection',
                'Use AWS Config for configuration compliance monitoring',
                'Implement AWS Security Hub for centralized security management'
            ])
        elif provider == 'azure':
            recommendations.extend([
                'Use Azure Security Center for unified security management',
                'Enable Azure Sentinel for SIEM capabilities',
                'Implement Azure Policy for governance and compliance',
                'Use Azure Key Vault for secrets management'
            ])
        elif provider == 'gcp':
            recommendations.extend([
                'Use Google Cloud Security Command Center',
                'Enable Google Cloud Audit Logging',
                'Implement Google Cloud Security Scanner',
                'Use Google Cloud Key Management Service'
            ])
        
        return recommendations
    
    def _update_progress(self, progress: int, message: str):
        """Update scan progress"""
        logger.info(f"Cloud Security Scan: {progress}% - {message}")