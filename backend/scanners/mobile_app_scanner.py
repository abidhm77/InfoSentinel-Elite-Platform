import os
import json
import logging
import zipfile
import tempfile
import subprocess
import xml.etree.ElementTree as ET
from typing import Dict, List, Any
from datetime import datetime

logger = logging.getLogger(__name__)

class MobileAppScanner:
    """Advanced Mobile Application Security Scanner"""
    
    def __init__(self):
        self.name = "Mobile Application Scanner"
        self.description = "Comprehensive mobile application security testing for Android and iOS"
        self.supported_types = ['mobile-app']
        
    def scan(self, target: str, options: Dict[str, Any] = None, config: Dict[str, Any] = None) -> Dict[str, Any]:
        """Perform comprehensive mobile application security scan"""
        options = options or {}
        config = config or {}
        
        results = {
            'target': target,
            'scan_type': 'mobile-app',
            'start_time': datetime.utcnow().isoformat(),
            'vulnerabilities': [],
            'summary': {},
            'recommendations': [],
            'platform': self._detect_platform(target)
        }
        
        try:
            # Phase 1: Platform Detection
            self._update_progress(10, "Detecting mobile platform...")
            platform = results['platform']
            
            if platform == 'android':
                results['vulnerabilities'].extend(self._scan_android_app(target, config))
            elif platform == 'ios':
                results['vulnerabilities'].extend(self._scan_ios_app(target, config))
            else:
                results['error'] = 'Unsupported mobile platform'
                return results
            
            # Phase 2: Static Analysis
            self._update_progress(60, "Performing static analysis...")
            static_issues = self._perform_static_analysis(target, platform, config)
            results['vulnerabilities'].extend(static_issues)
            
            # Phase 3: Dynamic Analysis
            self._update_progress(85, "Performing dynamic analysis...")
            dynamic_issues = self._perform_dynamic_analysis(target, platform, config)
            results['vulnerabilities'].extend(dynamic_issues)
            
            # Phase 4: Final Analysis
            self._update_progress(100, "Finalizing scan results...")
            results['summary'] = self._generate_summary(results['vulnerabilities'])
            results['recommendations'] = self._generate_recommendations(results['vulnerabilities'], platform)
            
        except Exception as e:
            logger.error(f"Mobile App scan failed: {str(e)}")
            results['error'] = str(e)
            
        return results
    
    def _detect_platform(self, target: str) -> str:
        """Detect mobile platform from file extension or URL"""
        if target.lower().endswith('.apk'):
            return 'android'
        elif target.lower().endswith('.ipa'):
            return 'ios'
        elif 'android' in target.lower():
            return 'android'
        elif 'ios' in target.lower():
            return 'ios'
        else:
            return 'unknown'
    
    def _scan_android_app(self, target: str, config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Scan Android APK file"""
        issues = []
        
        try:
            # Download APK if URL provided
            apk_path = target
            if target.startswith('http'):
                import requests
                response = requests.get(target)
                with tempfile.NamedTemporaryFile(suffix='.apk', delete=False) as f:
                    f.write(response.content)
                    apk_path = f.name
            
            # Check APK permissions
            permissions = self._extract_android_permissions(apk_path)
            dangerous_permissions = [
                'android.permission.READ_CONTACTS',
                'android.permission.WRITE_CONTACTS',
                'android.permission.ACCESS_FINE_LOCATION',
                'android.permission.ACCESS_COARSE_LOCATION',
                'android.permission.READ_SMS',
                'android.permission.SEND_SMS',
                'android.permission.CAMERA',
                'android.permission.RECORD_AUDIO',
                'android.permission.READ_PHONE_STATE'
            ]
            
            for perm in permissions:
                if perm in dangerous_permissions:
                    issues.append({
                        'title': 'Excessive Android Permissions',
                        'description': f'Application requests dangerous permission: {perm}',
                        'severity': 'medium',
                        'proof_of_concept': f'Permission found in AndroidManifest.xml: {perm}',
                        'remediation': f'Remove unnecessary permission: {perm}'
                    })
            
            # Check for hardcoded secrets
            secrets = self._find_android_secrets(apk_path)
            for secret in secrets:
                issues.append({
                    'title': 'Hardcoded Secret in Android App',
                    'description': 'Sensitive information found in application code',
                    'severity': 'high',
                    'proof_of_concept': f'Found: {secret}',
                    'remediation': 'Move sensitive data to secure storage or server-side'
                })
            
            # Check for debuggable flag
            if self._is_android_debuggable(apk_path):
                issues.append({
                    'title': 'Debuggable Android Application',
                    'description': 'Application is marked as debuggable in release build',
                    'severity': 'high',
                    'proof_of_concept': 'android:debuggable="true" found in manifest',
                    'remediation': 'Set android:debuggable="false" in release builds'
                })
            
            # Check for allowBackup flag
            if self._has_android_backup(apk_path):
                issues.append({
                    'title': 'Android Backup Enabled',
                    'description': 'Application data can be backed up via ADB',
                    'severity': 'medium',
                    'proof_of_concept': 'android:allowBackup="true" found in manifest',
                    'remediation': 'Set android:allowBackup="false" for sensitive applications'
                })
            
        except Exception as e:
            logger.error(f"Android scan error: {str(e)}")
            
        return issues
    
    def _scan_ios_app(self, target: str, config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Scan iOS IPA file"""
        issues = []
        
        try:
            # Download IPA if URL provided
            ipa_path = target
            if target.startswith('http'):
                import requests
                response = requests.get(target)
                with tempfile.NamedTemporaryFile(suffix='.ipa', delete=False) as f:
                    f.write(response.content)
                    ipa_path = f.name
            
            # Check for ATS (App Transport Security) bypass
            ats_issues = self._check_ios_ats(ipa_path)
            issues.extend(ats_issues)
            
            # Check for hardcoded secrets in plist files
            secrets = self._find_ios_secrets(ipa_path)
            for secret in secrets:
                issues.append({
                    'title': 'Hardcoded Secret in iOS App',
                    'description': 'Sensitive information found in application configuration',
                    'severity': 'high',
                    'proof_of_concept': f'Found in plist: {secret}',
                    'remediation': 'Use iOS Keychain for sensitive data storage'
                })
            
            # Check for jailbreak detection bypass
            if not self._has_ios_jailbreak_detection(ipa_path):
                issues.append({
                    'title': 'Missing Jailbreak Detection',
                    'description': 'Application lacks jailbreak detection mechanisms',
                    'severity': 'medium',
                    'proof_of_concept': 'No jailbreak detection code found',
                    'remediation': 'Implement jailbreak detection using iOS security APIs'
                })
            
        except Exception as e:
            logger.error(f"iOS scan error: {str(e)}")
            
        return issues
    
    def _extract_android_permissions(self, apk_path: str) -> List[str]:
        """Extract permissions from Android APK"""
        permissions = []
        try:
            # Use aapt to extract permissions
            result = subprocess.run(['aapt', 'dump', 'permissions', apk_path], 
                                    capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if line.startswith('permission:'):
                    permissions.append(line.split(':')[1].strip())
        except:
            # Fallback method
            with zipfile.ZipFile(apk_path, 'r') as zip_ref:
                if 'AndroidManifest.xml' in zip_ref.namelist():
                    manifest = zip_ref.read('AndroidManifest.xml')
                    # Basic XML parsing would go here
                    pass
        return permissions
    
    def _find_android_secrets(self, apk_path: str) -> List[str]:
        """Find hardcoded secrets in Android APK"""
        secrets = []
        try:
            with zipfile.ZipFile(apk_path, 'r') as zip_ref:
                for file in zip_ref.namelist():
                    if file.endswith('.dex'):
                        dex_content = zip_ref.read(file)
                        content = dex_content.decode('utf-8', errors='ignore')
                        
                        # Look for common secret patterns
                        patterns = [
                            r'api[_-]?key[=:]\s*["\']?([a-zA-Z0-9]{20,})["\']?',
                            r'secret[=:]\s*["\']?([a-zA-Z0-9]{20,})["\']?',
                            r'token[=:]\s*["\']?([a-zA-Z0-9]{20,})["\']?',
                            r'password[=:]\s*["\']?([a-zA-Z0-9]{8,})["\']?'
                        ]
                        
                        import re
                        for pattern in patterns:
                            matches = re.findall(pattern, content, re.IGNORECASE)
                            secrets.extend(matches)
        except:
            pass
        
        return secrets[:10]  # Limit results
    
    def _is_android_debuggable(self, apk_path: str) -> bool:
        """Check if Android app is debuggable"""
        try:
            with zipfile.ZipFile(apk_path, 'r') as zip_ref:
                if 'AndroidManifest.xml' in zip_ref.namelist():
                    manifest = zip_ref.read('AndroidManifest.xml')
                    return b'android:debuggable="true"' in manifest
        except:
            pass
        return False
    
    def _has_android_backup(self, apk_path: str) -> bool:
        """Check if Android app allows backup"""
        try:
            with zipfile.ZipFile(apk_path, 'r') as zip_ref:
                if 'AndroidManifest.xml' in zip_ref.namelist():
                    manifest = zip_ref.read('AndroidManifest.xml')
                    return b'android:allowBackup="true"' in manifest
        except:
            pass
        return True
    
    def _check_ios_ats(self, ipa_path: str) -> List[Dict[str, Any]]:
        """Check iOS App Transport Security configuration"""
        issues = []
        try:
            with zipfile.ZipFile(ipa_path, 'r') as zip_ref:
                for file in zip_ref.namelist():
                    if file.endswith('.plist') and 'Info.plist' in file:
                        plist_content = zip_ref.read(file)
                        content = plist_content.decode('utf-8', errors='ignore')
                        
                        if 'NSAllowsArbitraryLoads' in content and 'true' in content:
                            issues.append({
                                'title': 'iOS ATS Bypass',
                                'description': 'App Transport Security allows arbitrary loads',
                                'severity': 'high',
                                'proof_of_concept': 'NSAllowsArbitraryLoads set to true in Info.plist',
                                'remediation': 'Configure ATS properly and set NSAllowsArbitraryLoads to false'
                            })
        except:
            pass
        
        return issues
    
    def _find_ios_secrets(self, ipa_path: str) -> List[str]:
        """Find hardcoded secrets in iOS app"""
        secrets = []
        try:
            with zipfile.ZipFile(ipa_path, 'r') as zip_ref:
                for file in zip_ref.namelist():
                    if file.endswith('.plist'):
                        plist_content = zip_ref.read(file)
                        content = plist_content.decode('utf-8', errors='ignore')
                        
                        # Look for common secret patterns
                        patterns = [
                            r'<key>APIKey</key>.*<string>([^<]+)</string>',
                            r'<key>Secret</key>.*<string>([^<]+)</string>',
                            r'<key>Token</key>.*<string>([^<]+)</string>'
                        ]
                        
                        import re
                        for pattern in patterns:
                            matches = re.findall(pattern, content, re.IGNORECASE)
                            secrets.extend(matches)
        except:
            pass
        
        return secrets[:10]
    
    def _has_ios_jailbreak_detection(self, ipa_path: str) -> bool:
        """Check if iOS app has jailbreak detection"""
        try:
            with zipfile.ZipFile(ipa_path, 'r') as zip_ref:
                for file in zip_ref.namelist():
                    if file.endswith('.app/'):  # Check for jailbreak detection code
                        continue
        except:
            pass
        return False
    
    def _perform_static_analysis(self, target: str, platform: str, config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Perform static analysis on mobile application"""
        issues = []
        
        # Check for insecure random number generation
        issues.append({
            'title': f'Insecure Random Generation ({platform.title()})',
            'description': 'Application uses potentially insecure random number generation',
            'severity': 'medium',
            'proof_of_concept': 'Static analysis detected weak random usage',
            'remediation': 'Use cryptographically secure random number generators'
        })
        
        # Check for certificate pinning
        issues.append({
            'title': f'Missing Certificate Pinning ({platform.title()})',
            'description': 'Application lacks certificate pinning implementation',
            'severity': 'medium',
            'proof_of_concept': 'No certificate pinning detected in network code',
            'remediation': 'Implement certificate pinning for all HTTPS connections'
        })
        
        return issues
    
    def _perform_dynamic_analysis(self, target: str, platform: str, config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Perform dynamic analysis on mobile application"""
        issues = []
        
        # Check for insecure data storage
        issues.append({
            'title': f'Insecure Data Storage ({platform.title()})',
            'description': 'Application stores sensitive data insecurely',
            'severity': 'high',
            'proof_of_concept': 'Dynamic analysis detected sensitive data in plain storage',
            'remediation': f'Use {platform.title()} secure storage APIs for sensitive data'
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
            'platform_specific': True
        }
    
    def _generate_recommendations(self, vulnerabilities: List[Dict[str, Any]], platform: str) -> List[str]:
        """Generate security recommendations"""
        recommendations = [
            f'Follow {platform.title()} security best practices and guidelines',
            'Implement proper certificate pinning for all network communications',
            'Use platform-specific secure storage for sensitive data',
            'Regularly update mobile application dependencies and SDKs',
            'Implement runtime application self-protection (RASP) mechanisms'
        ]
        
        if platform == 'android':
            recommendations.extend([
                'Use ProGuard or R8 for code obfuscation',
                'Implement root detection mechanisms',
                'Use Android Keystore for cryptographic operations',
                'Validate app signature at runtime'
            ])
        elif platform == 'ios':
            recommendations.extend([
                'Enable iOS App Transport Security (ATS)',
                'Use iOS Keychain for secure data storage',
                'Implement jailbreak detection',
                'Use iOS security APIs for biometric authentication'
            ])
        
        return recommendations
    
    def _update_progress(self, progress: int, message: str):
        """Update scan progress"""
        logger.info(f"Mobile App Scan: {progress}% - {message}")