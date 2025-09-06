"""
Factory for creating scanner instances.
"""
from scanners.web_app_scanner import WebAppScanner
from scanners.api_security_scanner import APISecurityScanner
from scanners.mobile_app_scanner import MobileAppScanner
from scanners.cloud_security_scanner import CloudSecurityScanner
from scanners.social_engineering_scanner import SocialEngineeringScanner

class ScannerFactory:
    """Factory class for creating scanner instances."""
    
    @staticmethod
    def get_scanner(scan_type):
        """
        Get the appropriate scanner based on scan type.
        
        Args:
            scan_type: Type of scan to perform (web_app, api_security, mobile_app, cloud_security)
            
        Returns:
            Scanner instance
            
        Raises:
            ValueError: If scan type is not supported
        """
        scan_type = scan_type.lower()
        
        if scan_type == "web_app":
            return WebAppScanner()
        elif scan_type == "api_security":
            return APISecurityScanner()
        elif scan_type == "mobile_app":
            return MobileAppScanner()
        elif scan_type == "cloud_security":
            return CloudSecurityScanner()
        elif scan_type == "social_engineering":
            return SocialEngineeringScanner()
        else:
            raise ValueError(f"Unsupported scan type: {scan_type}")