#!/usr/bin/env python3
"""
Celery tasks for background scan processing.
"""
from celery import current_app
from services.celery_service import celery_app
from scanners.scanner_factory import ScannerFactory
from scanners.network_scanner import NetworkScanner
from scanners.web_app_scanner import WebAppScanner
from database.db import get_db
from datetime import datetime
import logging
import json

logger = logging.getLogger(__name__)

@celery_app.task(bind=True)
def execute_scan(self, scan_id, scan_type, target, options=None):
    """
    Execute a security scan in the background.
    
    Args:
        scan_id: Unique identifier for the scan
        scan_type: Type of scan to perform
        target: Target to scan
        options: Scan configuration options
        
    Returns:
        dict: Scan results
    """
    try:
        logger.info(f"Starting background scan {scan_id} of type {scan_type} for target {target}")
        
        # Update scan status to running
        db = get_db()
        db.scans.update_one(
            {"_id": scan_id},
            {
                "$set": {
                    "status": "running",
                    "start_time": datetime.utcnow(),
                    "celery_task_id": self.request.id
                }
            }
        )
        
        # Get appropriate scanner
        if scan_type == 'network':
            scanner = NetworkScanner()
        elif scan_type == 'web_app':
            scanner = WebAppScanner()
        else:
            scanner = ScannerFactory.get_scanner(scan_type)
        
        # Execute the scan
        scanner.start_scan(scan_id, target, options)
        
        # Get final results
        scan_result = db.scans.find_one({"_id": scan_id})
        
        logger.info(f"Background scan {scan_id} completed successfully")
        
        return {
            "scan_id": scan_id,
            "status": "completed",
            "vulnerability_count": scan_result.get("vulnerability_count", 0)
        }
        
    except Exception as e:
        logger.error(f"Background scan {scan_id} failed: {str(e)}")
        
        # Update scan status to failed
        db = get_db()
        db.scans.update_one(
            {"_id": scan_id},
            {
                "$set": {
                    "status": "failed",
                    "end_time": datetime.utcnow(),
                    "error": str(e)
                }
            }
        )
        
        raise

@celery_app.task
def process_nmap_results(scan_id, nmap_xml_output):
    """
    Process Nmap XML output and extract vulnerabilities.
    
    Args:
        scan_id: Scan identifier
        nmap_xml_output: Raw XML output from Nmap
        
    Returns:
        dict: Processed results
    """
    try:
        import xml.etree.ElementTree as ET
        
        logger.info(f"Processing Nmap results for scan {scan_id}")
        
        # Parse XML
        root = ET.fromstring(nmap_xml_output)
        
        vulnerabilities = []
        hosts_scanned = []
        
        # Extract host information
        for host in root.findall('host'):
            host_info = {}
            
            # Get host address
            address = host.find('address')
            if address is not None:
                host_info['ip'] = address.get('addr')
                host_info['type'] = address.get('addrtype')
            
            # Get hostname
            hostnames = host.find('hostnames')
            if hostnames is not None:
                hostname = hostnames.find('hostname')
                if hostname is not None:
                    host_info['hostname'] = hostname.get('name')
            
            # Get port information
            ports = host.find('ports')
            if ports is not None:
                host_info['ports'] = []
                for port in ports.findall('port'):
                    port_info = {
                        'port': port.get('portid'),
                        'protocol': port.get('protocol')
                    }
                    
                    # Get service information
                    service = port.find('service')
                    if service is not None:
                        port_info['service'] = {
                            'name': service.get('name'),
                            'product': service.get('product'),
                            'version': service.get('version')
                        }
                    
                    # Get script results
                    scripts = port.findall('script')
                    if scripts:
                        port_info['scripts'] = []
                        for script in scripts:
                            script_info = {
                                'id': script.get('id'),
                                'output': script.get('output')
                            }
                            port_info['scripts'].append(script_info)
                            
                            # Check for vulnerabilities in script output
                            if 'VULNERABLE' in script.get('output', '').upper():
                                vulnerability = {
                                    'title': f"Vulnerability detected by {script.get('id')}",
                                    'description': script.get('output', '')[:200],
                                    'severity': 'medium',
                                    'host': host_info.get('ip', 'unknown'),
                                    'port': port_info['port'],
                                    'service': port_info.get('service', {}).get('name', 'unknown')
                                }
                                vulnerabilities.append(vulnerability)
                    
                    host_info['ports'].append(port_info)
            
            hosts_scanned.append(host_info)
        
        # Store processed results
        db = get_db()
        db.scans.update_one(
            {"_id": scan_id},
            {
                "$set": {
                    "processed_results": {
                        "hosts": hosts_scanned,
                        "vulnerabilities": vulnerabilities,
                        "processed_at": datetime.utcnow()
                    }
                }
            }
        )
        
        logger.info(f"Processed Nmap results for scan {scan_id}: {len(hosts_scanned)} hosts, {len(vulnerabilities)} vulnerabilities")
        
        return {
            "hosts_count": len(hosts_scanned),
            "vulnerabilities_count": len(vulnerabilities)
        }
        
    except Exception as e:
        logger.error(f"Error processing Nmap results for scan {scan_id}: {str(e)}")
        raise

@celery_app.task
def cleanup_old_scans():
    """
    Clean up old scan data to free up storage.
    
    Returns:
        dict: Cleanup results
    """
    try:
        from datetime import timedelta
        
        logger.info("Starting cleanup of old scans")
        
        # Delete scans older than 30 days
        cutoff_date = datetime.utcnow() - timedelta(days=30)
        
        db = get_db()
        
        # Count scans to be deleted
        old_scans_count = db.scans.count_documents({
            "created_at": {"$lt": cutoff_date}
        })
        
        # Delete old scans
        result = db.scans.delete_many({
            "created_at": {"$lt": cutoff_date}
        })
        
        # Delete associated vulnerabilities
        vuln_result = db.vulnerabilities.delete_many({
            "created_at": {"$lt": cutoff_date}
        })
        
        logger.info(f"Cleanup completed: {result.deleted_count} scans and {vuln_result.deleted_count} vulnerabilities deleted")
        
        return {
            "scans_deleted": result.deleted_count,
            "vulnerabilities_deleted": vuln_result.deleted_count
        }
        
    except Exception as e:
        logger.error(f"Error during cleanup: {str(e)}")
        raise

@celery_app.task
def generate_scan_statistics():
    """
    Generate scan statistics for dashboard.
    
    Returns:
        dict: Statistics data
    """
    try:
        logger.info("Generating scan statistics")
        
        db = get_db()
        
        # Get total scans
        total_scans = db.scans.count_documents({})
        
        # Get active scans
        active_scans = db.scans.count_documents({"status": "running"})
        
        # Get completed scans in last 24 hours
        from datetime import timedelta
        yesterday = datetime.utcnow() - timedelta(days=1)
        recent_scans = db.scans.count_documents({
            "end_time": {"$gte": yesterday},
            "status": "completed"
        })
        
        # Get vulnerability statistics
        total_vulnerabilities = db.vulnerabilities.count_documents({})
        
        # Get vulnerabilities by severity
        high_vulns = db.vulnerabilities.count_documents({"severity": "high"})
        medium_vulns = db.vulnerabilities.count_documents({"severity": "medium"})
        low_vulns = db.vulnerabilities.count_documents({"severity": "low"})
        
        # Calculate success rate
        completed_scans = db.scans.count_documents({"status": "completed"})
        failed_scans = db.scans.count_documents({"status": "failed"})
        
        success_rate = 0
        if (completed_scans + failed_scans) > 0:
            success_rate = (completed_scans / (completed_scans + failed_scans)) * 100
        
        statistics = {
            "total_scans": total_scans,
            "active_scans": active_scans,
            "recent_scans": recent_scans,
            "total_vulnerabilities": total_vulnerabilities,
            "vulnerability_breakdown": {
                "high": high_vulns,
                "medium": medium_vulns,
                "low": low_vulns
            },
            "success_rate": round(success_rate, 1),
            "generated_at": datetime.utcnow().isoformat()
        }
        
        # Store statistics in cache/database
        db.statistics.replace_one(
            {"type": "scan_stats"},
            {"type": "scan_stats", "data": statistics, "updated_at": datetime.utcnow()},
            upsert=True
        )
        
        logger.info(f"Generated scan statistics: {statistics}")
        
        return statistics
        
    except Exception as e:
        logger.error(f"Error generating statistics: {str(e)}")
        raise