"""
Report controller for managing penetration testing reports.
"""
from flask import request, jsonify, send_file
from flask_restful import Resource
from datetime import datetime
import uuid
import os
import json
import tempfile

from database.db import get_db

class ReportController(Resource):
    """Controller for report operations."""
    
    def get(self, report_id=None):
        """
        Get report information or download a report.
        
        Args:
            report_id: Optional ID of specific report to retrieve
            
        Returns:
            JSON response with report data or a downloadable report file
        """
        db = get_db()
        
        if report_id:
            # Get specific report
            report = db.reports.find_one({"_id": report_id})
            if not report:
                return {"error": "Report not found"}, 404
            
            # Check if download is requested
            if request.args.get('download') == 'true':
                return self._generate_report_file(report)
            
            # Convert ObjectId to string for JSON serialization
            report["_id"] = str(report["_id"])
            return report
        else:
            # Get all reports with pagination
            page = int(request.args.get('page', 1))
            per_page = int(request.args.get('per_page', 10))
            
            reports = list(db.reports.find().sort("timestamp", -1)
                          .skip((page - 1) * per_page)
                          .limit(per_page))
            
            # Convert ObjectId to string for JSON serialization
            for report in reports:
                report["_id"] = str(report["_id"])
                
            return {"reports": reports, "page": page, "per_page": per_page}
    
    def post(self):
        """
        Generate a new report.
        
        Returns:
            JSON response with report ID and status
        """
        data = request.get_json()
        
        # Validate required fields
        if 'scan_id' not in data:
            return {"error": "Missing required field: scan_id"}, 400
        
        db = get_db()
        
        # Get scan data
        scan = db.scans.find_one({"_id": data['scan_id']})
        if not scan:
            return {"error": "Scan not found"}, 404
        
        # Get vulnerabilities
        vulnerabilities = list(db.vulnerabilities.find({"scan_id": data['scan_id']}))
        
        # Create report
        report_id = str(uuid.uuid4())
        report = {
            "_id": report_id,
            "scan_id": data['scan_id'],
            "target": scan['target'],
            "scan_type": scan['scan_type'],
            "timestamp": datetime.utcnow(),
            "summary": self._generate_summary(scan, vulnerabilities),
            "status": "generated"
        }
        
        # Save to database
        db.reports.insert_one(report)
        
        return {"report_id": report_id, "status": "generated"}, 201
    
    def _generate_summary(self, scan, vulnerabilities):
        """
        Generate a summary of the scan results.
        
        Args:
            scan: Scan data
            vulnerabilities: List of vulnerabilities
            
        Returns:
            Summary dictionary
        """
        # Count vulnerabilities by severity
        severity_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0
        }
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'info').lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        # Calculate risk score (0-100)
        weights = {
            "critical": 10,
            "high": 5,
            "medium": 2,
            "low": 1,
            "info": 0
        }
        
        total_vulns = sum(severity_counts.values())
        weighted_score = sum(severity_counts[sev] * weights[sev] for sev in severity_counts)
        
        # Normalize to 0-100 scale
        max_possible_score = total_vulns * weights["critical"]
        risk_score = 0
        if max_possible_score > 0:
            risk_score = min(100, int((weighted_score / max_possible_score) * 100))
        
        return {
            "total_vulnerabilities": total_vulns,
            "severity_counts": severity_counts,
            "risk_score": risk_score,
            "scan_duration": self._calculate_duration(scan),
            "top_vulnerabilities": self._get_top_vulnerabilities(vulnerabilities)
        }
    
    def _calculate_duration(self, scan):
        """
        Calculate the duration of a scan.
        
        Args:
            scan: Scan data
            
        Returns:
            Duration in seconds
        """
        start_time = scan.get('start_time')
        end_time = scan.get('end_time')
        
        if not start_time or not end_time:
            return 0
        
        return (end_time - start_time).total_seconds()
    
    def _get_top_vulnerabilities(self, vulnerabilities, limit=5):
        """
        Get the top vulnerabilities by severity.
        
        Args:
            vulnerabilities: List of vulnerabilities
            limit: Maximum number of vulnerabilities to return
            
        Returns:
            List of top vulnerabilities
        """
        # Sort by severity
        severity_order = {
            "critical": 0,
            "high": 1,
            "medium": 2,
            "low": 3,
            "info": 4
        }
        
        sorted_vulns = sorted(
            vulnerabilities,
            key=lambda v: severity_order.get(v.get('severity', 'info').lower(), 999)
        )
        
        # Return top vulnerabilities
        top_vulns = []
        for vuln in sorted_vulns[:limit]:
            top_vulns.append({
                "title": vuln.get('title', 'Unknown'),
                "severity": vuln.get('severity', 'info'),
                "description": vuln.get('description', '')
            })
        
        return top_vulns
    
    def _generate_report_file(self, report):
        """
        Generate a downloadable report file.
        
        Args:
            report: Report data
            
        Returns:
            File download response
        """
        db = get_db()
        
        # Get scan data
        scan = db.scans.find_one({"_id": report['scan_id']})
        
        # Get vulnerabilities
        vulnerabilities = list(db.vulnerabilities.find({"scan_id": report['scan_id']}))
        
        # Create report data
        report_data = {
            "report_id": report["_id"],
            "target": report["target"],
            "scan_type": report["scan_type"],
            "timestamp": report["timestamp"].isoformat(),
            "summary": report["summary"],
            "vulnerabilities": [
                {
                    "title": v.get("title", "Unknown"),
                    "description": v.get("description", ""),
                    "severity": v.get("severity", "info"),
                    "details": v.get("details", {})
                }
                for v in vulnerabilities
            ]
        }
        
        # Create temporary file
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as temp:
            temp.write(json.dumps(report_data, indent=2).encode('utf-8'))
            temp_path = temp.name
        
        # Return file
        return send_file(
            temp_path,
            as_attachment=True,
            download_name=f"security_report_{report['_id']}.json",
            mimetype='application/json'
        )