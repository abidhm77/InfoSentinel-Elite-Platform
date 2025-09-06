"""
Scan Progress Controller for real-time monitoring of penetration tests.
"""
from flask import jsonify, request
from flask_restful import Resource
from database.db import get_db
from datetime import datetime

class ScanProgressController(Resource):
    """Controller for monitoring scan progress in real-time."""
    
    def get(self, scan_id):
        """
        Get the current progress of a scan.
        
        Args:
            scan_id: ID of the scan to check
            
        Returns:
            JSON response with scan progress data
        """
        if not scan_id:
            return {"error": "Scan ID is required"}, 400
        
        db = get_db()
        scan = db.scans.find_one({"_id": scan_id})
        
        if not scan:
            return {"error": "Scan not found"}, 404
        
        # Extract progress information
        progress_data = {
            "scan_id": scan_id,
            "status": scan.get("status", "unknown"),
            "progress": scan.get("progress", 0),
            "message": scan.get("message", ""),
            "start_time": scan.get("start_time", datetime.utcnow()).isoformat(),
            "estimated_time": scan.get("estimated_time", 0),
            "current_phase": scan.get("current_phase", "")
        }
        
        # Add end time if available
        if "end_time" in scan:
            progress_data["end_time"] = scan["end_time"].isoformat()
        
        # Add vulnerability count if available
        if "results" in scan and "vulnerabilities" in scan["results"]:
            progress_data["vulnerability_count"] = len(scan["results"]["vulnerabilities"])
        
        return progress_data
    
    def post(self, scan_id):
        """
        Update the progress of a scan (for internal use by scanners).
        
        Args:
            scan_id: ID of the scan to update
            
        Returns:
            JSON response with update status
        """
        if not scan_id:
            return {"error": "Scan ID is required"}, 400
        
        data = request.get_json()
        
        # Validate required fields
        required_fields = ["status", "progress"]
        for field in required_fields:
            if field not in data:
                return {"error": f"Missing required field: {field}"}, 400
        
        # Prepare update data
        update_data = {
            "status": data["status"],
            "progress": data["progress"],
            "message": data.get("message", ""),
            "current_phase": data.get("current_phase", "")
        }
        
        # Add end time if scan is completed or failed
        if data["status"] in ["completed", "failed"]:
            update_data["end_time"] = datetime.utcnow()
        
        # Update scan in database
        db = get_db()
        result = db.scans.update_one(
            {"_id": scan_id},
            {"$set": update_data}
        )
        
        if result.matched_count == 0:
            return {"error": "Scan not found"}, 404
        
        return {"message": "Scan progress updated successfully"}, 200