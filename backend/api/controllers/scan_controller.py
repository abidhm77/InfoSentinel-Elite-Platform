"""
Scan controller for managing penetration testing scans.
"""
from flask import request, jsonify
from flask_restful import Resource
from datetime import datetime
import uuid
import asyncio

from database.db import get_db
from orchestration.scan_orchestrator import ScanOrchestrator, ScanRequest, ScanType

class ScanController(Resource):
    """Controller for scan operations."""
    
    def get(self, scan_id=None):
        """
        Get scan information.
        
        Args:
            scan_id: Optional ID of specific scan to retrieve
            
        Returns:
            JSON response with scan data
        """
        db = get_db()
        
        if scan_id:
            # Get specific scan
            scan = db.scans.find_one({"_id": scan_id})
            if not scan:
                return {"error": "Scan not found"}, 404
            
            # Convert ObjectId to string for JSON serialization
            scan["_id"] = str(scan["_id"])
            return scan
        else:
            # Get all scans with pagination
            page = int(request.args.get('page', 1))
            per_page = int(request.args.get('per_page', 10))
            
            scans = list(db.scans.find().sort("timestamp", -1)
                        .skip((page - 1) * per_page)
                        .limit(per_page))
            
            # Convert ObjectId to string for JSON serialization
            for scan in scans:
                scan["_id"] = str(scan["_id"])
                
            return {"scans": scans, "page": page, "per_page": per_page}
    
    def post(self):
        """
        Create a new scan.
        
        Returns:
            JSON response with scan ID, status, and initial scan information
        """
        data = request.get_json()
        
        # Validate required fields
        required_fields = ["target", "scan_type"]
        for field in required_fields:
            if field not in data:
                return {"error": f"Missing required field: {field}"}, 400
        
        # Create scan record
        scan_id = str(uuid.uuid4())
        start_time = datetime.utcnow()
        
        scan = {
            "_id": scan_id,
            "target": data["target"],
            "scan_type": data["scan_type"],
            "status": "initializing",
            "progress": 0,
            "start_time": start_time,
            "options": data.get("options", {}),
            "message": "Initializing penetration test...",
            "results": {
                "vulnerabilities": [],
                "recommendations": [],
                "target_info": {}
            }
        }
        
        # Save to database
        db = get_db()
        db.scans.insert_one(scan)
        
        # Start scan in background using unified orchestrator
        try:
            orchestrator = ScanOrchestrator()
            
            # Create scan request
            scan_request = ScanRequest(
                scan_id=scan_id,
                target=data["target"],
                scan_type=ScanType(data["scan_type"]),
                options=data.get("options", {}),
                user_id="system",  # TODO: Get from auth context
                priority=5
            )
            
            # Submit scan through orchestrator
            scan_id_result = asyncio.run(orchestrator.submit_scan(scan_request))
            
            # Update scan with orchestrator response
            db.scans.update_one(
                {"_id": scan_id},
                {"$set": {
                    "status": "queued",
                    "message": "Scan queued for execution",
                    "orchestrator_task_id": scan_id_result
                }}
            )
            scan["status"] = "queued"
            scan["message"] = "Scan queued for execution"
            
        except Exception as e:
            db.scans.update_one(
                {"_id": scan_id},
                {"$set": {"status": "failed", "message": f"Failed to start scan: {str(e)}"}}
            )
            return {"error": f"Failed to start scan: {str(e)}"}, 500
        
        return scan, 201
    
    def delete(self, scan_id):
        """
        Delete a scan.
        
        Args:
            scan_id: ID of scan to delete
            
        Returns:
            JSON response with deletion status
        """
        if not scan_id:
            return {"error": "Scan ID is required"}, 400
        
        db = get_db()
        result = db.scans.delete_one({"_id": scan_id})
        
        if result.deleted_count == 0:
            return {"error": "Scan not found"}, 404
        
        # Also delete related vulnerabilities
        db.vulnerabilities.delete_many({"scan_id": scan_id})
        
        return {"message": "Scan deleted successfully"}, 200