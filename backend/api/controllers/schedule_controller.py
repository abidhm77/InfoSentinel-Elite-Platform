"""
Schedule controller for managing scheduled penetration tests.
Provides endpoints for creating, managing, and executing scheduled scans.
"""
from flask import request, jsonify
from flask_restful import Resource
from datetime import datetime, timedelta
import uuid
from bson.objectid import ObjectId

from database.db import get_db

class ScheduleController(Resource):
    """Controller for scheduled penetration testing operations."""
    
    def get(self, schedule_id=None):
        """
        Get scheduled scan information.
        
        Args:
            schedule_id: Optional ID of specific schedule to retrieve
            
        Returns:
            JSON response with schedule data
        """
        db = get_db()
        
        if schedule_id:
            # Get specific schedule
            schedule = db.schedules.find_one({"_id": schedule_id})
            if not schedule:
                return {"error": "Schedule not found"}, 404
            
            # Convert ObjectId to string for JSON serialization
            if isinstance(schedule.get("_id"), ObjectId):
                schedule["_id"] = str(schedule["_id"])
            
            return schedule
        else:
            # Get all schedules, sorted by next run time
            schedules = list(db.schedules.find().sort("schedule_datetime", 1))
            
            # Convert ObjectId to string for JSON serialization
            for schedule in schedules:
                if isinstance(schedule.get("_id"), ObjectId):
                    schedule["_id"] = str(schedule["_id"])
            
            return schedules
    
    def post(self):
        """
        Create a new scheduled scan.
        
        Returns:
            JSON response with schedule details
        """
        data = request.get_json()
        
        # Validate required fields
        required_fields = ["name", "target", "scan_type", "schedule_date", "schedule_time"]
        for field in required_fields:
            if field not in data:
                return {"error": f"Missing required field: {field}"}, 400
        
        # Parse schedule datetime
        try:
            schedule_datetime = datetime.strptime(
                f"{data['schedule_date']} {data['schedule_time']}", 
                "%Y-%m-%d %H:%M"
            )
        except ValueError:
            return {"error": "Invalid date or time format"}, 400
        
        # Ensure schedule is in the future
        if schedule_datetime < datetime.utcnow():
            return {"error": "Schedule date must be in the future"}, 400
        
        # Create schedule record
        schedule_id = str(uuid.uuid4())
        created_at = datetime.utcnow()
        
        schedule = {
            "_id": schedule_id,
            "name": data["name"],
            "target": data["target"],
            "scan_type": data["scan_type"],
            "schedule_datetime": schedule_datetime,
            "email_notifications": data.get("email_notifications", False),
            "notes": data.get("notes", ""),
            "options": data.get("options", {}),
            "config": data.get("config", {}),
            "status": "active",
            "created_at": created_at,
            "last_run": None,
            "next_run": schedule_datetime,
            "run_count": 0
        }
        
        # Save to database
        db = get_db()
        db.schedules.insert_one(schedule)
        
        return schedule, 201
    
    def delete(self, schedule_id):
        """
        Delete a scheduled scan.
        
        Args:
            schedule_id: ID of schedule to delete
            
        Returns:
            JSON response with operation status
        """
        if not schedule_id:
            return {"error": "Schedule ID is required"}, 400
        
        db = get_db()
        result = db.schedules.delete_one({"_id": schedule_id})
        
        if result.deleted_count == 0:
            return {"error": "Schedule not found"}, 404
        
        return {"message": "Schedule deleted successfully"}, 200
    
    def put(self, schedule_id):
        """
        Update an existing scheduled scan.
        
        Args:
            schedule_id: ID of schedule to update
            
        Returns:
            JSON response with updated schedule details
        """
        if not schedule_id:
            return {"error": "Schedule ID is required"}, 400
        
        data = request.get_json()
        
        # Parse schedule datetime if provided
        update_data = {}
        
        if "schedule_date" in data and "schedule_time" in data:
            try:
                schedule_datetime = datetime.strptime(
                    f"{data['schedule_date']} {data['schedule_time']}", 
                    "%Y-%m-%d %H:%M"
                )
                if schedule_datetime < datetime.utcnow():
                    return {"error": "Schedule date must be in the future"}, 400
                update_data["schedule_datetime"] = schedule_datetime
                update_data["next_run"] = schedule_datetime
            except ValueError:
                return {"error": "Invalid date or time format"}, 400
        
        # Update other fields
        updatable_fields = ["name", "target", "scan_type", "email_notifications", "notes", "options", "config"]
        for field in updatable_fields:
            if field in data:
                update_data[field] = data[field]
        
        if not update_data:
            return {"error": "No valid fields to update"}, 400
        
        db = get_db()
        result = db.schedules.update_one(
            {"_id": schedule_id},
            {"$set": update_data}
        )
        
        if result.matched_count == 0:
            return {"error": "Schedule not found"}, 404
        
        # Return updated schedule
        updated_schedule = db.schedules.find_one({"_id": schedule_id})
        if isinstance(updated_schedule.get("_id"), ObjectId):
            updated_schedule["_id"] = str(updated_schedule["_id"])
        
        return updated_schedule